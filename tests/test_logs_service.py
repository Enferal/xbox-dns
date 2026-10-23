import json
import struct
import unittest

import helpers
from egress_ui.logparse import enrich, parse_line, summarize
from egress_ui.service import (
    SystemdService,
    docker_frames,
    docker_log_entry,
    journal_entry,
    parse_docker_time,
    parse_show,
)


class LogParseTest(unittest.TestCase):
    def test_kinds(self):
        cases = [
            ("Отказ DNS клиенту 198.51.100.7: адреса нет в ALLOW_CLIENTS", "refused", "198.51.100.7", ""),
            ("Прокси user.auth.xboxlive.com:443 -> 20.1.2.3 с адреса 203.0.113.5 клиент=198.51.100.7", "proxy", "198.51.100.7", "user.auth.xboxlive.com"),
            ("DNS user.auth.xboxlive.com A -> 203.0.113.5 клиент=198.51.100.7", "dns", "198.51.100.7", "user.auth.xboxlive.com"),
            ("DNS assets1.xboxlive.com A закачка напрямую, адрес сети доставки клиент=2001:db8::7", "direct", "2001:db8::7", "assets1.xboxlive.com"),
            ("TCP входящий порт=443 клиент=198.51.100.7:51234", "tcp", "198.51.100.7", ""),
            ("TCP входящий порт=443 клиент=2001:db8::7:51234", "tcp", "2001:db8::7", ""),
            ("Прокси ошибка клиент=198.51.100.7 порт=443: timed out", "error", "198.51.100.7", ""),
            ("Прокси закрыл соединение без подходящего имени, клиент=198.51.100.7:5000 порт=443 имя=evil.com", "error", "198.51.100.7", "evil.com"),
            ("Сервис запущен", "other", "", ""),
        ]
        for message, kind, client, domain in cases:
            event = parse_line(message)
            self.assertEqual(event["kind"], kind, message)
            self.assertEqual(event["client"], client, message)
            self.assertEqual(event["domain"], domain, message)
        self.assertEqual(parse_line("TCP входящий порт=15007 клиент=1.2.3.4:5")["port"], 15007)

    def test_priority_marks_error(self):
        self.assertEqual(enrich({"msg": "Traceback", "prio": 3})["kind"], "error")
        self.assertEqual(enrich({"msg": "Traceback", "prio": 6})["kind"], "other")

    def test_summarize(self):
        lines = [
            "Прокси a.ea.com:443 -> 1.1.1.1 с адреса 2.2.2.2 клиент=10.0.0.1",
            "Прокси a.ea.com:15007 -> 1.1.1.1 с адреса 2.2.2.2 клиент=10.0.0.1",
            "Прокси b.ea.com:443 -> 1.1.1.1 с адреса 2.2.2.2 клиент=10.0.0.2",
            "Отказ прокси клиенту 198.51.100.9: адреса нет в ALLOW_CLIENTS",
            "Отказ DNS клиенту 198.51.100.9: адреса нет в ALLOW_CLIENTS",
            "DNS ошибка что-то",
        ]
        summary = summarize([{"msg": line, "ts": index, "prio": 6} for index, line in enumerate(lines)])
        self.assertEqual(summary["top_domains"][0], ("a.ea.com", 2))
        self.assertEqual(summary["top_clients"][0], ("10.0.0.1", 2))
        self.assertEqual(dict(summary["top_ports"])[443], 2)
        self.assertEqual(summary["refused"], [{"client": "198.51.100.9", "count": 2, "last": 4}])
        self.assertEqual(len(summary["errors"]), 1)
        self.assertEqual(summary["lines"], 6)


class JournalTest(unittest.TestCase):
    def test_entry(self):
        entry = journal_entry(json.dumps({"MESSAGE": "привет", "PRIORITY": "3", "__REALTIME_TIMESTAMP": "1700000000000000"}), "proxy")
        self.assertEqual(entry, {"ts": 1700000000.0, "msg": "привет", "prio": 3, "unit": "proxy"})
        raw = list("байты".encode("utf-8"))
        self.assertEqual(journal_entry(json.dumps({"MESSAGE": raw}))["msg"], "байты")
        self.assertIsNone(journal_entry("не json"))
        self.assertEqual(journal_entry(json.dumps({"MESSAGE": None}))["msg"], "")

    def test_show(self):
        self.assertEqual(parse_show("ActiveState=active\nNRestarts=2\nbad\n"), {"ActiveState": "active", "NRestarts": "2"})

    def test_restart_detects_crash_loop(self):
        states = iter(["1", "1", "2"])
        runner = helpers.FakeRunner()

        def show(argv, env):
            return helpers.Result(0, f"ActiveState=active\nSubState=running\nNRestarts={next(states, '2')}\nMainPID=5\n", "")

        runner.on(["systemctl", "show"], show)
        runner.add(["journalctl"], 0, json.dumps({"MESSAGE": "упал"}) + "\n")
        service = SystemdService(runner, "egress-proxy", "egress-proxy-ui", settle=1.0, sleep=lambda _: None)
        result = service.restart_and_wait()
        self.assertFalse(result["ok"])
        self.assertEqual(result["logs"][0]["msg"], "упал")
        self.assertIn(["systemctl", "restart", "egress-proxy"], runner.calls)

    def test_restart_ok_and_bad_action(self):
        runner = helpers.FakeRunner()
        runner.add(["systemctl", "show"], 0, "ActiveState=active\nNRestarts=0\n")
        service = SystemdService(runner, "egress-proxy", "egress-proxy-ui", settle=1.0, sleep=lambda _: None)
        self.assertTrue(service.restart_and_wait()["ok"])
        self.assertFalse(service.action("kill")["ok"])
        with self.assertRaises(ValueError):
            SystemdService(runner, "bad unit; rm", "x")


class DockerTest(unittest.TestCase):
    def test_frames(self):
        def frame(stream, text):
            data = text.encode("utf-8")
            return bytes([stream, 0, 0, 0]) + struct.pack(">I", len(data)) + data

        blob = frame(1, "2024-05-01T10:00:00.123456789Z Сервис запущен\n") + frame(2, "2024-05-01T10:00:01Z ошибка\n") + b"\x01\x00"
        pos = 0

        def read(size):
            nonlocal pos
            chunk = blob[pos : pos + size]
            pos += len(chunk)
            return chunk

        frames = list(docker_frames(read))
        self.assertEqual(len(frames), 2)
        first = docker_log_entry(frames[0][1].decode().rstrip("\n"), frames[0][0])
        self.assertEqual(first["msg"], "Сервис запущен")
        self.assertAlmostEqual(first["ts"], 1714557600.123456, places=5)
        second = docker_log_entry(frames[1][1].decode(), frames[1][0])
        self.assertEqual(second["prio"], 3)

    def test_time(self):
        self.assertIsNone(parse_docker_time("0001-01-01T00:00:00Z"))
        self.assertIsNone(parse_docker_time("вчера"))
        self.assertEqual(parse_docker_time("2024-05-01T13:00:00+03:00"), 1714557600.0)


if __name__ == "__main__":
    unittest.main()
