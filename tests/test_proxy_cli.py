import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

import helpers
import egress_proxy
from egress_ui.diagnostics import dns_query, match_name, service_port_list


def run(argv, env=None, input_text=None):
    return subprocess.run(argv, capture_output=True, text=True, env=env, input=input_text, timeout=60)


class CheckConfigJsonTest(unittest.TestCase):
    def test_error_json(self):
        with tempfile.TemporaryDirectory() as folder:
            env_file = os.path.join(folder, "egress.env")
            with open(env_file, "w", encoding="utf-8") as handle:
                handle.write(f"DESTINATIONS_FILE={os.path.join(folder, 'missing.txt')}\n")
            out = run([sys.executable, helpers.PROXY_SCRIPT, "--check-config", "--json", "--env-file", env_file])
            self.assertEqual(out.returncode, 1)
            data = json.loads(out.stdout.strip().splitlines()[-1])
            self.assertFalse(data["ok"])
            self.assertIn("missing.txt", data["error"])
            self.assertIn("Ошибка конфигурации", out.stderr)

    def test_missing_env_file(self):
        out = run([sys.executable, helpers.PROXY_SCRIPT, "--check-config", "--json", "--env-file", "/nonexistent/egress.env"])
        self.assertEqual(out.returncode, 1)
        self.assertFalse(json.loads(out.stdout)["ok"])

    def test_bad_number_is_config_error(self):
        tmp = helpers.TempConfig(env="ANSWER_TTL=abc\n")
        try:
            env = dict(os.environ, DESTINATIONS_FILE=tmp.path("allow-destinations.txt"), EXIT_IPS_FILE=tmp.path("exit-ips.txt"))
            out = run([sys.executable, helpers.PROXY_SCRIPT, "--check-config", "--json", "--env-file", tmp.path("egress.env")], env)
            self.assertEqual(out.returncode, 1, out.stderr)
            self.assertFalse(json.loads(out.stdout.strip().splitlines()[-1])["ok"])
        finally:
            tmp.cleanup()

    @unittest.skipUnless(helpers.has_default_route(), "нужен ip и маршрут по умолчанию")
    def test_ok_json(self):
        tmp = helpers.TempConfig(env="PROXY_PORTS=80,443,15000-15099\nALLOW_CLIENTS=203.0.113.8\n")
        try:
            env = dict(
                os.environ,
                DESTINATIONS_FILE=tmp.path("allow-destinations.txt"),
                EXIT_IPS_FILE=tmp.path("exit-ips.txt"),
                EGRESS_ENV_FILE=tmp.path("egress.env"),
            )
            out = run([sys.executable, helpers.PROXY_SCRIPT, "--check-config", "--json"], env)
            self.assertEqual(out.returncode, 0, out.stderr)
            data = json.loads(out.stdout)
            self.assertTrue(data["ok"])
            self.assertEqual(data["plan"]["proxy_ports"], "80, 443, 15000-15099")
            self.assertEqual(data["plan"]["allow"], ["203.0.113.8/32"])
            self.assertTrue(data["plan"]["exits_v4"])
        finally:
            tmp.cleanup()


class StatusFileTest(unittest.TestCase):
    def test_write_status(self):
        settings = egress_proxy.Settings(["xboxlive.com"], ["203.0.113.5"], [], set(), "0.0.0.0", 53, [80, 443], ["1.1.1.1"], [], 4, 60)
        settings.count("dns_queries")
        settings.count("dns_queries")
        settings.count("proxy_ok")
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "status.json")
            egress_proxy.write_status(path, settings, 1000.0)
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(os.listdir(folder), ["status.json"])
        self.assertEqual(data["counters"], {"dns_queries": 2, "proxy_ok": 1})
        self.assertEqual(data["started_at"], 1000.0)
        self.assertEqual(data["plan"]["domains"], ["xboxlive.com"])
        self.assertEqual(data["plan"]["proxy_ports"], "80, 443")
        self.assertEqual(data["pid"], os.getpid())


class UiCliTest(unittest.TestCase):
    def env(self, folder):
        return dict(os.environ, PYTHONPATH=helpers.SCRIPTS, UI_ENV_FILE=os.path.join(folder, "ui.env"))

    def test_set_password_stdin(self):
        with tempfile.TemporaryDirectory() as folder:
            out = run([sys.executable, "-m", "egress_ui", "set-password", "--stdin"], self.env(folder), "correct horse battery\n")
            self.assertEqual(out.returncode, 0, out.stderr)
            path = os.path.join(folder, "ui.env")
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            self.assertTrue(text.startswith("UI_PASSWORD_HASH=pbkdf2_sha256$600000$"))
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            from egress_ui.auth import verify_password

            self.assertTrue(verify_password("correct horse battery", text.strip().split("=", 1)[1]))
            short = run([sys.executable, "-m", "egress_ui", "set-password", "--stdin"], self.env(folder), "short\n")
            self.assertEqual(short.returncode, 1)

    def test_serve_without_password(self):
        with tempfile.TemporaryDirectory() as folder:
            env = self.env(folder)
            env.update(UI_LISTEN="127.0.0.1", UI_INSECURE_HTTP="1", UI_SERVICE_BACKEND="none")
            out = run([sys.executable, "-m", "egress_ui"], env)
            self.assertEqual(out.returncode, 1)
            self.assertIn("set-password", out.stderr)
            env.update(UI_LISTEN="0.0.0.0")
            out = run([sys.executable, "-m", "egress_ui", "serve"], env)
            self.assertEqual(out.returncode, 2)
            self.assertIn("127.0.0.1", out.stderr)


class DiagnosticsTest(unittest.TestCase):
    def test_match(self):
        proxy = "xboxlive.com\nea.com # EA\n"
        direct = "assets1.xboxlive.com\n"
        self.assertEqual(match_name("a.b.xboxlive.com", proxy, direct, 4)["verdict"], "proxy")
        self.assertEqual(match_name("assets1.xboxlive.com", proxy, direct, 4)["verdict"], "direct")
        self.assertEqual(match_name("a.b.c.d.e.xboxlive.com", proxy, direct, 4)["verdict"], "none")
        self.assertEqual(match_name("example.org", proxy, direct, 4)["verdict"], "none")
        sites = "themoviedb.org\nxboxlive.com\n"
        self.assertTrue(match_name("media.themoviedb.org", sites, "", 4)["alias"])
        self.assertFalse(match_name("www.themoviedb.org", sites, "", 4)["alias"])
        self.assertFalse(match_name("user.auth.xboxlive.com", sites, "", 4)["alias"])
        self.assertFalse(match_name("media.themoviedb.org", sites, "", 4, "themoviedb.org\n")["alias"])
        self.assertFalse(match_name("media.themoviedb.org", sites, "", 4, None, False)["alias"])
        with self.assertRaises(ValueError):
            match_name("bad name", proxy, direct, 4)

    def test_ports(self):
        self.assertEqual(service_port_list("53", "80,443,53,15000-15002"), [53, 80, 443, 15000, 15001, 15002])

    def test_dns_query(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def answer():
            data, addr = server.recvfrom(4096)
            server.sendto(egress_proxy.synthetic_response(data, egress_proxy.QTYPE_A, ["203.0.113.5"], 60), addr)

        thread = threading.Thread(target=answer, daemon=True)
        thread.start()
        try:
            result = dns_query("user.auth.xboxlive.com", "A", "127.0.0.1", port, timeout=3)
        finally:
            thread.join(5)
            server.close()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["rcode"], "NOERROR")
        self.assertEqual(result["answers"], ["203.0.113.5"])
        with self.assertRaises(ValueError):
            dns_query("x", "MX")

    def test_dns_timeout(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(("127.0.0.1", 0))
            result = dns_query("example.com", "A", "127.0.0.1", silent.getsockname()[1], timeout=0.3)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
