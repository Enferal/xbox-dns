import os
import sys
import unittest

import helpers
from egress_ui.configstore import ConfigStore, ConflictError, Snapshot, ValidationError
from egress_ui.system import Runner


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = helpers.TempConfig()
        self.runner = helpers.FakeRunner()
        self.runner.on([sys.executable], helpers.check_reply(ok=True))
        self.service = helpers.FakeService()
        self.store = ConfigStore(self.tmp.cfg, self.runner, self.service)

    def tearDown(self):
        self.tmp.cleanup()

    def test_state(self):
        state = self.store.state()
        self.assertEqual(state["env"]["DNS_PORT"], "53")
        self.assertEqual(state["files"]["proxy"], helpers.PROXY_TEXT)
        self.assertIsNone(state["files"]["direct"])
        self.assertEqual(len(state["etag"]), 32)
        self.assertEqual(state["etag"], self.store.state()["etag"])

    def test_validate_diff_and_check_args(self):
        result = self.store.validate({"env": {"PROXY_PORTS": "80,443,15000-15099"}})
        self.assertTrue(result["ok"], result)
        self.assertIn("+PROXY_PORTS=80,443,15000-15099", result["diff"]["env"])
        self.assertIn("-PROXY_PORTS=80,443", result["diff"]["env"])
        argv = self.runner.calls[-1]
        self.assertIn("--check-config", argv)
        self.assertIn("--json", argv)
        self.assertEqual(argv[argv.index("--env-file") + 1].rsplit(os.sep, 1)[-1], "egress.env")

    def test_validate_errors_without_check(self):
        result = self.store.validate({"env": {"DNS_PORT": "abc"}, "files": {"proxy": "1.2.3.4\n"}})
        self.assertFalse(result["ok"])
        self.assertIn("DNS_PORT", result["errors"])
        self.assertIn("proxy", result["errors"])
        self.assertEqual(self.runner.calls, [])

    def test_apply_writes_backup_and_restarts(self):
        before = self.store.state()["etag"]
        result = self.store.apply({"etag": before, "files": {"proxy": "xboxlive.com\nea.com"}})
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["changed"])
        self.assertEqual(self.tmp.read("allow-destinations.txt"), "xboxlive.com\nea.com\n")
        self.assertEqual(self.service.restarts, 1)
        backups = self.store.backups()
        self.assertEqual(len(backups), 1)
        self.assertEqual(self.store.load_backup(backups[0]["id"]).texts["proxy"], helpers.PROXY_TEXT)
        if os.name == "posix":
            self.assertEqual(os.stat(self.tmp.path("allow-destinations.txt")).st_mode & 0o777, 0o640)

    def test_apply_no_changes(self):
        result = self.store.apply({"files": {"proxy": helpers.PROXY_TEXT}})
        self.assertTrue(result["ok"])
        self.assertFalse(result["changed"])
        self.assertEqual(self.service.restarts, 0)
        self.assertEqual(self.store.backups(), [])

    def test_conflict(self):
        with self.assertRaises(ConflictError):
            self.store.apply({"etag": "0" * 32, "env": {"IPV6": "0"}})

    def test_check_failure_keeps_files(self):
        runner = helpers.FakeRunner()
        runner.on([sys.executable], helpers.check_reply(ok=False, error="Нет доменов"))
        store = ConfigStore(self.tmp.cfg, runner, self.service)
        result = store.apply({"env": {"IPV6": "0"}})
        self.assertFalse(result["ok"])
        self.assertEqual(result["errors"]["check"], "Нет доменов")
        self.assertEqual(self.tmp.read("egress.env"), helpers.ENV_TEXT)
        self.assertEqual(self.service.restarts, 0)

    def test_rollback_when_service_fails(self):
        service = helpers.FakeService([{"ok": False, "error": "failed"}, {"ok": True}])
        store = ConfigStore(self.tmp.cfg, self.runner, service)
        result = store.apply({"env": {"ALLOW_CLIENTS": "203.0.113.8"}, "files": {"direct": "dl.example.com\n"}})
        self.assertFalse(result["ok"])
        self.assertTrue(result["rolled_back"])
        self.assertEqual(service.restarts, 2)
        self.assertEqual(self.tmp.read("egress.env"), helpers.ENV_TEXT)
        self.assertFalse(os.path.exists(self.tmp.path("direct-destinations.txt")))

    def test_restore(self):
        first = self.store.apply({"env": {"IPV6": "0"}})
        self.assertTrue(first["ok"])
        self.assertIn("IPV6=0", self.tmp.read("egress.env"))
        restored = self.store.apply({"restore": first["backup"]}, reason="возврат")
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(self.tmp.read("egress.env"), helpers.ENV_TEXT)
        self.assertEqual(len(self.store.backups()), 2)

    def test_restore_unknown(self):
        with self.assertRaises(ValidationError):
            self.store.apply({"restore": "../../etc"})

    def test_env_keeps_comments(self):
        self.store.apply({"env": {"ALLOW_CLIENTS": "203.0.113.8"}})
        text = self.tmp.read("egress.env")
        self.assertTrue(text.startswith("# Настройки egress-proxy\n"))
        self.assertIn("ALLOW_CLIENTS=203.0.113.8\n", text)


@unittest.skipUnless(helpers.has_default_route(), "нужен ip и маршрут по умолчанию")
class RealCheckTest(unittest.TestCase):
    """Черновик проверяет настоящий egress_proxy.py --check-config --json."""

    def setUp(self):
        self.tmp = helpers.TempConfig(env=helpers.ENV_TEXT + "DESTINATIONS_FILE=/nonexistent\n")
        self.store = ConfigStore(self.tmp.cfg, Runner(), helpers.FakeService())

    def tearDown(self):
        self.tmp.cleanup()

    def test_ok(self):
        check = self.store.check(self.store.read())
        self.assertTrue(check["ok"], check)
        self.assertEqual(check["plan"]["domains"], ["xboxlive.com", "xbox.com"])
        self.assertEqual(check["plan"]["proxy_ports"], "80, 443")

    def test_error(self):
        snapshot = self.store.read()
        texts = dict(snapshot.texts)
        texts["env"] = helpers.ENV_TEXT.replace("MAX_WILDCARD_DEPTH=4", "MAX_WILDCARD_DEPTH=99")
        check = self.store.check(Snapshot(texts))
        self.assertFalse(check["ok"])
        self.assertIn("MAX_WILDCARD_DEPTH", check["error"])


if __name__ == "__main__":
    unittest.main()
