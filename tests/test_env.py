import os
import tempfile
import unittest
from unittest import mock

import helpers
import egress_proxy
from egress_ui.configstore import (
    ENV_DEFAULTS,
    strip_env_keys,
    update_env_text,
    validate_env,
    validate_list,
    warnings_for,
)
from egress_ui.settings import UiConfigError, load_ui_config, set_ui_value


class ParseEnvTest(unittest.TestCase):
    def test_parse(self):
        text = (
            "# комментарий\n"
            "; тоже\n"
            "\n"
            "DNS_PORT=5353\n"
            "export IPV6=0\n"
            "ALLOW_CLIENTS = '203.0.113.8' \n"
            'DNS_UPSTREAM="1.1.1.1"\n'
            "1BAD=x\n"
            "NOEQUALS\n"
            "EMPTY=\n"
            "DNS_PORT=53\n"
        )
        parsed = egress_proxy.parse_env_text(text)
        self.assertEqual(parsed["DNS_PORT"], "53")
        self.assertEqual(parsed["IPV6"], "0")
        self.assertEqual(parsed["ALLOW_CLIENTS"], "203.0.113.8")
        self.assertEqual(parsed["DNS_UPSTREAM"], "1.1.1.1")
        self.assertEqual(parsed["EMPTY"], "")
        self.assertNotIn("1BAD", parsed)
        self.assertNotIn("NOEQUALS", parsed)

    def test_apply_env_file_overrides(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "egress.env")
            with open(path, "w", encoding="utf-8-sig") as handle:
                handle.write("DNS_PORT=5353\n")
            with mock.patch.dict(os.environ, {"DNS_PORT": "53"}):
                egress_proxy.apply_env_file(path, required=True)
                self.assertEqual(os.environ["DNS_PORT"], "5353")
            with self.assertRaises(egress_proxy.ConfigError):
                egress_proxy.apply_env_file(os.path.join(folder, "nope"), required=True)
            egress_proxy.apply_env_file(os.path.join(folder, "nope"), required=False)


class UpdateEnvTest(unittest.TestCase):
    def test_in_place(self):
        text = "# шапка\nDNS_PORT=53\n# про порты\nPROXY_PORTS=80,443\nOTHER=1\nPROXY_PORTS=1\n"
        updated = update_env_text(text, {"PROXY_PORTS": "80,443,15000-15099", "DNS_PORT": "53"})
        self.assertEqual(
            updated,
            "# шапка\nDNS_PORT=53\n# про порты\nPROXY_PORTS=80,443,15000-15099\nOTHER=1\n",
        )

    def test_append_missing(self):
        updated = update_env_text("DNS_PORT=53", {"ALLOW_CLIENTS": "203.0.113.8"})
        self.assertEqual(updated, "DNS_PORT=53\n\n# Добавлено через Web UI\nALLOW_CLIENTS=203.0.113.8\n")
        self.assertEqual(update_env_text("", {"IPV6": "0"}), "# Добавлено через Web UI\nIPV6=0\n")

    def test_export_and_comment(self):
        updated = update_env_text("export IPV6=1\n#IPV6=0\n", {"IPV6": "0"})
        self.assertEqual(updated, "IPV6=0\n#IPV6=0\n")

    def test_strip_keys(self):
        text = "DESTINATIONS_FILE=/x\nDNS_PORT=53\n# DIRECT_FILE=/y\n"
        self.assertEqual(strip_env_keys(text, {"DESTINATIONS_FILE", "DIRECT_FILE"}), "DNS_PORT=53\n# DIRECT_FILE=/y\n")


class ValidateTest(unittest.TestCase):
    def values(self, **changes):
        found = dict(ENV_DEFAULTS)
        found.update(changes)
        return found

    def test_defaults_ok(self):
        self.assertEqual(validate_env(self.values(), 8443), {})
        self.assertEqual(validate_env(self.values(PROXY_PORTS="80,443,42130,44326,15000-15099", ALLOW_CLIENTS="203.0.113.8, 198.51.100.0/24"), 8443), {})

    def test_errors(self):
        cases = {
            "DNS_PORT": ("70000", "DNS_PORT"),
            "LISTEN_IP": ("localhost", "LISTEN_IP"),
            "IPV6": ("2", "IPV6"),
            "DNS_UPSTREAM": ("1.1.1.1,dns.google", "DNS_UPSTREAM"),
            "ALLOW_CLIENTS": ("203.0.113.300", "ALLOW_CLIENTS"),
            "MAX_WILDCARD_DEPTH": ("21", "MAX_WILDCARD_DEPTH"),
            "ANSWER_TTL": ("x", "ANSWER_TTL"),
        }
        for key, (value, expected) in cases.items():
            errors = validate_env(self.values(**{key: value}), 8443)
            self.assertIn(expected, errors, key)

    def test_port_conflicts(self):
        self.assertIn("22", validate_env(self.values(PROXY_PORTS="20-30"), 8443)["PROXY_PORTS"])
        self.assertIn("8443", validate_env(self.values(PROXY_PORTS="443,8443"), 8443)["PROXY_PORTS"])
        self.assertIn("53", validate_env(self.values(PROXY_PORTS="53,80"), 8443)["PROXY_PORTS"])
        self.assertIn("PROXY_PORTS", validate_env(self.values(PROXY_PORTS="1-1000"), 8443))

    def test_injection(self):
        errors = validate_env(self.values(ALLOW_CLIENTS="1.2.3.4\nDNS_PORT=5"), 8443)
        self.assertIn("ALLOW_CLIENTS", errors)
        self.assertIn("NEW_KEY", validate_env(self.values(NEW_KEY="1"), 8443))

    def test_lists(self):
        self.assertEqual(validate_list("proxy", "xboxlive.com\n*.xbox.com # c\n"), [])
        self.assertTrue(validate_list("proxy", "# только комментарий\n"))
        self.assertIn("строка 2", validate_list("proxy", "xboxlive.com\n203.0.113.8\n")[0])
        self.assertTrue(validate_list("proxy", "com\n"))
        self.assertEqual(validate_list("direct", ""), [])
        self.assertEqual(validate_list("exits", "auto\n203.0.113.5\n[2001:db8::1]\nvps.example.com\n"), [])
        self.assertTrue(validate_list("exits", "not a host!\n"))
        self.assertTrue(validate_list("exits", ""))
        self.assertTrue(validate_list("proxy", "a\x00b.com"))

    def test_warnings(self):
        found = warnings_for({"ALLOW_CLIENTS": ""}, "microsoft.com\nxboxlive.com\n")
        self.assertTrue(any("ALLOW_CLIENTS" in item for item in found))
        self.assertTrue(any("microsoft.com" in item for item in found))
        found = warnings_for({"ALLOW_CLIENTS": "203.0.113.8"}, "xboxlive.com\n")
        self.assertFalse(any("ALLOW_CLIENTS" in item for item in found))


class UiSettingsTest(unittest.TestCase):
    def test_load_and_env(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "ui.env")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("UI_PORT=9443\nUI_ALLOW_CLIENTS=203.0.113.0/24\nUI_PASSWORD_HASH=x\n")
            cfg = load_ui_config(path, {"UI_LISTEN": "127.0.0.1", "EGRESS_CONFIG_DIR": "/srv/egress", "HOME": "/root"})
            self.assertEqual(cfg.port, 9443)
            self.assertEqual(cfg.listen, "127.0.0.1")
            self.assertEqual(cfg.env_file, "/srv/egress/egress.env")
            self.assertEqual(cfg.destinations_file, "/srv/egress/allow-destinations.txt")
            self.assertEqual([str(item) for item in cfg.allow_clients], ["203.0.113.0/24"])
            self.assertTrue(cfg.tls)
            docker = load_ui_config(path, {"UI_SERVICE_BACKEND": "docker"})
            self.assertEqual(docker.firewall_backend, "none")

    def test_rejects(self):
        with self.assertRaises(UiConfigError):
            load_ui_config("/nonexistent/ui.env", {"UI_INSECURE_HTTP": "1"})
        with self.assertRaises(UiConfigError):
            load_ui_config("/nonexistent/ui.env", {"UI_INSECURE_HTTP": "1", "UI_LISTEN": "203.0.113.5"})
        tunnel = load_ui_config("/nonexistent/ui.env", {"UI_INSECURE_HTTP": "1", "UI_LISTEN": "127.0.0.1", "UI_SSH_PORT": "2222", "UI_PUBLIC_HOST": "203.0.113.5"})
        self.assertTrue(tunnel.tunnel)
        self.assertFalse(tunnel.tls)
        self.assertEqual((tunnel.ssh_port, tunnel.public_host), (2222, "203.0.113.5"))
        self.assertTrue(load_ui_config("/nonexistent/ui.env", {"UI_INSECURE_HTTP": "yes", "UI_LISTEN": "::1"}).tunnel)
        with self.assertRaises(UiConfigError):
            load_ui_config("/nonexistent/ui.env", {"UI_PUBLIC_HOST": "evil host;rm"})
        for env in ({"UI_PORT": "0"}, {"UI_PORT": "x"}, {"UI_LISTEN": "host"}, {"UI_SERVICE_BACKEND": "k8s"}, {"UI_ALLOW_CLIENTS": "x"}):
            with self.assertRaises(UiConfigError, msg=str(env)):
                load_ui_config("/nonexistent/ui.env", env)

    def test_set_value(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "sub", "ui.env")
            set_ui_value(path, "UI_PASSWORD_HASH", "first")
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("# комментарий\nUI_PORT=8443\n")
            set_ui_value(path, "UI_PASSWORD_HASH", "second")
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "UI_PASSWORD_HASH=second\n# комментарий\nUI_PORT=8443\n")
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaises(UiConfigError):
                set_ui_value(path, "UI_PORT", "1\nUI_X=2")


if __name__ == "__main__":
    unittest.main()
