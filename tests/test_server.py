import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings

import helpers
from egress_ui.auth import hash_password
from egress_ui.server import App, UiServer, make_ssl_context
from egress_ui.service import NullService

PASSWORD = "correct horse battery"
PASSWORD_HASH = hash_password(PASSWORD, iterations=1000)


class ServerCase(unittest.TestCase):
    tls = False

    @classmethod
    def setUpClass(cls):
        cls.tmp = helpers.TempConfig()
        cls.tmp.cfg.password_hash = PASSWORD_HASH
        cls.tmp.cfg.public_host = "203.0.113.5"
        cls.tmp.cfg.ssh_port = 2222
        cls.runner = helpers.FakeRunner()
        cls.runner.on([sys.executable], helpers.check_reply(ok=True))
        context = cls.make_context()
        cls.app = App(cls.tmp.cfg, runner=cls.runner, service=NullService())
        cls.server = UiServer(cls.app, context)
        cls.port = cls.server.server_address[1]
        cls.tmp.cfg.port = cls.port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def make_context(cls):
        return None

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def connection(self):
        if self.tls:
            return http.client.HTTPSConnection("127.0.0.1", self.port, timeout=10, context=ssl._create_unverified_context())
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)

    def request(self, method, path, body=None, headers=None):
        conn = self.connection()
        data = None
        all_headers = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode()
            all_headers.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=all_headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw
        return resp, payload

    def login(self):
        resp, data = self.request("POST", "/api/login", {"password": PASSWORD}, {"X-Requested-With": "egress-ui"})
        self.assertEqual(resp.status, 200, data)
        cookie = resp.getheader("Set-Cookie")
        return cookie.split(";", 1)[0], data["csrf"], cookie


class HttpServerTest(ServerCase):
    def test_static_and_headers(self):
        resp, body = self.request("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn("text/html", resp.getheader("Content-Type"))
        self.assertIn("default-src 'self'", resp.getheader("Content-Security-Policy"))
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Referrer-Policy"), "no-referrer")
        self.assertIsNone(resp.getheader("Strict-Transport-Security"))
        for name in ("/static/app.js", "/static/lib.js", "/static/style.css"):
            resp, _ = self.request("GET", name)
            self.assertEqual(resp.status, 200, name)
        self.assertIn("javascript", self.request("GET", "/static/app.js")[0].getheader("Content-Type"))

    def test_static_traversal(self):
        for path in ("/static/../server.py", "/..%2fserver.py", "/server.py", "/static/missing.js", "/%2e%2e/etc/passwd"):
            resp, _ = self.request("GET", path)
            self.assertEqual(resp.status, 404, path)

    def test_requires_session(self):
        resp, data = self.request("GET", "/api/overview")
        self.assertEqual(resp.status, 401)
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        resp, _ = self.request("POST", "/api/service", {"action": "stop"})
        self.assertEqual(resp.status, 401)
        resp, _ = self.request("GET", "/api/nope")
        self.assertEqual(resp.status, 404)

    def test_login_rules(self):
        resp, _ = self.request("POST", "/api/login", {"password": PASSWORD})
        self.assertEqual(resp.status, 403, "без X-Requested-With")
        resp, _ = self.request("POST", "/api/login", {"password": "wrong password!"}, {"X-Requested-With": "egress-ui", "X-Forwarded-For": "1.1.1.1"})
        self.assertEqual(resp.status, 401)
        self.app.limiter.success("127.0.0.1")

    def test_session_flow(self):
        cookie, csrf, raw_cookie = self.login()
        self.assertTrue(cookie.startswith("egress_ui="), raw_cookie)
        self.assertIn("HttpOnly", raw_cookie)
        self.assertIn("SameSite=Strict", raw_cookie)
        self.assertNotIn("Secure", raw_cookie, "по http без Secure")
        self.assertNotIn("__Host-", raw_cookie)

        resp, data = self.request("GET", "/api/session", headers={"Cookie": cookie})
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["csrf"], csrf)
        self.assertEqual(data["ui"]["access"]["mode"], "tunnel")

        resp, data = self.request("GET", "/api/config", headers={"Cookie": cookie})
        self.assertEqual(resp.status, 200)
        self.assertEqual(data["env"]["DNS_PORT"], "53")

        resp, data = self.request("POST", "/api/config/validate", {"env": {"IPV6": "0"}}, {"Cookie": cookie})
        self.assertEqual(resp.status, 403, "без CSRF")
        resp, data = self.request("POST", "/api/config/validate", {"env": {"IPV6": "0"}}, {"Cookie": cookie, "X-CSRF-Token": "x" + csrf})
        self.assertEqual(resp.status, 403, "чужой CSRF")
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        resp, data = self.request("POST", "/api/config/validate", {"env": {"IPV6": "0"}}, headers)
        self.assertEqual(resp.status, 200, data)
        self.assertTrue(data["ok"])
        self.assertIn("+IPV6=0", data["diff"]["env"])

        resp, data = self.request("POST", "/api/config/validate", {}, dict(headers, Origin="https://evil.example"))
        self.assertEqual(resp.status, 403, "чужой Origin")
        resp, data = self.request("POST", "/api/config/validate", {}, dict(headers, Origin=f"http://127.0.0.1:{self.port}"))
        self.assertEqual(resp.status, 200, "свой Origin")

        conn = self.connection()
        conn.request("POST", "/api/config/validate", body=b"{}", headers=dict(headers, **{"Content-Type": "text/plain"}))
        self.assertEqual(conn.getresponse().status, 415)
        conn.close()

        resp, data = self.request("POST", "/api/diag/match", {"name": "a.b.xboxlive.com"}, headers)
        self.assertEqual(data["verdict"], "proxy")
        resp, data = self.request("POST", "/api/config/apply", {"env": {"PROXY_PORTS": "80,22"}}, headers)
        self.assertEqual(resp.status, 200)
        self.assertFalse(data["ok"])
        self.assertIn("PROXY_PORTS", data["errors"])
        resp, data = self.request("POST", "/api/config/apply", {"env": {"IPV6": "0"}, "etag": "0" * 32}, headers)
        self.assertEqual(resp.status, 409)
        resp, data = self.request("GET", "/api/presets", headers={"Cookie": cookie})
        self.assertIn("xboxlive.com", data["xbox_domains"])
        resp, data = self.request("GET", "/api/firewall", headers={"Cookie": cookie})
        self.assertFalse(data["available"])
        resp, data = self.request("GET", "/api/overview", headers={"Cookie": cookie})
        self.assertEqual(resp.status, 200, data)
        self.assertIn("warnings", data)

        resp, _ = self.request("POST", "/api/logout", {}, headers)
        self.assertEqual(resp.status, 200)
        resp, _ = self.request("GET", "/api/config", headers={"Cookie": cookie})
        self.assertEqual(resp.status, 401)

    def test_tunnel_hint_for_anonymous(self):
        resp, data = self.request("GET", "/api/session")
        self.assertFalse(data["authenticated"])
        access = data["access"]
        self.assertEqual(access["mode"], "tunnel")
        self.assertEqual(access["command"], f"ssh -N -L {self.tmp.cfg.port}:127.0.0.1:{self.tmp.cfg.port} -p 2222 root@203.0.113.5")
        self.assertEqual(access["url"], f"http://127.0.0.1:{self.tmp.cfg.port}/")
        self.assertIn("Tunnels", access["putty"])
        self.assertNotIn("csrf", data)
        self.assertNotIn("ui", data)

    def test_client_filter(self):
        import ipaddress

        self.app.cfg.allow_clients = [ipaddress.ip_network("10.0.0.0/8")]
        try:
            self.assertTrue(self.app.client_allowed("127.0.0.1"))
            self.assertTrue(self.app.client_allowed("10.1.2.3"))
            self.assertTrue(self.app.client_allowed("::ffff:10.1.2.3"))
            self.assertFalse(self.app.client_allowed("203.0.113.9"))
            self.assertFalse(self.app.client_allowed("junk"))
        finally:
            self.app.cfg.allow_clients = []


class RateLimitTest(ServerCase):
    def test_lockout(self):
        statuses = []
        for _ in range(6):
            resp, _ = self.request("POST", "/api/login", {"password": "wrong password!"}, {"X-Requested-With": "egress-ui"})
            statuses.append(resp.status)
        self.assertEqual(statuses[:5], [401] * 5)
        self.assertEqual(statuses[5], 429)
        resp, _ = self.request("POST", "/api/login", {"password": PASSWORD}, {"X-Requested-With": "egress-ui"})
        self.assertEqual(resp.status, 429, "верный пароль во время блокировки тоже ждёт")


@unittest.skipUnless(shutil.which("openssl"), "нужен openssl")
class TlsServerTest(ServerCase):
    tls = True

    @classmethod
    def make_context(cls):
        cls.certs = tempfile.mkdtemp(prefix="egress-cert-")
        cert = os.path.join(cls.certs, "tls.crt")
        key = os.path.join(cls.certs, "tls.key")
        env = dict(os.environ, PYTHONPATH=helpers.SCRIPTS, UI_ENV_FILE=os.path.join(cls.certs, "ui.env"))
        out = subprocess.run(
            [sys.executable, "-m", "egress_ui", "gen-cert", "--ip", "127.0.0.1", "--cert", cert, "--key", key, "--days", "2"],
            capture_output=True, text=True, env=env, timeout=120,
        )
        assert out.returncode == 0, out.stderr
        assert "SHA-256: " in out.stdout, out.stdout
        cls.fingerprint_out = out.stdout
        cls.tmp.cfg.insecure_http = False
        cls.tmp.cfg.tls_cert = cert
        cls.tmp.cfg.tls_key = key
        return make_ssl_context(cls.tmp.cfg)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(cls.certs, ignore_errors=True)

    def test_https_login(self):
        resp, _ = self.request("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn("max-age", resp.getheader("Strict-Transport-Security"))
        cookie, csrf, raw = self.login()
        self.assertTrue(cookie.startswith("__Host-egress_ui="))
        self.assertIn("Secure", raw)
        resp, data = self.request("GET", "/api/session")
        self.assertNotIn("access", data, "в режиме HTTPS подсказки туннеля нет")
        resp, data = self.request("GET", "/api/session", headers={"Cookie": cookie})
        self.assertEqual(data["ui"]["access"]["mode"], "https")
        if os.name == "posix":
            self.assertEqual(os.stat(self.tmp.cfg.tls_key).st_mode & 0o777, 0o600)

    def test_old_tls_refused(self):
        import socket

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, AttributeError):
            self.skipTest("клиент не умеет TLS 1.1")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            with self.assertRaises((ssl.SSLError, OSError)):
                with context.wrap_socket(raw) as conn:
                    conn.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                    conn.recv(10)


if __name__ == "__main__":
    unittest.main()
