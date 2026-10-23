"""HTTPS-сервер Web UI: статика, JSON API и живой журнал по SSE."""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import sys
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import egress_proxy

from . import __version__
from .auth import LoginLimiter, SessionStore, verify_password
from .configstore import ConfigStore, ConflictError, ValidationError
from .diagnostics import check_ports, dns_query, match_name, service_port_list
from .firewall import FirewallError, Ufw
from .logparse import KINDS, enrich, summarize
from .service import DockerService, NullService, SystemdService
from .settings import UiConfig
from .system import Runner
from .updater import Updater

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)
MAX_BODY = 1024 * 1024
MAX_STREAMS = 8
UFC5_PORTS = "80,443,42130,44326,15000-15099"
UPDATE_MARKER = "Обновление egress-proxy: начало"


def audit(message: str) -> None:
    print(f"UI: {message}", flush=True)


def ssh_ports(runner: Runner) -> list[str]:
    found = {"22"}
    result = runner.run(["ss", "-Htlpn"], timeout=10)
    for line in result.out.splitlines():
        if "sshd" not in line:
            continue
        parts = line.split()
        if len(parts) >= 4:
            port = parts[3].rsplit(":", 1)[-1]
            if port.isdigit():
                found.add(port)
    return sorted(found, key=int)


class HttpError(Exception):
    def __init__(self, status: int, message: str, extra: dict | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra or {}


class App:
    def __init__(self, cfg: UiConfig, runner: Runner | None = None, service=None, firewall=None, updater=None):
        self.cfg = cfg
        self.runner = runner or Runner()
        if service is None:
            if cfg.service_backend == "systemd":
                service = SystemdService(self.runner, cfg.service_name, cfg.ui_service_name)
            elif cfg.service_backend == "docker":
                service = DockerService(cfg.docker_socket, cfg.docker_container)
            else:
                service = NullService()
        self.service = service
        self.store = ConfigStore(cfg, self.runner, service)
        self._ssh_ports: list[str] | None = None
        self._public_host: str | None = None
        if firewall is None and cfg.firewall_backend == "ufw":
            firewall = Ufw(self.runner, self.ssh_port_list() + [str(cfg.port)])
        self.firewall = firewall
        self.updater = updater or Updater(
            self.runner, cfg.repo_dir, cfg.proxy_script, supported=cfg.service_backend == "systemd"
        )
        idle = max(0.1, cfg.session_hours) * 3600
        self.sessions = SessionStore(idle, absolute_seconds=max(idle, 24 * 3600))
        self.limiter = LoginLimiter()
        self.streams = threading.BoundedSemaphore(MAX_STREAMS)

    def ssh_port_list(self) -> list[str]:
        if self._ssh_ports is None:
            self._ssh_ports = ssh_ports(self.runner)
        return self._ssh_ports

    def client_allowed(self, address: str) -> bool:
        if not self.cfg.allow_clients:
            return True
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return False
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped
        return ip.is_loopback or any(ip in network for network in self.cfg.allow_clients)

    def cookie_name(self) -> str:
        return "__Host-egress_ui" if self.cfg.tls else "egress_ui"

    def read_status_file(self) -> dict | None:
        try:
            with open(self.cfg.status_file, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return None
        data["stale"] = time.time() - float(data.get("updated_at", 0)) > 30
        return data

    def overview(self) -> dict:
        state = self.store.state()
        status = self.service.status()
        runtime = self.read_status_file()
        exits = []
        if runtime and runtime.get("plan"):
            exits = runtime["plan"].get("exits_v4", []) + runtime["plan"].get("exits_v6", [])
        if not exits:
            try:
                exits = [egress_proxy.primary_ipv4()]
            except Exception:
                exits = []
        recent = summarize([enrich(item) for item in self.service.logs(2000)])
        return {
            "service": status,
            "runtime": runtime,
            "dns_addresses": exits,
            "env": state["env"],
            "warnings": state["warnings"],
            "recent": recent,
            "ui": self.ui_info(),
        }

    def public_host(self) -> str:
        if self.cfg.public_host:
            return self.cfg.public_host
        if self._public_host is None:
            try:
                self._public_host = egress_proxy.primary_ipv4()
            except Exception:
                self._public_host = ""
        return self._public_host

    def ssh_port(self) -> int:
        if self.cfg.ssh_port:
            return self.cfg.ssh_port
        others = [port for port in self.ssh_port_list() if port != "22"]
        return int(others[0]) if len(others) == 1 else 22

    def access_info(self) -> dict:
        if not self.cfg.tunnel:
            return {"mode": "https", "port": self.cfg.port}
        port = self.cfg.port
        ssh_port = self.ssh_port()
        host = self.public_host() or "АДРЕС_VPS"
        flag = f" -p {ssh_port}" if ssh_port != 22 else ""
        return {
            "mode": "tunnel",
            "port": port,
            "ssh_port": ssh_port,
            "host": host,
            "url": f"http://127.0.0.1:{port}/",
            "command": f"ssh -N -L {port}:127.0.0.1:{port}{flag} root@{host}",
            "putty": f"Session: {host}, порт {ssh_port}. Connection → SSH → Tunnels: Source port {port}, Destination 127.0.0.1:{port}, Add.",
        }

    def ui_info(self) -> dict:
        return {
            "version": __version__,
            "port": self.cfg.port,
            "tls": self.cfg.tls,
            "access": self.access_info(),
            "service_backend": self.cfg.service_backend,
            "firewall": self.firewall is not None,
            "update": self.updater.supported,
            "log_sources": self.service.sources(),
        }

    def presets(self) -> dict:
        def read(name: str) -> str | None:
            try:
                with open(os.path.join(self.cfg.presets, name), encoding="utf-8-sig") as handle:
                    return handle.read()
            except OSError:
                return None

        return {
            "xbox_domains": read("allow-destinations.xbox.txt"),
            "direct": read("direct-destinations.txt"),
            "ufc5_ports": UFC5_PORTS,
            "same_port": egress_proxy.same_port_preset(),
            "alias_ports": egress_proxy.alias_port_range(),
        }

    def firewall_state(self) -> dict:
        if self.firewall is None:
            return {
                "available": False,
                "error": "Управление ufw выключено. В Docker правила задаются на хосте командами ufw.",
            }
        data = self.firewall.snapshot()
        env = self.store.env_values()
        data["service"] = {
            "dns_port": env["DNS_PORT"],
            "proxy_ports": env["PROXY_PORTS"],
            "alias_ports": egress_proxy.alias_port_range() if env.get("SPLIT_HTTPS", "1") == "1" else "",
            "clients": env["ALLOW_CLIENTS"],
        }
        data["ssh_ports"] = self.ssh_port_list()
        return data


def json_bytes(data) -> bytes:
    return json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "egress-ui"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, format: str, *args) -> None:
        return

    def client_ip(self) -> str:
        return str(self.client_address[0])

    def send_security_headers(self) -> None:
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if self.app.cfg.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def send_json(self, status: int, data, cookies: list[str] | None = None) -> None:
        body = json_bytes(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.send_security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def session_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            cookie = SimpleCookie()
            cookie.load(raw)
        except Exception:
            return None
        morsel = cookie.get(self.app.cookie_name())
        return morsel.value if morsel else None

    def session(self):
        return self.app.sessions.get(self.session_token())

    def require_session(self, mutating: bool):
        session = self.session()
        if session is None:
            raise HttpError(401, "Нужен вход")
        if mutating:
            token = self.headers.get("X-CSRF-Token", "")
            if not token or not hmac.compare_digest(token, session.csrf):
                raise HttpError(403, "Неверный CSRF-токен. Обновите страницу.")
        return session

    def check_origin(self) -> None:
        origin = self.headers.get("Origin")
        if not origin:
            return
        host = self.headers.get("Host", "")
        parsed = urlsplit(origin)
        scheme = "https" if self.app.cfg.tls else "http"
        if parsed.scheme != scheme or parsed.netloc != host:
            raise HttpError(403, "Запрос с чужого сайта отклонён")

    def read_json(self) -> dict:
        ctype = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise HttpError(415, "Нужен Content-Type: application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise HttpError(400, "Неверный Content-Length")
        if length > MAX_BODY:
            raise HttpError(413, "Слишком большой запрос")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise HttpError(400, "Тело запроса — не JSON")
        if not isinstance(data, dict):
            raise HttpError(400, "Ожидался JSON-объект")
        return data

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        self.dispatch("GET")

    def do_POST(self) -> None:
        self.dispatch("POST")

    def do_PUT(self) -> None:
        self.send_json(405, {"error": "Метод не поддерживается"})

    do_DELETE = do_PUT
    do_PATCH = do_PUT

    def dispatch(self, method: str) -> None:
        url = urlsplit(self.path)
        path = url.path
        query = {key: values[-1] for key, values in parse_qs(url.query).items()}
        try:
            if not path.startswith("/api/"):
                if method != "GET":
                    raise HttpError(405, "Метод не поддерживается")
                return self.static(path)
            if method == "POST":
                self.check_origin()
            route = ROUTES.get((method, path))
            if route is None:
                raise HttpError(404, "Нет такого адреса")
            handler, public = route
            body = self.read_json() if method == "POST" else {}
            if not public:
                session = self.require_session(mutating=method == "POST")
                self.current_session = session
            result = handler(self, body, query)
            if result is not None:
                self.send_json(200, result)
        except HttpError as exc:
            payload = {"error": exc.message}
            payload.update(exc.extra)
            self.send_json(exc.status, payload)
        except ValidationError as exc:
            self.send_json(400, {"error": "Проверка не прошла", "errors": exc.errors})
        except ConflictError as exc:
            self.send_json(409, {"error": str(exc)})
        except FirewallError as exc:
            self.send_json(400, {"error": str(exc)})
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            self.close_connection = True
        except Exception as exc:
            print(f"UI: ошибка обработки {method} {path}: {exc!r}", file=sys.stderr, flush=True)
            try:
                self.send_json(500, {"error": f"Внутренняя ошибка: {exc}"})
            except OSError:
                self.close_connection = True

    def static(self, path: str) -> None:
        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        if name.startswith("static/"):
            name = name[len("static/") :]
        if not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9]+)+", name):
            raise HttpError(404, "Нет такого файла")
        full = os.path.join(STATIC_DIR, name)
        ext = os.path.splitext(name)[1]
        if ext not in STATIC_TYPES or not os.path.isfile(full):
            raise HttpError(404, "Нет такого файла")
        with open(full, "rb") as handle:
            body = handle.read()
        self.send_response(200)
        self.send_header("Content-Type", STATIC_TYPES[ext])
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # --- маршруты ---

    def api_session(self, body, query):
        session = self.session()
        info = {"authenticated": session is not None}
        if self.app.cfg.tunnel:
            # В режиме туннеля сюда доходят только с loopback, подсказка ничего не раскрывает.
            info["access"] = self.app.access_info()
        if session is not None:
            info["csrf"] = session.csrf
            info["ui"] = self.app.ui_info()
            info["client"] = self.client_ip()
        return info

    def api_login(self, body, query):
        if self.headers.get("X-Requested-With") != "egress-ui":
            raise HttpError(403, "Нет заголовка X-Requested-With")
        client = self.client_ip()
        wait = self.app.limiter.retry_after(client)
        if wait > 0:
            raise HttpError(429, f"Слишком много попыток. Повторите через {int(wait) + 1} с", {"retry_after": int(wait) + 1})
        password = body.get("password")
        if not isinstance(password, str) or not password or len(password) > 1024:
            raise HttpError(400, "Введите пароль")
        if not self.app.cfg.password_hash or not verify_password(password, self.app.cfg.password_hash):
            self.app.limiter.failure(client)
            audit(f"неверный пароль с адреса {client}")
            time.sleep(0.5)
            raise HttpError(401, "Неверный пароль")
        self.app.limiter.success(client)
        session = self.app.sessions.create(client)
        audit(f"вход с адреса {client}")
        cookie = f"{self.app.cookie_name()}={session.token}; Path=/; HttpOnly; SameSite=Strict"
        if self.app.cfg.tls:
            cookie += "; Secure"
        self.send_json(
            200,
            {"ok": True, "csrf": session.csrf, "ui": self.app.ui_info(), "client": client},
            cookies=[cookie],
        )
        return None

    def api_logout(self, body, query):
        self.app.sessions.drop(self.session_token())
        cookie = f"{self.app.cookie_name()}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        if self.app.cfg.tls:
            cookie += "; Secure"
        self.send_json(200, {"ok": True}, cookies=[cookie])
        return None

    def api_overview(self, body, query):
        return self.app.overview()

    def api_service(self, body, query):
        action = str(body.get("action", ""))
        audit(f"служба {action} с адреса {self.client_ip()}")
        result = self.app.service.action(action)
        result["status"] = self.app.service.status()
        return result

    def api_config(self, body, query):
        return self.app.store.state()

    def api_config_validate(self, body, query):
        return self.app.store.validate(body)

    def api_config_apply(self, body, query):
        audit(f"применение настроек с адреса {self.client_ip()}")
        result = self.app.store.apply(body, restart=body.get("restart", True) is not False)
        audit("настройки " + ("применены" if result.get("ok") else "не применены: " + json.dumps(result.get("errors"), ensure_ascii=False)))
        return result

    def api_backups(self, body, query):
        return {"backups": self.app.store.backups()}

    def api_restore(self, body, query):
        backup = str(body.get("id", ""))
        audit(f"возврат копии {backup} с адреса {self.client_ip()}")
        return self.app.store.apply({"restore": backup, "etag": body.get("etag")}, reason=f"перед возвратом {backup}")

    def api_presets(self, body, query):
        return self.app.presets()

    def api_logs(self, body, query):
        source = query.get("source", "proxy")
        if source not in self.app.service.sources():
            source = "proxy"
        lines = int(query.get("lines", "300")) if query.get("lines", "300").isdigit() else 300
        entries = [enrich(item) for item in self.app.service.logs(min(lines, 5000), source)]
        return {"entries": entries, "kinds": list(KINDS)}

    def api_stats(self, body, query):
        lines = int(query.get("lines", "5000")) if query.get("lines", "5000").isdigit() else 5000
        return summarize([enrich(item) for item in self.app.service.logs(min(lines, 20000))])

    def api_logs_stream(self, body, query):
        source = query.get("source", "proxy")
        if source not in self.app.service.sources():
            raise HttpError(400, "Нет такого журнала")
        backlog = int(query.get("backlog", "100")) if query.get("backlog", "100").isdigit() else 100
        if not self.app.streams.acquire(blocking=False):
            raise HttpError(429, "Открыто слишком много живых журналов")
        token = self.session_token()
        try:
            follower = self.app.service.follow(source, min(backlog, 1000))
        except Exception:
            self.app.streams.release()
            raise
        items: queue.Queue = queue.Queue(maxsize=2000)

        def pump() -> None:
            try:
                for entry in follower:
                    items.put(entry)
            except Exception:
                pass
            items.put(None)

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        self.close_connection = True
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                try:
                    entry = items.get(timeout=15)
                except queue.Empty:
                    if self.app.sessions.get(token) is None:
                        self.wfile.write(b"event: logout\ndata: {}\n\n")
                        break
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                if entry is None:
                    self.wfile.write(b"event: end\ndata: {}\n\n")
                    break
                self.wfile.write(b"data: " + json_bytes(enrich(entry)) + b"\n\n")
                if items.empty():
                    self.wfile.flush()
        except OSError:
            pass
        finally:
            follower.close()
            self.app.streams.release()
        return None

    def api_firewall(self, body, query):
        return self.app.firewall_state()

    def _firewall(self) -> Ufw:
        if self.app.firewall is None:
            raise HttpError(400, "Управление ufw выключено")
        return self.app.firewall

    def api_firewall_rule(self, body, query):
        fw = self._firewall()
        audit(f"ufw добавить {body} с адреса {self.client_ip()}")
        return fw.add(
            str(body.get("action", "allow")),
            str(body.get("port", "")),
            str(body.get("proto", "tcp")),
            str(body.get("source", "any")),
            str(body.get("comment", "egress-ui")),
        )

    def api_firewall_delete(self, body, query):
        fw = self._firewall()
        try:
            num = int(body.get("num"))
        except (TypeError, ValueError):
            raise HttpError(400, "Нужен номер правила")
        audit(f"ufw удалить {num} ({body.get('rule')}) с адреса {self.client_ip()}")
        return fw.delete(num, str(body.get("rule", "")))

    def _mode_args(self) -> tuple[str, str, str]:
        env = self.app.store.env_values()
        ports = egress_proxy.proxy_ports_with_alias(env["PROXY_PORTS"], env.get("SPLIT_HTTPS", "1"))
        return env["DNS_PORT"], ports, env["ALLOW_CLIENTS"]

    def api_firewall_plan(self, body, query):
        plan = self._firewall().plan(str(body.get("mode", "")), *self._mode_args())
        plan.pop("add_argv", None)
        return plan

    def api_firewall_mode(self, body, query):
        mode = str(body.get("mode", ""))
        audit(f"ufw режим {mode} с адреса {self.client_ip()}")
        return self._firewall().apply_mode(mode, *self._mode_args())

    def api_firewall_enable(self, body, query):
        audit(f"ufw включить с адреса {self.client_ip()}")
        return self._firewall().enable(self.app.ssh_port_list())

    def api_diag_dns(self, body, query):
        env = self.app.store.env_values()
        server = "127.0.0.1"
        try:
            return dns_query(str(body.get("name", "")), str(body.get("type", "A")), server, int(env["DNS_PORT"]))
        except ValueError as exc:
            raise HttpError(400, str(exc))

    def api_diag_ports(self, body, query):
        env = self.app.store.env_values()
        try:
            ports = service_port_list(
                env["DNS_PORT"],
                egress_proxy.proxy_ports_with_alias(env["PROXY_PORTS"], env.get("SPLIT_HTTPS", "1")),
            )
        except Exception as exc:
            raise HttpError(400, str(exc))
        return {"ports": check_ports(ports)}

    def api_diag_match(self, body, query):
        state = self.app.store.state()
        proxy = body.get("proxy") if isinstance(body.get("proxy"), str) else state["files"]["proxy"] or ""
        direct = body.get("direct") if isinstance(body.get("direct"), str) else state["files"]["direct"]
        if direct is None:
            direct = "\n".join(egress_proxy.DIRECT_DOWNLOADS)
        if isinstance(body.get("sameport"), str):
            same = body.get("sameport")
        else:
            same = state["files"].get("sameport")
        split = state["env"].get("SPLIT_HTTPS", "1") == "1"
        try:
            depth = int(state["env"]["MAX_WILDCARD_DEPTH"])
            return match_name(str(body.get("name", "")), proxy, direct, depth, same, split)
        except ValueError as exc:
            raise HttpError(400, str(exc))

    def api_update(self, body, query):
        return self.app.updater.info()

    def api_update_fetch(self, body, query):
        return self.app.updater.fetch()

    def api_update_start(self, body, query):
        audit(f"запуск обновления с адреса {self.client_ip()}")
        return self.app.updater.start()

    def api_update_status(self, body, query):
        state = self.app.updater.state()
        if self.app.cfg.service_backend == "systemd":
            entries = self.app.service.logs(500, "update")
            starts = [index for index, item in enumerate(entries) if UPDATE_MARKER in item.get("msg", "")]
            state["entries"] = entries[starts[-1] :] if starts else entries[-200:]
        return state


ROUTES = {
    ("GET", "/api/session"): (Handler.api_session, True),
    ("POST", "/api/login"): (Handler.api_login, True),
    ("POST", "/api/logout"): (Handler.api_logout, False),
    ("GET", "/api/overview"): (Handler.api_overview, False),
    ("POST", "/api/service"): (Handler.api_service, False),
    ("GET", "/api/config"): (Handler.api_config, False),
    ("POST", "/api/config/validate"): (Handler.api_config_validate, False),
    ("POST", "/api/config/apply"): (Handler.api_config_apply, False),
    ("GET", "/api/config/backups"): (Handler.api_backups, False),
    ("POST", "/api/config/restore"): (Handler.api_restore, False),
    ("GET", "/api/presets"): (Handler.api_presets, False),
    ("GET", "/api/logs"): (Handler.api_logs, False),
    ("GET", "/api/logs/stream"): (Handler.api_logs_stream, False),
    ("GET", "/api/stats"): (Handler.api_stats, False),
    ("GET", "/api/firewall"): (Handler.api_firewall, False),
    ("POST", "/api/firewall/rule"): (Handler.api_firewall_rule, False),
    ("POST", "/api/firewall/delete"): (Handler.api_firewall_delete, False),
    ("POST", "/api/firewall/plan"): (Handler.api_firewall_plan, False),
    ("POST", "/api/firewall/mode"): (Handler.api_firewall_mode, False),
    ("POST", "/api/firewall/enable"): (Handler.api_firewall_enable, False),
    ("POST", "/api/diag/dns"): (Handler.api_diag_dns, False),
    ("POST", "/api/diag/ports"): (Handler.api_diag_ports, False),
    ("POST", "/api/diag/match"): (Handler.api_diag_match, False),
    ("GET", "/api/update"): (Handler.api_update, False),
    ("POST", "/api/update/fetch"): (Handler.api_update_fetch, False),
    ("POST", "/api/update/start"): (Handler.api_update_start, False),
    ("GET", "/api/update/status"): (Handler.api_update_status, False),
}


class UiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app: App, ssl_context: ssl.SSLContext | None):
        self.app = app
        self.ssl_context = ssl_context
        self.address_family = socket.AF_INET6 if ":" in app.cfg.listen else socket.AF_INET
        super().__init__((app.cfg.listen, app.cfg.port), Handler)

    def verify_request(self, request, client_address) -> bool:
        allowed = self.app.client_allowed(str(client_address[0]))
        if not allowed:
            audit(f"отклонено соединение с адреса {client_address[0]}: нет в UI_ALLOW_CLIENTS")
        return allowed

    def handle_error(self, request, client_address) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionError, TimeoutError, socket.timeout, ssl.SSLError)):
            return
        print(f"UI: ошибка соединения с {client_address[0]}: {error!r}", file=sys.stderr, flush=True)

    def finish_request(self, request, client_address) -> None:
        if self.ssl_context is None:
            super().finish_request(request, client_address)
            return
        request.settimeout(15)
        try:
            wrapped = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(wrapped, client_address, self)
        finally:
            try:
                wrapped.close()
            except OSError:
                pass


def make_ssl_context(cfg: UiConfig) -> ssl.SSLContext | None:
    if not cfg.tls:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    return context


def serve(cfg: UiConfig) -> int:
    if not cfg.password_hash:
        print(
            "Пароль Web UI не задан. Выполните: python3 -m egress_ui set-password",
            file=sys.stderr,
        )
        return 1
    try:
        context = make_ssl_context(cfg)
    except (OSError, ssl.SSLError) as exc:
        print(
            f"Не удалось загрузить сертификат {cfg.tls_cert}: {exc}. "
            "Создать самоподписанный: python3 -m egress_ui gen-cert",
            file=sys.stderr,
        )
        return 1
    app = App(cfg)
    try:
        server = UiServer(app, context)
    except OSError as exc:
        print(f"Не удалось занять {cfg.listen}:{cfg.port}: {exc}", file=sys.stderr)
        return 1
    scheme = "https" if context else "http"
    print(f"Web UI слушает {scheme}://{cfg.listen}:{cfg.port}", flush=True)
    if cfg.tunnel:
        access = app.access_info()
        print(f"Режим без HTTPS. На своём компьютере: {access['command']}, затем {access['url']}", flush=True)
    elif not cfg.allow_clients:
        print("UI_ALLOW_CLIENTS пуст: страницу входа видит любой адрес. Ограничьте ufw или UI_ALLOW_CLIENTS.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
