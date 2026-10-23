"""Статус, запуск и журнал службы: systemd или контейнер Docker."""

from __future__ import annotations

import http.client
import json
import re
import socket
import time
from datetime import datetime
from typing import Iterator
from urllib.parse import quote

from .system import Runner

ACTIONS = {"start", "stop", "restart"}
UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]{1,128}$")


def journal_entry(line: bytes | str, unit: str = "") -> dict | None:
    try:
        data = json.loads(line)
    except ValueError:
        return None
    message = data.get("MESSAGE", "")
    if isinstance(message, list):
        message = bytes(item & 0xFF for item in message if isinstance(item, int)).decode("utf-8", "replace")
    elif message is None:
        message = ""
    try:
        ts = int(data.get("__REALTIME_TIMESTAMP", "0")) / 1_000_000
    except (TypeError, ValueError):
        ts = 0.0
    try:
        prio = int(data.get("PRIORITY", "6"))
    except (TypeError, ValueError):
        prio = 6
    return {"ts": ts, "msg": str(message), "prio": prio, "unit": unit}


class Follower:
    """Живой поток журнала. close() можно звать из другого потока."""

    def __init__(self, entries: Iterator[dict], closer):
        self._entries = entries
        self._closer = closer

    def __iter__(self) -> Iterator[dict]:
        return self._entries

    def close(self) -> None:
        try:
            self._closer()
        except OSError:
            pass


def parse_show(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            found[key.strip()] = value.strip()
    return found


class NullService:
    name = "none"

    def status(self) -> dict:
        return {"backend": "none", "state": "unknown", "detail": "Управление службой выключено"}

    def action(self, action: str) -> dict:
        return {"ok": False, "error": "Управление службой выключено (UI_SERVICE_BACKEND=none)"}

    def restart_and_wait(self) -> dict:
        return {"ok": True, "skipped": True}

    def logs(self, lines: int = 200, source: str = "proxy") -> list[dict]:
        return []

    def follow(self, source: str = "proxy", backlog: int = 0) -> Follower:
        return Follower(iter(()), lambda: None)

    def sources(self) -> list[str]:
        return []


class SystemdService:
    name = "systemd"

    def __init__(self, runner: Runner, unit: str, ui_unit: str, settle: float = 4.0, sleep=time.sleep):
        if not UNIT_RE.fullmatch(unit) or not UNIT_RE.fullmatch(ui_unit):
            raise ValueError("Недопустимое имя юнита")
        self.runner = runner
        self.unit = unit
        self.ui_unit = ui_unit
        self.settle = settle
        self.sleep = sleep
        self.extra_units: set[str] = set()

    def sources(self) -> list[str]:
        return ["proxy", "ui", "update"]

    def unit_for(self, source: str) -> str:
        if source == "ui":
            return self.ui_unit
        if source == "update":
            return "egress-proxy-update"
        return self.unit

    def status(self) -> dict:
        result = self.runner.run(
            [
                "systemctl",
                "show",
                self.unit,
                "--no-pager",
                "-p",
                "ActiveState,SubState,MainPID,NRestarts,UnitFileState,Result,LoadState,ActiveEnterTimestampMonotonic,ExecMainStatus",
            ],
            timeout=10,
        )
        if not result.ok:
            return {"backend": "systemd", "state": "unknown", "detail": result.text}
        data = parse_show(result.out)
        uptime = None
        if data.get("ActiveState") == "active":
            try:
                entered = int(data.get("ActiveEnterTimestampMonotonic", "0")) / 1_000_000
                if entered > 0:
                    uptime = max(0.0, time.monotonic() - entered)
            except ValueError:
                uptime = None
        return {
            "backend": "systemd",
            "unit": self.unit,
            "state": data.get("ActiveState", "unknown"),
            "sub": data.get("SubState", ""),
            "pid": int(data.get("MainPID", "0") or 0),
            "restarts": int(data.get("NRestarts", "0") or 0) if data.get("NRestarts", "").isdigit() else None,
            "enabled": data.get("UnitFileState", ""),
            "result": data.get("Result", ""),
            "loaded": data.get("LoadState", ""),
            "exit_status": data.get("ExecMainStatus", ""),
            "uptime": uptime,
        }

    def action(self, action: str) -> dict:
        if action not in ACTIONS:
            return {"ok": False, "error": "Неизвестное действие"}
        result = self.runner.run(["systemctl", action, self.unit], timeout=90)
        return {"ok": result.ok, "error": "" if result.ok else result.text or f"systemctl {action} вернул {result.code}"}

    def restart_and_wait(self) -> dict:
        before = self.status().get("restarts")
        outcome = self.action("restart")
        if not outcome["ok"]:
            outcome["logs"] = self.logs(30)
            return outcome
        waited = 0.0
        status = self.status()
        while waited < self.settle:
            self.sleep(0.5)
            waited += 0.5
            status = self.status()
            if status.get("state") != "active":
                break
        restarts = status.get("restarts")
        grew = before is not None and restarts is not None and restarts > before
        ok = status.get("state") == "active" and not grew
        result = {"ok": ok, "status": status}
        if not ok:
            result["error"] = f"Служба в состоянии {status.get('state')}/{status.get('sub')}"
            result["logs"] = self.logs(30)
        return result

    def _journal_argv(self, source: str, lines: int) -> list[str]:
        return [
            "journalctl",
            "-u",
            self.unit_for(source),
            "-n",
            str(max(0, min(int(lines), 5000))),
            "-o",
            "json",
            "--no-pager",
            "--output-fields=MESSAGE,PRIORITY",
        ]

    def logs(self, lines: int = 200, source: str = "proxy") -> list[dict]:
        result = self.runner.run(self._journal_argv(source, lines), timeout=20)
        found = []
        for line in result.out.splitlines():
            entry = journal_entry(line, source)
            if entry is not None:
                found.append(entry)
        return found

    def follow(self, source: str = "proxy", backlog: int = 0) -> Follower:
        proc = self.runner.popen(self._journal_argv(source, backlog) + ["-f"])

        def entries() -> Iterator[dict]:
            assert proc.stdout is not None
            for line in proc.stdout:
                entry = journal_entry(line, source)
                if entry is not None:
                    yield entry

        def close() -> None:
            proc.kill()
            proc.wait(timeout=5)

        return Follower(entries(), close)


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float | None = 30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        sock.connect(self.path)
        self.sock = sock


def parse_docker_time(value: str) -> float | None:
    match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$", value or "")
    if not match or value.startswith("0001-"):
        return None
    fraction = (match.group(2) or ".")[1:7].ljust(6, "0")
    zone = "+00:00" if match.group(3) == "Z" else match.group(3)
    return datetime.fromisoformat(f"{match.group(1)}.{fraction}{zone}").timestamp()


def docker_frames(read) -> Iterator[tuple[int, bytes]]:
    """Поток логов Docker без TTY: 8 байт заголовка, затем данные."""
    while True:
        header = read(8)
        if len(header) < 8:
            return
        stream = header[0]
        size = int.from_bytes(header[4:8], "big")
        payload = read(size) if size else b""
        if len(payload) < size:
            return
        yield stream, payload


def docker_log_entry(line: str, stream: int) -> dict:
    ts = 0.0
    message = line
    if " " in line:
        stamp, rest = line.split(" ", 1)
        parsed = parse_docker_time(stamp)
        if parsed is not None:
            ts, message = parsed, rest
    return {"ts": ts, "msg": message.rstrip("\r\n"), "prio": 3 if stream == 2 else 6, "unit": "proxy"}


class DockerService:
    name = "docker"

    def __init__(self, socket_path: str, container: str, settle: float = 4.0, sleep=time.sleep):
        if not UNIT_RE.fullmatch(container):
            raise ValueError("Недопустимое имя контейнера")
        self.socket_path = socket_path
        self.container = container
        self.settle = settle
        self.sleep = sleep

    def sources(self) -> list[str]:
        return ["proxy"]

    def _request(self, method: str, path: str, timeout: float = 30) -> tuple[int, bytes]:
        conn = UnixHTTPConnection(self.socket_path, timeout=timeout)
        try:
            conn.request(method, path, headers={"Host": "docker"})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def _base(self) -> str:
        return f"/containers/{quote(self.container, safe='')}"

    def status(self) -> dict:
        try:
            code, body = self._request("GET", self._base() + "/json", timeout=10)
        except OSError as exc:
            return {"backend": "docker", "state": "unknown", "detail": f"Docker недоступен: {exc}"}
        if code != 200:
            return {"backend": "docker", "state": "unknown", "detail": f"Docker ответил {code}"}
        data = json.loads(body)
        state = data.get("State", {})
        started = parse_docker_time(state.get("StartedAt", ""))
        running = state.get("Running")
        return {
            "backend": "docker",
            "unit": self.container,
            "state": "active" if running else ("activating" if state.get("Restarting") else "inactive"),
            "sub": state.get("Status", ""),
            "pid": state.get("Pid", 0),
            "restarts": data.get("RestartCount"),
            "health": (state.get("Health") or {}).get("Status", ""),
            "exit_status": str(state.get("ExitCode", "")),
            "uptime": (time.time() - started) if running and started else None,
        }

    def action(self, action: str) -> dict:
        if action not in ACTIONS:
            return {"ok": False, "error": "Неизвестное действие"}
        try:
            code, body = self._request("POST", f"{self._base()}/{action}?t=10", timeout=60)
        except OSError as exc:
            return {"ok": False, "error": f"Docker недоступен: {exc}"}
        if code in (204, 304):
            return {"ok": True, "error": ""}
        return {"ok": False, "error": body.decode("utf-8", "replace")[:500] or f"Docker ответил {code}"}

    def restart_and_wait(self) -> dict:
        outcome = self.action("restart")
        if not outcome["ok"]:
            return outcome
        waited = 0.0
        status = self.status()
        while waited < self.settle:
            self.sleep(0.5)
            waited += 0.5
            status = self.status()
            if status.get("state") != "active":
                break
        ok = status.get("state") == "active"
        result = {"ok": ok, "status": status}
        if not ok:
            result["error"] = f"Контейнер в состоянии {status.get('sub')}"
            result["logs"] = self.logs(30)
        return result

    def logs(self, lines: int = 200, source: str = "proxy") -> list[dict]:
        tail = max(0, min(int(lines), 5000))
        try:
            code, body = self._request(
                "GET", f"{self._base()}/logs?stdout=1&stderr=1&timestamps=1&tail={tail}", timeout=20
            )
        except OSError:
            return []
        if code != 200:
            return []
        pos = 0

        def read(size: int) -> bytes:
            nonlocal pos
            chunk = body[pos : pos + size]
            pos += len(chunk)
            return chunk

        found = []
        for stream, payload in docker_frames(read):
            for line in payload.decode("utf-8", "replace").splitlines():
                found.append(docker_log_entry(line, stream))
        return found

    def follow(self, source: str = "proxy", backlog: int = 0) -> Follower:
        conn = UnixHTTPConnection(self.socket_path, timeout=None)
        conn.request(
            "GET",
            f"{self._base()}/logs?stdout=1&stderr=1&timestamps=1&follow=1&tail={max(0, int(backlog))}",
            headers={"Host": "docker"},
        )
        resp = conn.getresponse()

        def entries() -> Iterator[dict]:
            if resp.status != 200:
                return
            for stream, payload in docker_frames(resp.read):
                for line in payload.decode("utf-8", "replace").splitlines():
                    yield docker_log_entry(line, stream)

        def close() -> None:
            if conn.sock is not None:
                conn.sock.shutdown(socket.SHUT_RDWR)
            conn.close()

        return Follower(entries(), close)
