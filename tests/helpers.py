"""Общие заготовки тестов: путь к scripts/, фейковые команды и служба, временный конфиг."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
PROXY_SCRIPT = os.path.join(SCRIPTS, "egress_proxy.py")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from egress_ui.settings import UiConfig  # noqa: E402
from egress_ui.system import Result  # noqa: E402

ENV_TEXT = """# Настройки egress-proxy
LISTEN_IP=0.0.0.0
DNS_PORT=53
PROXY_PORTS=80,443
DNS_UPSTREAM=1.1.1.1,8.8.8.8
MAX_WILDCARD_DEPTH=4
ANSWER_TTL=60
IPV6=1
ALLOW_CLIENTS=
"""
PROXY_TEXT = "# Xbox\nxboxlive.com\nxbox.com  # магазин\n"
EXITS_TEXT = "auto\n"


class FakeRunner:
    """Отвечает по первому совпавшему префиксу команды и запоминает вызовы."""

    def __init__(self, replies=None):
        self.replies = list(replies or [])
        self.calls: list[list[str]] = []

    def add(self, prefix, code=0, out="", err=""):
        self.replies.append((list(prefix), Result(code, out, err)))

    def on(self, prefix, reply):
        self.replies.append((list(prefix), reply))

    def run(self, argv, timeout=30, env=None, input_text=None):
        self.calls.append(list(argv))
        for prefix, result in self.replies:
            if callable(result):
                if argv[: len(prefix)] == prefix:
                    return result(argv, env)
            elif argv[: len(prefix)] == prefix:
                return result
        return Result(0, "", "")

    def popen(self, argv):
        raise RuntimeError("popen в тестах не нужен")


def check_reply(ok=True, error="", plan=None):
    def reply(argv, env):
        data = {"ok": True, "plan": plan or {"domains": []}} if ok else {"ok": False, "error": error}
        return Result(0 if ok else 1, json.dumps(data, ensure_ascii=False) + "\n", "" if ok else f"Ошибка конфигурации: {error}")

    return reply


class FakeService:
    name = "fake"

    def __init__(self, restart_results=None):
        self.restart_results = list(restart_results or [])
        self.restarts = 0

    def status(self):
        return {"backend": "fake", "state": "active", "uptime": 10}

    def action(self, action):
        return {"ok": True, "error": ""}

    def restart_and_wait(self):
        self.restarts += 1
        if self.restart_results:
            return self.restart_results.pop(0)
        return {"ok": True}

    def logs(self, lines=200, source="proxy"):
        return []

    def sources(self):
        return ["proxy"]


class TempConfig:
    """Каталог с egress.env и списками, UiConfig на него."""

    def __init__(self, env=ENV_TEXT, proxy=PROXY_TEXT, exits=EXITS_TEXT, direct=None):
        self.root = tempfile.mkdtemp(prefix="egress-test-")
        self.config_dir = os.path.join(self.root, "etc")
        os.makedirs(self.config_dir)
        self.write("egress.env", env)
        self.write("allow-destinations.txt", proxy)
        self.write("exit-ips.txt", exits)
        if direct is not None:
            self.write("direct-destinations.txt", direct)
        self.cfg = UiConfig(
            listen="127.0.0.1",
            port=0,
            insecure_http=True,
            config_dir=self.config_dir,
            env_file=self.path("egress.env"),
            destinations_file=self.path("allow-destinations.txt"),
            direct_file=self.path("direct-destinations.txt"),
            exit_ips_file=self.path("exit-ips.txt"),
            status_file=os.path.join(self.root, "status.json"),
            state_dir=os.path.join(self.root, "state"),
            proxy_script=PROXY_SCRIPT,
            repo_dir=ROOT,
            presets_dir=os.path.join(ROOT, "config"),
            service_backend="none",
            firewall_backend="none",
            config_group="",
        )

    def path(self, name):
        return os.path.join(self.config_dir, name)

    def write(self, name, text):
        with open(os.path.join(self.config_dir, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    def read(self, name):
        with open(self.path(name), encoding="utf-8") as handle:
            return handle.read()

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def has_default_route() -> bool:
    if not shutil.which("ip"):
        return False
    import subprocess

    try:
        out = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and " src " in out.stdout
