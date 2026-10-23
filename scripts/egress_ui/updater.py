"""Версия кода в git и запуск обновления вне cgroup UI."""

from __future__ import annotations

import hashlib
import os
import time

from .system import Runner

UPDATE_UNIT = "egress-proxy-update"


def file_hash(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read().replace(b"\r\n", b"\n")).hexdigest()
    except OSError:
        return ""


class Updater:
    def __init__(self, runner: Runner, repo: str, installed_script: str, supported: bool):
        self.runner = runner
        self.repo = repo
        self.installed_script = installed_script
        self.supported = supported

    def git(self, *args: str, timeout: float = 30):
        return self.runner.run(["git", "-c", f"safe.directory={self.repo}", "-C", self.repo, *args], timeout=timeout)

    def info(self) -> dict:
        if not os.path.isdir(os.path.join(self.repo, ".git")):
            return {"available": False, "supported": self.supported, "error": f"{self.repo} не git-репозиторий"}
        head = self.git("log", "-1", "--format=%H%x1f%h%x1f%s%x1f%cI")
        branch = self.git("rev-parse", "--abbrev-ref", "HEAD")
        upstream = self.git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
        dirty = self.git("status", "--porcelain", "--untracked-files=no")
        info = {"available": head.ok, "supported": self.supported, "repo": self.repo}
        if head.ok:
            full, short, subject, date = (head.out.strip().split("\x1f") + ["", "", "", ""])[:4]
            info.update(commit=full, short=short, subject=subject, date=date)
        info["branch"] = branch.out.strip() if branch.ok else ""
        info["upstream"] = upstream.out.strip() if upstream.ok else ""
        info["dirty"] = bool(dirty.out.strip()) if dirty.ok else None
        if info["upstream"]:
            behind = self.git("rev-list", "--count", "HEAD..@{u}")
            info["behind"] = int(behind.out.strip()) if behind.ok and behind.out.strip().isdigit() else None
        repo_script = os.path.join(self.repo, "scripts", "egress_proxy.py")
        info["installed_matches"] = file_hash(repo_script) == file_hash(self.installed_script) != ""
        return info

    def fetch(self) -> dict:
        result = self.git("fetch", "--quiet", timeout=90)
        info = self.info()
        info["fetch_ok"] = result.ok
        info["fetch_output"] = result.text
        if result.ok and info.get("upstream"):
            log = self.git("log", "--format=%h %s", "HEAD..@{u}", "-n", "50")
            info["incoming"] = log.out.strip().splitlines() if log.ok else []
        return info

    def start(self) -> dict:
        if not self.supported:
            return {"ok": False, "error": "Обновление из UI работает только с systemd"}
        script = os.path.join(self.repo, "deploy", "update.sh")
        if not os.path.isfile(script):
            return {"ok": False, "error": f"Нет {script}"}
        active = self.runner.run(["systemctl", "is-active", UPDATE_UNIT], timeout=10)
        if active.out.strip() in {"active", "activating"}:
            return {"ok": False, "error": "Обновление уже идёт"}
        self.runner.run(["systemctl", "reset-failed", UPDATE_UNIT], timeout=10)
        argv = [
            "systemd-run",
            f"--unit={UPDATE_UNIT}",
            "--collect",
            "--description=Обновление egress-proxy из Web UI",
            f"--setenv=REPO={self.repo}",
            "/bin/sh",
            script,
        ]
        result = self.runner.run(argv, timeout=30)
        return {"ok": result.ok, "unit": UPDATE_UNIT, "started": time.time(), "output": result.text}

    def state(self) -> dict:
        result = self.runner.run(["systemctl", "is-active", UPDATE_UNIT], timeout=10)
        return {"unit": UPDATE_UNIT, "state": result.out.strip() or "unknown"}
