"""Запуск внешних команд. Только список аргументов, без shell."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

ALLOWED_COMMANDS = {
    "systemctl",
    "journalctl",
    "systemd-run",
    "ufw",
    "git",
    "openssl",
    "python3",
    "ss",
    "ip",
}


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def text(self) -> str:
        return "\n".join(part for part in (self.out.strip(), self.err.strip()) if part)


class Runner:
    def run(
        self,
        argv: list[str],
        timeout: float = 30,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> Result:
        name = os.path.basename(argv[0])
        if name not in ALLOWED_COMMANDS and not name.startswith("python3"):
            raise ValueError(f"Команда {name} не разрешена")
        if any("\x00" in arg for arg in argv):
            raise ValueError("Недопустимый аргумент")
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                input=input_text,
                errors="replace",
            )
        except FileNotFoundError:
            return Result(127, "", f"Нет программы {argv[0]}")
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            return Result(124, out or "", f"Команда не уложилась в {timeout:g} с")
        return Result(proc.returncode, proc.stdout, proc.stderr)

    def popen(self, argv: list[str]) -> subprocess.Popen:
        name = os.path.basename(argv[0])
        if name not in ALLOWED_COMMANDS:
            raise ValueError(f"Команда {name} не разрешена")
        return subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
