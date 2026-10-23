"""Чтение, проверка и применение настроек службы."""

from __future__ import annotations

import difflib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass

from egress_proxy import (
    ConfigError,
    _is_ip,
    ascii_name,
    parse_allow,
    parse_domain,
    parse_env_text,
    parse_ports,
)

from .settings import UiConfig
from .system import Runner

ENV_FIELDS = [
    ("LISTEN_IP", "0.0.0.0", "Адрес, на котором принимать клиентов. 0.0.0.0 — все интерфейсы."),
    ("DNS_PORT", "53", "Порт DNS, который указывают на устройстве."),
    ("PROXY_PORTS", "80,443", "TCP-порты прокси через запятую, диапазон: 15000-15099."),
    ("DNS_UPSTREAM", "1.1.1.1,8.8.8.8", "Куда сервер спрашивает настоящие адреса сайтов."),
    ("MAX_WILDCARD_DEPTH", "4", "Сколько меток поддомена покрывает имя из списка (0–20)."),
    ("ANSWER_TTL", "60", "Сколько секунд устройство помнит ответ DNS."),
    ("IPV6", "1", "1 — отдавать и проксировать IPv6, 0 — только IPv4."),
    ("ALLOW_CLIENTS", "", "Кто может обращаться. Пусто — любой адрес. IP или сети через запятую."),
]
ENV_KEYS = [key for key, _default, _hint in ENV_FIELDS]
ENV_DEFAULTS = {key: default for key, default, _hint in ENV_FIELDS}
VALUE_RE = re.compile(r"^[A-Za-z0-9.,:/\- ]*$")
LIST_KINDS = ("proxy", "direct", "exits")
MAX_FILE_BYTES = 256 * 1024
KEEP_BACKUPS = 30
WIDE_ZONES = {
    "microsoft.com",
    "akamai.net",
    "akamaized.net",
    "akamaiedge.net",
    "ea.com",
    "blob.core.windows.net",
    "windows.net",
    "live.com",
    "windowsupdate.com",
    "bing.com",
    "azureedge.net",
    "cloudfront.net",
    "amazonaws.com",
    "googleapis.com",
}
SSH_PORT = 22
# Черновик проверяется со своими путями: строки с путями из egress.env его бы перебили.
PATH_KEYS = {"DESTINATIONS_FILE", "DIRECT_FILE", "EXIT_IPS_FILE", "STATUS_FILE", "EGRESS_ENV_FILE"}


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__("; ".join(f"{key}: {value}" for key, value in errors.items()))
        self.errors = errors


class ConflictError(Exception):
    pass


@dataclass
class Snapshot:
    texts: dict[str, str | None]

    @property
    def etag(self) -> str:
        digest = hashlib.sha256()
        for key in ("env",) + LIST_KINDS:
            value = self.texts.get(key)
            digest.update(key.encode())
            digest.update(b"\x00" if value is None else b"\x01" + value.encode("utf-8"))
        return digest.hexdigest()[:32]


def entries(text: str) -> list[str]:
    found = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            found.append(line)
    return found


def strip_env_keys(text: str, keys: set[str]) -> str:
    kept = []
    for line in text.splitlines():
        parsed = parse_env_text(line)
        if parsed and set(parsed) <= keys:
            continue
        kept.append(line)
    return "\n".join(kept) + "\n"


def update_env_text(text: str, values: dict[str, str]) -> str:
    """Меняет строки KEY=VALUE на месте, сохраняет комментарии и чужие ключи."""
    lines = text.splitlines()
    done: set[str] = set()
    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        key = stripped.split("=", 1)[0].strip() if "=" in stripped and not stripped.startswith("#") else ""
        if key.startswith("export "):
            key = key[7:].strip()
        if key in values:
            if key in done:
                continue
            result.append(f"{key}={values[key]}")
            done.add(key)
        else:
            result.append(line)
    missing = [key for key in values if key not in done]
    if missing:
        if result and result[-1].strip():
            result.append("")
        result.append("# Добавлено через Web UI")
        for key in missing:
            result.append(f"{key}={values[key]}")
    return "\n".join(result) + "\n"


def validate_env(values: dict[str, str], ui_port: int | None) -> dict[str, str]:
    errors: dict[str, str] = {}
    for key, value in values.items():
        if key not in ENV_KEYS:
            errors[key] = "Неизвестный параметр"
            continue
        if not VALUE_RE.fullmatch(value):
            errors[key] = "Допустимы латинские буквы, цифры, точка, запятая, двоеточие, косая черта и дефис"
    if errors:
        return errors

    def number(key: str, low: int, high: int) -> int | None:
        try:
            value = int(values[key])
        except ValueError:
            errors[key] = "Нужно целое число"
            return None
        if not low <= value <= high:
            errors[key] = f"Нужно число от {low} до {high}"
            return None
        return value

    try:
        ipaddress.ip_address(values["LISTEN_IP"])
    except ValueError:
        errors["LISTEN_IP"] = "Нужен IP-адрес, например 0.0.0.0"
    dns_port = number("DNS_PORT", 1, 65535)
    number("MAX_WILDCARD_DEPTH", 0, 20)
    number("ANSWER_TTL", 0, 86400)
    if values["IPV6"] not in {"0", "1"}:
        errors["IPV6"] = "Нужно 0 или 1"
    upstreams = [item.strip() for item in values["DNS_UPSTREAM"].split(",") if item.strip()]
    if not upstreams:
        errors["DNS_UPSTREAM"] = "Нужен хотя бы один адрес DNS"
    for item in upstreams:
        try:
            ipaddress.ip_address(item)
        except ValueError:
            errors["DNS_UPSTREAM"] = f"{item!r} не IP-адрес"
            break
    try:
        ports = parse_ports(values["PROXY_PORTS"])
    except ConfigError as exc:
        errors["PROXY_PORTS"] = str(exc)
    else:
        if SSH_PORT in ports:
            errors["PROXY_PORTS"] = "Порт 22 занят SSH"
        elif ui_port is not None and ui_port in ports:
            errors["PROXY_PORTS"] = f"Порт {ui_port} занят Web UI"
        elif dns_port is not None and dns_port in ports:
            errors["PROXY_PORTS"] = f"Порт {dns_port} уже занят DNS"
    try:
        parse_allow(values["ALLOW_CLIENTS"])
    except ConfigError as exc:
        errors["ALLOW_CLIENTS"] = str(exc)
    return errors


def validate_list(kind: str, text: str) -> list[str]:
    problems: list[str] = []
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        return [f"Файл больше {MAX_FILE_BYTES // 1024} КБ"]
    if "\x00" in text:
        return ["Недопустимый символ"]
    for number, raw in enumerate(text.splitlines(), 1):
        token = raw.split("#", 1)[0].strip()
        if not token:
            continue
        try:
            if kind == "exits":
                bare = token[1:-1] if token.startswith("[") and token.endswith("]") else token
                if token != "auto" and not _is_ip(bare):
                    ascii_name(token)
            else:
                if _is_ip(token) or "/" in token:
                    raise ConfigError("нужен домен, а не адрес")
                parse_domain(token)
        except ConfigError as exc:
            problems.append(f"строка {number}: {token} — {exc}")
    if kind == "proxy" and not entries(text):
        problems.append("Список пуст: служба не запустится без хотя бы одного домена")
    if kind == "exits" and not entries(text):
        problems.append("Нужен хотя бы один адрес или auto")
    return problems[:50]


def warnings_for(env_values: dict[str, str], proxy_text: str | None) -> list[str]:
    found: list[str] = []
    if not env_values.get("ALLOW_CLIENTS", "").strip():
        found.append("ALLOW_CLIENTS пуст: DNS и прокси открыты для любого адреса из интернета.")
    wide = []
    for token in entries(proxy_text or ""):
        try:
            name = parse_domain(token)
        except ConfigError:
            continue
        if name in WIDE_ZONES:
            wide.append(name)
    if wide:
        found.append("Широкие зоны в списке, через VPS пойдёт весь их трафик: " + ", ".join(sorted(set(wide))))
    found.append("UDP (голос, часть мультиплеера) не проксируется — это ограничение службы.")
    return found


class ConfigStore:
    def __init__(self, cfg: UiConfig, runner: Runner, service=None, clock=time.time):
        self.cfg = cfg
        self.runner = runner
        self.service = service
        self.clock = clock
        self.lock = threading.Lock()

    @property
    def backups_dir(self) -> str:
        return os.path.join(self.cfg.state_dir, "backups")

    def read(self) -> Snapshot:
        texts: dict[str, str | None] = {}
        for kind, path in self.cfg.files().items():
            try:
                with open(path, encoding="utf-8-sig") as handle:
                    texts[kind] = handle.read()
            except FileNotFoundError:
                texts[kind] = None
        return Snapshot(texts)

    def env_values(self, snapshot: Snapshot | None = None) -> dict[str, str]:
        snapshot = snapshot or self.read()
        parsed = parse_env_text(snapshot.texts.get("env") or "")
        return {key: parsed.get(key, ENV_DEFAULTS[key]) for key in ENV_KEYS}

    def state(self) -> dict:
        snapshot = self.read()
        values = self.env_values(snapshot)
        return {
            "etag": snapshot.etag,
            "env": values,
            "fields": [{"key": key, "default": default, "hint": hint} for key, default, hint in ENV_FIELDS],
            "files": {kind: snapshot.texts.get(kind) for kind in LIST_KINDS},
            "paths": self.cfg.files(),
            "warnings": warnings_for(values, snapshot.texts.get("proxy")),
        }

    def build(self, draft: dict) -> tuple[Snapshot, Snapshot, dict[str, str]]:
        current = self.read()
        values = self.env_values(current)
        env_draft = draft.get("env") or {}
        if not isinstance(env_draft, dict):
            raise ValidationError({"env": "Ожидался объект"})
        merged = dict(values)
        for key, value in env_draft.items():
            merged[str(key)] = str(value).strip()
        errors = validate_env(merged, self.cfg.port)
        texts = dict(current.texts)
        if env_draft:
            changed = {key: merged[key] for key in ENV_KEYS if key in env_draft}
            texts["env"] = update_env_text(current.texts.get("env") or "", changed)
        files = draft.get("files") or {}
        if not isinstance(files, dict):
            raise ValidationError({"files": "Ожидался объект"})
        for kind, text in files.items():
            if kind not in LIST_KINDS:
                errors[kind] = "Неизвестный файл"
                continue
            if text is None:
                continue
            text = str(text).replace("\r\n", "\n")
            if text and not text.endswith("\n"):
                text += "\n"
            problems = validate_list(kind, text)
            if problems:
                errors[kind] = "; ".join(problems)
            texts[kind] = text
        if texts.get("proxy") is None:
            errors.setdefault("proxy", "Нет файла со списком доменов")
        if texts.get("exits") is None:
            errors.setdefault("exits", "Нет файла exit-ips.txt")
        if errors:
            raise ValidationError(errors)
        return current, Snapshot(texts), merged

    def diff(self, before: Snapshot, after: Snapshot) -> dict[str, str]:
        result: dict[str, str] = {}
        for kind, path in self.cfg.files().items():
            old = before.texts.get(kind)
            new = after.texts.get(kind)
            if old == new:
                continue
            lines = difflib.unified_diff(
                (old or "").splitlines(),
                (new or "").splitlines(),
                fromfile=f"{path} (сейчас)",
                tofile=f"{path} (новый)",
                lineterm="",
            )
            result[kind] = "\n".join(lines)
        return result

    def check(self, snapshot: Snapshot) -> dict:
        """Запускает egress_proxy.py --check-config на черновике во временном каталоге."""
        with tempfile.TemporaryDirectory(prefix="egress-ui-") as folder:
            names = {
                "env": "egress.env",
                "proxy": "allow-destinations.txt",
                "direct": "direct-destinations.txt",
                "exits": "exit-ips.txt",
            }
            for kind, name in names.items():
                text = snapshot.texts.get(kind)
                if kind == "env" and text is not None:
                    text = strip_env_keys(text, PATH_KEYS)
                if text is not None:
                    with open(os.path.join(folder, name), "w", encoding="utf-8") as handle:
                        handle.write(text)
            env = {
                key: value
                for key, value in os.environ.items()
                if key not in ENV_KEYS and key not in PATH_KEYS and not key.startswith("UI_")
            }
            env["DESTINATIONS_FILE"] = os.path.join(folder, names["proxy"])
            env["DIRECT_FILE"] = os.path.join(folder, names["direct"])
            env["EXIT_IPS_FILE"] = os.path.join(folder, names["exits"])
            env_path = os.path.join(folder, names["env"])
            if not os.path.exists(env_path):
                open(env_path, "w", encoding="utf-8").close()
            argv = [sys.executable or "python3", self.cfg.proxy_script, "--check-config", "--json", "--env-file", env_path]
            result = self.runner.run(argv, timeout=45, env=env)
        parsed: dict = {}
        for line in reversed(result.out.splitlines()):
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                except ValueError:
                    parsed = {}
                break
        ok = result.ok and bool(parsed.get("ok"))
        error = parsed.get("error") or ("" if ok else result.text or "Проверка не прошла")
        stderr = "\n".join(
            line for line in result.err.splitlines() if not line.startswith("Ошибка конфигурации:")
        ).strip()
        return {"ok": ok, "error": error, "plan": parsed.get("plan"), "messages": stderr}

    def validate(self, draft: dict) -> dict:
        try:
            current, new, merged = self.build(draft)
        except ValidationError as exc:
            return {"ok": False, "errors": exc.errors, "diff": {}, "check": None}
        check = self.check(new)
        return {
            "ok": check["ok"],
            "errors": {} if check["ok"] else {"check": check["error"]},
            "diff": self.diff(current, new),
            "check": check,
            "warnings": warnings_for(merged, new.texts.get("proxy")),
            "etag": current.etag,
        }

    def backup(self, snapshot: Snapshot, reason: str) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(self.clock()))
        folder = os.path.join(self.backups_dir, stamp)
        suffix = 1
        while os.path.exists(folder):
            suffix += 1
            folder = os.path.join(self.backups_dir, f"{stamp}-{suffix}")
        os.makedirs(folder, mode=0o700)
        manifest = {"created": self.clock(), "reason": reason, "files": {}}
        for kind, path in self.cfg.files().items():
            text = snapshot.texts.get(kind)
            manifest["files"][kind] = text is not None
            if text is not None:
                with open(os.path.join(folder, kind), "w", encoding="utf-8") as handle:
                    handle.write(text)
        with open(os.path.join(folder, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False)
        self._prune()
        return os.path.basename(folder)

    def _prune(self) -> None:
        names = sorted(self._backup_names())
        for name in names[:-KEEP_BACKUPS]:
            shutil.rmtree(os.path.join(self.backups_dir, name), ignore_errors=True)

    def _backup_names(self) -> list[str]:
        if not os.path.isdir(self.backups_dir):
            return []
        return [
            name
            for name in os.listdir(self.backups_dir)
            if re.fullmatch(r"\d{8}-\d{6}(-\d+)?", name)
            and os.path.isfile(os.path.join(self.backups_dir, name, "manifest.json"))
        ]

    def backups(self) -> list[dict]:
        found = []
        for name in sorted(self._backup_names(), reverse=True):
            try:
                with open(os.path.join(self.backups_dir, name, "manifest.json"), encoding="utf-8") as handle:
                    manifest = json.load(handle)
            except (OSError, ValueError):
                continue
            found.append({"id": name, "created": manifest.get("created"), "reason": manifest.get("reason", "")})
        return found

    def load_backup(self, name: str) -> Snapshot:
        if name not in self._backup_names():
            raise ValidationError({"backup": "Нет такой копии"})
        folder = os.path.join(self.backups_dir, name)
        with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
        texts: dict[str, str | None] = {}
        for kind in self.cfg.files():
            if manifest.get("files", {}).get(kind):
                with open(os.path.join(folder, kind), encoding="utf-8") as handle:
                    texts[kind] = handle.read()
            else:
                texts[kind] = None
        return Snapshot(texts)

    def write(self, snapshot: Snapshot, previous: Snapshot) -> None:
        for kind, path in self.cfg.files().items():
            text = snapshot.texts.get(kind)
            if text == previous.texts.get(kind):
                continue
            if text is None:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
                continue
            write_atomic(path, text, self.cfg.config_group)

    def apply(self, draft: dict, restart: bool = True, reason: str = "изменение через UI") -> dict:
        with self.lock:
            current = self.read()
            if draft.get("etag") and draft["etag"] != current.etag:
                raise ConflictError("Файлы изменились после загрузки страницы. Обновите страницу.")
            if "restore" in draft:
                new = self.load_backup(str(draft["restore"]))
                merged = self.env_values(new)
                errors = validate_env(merged, self.cfg.port)
                if errors:
                    return {"ok": False, "errors": errors}
            else:
                try:
                    _current, new, merged = self.build(draft)
                except ValidationError as exc:
                    return {"ok": False, "errors": exc.errors}
            check = self.check(new)
            if not check["ok"]:
                return {"ok": False, "errors": {"check": check["error"]}, "check": check}
            diff = self.diff(current, new)
            if not diff:
                return {"ok": True, "changed": False, "check": check, "message": "Изменений нет"}
            backup_id = self.backup(current, reason)
            self.write(new, current)
            result = {"ok": True, "changed": True, "backup": backup_id, "check": check, "diff": diff}
            if not restart or self.service is None:
                result["message"] = "Файлы сохранены. Служба не перезапускалась."
                return result
            outcome = self.service.restart_and_wait()
            result["service"] = outcome
            if outcome.get("skipped"):
                result["message"] = "Файлы сохранены. Управление службой выключено — перезапустите её сами."
                return result
            if outcome.get("ok"):
                result["message"] = "Настройки применены, служба перезапущена."
                return result
            self.write(current, new)
            rollback = self.service.restart_and_wait()
            result.update(
                ok=False,
                rolled_back=True,
                rollback_service=rollback,
                errors={"service": "Служба не поднялась с новыми настройками. Прежние файлы возвращены."},
            )
            return result


def write_atomic(path: str, text: str, group: str = "", mode: int = 0o640) -> None:
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".egress-ui-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if group and hasattr(os, "chown"):
            try:
                import grp

                os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
            except (KeyError, PermissionError, ImportError, OSError):
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
