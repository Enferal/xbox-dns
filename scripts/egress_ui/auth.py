"""Пароль, сессии и защита от перебора."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass

ALGO = "pbkdf2_sha256"
ITERATIONS = 600_000
MIN_PASSWORD = 10


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, iterations: int = ITERATIONS, salt: bytes | None = None) -> str:
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"Пароль короче {MIN_PASSWORD} символов")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGO}${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != ALGO:
            return False
        rounds = int(iterations)
        if not 1_000 <= rounds <= 10_000_000:
            return False
        expected = _unb64(digest)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _unb64(salt), rounds)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


@dataclass
class Session:
    token: str
    csrf: str
    created: float
    seen: float
    client: str


class SessionStore:
    def __init__(self, idle_seconds: float, absolute_seconds: float | None = None, clock=time.monotonic):
        self.idle = idle_seconds
        self.absolute = absolute_seconds or idle_seconds * 2
        self.clock = clock
        self._items: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, client: str) -> Session:
        now = self.clock()
        session = Session(secrets.token_urlsafe(32), secrets.token_urlsafe(32), now, now, client)
        with self._lock:
            self._purge(now)
            self._items[session.token] = session
        return session

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        now = self.clock()
        with self._lock:
            session = self._items.get(token)
            if session is None:
                return None
            if now - session.seen > self.idle or now - session.created > self.absolute:
                del self._items[token]
                return None
            session.seen = now
            return session

    def drop(self, token: str | None) -> None:
        with self._lock:
            self._items.pop(token or "", None)

    def drop_all(self) -> None:
        with self._lock:
            self._items.clear()

    def _purge(self, now: float) -> None:
        stale = [
            key
            for key, item in self._items.items()
            if now - item.seen > self.idle or now - item.created > self.absolute
        ]
        for key in stale:
            del self._items[key]


class LoginLimiter:
    """После max_failures ошибок за window секунд адрес ждёт lock секунд."""

    def __init__(self, max_failures: int = 5, window: float = 900, lock: float = 900, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window
        self.lock = lock
        self.clock = clock
        self._fails: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}
        self._mutex = threading.Lock()

    def retry_after(self, client: str) -> float:
        now = self.clock()
        with self._mutex:
            until = self._locked.get(client, 0)
            if until > now:
                return until - now
            self._locked.pop(client, None)
            return 0

    def failure(self, client: str) -> None:
        now = self.clock()
        with self._mutex:
            items = [stamp for stamp in self._fails.get(client, []) if now - stamp < self.window]
            items.append(now)
            if len(items) >= self.max_failures:
                self._locked[client] = now + self.lock
                items = []
            self._fails[client] = items
            if len(self._fails) > 10_000:
                self._fails.clear()

    def success(self, client: str) -> None:
        with self._mutex:
            self._fails.pop(client, None)
            self._locked.pop(client, None)
