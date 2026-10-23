import unittest

import helpers  # noqa: F401
from egress_ui.auth import LoginLimiter, SessionStore, hash_password, verify_password


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class PasswordTest(unittest.TestCase):
    def test_roundtrip(self):
        stored = hash_password("correct horse battery", iterations=1000)
        self.assertTrue(stored.startswith("pbkdf2_sha256$1000$"))
        self.assertTrue(verify_password("correct horse battery", stored))
        self.assertFalse(verify_password("correct horse batterY", stored))

    def test_salt_differs(self):
        self.assertNotEqual(hash_password("a" * 12, iterations=1000), hash_password("a" * 12, iterations=1000))

    def test_short_password(self):
        with self.assertRaises(ValueError):
            hash_password("short")

    def test_bad_stored(self):
        for stored in ("", "garbage", "md5$1000$aa$bb", "pbkdf2_sha256$10$aa$bb", "pbkdf2_sha256$x$aa$bb"):
            self.assertFalse(verify_password("whatever-123", stored), stored)


class SessionTest(unittest.TestCase):
    def test_idle_and_absolute(self):
        clock = Clock()
        store = SessionStore(60, absolute_seconds=200, clock=clock)
        session = store.create("127.0.0.1")
        self.assertNotEqual(session.token, session.csrf)
        clock.now += 50
        self.assertIs(store.get(session.token), session)
        clock.now += 50
        self.assertIs(store.get(session.token), session)
        clock.now += 61
        self.assertIsNone(store.get(session.token))

        other = store.create("127.0.0.1")
        for _ in range(5):
            clock.now += 45
            store.get(other.token)
        self.assertIsNone(store.get(other.token), "абсолютный срок сессии")

    def test_drop(self):
        store = SessionStore(60)
        session = store.create("127.0.0.1")
        store.drop(session.token)
        self.assertIsNone(store.get(session.token))
        self.assertIsNone(store.get(None))
        self.assertIsNone(store.get(""))


class LimiterTest(unittest.TestCase):
    def test_lock_after_failures(self):
        clock = Clock()
        limiter = LoginLimiter(max_failures=5, window=900, lock=900, clock=clock)
        for _ in range(4):
            limiter.failure("203.0.113.1")
        self.assertEqual(limiter.retry_after("203.0.113.1"), 0)
        limiter.failure("203.0.113.1")
        self.assertGreater(limiter.retry_after("203.0.113.1"), 800)
        self.assertEqual(limiter.retry_after("203.0.113.2"), 0)
        clock.now += 901
        self.assertEqual(limiter.retry_after("203.0.113.1"), 0)

    def test_window_and_success(self):
        clock = Clock()
        limiter = LoginLimiter(max_failures=3, window=60, lock=100, clock=clock)
        limiter.failure("a")
        limiter.failure("a")
        clock.now += 61
        limiter.failure("a")
        self.assertEqual(limiter.retry_after("a"), 0, "старые ошибки вне окна")
        limiter.failure("a")
        limiter.success("a")
        limiter.failure("a")
        self.assertEqual(limiter.retry_after("a"), 0)


if __name__ == "__main__":
    unittest.main()
