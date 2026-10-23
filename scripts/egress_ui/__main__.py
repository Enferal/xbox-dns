"""python3 -m egress_ui [serve|set-password|hash-password|gen-cert|fingerprint]"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import os
import ssl
import sys

import egress_proxy

from .auth import MIN_PASSWORD, hash_password
from .server import serve
from .settings import DEFAULT_UI_ENV, UiConfigError, load_ui_config, set_ui_value
from .system import Runner


def ui_env_path(args) -> str:
    return args.ui_env or os.environ.get("UI_ENV_FILE") or DEFAULT_UI_ENV


def read_password(from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass(f"Новый пароль Web UI (не короче {MIN_PASSWORD} символов): ")
        again = getpass.getpass("Повторите пароль: ")
        if password != again:
            raise ValueError("Пароли не совпали")
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"Пароль короче {MIN_PASSWORD} символов")
    return password


def fingerprint(path: str) -> str:
    with open(path, encoding="ascii") as handle:
        der = ssl.PEM_cert_to_DER_cert(handle.read())
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def cert_addresses(extra: list[str]) -> list[str]:
    found: list[str] = []
    candidates = list(extra)
    if not candidates:
        try:
            candidates.append(egress_proxy.primary_ipv4())
        except egress_proxy.ConfigError:
            pass
        address_v6 = egress_proxy.primary_ipv6()
        if address_v6:
            candidates.append(address_v6)
    candidates += ["127.0.0.1", "::1"]
    for item in candidates:
        text = str(ipaddress.ip_address(item.strip()))
        if text not in found:
            found.append(text)
    return found


def cmd_serve(args) -> int:
    try:
        cfg = load_ui_config(args.ui_env)
    except UiConfigError as exc:
        print(f"Ошибка настроек Web UI: {exc}", file=sys.stderr)
        return 2
    return serve(cfg)


def cmd_set_password(args) -> int:
    try:
        password = read_password(args.stdin)
        set_ui_value(ui_env_path(args), "UI_PASSWORD_HASH", hash_password(password))
    except (ValueError, UiConfigError, OSError) as exc:
        print(f"Пароль не задан: {exc}", file=sys.stderr)
        return 1
    print(f"Пароль записан в {ui_env_path(args)}. Перезапустите UI: systemctl restart egress-proxy-ui")
    return 0


def cmd_hash_password(args) -> int:
    try:
        print(hash_password(read_password(args.stdin)))
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


def cmd_gen_cert(args) -> int:
    try:
        cfg = load_ui_config(args.ui_env)
    except UiConfigError as exc:
        print(f"Ошибка настроек Web UI: {exc}", file=sys.stderr)
        return 2
    cert = args.cert or cfg.tls_cert
    key = args.key or cfg.tls_key
    if os.path.exists(cert) and not args.force:
        print(f"Сертификат уже есть: {cert}. Заменить: --force", file=sys.stderr)
        print(f"SHA-256: {fingerprint(cert)}")
        return 0
    try:
        addresses = cert_addresses(args.ip or [])
    except ValueError as exc:
        print(f"Неверный адрес: {exc}", file=sys.stderr)
        return 1
    for path in (cert, key):
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    san = ",".join(f"IP:{item}" for item in addresses)
    argv = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", str(args.days), "-keyout", key, "-out", cert,
        "-subj", f"/CN={addresses[0]}/O=egress-proxy-ui",
        "-addext", f"subjectAltName={san}",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "extendedKeyUsage=serverAuth",
    ]
    old_mask = os.umask(0o077)
    try:
        result = Runner().run(argv, timeout=120)
    finally:
        os.umask(old_mask)
    if not result.ok:
        print(f"openssl не создал сертификат: {result.text}", file=sys.stderr)
        return 1
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    print(f"Сертификат {cert} для {', '.join(addresses)} на {args.days} дней")
    print(f"SHA-256: {fingerprint(cert)}")
    return 0


def cmd_fingerprint(args) -> int:
    try:
        cfg = load_ui_config(args.ui_env)
        print(fingerprint(args.cert or cfg.tls_cert))
    except (UiConfigError, OSError, ValueError) as exc:
        print(f"Не удалось прочитать сертификат: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m egress_ui", description="Web UI для egress-proxy")
    parser.add_argument("--ui-env", help=f"файл настроек UI, по умолчанию {DEFAULT_UI_ENV}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="запустить UI (по умолчанию)")
    for name, text in (("set-password", "задать пароль"), ("hash-password", "напечатать хэш пароля")):
        item = sub.add_parser(name, help=text)
        item.add_argument("--stdin", action="store_true", help="прочитать пароль одной строкой из stdin")
    cert = sub.add_parser("gen-cert", help="создать самоподписанный сертификат")
    cert.add_argument("--ip", action="append", help="адрес для SAN, можно несколько раз")
    cert.add_argument("--days", type=int, default=3650)
    cert.add_argument("--cert")
    cert.add_argument("--key")
    cert.add_argument("--force", action="store_true", help="заменить существующий")
    printed = sub.add_parser("fingerprint", help="SHA-256 отпечаток сертификата")
    printed.add_argument("--cert")
    args = parser.parse_args(argv)
    commands = {
        None: cmd_serve,
        "serve": cmd_serve,
        "set-password": cmd_set_password,
        "hash-password": cmd_hash_password,
        "gen-cert": cmd_gen_cert,
        "fingerprint": cmd_fingerprint,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
