"""DNS-запрос к своему серверу, проверка портов и попадания имени в списки."""

from __future__ import annotations

import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from egress_proxy import (
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_HTTPS,
    ConfigError,
    ascii_name,
    build_query,
    domain_matches,
    parse_answers,
    parse_domain,
    parse_ports,
)

from .configstore import entries

QTYPES = {"A": QTYPE_A, "AAAA": QTYPE_AAAA, "HTTPS": QTYPE_HTTPS}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns_query(name: str, qtype: str = "A", server: str = "127.0.0.1", port: int = 53, timeout: float = 3) -> dict:
    if qtype not in QTYPES:
        raise ValueError("Тип запроса: A, AAAA или HTTPS")
    try:
        host = ascii_name(name)
    except ConfigError as exc:
        raise ValueError(str(exc)) from exc
    query = build_query(host, QTYPES[qtype])
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    started = time.monotonic()
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (server, port))
            while True:
                response, _addr = sock.recvfrom(4096)
                if response[:2] == query[:2]:
                    break
        except socket.timeout:
            return {"ok": False, "error": f"DNS {server}:{port} не ответил за {timeout:g} с"}
        except OSError as exc:
            return {"ok": False, "error": f"DNS {server}:{port}: {exc}"}
    elapsed = (time.monotonic() - started) * 1000
    rcode = response[3] & 0x0F if len(response) >= 4 else -1
    answers, cname = parse_answers(response)
    ancount = struct.unpack("!H", response[6:8])[0] if len(response) >= 8 else 0
    return {
        "ok": True,
        "name": host,
        "type": qtype,
        "rcode": RCODES.get(rcode, str(rcode)),
        "answers": [ip for ip, _ttl in answers],
        "ttl": [ttl for _ip, ttl in answers],
        "records": ancount,
        "cname": cname,
        "ms": round(elapsed, 1),
    }


def check_ports(ports: list[int], host: str = "127.0.0.1", timeout: float = 1.0) -> list[dict]:
    def probe(port: int) -> dict:
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout):
                pass
        except OSError as exc:
            return {"port": port, "ok": False, "error": str(exc)}
        return {"port": port, "ok": True, "ms": round((time.monotonic() - started) * 1000, 1)}

    with ThreadPoolExecutor(max_workers=32) as pool:
        return list(pool.map(probe, ports))


def service_port_list(dns_port: str, proxy_ports: str) -> list[int]:
    found = [int(dns_port)]
    for port in parse_ports(proxy_ports):
        if port not in found:
            found.append(port)
    return found


def match_name(name: str, proxy_text: str, direct_text: str, depth: int) -> dict:
    try:
        host = ascii_name(name)
    except ConfigError as exc:
        raise ValueError(str(exc)) from exc

    def which(text: str) -> str:
        names = []
        for token in entries(text):
            try:
                names.append(parse_domain(token))
            except ConfigError:
                continue
        for base in names:
            if domain_matches(host, [base], depth):
                return base
        return ""

    direct = which(direct_text)
    proxy = which(proxy_text)
    if direct:
        verdict = "direct"
    elif proxy:
        verdict = "proxy"
    else:
        verdict = "none"
    return {"name": host, "verdict": verdict, "proxy_rule": proxy, "direct_rule": direct, "depth": depth}
