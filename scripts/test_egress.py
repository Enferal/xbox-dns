#!/usr/bin/env python3
"""Проверки сопоставления доменов, DNS-ответа и разбора имени из TLS."""

from __future__ import annotations

import ipaddress
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from egress_proxy import (
    ConfigError,
    acceptable_origin,
    build_query,
    domain_matches,
    NCSI_IPV4,
    Settings,
    answer_query,
    connect_test_response,
    connectivity_addresses,
    dns_trace,
    extract_host,
    extract_sni,
    first_question,
    opt_facts,
    is_connectivity_probe,
    log_text,
    parse_answers,
    parse_domain,
    synthetic_response,
)


def client_hello(server_name: str) -> bytes:
    encoded = server_name.encode("ascii")
    sni = struct.pack("!HBH", len(encoded) + 3, 0, len(encoded)) + encoded
    extension = struct.pack("!HH", 0, len(sni)) + sni
    hello = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00"
    hello += struct.pack("!H", len(extension)) + extension
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def main() -> int:
    base = parse_domain("*.Example.COM.")
    if base != "example.com":
        print(base)
        return 1
    domains = [base, parse_domain("пример.рф")]
    matched = [
        "example.com",
        "www.example.com",
        "a.b.example.com",
        "a.b.c.example.com",
        "a.b.c.d.example.com",
        "ПРИМЕР.рф",
        "a.b.c.d.пример.рф",
    ]
    skipped = [
        "a.b.c.d.e.example.com",
        "notexample.com",
        "example.com.evil.net",
        "a.b.c.d.e.пример.рф",
    ]
    for name in matched:
        if not domain_matches(name, domains, 4):
            print(f"должно совпасть: {name}")
            return 1
    for name in skipped:
        if domain_matches(name, domains, 4):
            print(f"не должно совпасть: {name}")
            return 1
    try:
        parse_domain("com")
    except ConfigError:
        pass
    else:
        print("однокомпонентное имя прошло")
        return 1

    query = build_query("www.example.com", 1)
    response = synthetic_response(query, 1, ["203.0.113.10", "203.0.113.11"], 60)
    name, qtype, _qclass, _end = first_question(response)
    records, cname = parse_answers(response)
    if name != "www.example.com" or qtype != 1 or cname is not None:
        print(name, qtype, cname)
        return 1
    if [item[0] for item in records] != ["203.0.113.10", "203.0.113.11"]:
        print(records)
        return 1
    empty = synthetic_response(query, 28, ["203.0.113.10"], 60)
    if parse_answers(empty)[0]:
        print("AAAA не должен получать IPv4")
        return 1
    if not is_connectivity_probe("dns.msftncsi.com") or not is_connectivity_probe("www.msftconnecttest.com"):
        print("проверка связи не распознана")
        return 1
    if is_connectivity_probe("device.auth.xboxlive.com") or is_connectivity_probe("evilmsftncsi.com"):
        print("лишнее имя принято за проверку связи")
        return 1
    settings = Settings(
        domains=["microsoft.com", "xboxlive.com"],
        exits_v4=["203.0.113.10"],
        exits_v6=[],
        own_ips=set(),
        listen_ip="0.0.0.0",
        dns_port=53,
        proxy_ports=[443],
        upstreams=["1.1.1.1"],
        allow=[],
        depth=4,
        ttl=60,
        direct=["dl.delivery.mp.microsoft.com", "assets1.xboxlive.com"],
    )
    if answer_query(settings, build_query("dns.msftncsi.com", 1)) is not None:
        print("dns.msftncsi.com нельзя подменять")
        return 1
    hijacked = answer_query(settings, build_query("device.auth.xboxlive.com", 1))
    if hijacked is None or [item[0] for item in parse_answers(hijacked)[0]] != ["203.0.113.10"]:
        print("device.auth.xboxlive.com должен указывать на VPS")
        return 1
    if answer_query(settings, build_query("assets1.xboxlive.com", 1)) is not None:
        print("закачка assets1.xboxlive.com должна идти мимо VPS")
        return 1
    if answer_query(settings, build_query("tlu.dl.delivery.mp.microsoft.com", 1)) is not None:
        print("закачка dl.delivery.mp.microsoft.com должна идти мимо VPS")
        return 1
    https = answer_query(settings, build_query("device.auth.xboxlive.com", 65))
    if https is None or ipaddress.IPv4Address("203.0.113.10").packed not in https or b"h3" in https:
        print("HTTPS-запись должна вести на VPS по TCP")
        return 1
    if is_connectivity_probe("xbox.ipv6.microsoft.com"):
        print("xbox.ipv6.microsoft.com не надо отдавать как настоящий IPv6")
        return 1
    if connectivity_addresses("dns.msftncsi.com", 1) != [NCSI_IPV4]:
        print("dns.msftncsi.com обязан быть адресом проверки Microsoft")
        return 1
    if connectivity_addresses("www.msftconnecttest.com", 1) is not None:
        print("фиксированный адрес Microsoft только у dns.msftncsi.com")
        return 1
    connect = answer_query(settings, build_query("www.msftconnecttest.com", 1))
    if connect is None or [item[0] for item in parse_answers(connect)[0]] != ["203.0.113.10"]:
        print("www.msftconnecttest.com должен указывать на VPS")
        return 1
    if parse_answers(answer_query(settings, build_query("www.msftconnecttest.com", 28)) or b"")[0]:
        print("www.msftconnecttest.com не должен получать IPv6")
        return 1
    capability = answer_query(settings, build_query("xbox.ipv6.microsoft.com", 1))
    if capability is None or [item[0] for item in parse_answers(capability)[0]] != ["203.0.113.10"]:
        print("xbox.ipv6.microsoft.com должен указывать на VPS")
        return 1
    flags = struct.unpack("!H", hijacked[2:4])[0]
    if flags & 0x0400 or not (flags & 0x8000) or not (flags & 0x0080):
        print(f"флаги ответа {flags:#06x}")
        return 1
    cookie = struct.pack("!HH", 10, 8) + b"\x11" * 8
    opted = bytearray(build_query("device.auth.xboxlive.com", 1))
    struct.pack_into("!H", opted, 10, 1)
    # OPT: корень, тип 41, размер 1232, TTL с битом DO и cookie клиента
    opted += b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, len(cookie)) + cookie
    echoed = answer_query(settings, bytes(opted))
    if echoed is None or struct.unpack("!H", echoed[10:12])[0] != 1:
        print("EDNS из запроса должен вернуться")
        return 1
    qsize, qdo, qcookie = opt_facts(bytes(opted))
    rsize, rdo, rcookie = opt_facts(echoed)
    if (qsize, qdo, qcookie) != (1232, True, True) or (rsize, rdo, rcookie) != (1232, False, True):
        print(qsize, qdo, qcookie, rsize, rdo, rcookie)
        return 1
    trace = dns_trace(bytes(opted), echoed, "203.0.113.5", 5353, "udp")
    head, _, tail = trace.partition(" ответ=")
    if "DO" not in head or "cookie" not in head or "+DO" in tail or "an=1" not in tail:
        print(trace)
        return 1
    page = connect_test_response(
        "www.msftconnecttest.com",
        b"GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n\r\n",
    )
    if page is None or b"Microsoft Connect Test" not in page:
        print(page)
        return 1

    sni = extract_sni(client_hello("api.example.com"))
    if sni != "api.example.com":
        print(sni)
        return 1
    host = extract_host(b"GET / HTTP/1.1\r\nHost: API.Example.COM:443\r\n\r\n")
    if host != "API.Example.COM":
        print(host)
        return 1
    if not acceptable_origin("20.201.192.51", set()) or not acceptable_origin("2001:4860:4860::8888", set()):
        print("публичный адрес Microsoft должен остаться целью")
        return 1
    for blocked in ("192.168.1.1", "10.1.2.3", "172.16.0.1", "100.64.0.1", "203.0.113.10", "127.0.0.1", "::ffff:10.1.1.1"):
        if acceptable_origin(blocked, set()):
            print(f"внутренний адрес нельзя выбирать целью: {blocked}")
            return 1
    if acceptable_origin("::ffff:8.8.8.8", set()):
        pass
    else:
        print("публичный адрес внутри IPv6-записи должен остаться целью")
        return 1
    if "\n" in log_text("xbox\nlive") or log_text("xbox\nlive") != "xbox?live":
        print(log_text("xbox\nlive"))
        return 1
    print("egress_proxy: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
