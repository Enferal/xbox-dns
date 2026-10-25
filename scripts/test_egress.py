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
    NeedMore,
    Settings,
    ALIAS_PORT_BASE,
    ALIAS_PORT_COUNT,
    answer_query,
    connect_test_response,
    connectivity_addresses,
    dns_trace,
    extract_host,
    extract_sni,
    first_question,
    opt_facts,
    is_connectivity_probe,
    is_nxdomain,
    log_text,
    origin_port,
    parse_answers,
    proxy_ports_with_alias,
    parse_domain,
    service_binding_rdata,
    parse_ports,
    format_ports,
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
    if answer_query(settings, build_query("xbox.ipv6.microsoft.com", 1)) is not None:
        print("xbox.ipv6.microsoft.com нельзя подменять")
        return 1
    gone = bytearray(build_query("pti.store.microsoft.com", 1))
    gone[3] = 3
    if not is_nxdomain(bytes(gone)):
        print("NXDOMAIN не распознан")
        return 1
    if is_nxdomain(build_query("device.auth.xboxlive.com", 1)):
        print("обычный запрос принят за отсутствующее имя")
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

    hello = client_hello("api2.cursor.sh")
    sni = extract_sni(hello)
    if sni != "api2.cursor.sh":
        print(sni)
        return 1
    longer = hello + b"\x00" * 400
    longer = longer[:3] + struct.pack("!H", int.from_bytes(hello[3:5], "big") + 400) + longer[5:]
    if extract_sni(longer[: len(hello)]) != "api2.cursor.sh":
        print("имя должно читаться из первого сегмента")
        return 1
    try:
        extract_sni(hello[:40])
    except NeedMore:
        pass
    else:
        print("обрезанное рукопожатие без имени должно ждать хвост")
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
    ports = parse_ports("80,443,42130,44326,15000-15002,443")
    if ports != [80, 443, 42130, 44326, 15000, 15001, 15002]:
        print(ports)
        return 1
    if format_ports(ports) != "80, 443, 15000-15002, 42130, 44326":
        print(format_ports(ports))
        return 1
    for bad in ("0", "65536", "15099-15000", "abc", "80-"):
        try:
            parse_ports(bad)
        except ConfigError:
            pass
        else:
            print(f"порт должен быть отвергнут: {bad}")
            return 1
    if "\n" in log_text("xbox\nlive") or log_text("xbox\nlive") != "xbox?live":
        print(log_text("xbox\nlive"))
        return 1

    def svcb_keys(rdata: bytes) -> list[tuple[int, bytes]]:
        pos = 3
        found = []
        while pos + 4 <= len(rdata):
            key, length = struct.unpack("!HH", rdata[pos : pos + 4])
            pos += 4
            found.append((key, rdata[pos : pos + length]))
            pos += length
        return found

    plain = svcb_keys(service_binding_rdata(["203.0.113.10"]))
    if [key for key, _value in plain] != [1, 4]:
        print(plain)
        return 1
    shifted = svcb_keys(service_binding_rdata(["203.0.113.10"], 44410))
    if [key for key, _value in shifted] != [1, 3, 4] or shifted[1][1] != struct.pack("!H", 44410):
        print(shifted)
        return 1
    web = Settings(
        domains=["themoviedb.org", "xboxlive.com"],
        exits_v4=["203.0.113.10"],
        exits_v6=[],
        own_ips=set(),
        listen_ip="0.0.0.0",
        dns_port=53,
        proxy_ports=[80, 443],
        upstreams=["1.1.1.1"],
        allow=[],
        depth=4,
        ttl=60,
    )
    www = answer_query(web, build_query("www.themoviedb.org", 65))
    media = answer_query(web, build_query("media.themoviedb.org", 65))
    if www is None or media is None or web.name_ports.port_of("media.themoviedb.org") == 0:
        print("порт картинок должен быть стабильным")
        return 1
    if web.name_ports.assign("media.themoviedb.org", "themoviedb.org") != web.name_ports.port_of("media.themoviedb.org"):
        print("повторный запрос сменил порт")
        return 1
    if struct.pack("!HHH", 3, 2, 0)[:4] in www:
        print("www остаётся на 443")
        return 1
    media_port = web.name_ports.port_of("media.themoviedb.org")
    if not ALIAS_PORT_BASE <= media_port < ALIAS_PORT_BASE + ALIAS_PORT_COUNT or struct.pack("!H", media_port) not in media:
        print(media_port)
        return 1
    api_port = web.name_ports.assign("api.themoviedb.org", "themoviedb.org")
    if api_port == media_port or api_port == 0:
        print(api_port, media_port)
        return 1
    for host in ("user.auth.xboxlive.com", "title.mgt.xboxlive.com"):
        packet = answer_query(web, build_query(host, 65))
        if packet is None or web.name_ports.port_of(host):
            print(host)
            return 1
    if origin_port(443) != 443 or origin_port(media_port) != 443 or origin_port(80) != 80:
        print("дополнительный порт должен открывать у сайта 443")
        return 1
    off = Settings(
        domains=["themoviedb.org"],
        exits_v4=["203.0.113.10"],
        exits_v6=[],
        own_ips=set(),
        listen_ip="0.0.0.0",
        dns_port=53,
        proxy_ports=[80, 443],
        upstreams=["1.1.1.1"],
        allow=[],
        depth=4,
        ttl=60,
        split_https=False,
    )
    if answer_query(off, build_query("media.themoviedb.org", 65)) is None or off.name_ports.port_of("media.themoviedb.org"):
        print("выключенный SPLIT_HTTPS должен оставить 443")
        return 1
    held = Settings(
        domains=["themoviedb.org"],
        exits_v4=["203.0.113.10"],
        exits_v6=[],
        own_ips=set(),
        listen_ip="0.0.0.0",
        dns_port=53,
        proxy_ports=[80, 443],
        upstreams=["1.1.1.1"],
        allow=[],
        depth=4,
        ttl=60,
        same_port=["themoviedb.org"],
    )
    if answer_query(held, build_query("media.themoviedb.org", 65)) is None or held.name_ports.port_of("media.themoviedb.org"):
        print("зона общего порта должна остаться на 443")
        return 1
    if proxy_ports_with_alias("80,443", "0") != "80,443" or proxy_ports_with_alias("80,443", "1") != "80,443,44400-44463":
        print(proxy_ports_with_alias("80,443", "1"))
        return 1
    print("egress_proxy: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
