#!/usr/bin/env python3
"""DNS на VPS и прокси для доменов из списка.

Устройство использует этот сервер как DNS. Для доменов из списка ответ — адрес VPS.
Дальше VPS принимает TCP, читает имя из TLS или HTTP и открывает соединение
с настоящим сервером со своего адреса. Остальные имена резолвятся как обычно.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import random
import re
import socket
import struct
import sys
import time
import zlib
from dataclasses import dataclass, field


LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
QTYPE_A = 1
QTYPE_CNAME = 5
QTYPE_AAAA = 28
QTYPE_HTTPS = 65
QTYPE_SVCB = 64
QTYPE_OPT = 41
HIJACK_TYPES = {QTYPE_A, QTYPE_AAAA, QTYPE_HTTPS, QTYPE_SVCB}
# Эти имена приставка использует, чтобы решить, есть ли интернет.
# dns.msftncsi.com обязан ответить фиксированным адресом Microsoft. Соединения туда нет.
# www.msftconnecttest.com приставка открывает по HTTP. Ответ «Microsoft Connect Test»
# отдаёт сам VPS, поэтому Microsoft не видит домашний адрес.
CONNECTIVITY_PROBES = (
    "msftncsi.com",
    "msftconnecttest.com",
)
NCSI_IPV4 = "131.107.255.255"
NCSI_IPV6 = "fd3e:4f5a:5b81::1"
# Приставка не открывает это имя, если ответ совпадает с адресом её DNS.
# Поэтому здесь остаётся настоящий адрес Microsoft, соединение идёт с дома.
IPV6_CAPABILITY = "xbox.ipv6.microsoft.com"
CONNECT_TEST_BODY = b"Microsoft Connect Test"
# Крупные файлы. Эти имена не подменяются: приставка качает их со своего адреса.
DIRECT_DOWNLOADS = (
    "dl.delivery.mp.microsoft.com",
    "dlassets.xboxlive.com",
    "dlassets2.xboxlive.com",
    "assets1.xboxlive.com",
    "assets2.xboxlive.com",
    "assets3.xboxlive.com",
    "assets4.xboxlive.com",
    "assets5.xboxlive.com",
)
# Приставке хватает десятков соединений. Потолок режет только поток, который хочет занять весь сервер.
MAX_DNS_INFLIGHT = 256
MAX_PROXY_CONNECTIONS = 256
# Один адрес VPS на все имена. Браузер склеивает HTTP/2, если сертификат покрывает оба имени
# и порт один: картинки media.themoviedb.org уезжают в соединение www. Чужой порт в записи HTTPS
# этого не даёт. Зоны приставки сюда не входят и остаются на 443.
ALIAS_PORT_BASE = 44400
ALIAS_PORT_COUNT = 64
SAME_PORT_ZONES = frozenset(
    {
        "xboxlive.com",
        "xbox.com",
        "xboxservices.com",
        "gamepass.com",
        "bing.com",
        "microsoft.com",
        "akamai.net",
        "windowsupdate.com",
        "akamaized.net",
        "live.com",
        "microsoftonline.com",
        "microsoftonline-p.com",
        "msauth.net",
        "msauthimages.net",
        "msftauth.net",
        "msftauthimages.net",
        "ea.com",
        "blob.core.windows.net",
    }
)


class ConfigError(Exception):
    pass


class NeedMore(Exception):
    pass


class NamePorts:
    """Порт, который браузер откроет к VPS. 0 значит обычный 443."""

    def __init__(self) -> None:
        self._ports: dict[str, int] = {}
        self._used: set[int] = set()

    def assign(self, name: str, base: str) -> int:
        if name in self._ports:
            return self._ports[name]
        if shared_port_name(name, base):
            self._ports[name] = 0
            return 0
        start = zlib.crc32(name.encode("ascii")) % ALIAS_PORT_COUNT
        chosen = 0
        for step in range(ALIAS_PORT_COUNT):
            candidate = ALIAS_PORT_BASE + (start + step) % ALIAS_PORT_COUNT
            if candidate not in self._used:
                chosen = candidate
                break
        if not chosen:
            chosen = ALIAS_PORT_BASE + start
        self._used.add(chosen)
        self._ports[name] = chosen
        return chosen

    def port_of(self, name: str) -> int:
        return self._ports.get(name, 0)


def shared_port_name(name: str, base: str) -> bool:
    """Само имя зоны и www остаются на 443. Остальные имена получают свой порт."""
    labels = name.split(".")
    base_labels = base.split(".")
    if len(labels) < len(base_labels) or labels[-len(base_labels) :] != base_labels:
        return False
    head = labels[: len(labels) - len(base_labels)]
    return head in ([], ["www"])


def alias_port_range() -> str:
    return f"{ALIAS_PORT_BASE}-{ALIAS_PORT_BASE + ALIAS_PORT_COUNT - 1}"


def proxy_ports_with_alias(proxy_ports: str, split_https: str) -> str:
    if str(split_https).strip().lower() not in {"1", "true", "yes", "on"}:
        return proxy_ports
    extra = alias_port_range()
    tokens = [item.strip() for item in proxy_ports.split(",") if item.strip()]
    if extra in tokens:
        return proxy_ports
    return ",".join([*tokens, extra])


def alias_listen_ports(proxy_ports: list[int]) -> list[int]:
    occupied = set(proxy_ports)
    return [ALIAS_PORT_BASE + offset for offset in range(ALIAS_PORT_COUNT) if ALIAS_PORT_BASE + offset not in occupied]


def origin_port(local_port: int) -> int:
    if ALIAS_PORT_BASE <= local_port < ALIAS_PORT_BASE + ALIAS_PORT_COUNT:
        return 443
    return local_port


@dataclass
class Settings:
    domains: list[str]
    exits_v4: list[str]
    exits_v6: list[str]
    own_ips: set[str]
    listen_ip: str
    dns_port: int
    proxy_ports: list[int]
    upstreams: list[str]
    allow: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    depth: int
    ttl: int
    ipv6: bool = False
    direct: list[str] = field(default_factory=list)
    origin_cache: dict[str, tuple[float, list[str]]] = field(default_factory=dict)
    nx_cache: dict[str, tuple[float, bool]] = field(default_factory=dict)
    dns_inflight: int = 0
    proxy_inflight: int = 0
    stats: dict[str, int] = field(default_factory=dict)
    name_ports: NamePorts = field(default_factory=lambda: NamePorts())
    split_https: bool = True
    same_port: list[str] | None = None

    def count(self, key: str) -> None:
        self.stats[key] = self.stats.get(key, 0) + 1

    @property
    def exit_set(self) -> set[str]:
        return set(self.exits_v4) | set(self.exits_v6)


def fail(message: str) -> None:
    raise ConfigError(message)


def log_text(value: str, limit: int = 253) -> str:
    """В журнал нельзя писать перевод строки: им рисуют лишнюю запись."""
    cleaned = []
    for char in value:
        if char.isprintable() and char not in "\r\n\t":
            cleaned.append(char)
        else:
            cleaned.append("?")
    text = "".join(cleaned).strip()
    if len(text) > limit:
        return text[:limit]
    return text or "-"


_full_note_at = 0.0


def note_full(kind: str, client: str) -> None:
    global _full_note_at
    now = time.monotonic()
    if now - _full_note_at < 2:
        return
    _full_note_at = now
    print(f"{kind} очередь полная, лишнее закрыто клиент={client}")


def read_lines(path: str) -> list[str]:
    if not os.path.isfile(path):
        fail(f"Нет файла {path}")
    lines: list[str] = []
    with open(path, encoding="utf-8-sig") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if line:
                lines.append(line)
    return lines


def ascii_name(name: str) -> str:
    text = name.strip().lower().rstrip(".")
    if not text or any(char.isspace() for char in text) or "/" in text:
        fail(f"{name!r} не является доменом")
    try:
        ascii_text = text.encode("idna").decode("ascii")
    except UnicodeError:
        fail(f"{name!r} не удалось перекодировать в punycode")
    labels = ascii_text.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels) or len(ascii_text) > 253:
        fail(f"{name!r} не является доменом")
    return ascii_text


def parse_domain(token: str) -> str:
    name = token.strip().lower()
    while name.startswith("*."):
        name = name[2:]
    name = ascii_name(name)
    if name.count(".") < 1:
        fail(f"{token!r} слишком короткий домен. Укажите имя вроде example.com")
    return name


def load_direct(path: str) -> list[str]:
    """Файл заменяет встроенный список. Если файла нет, закачка идёт мимо VPS по встроенным именам."""
    if not os.path.isfile(path):
        return list(DIRECT_DOWNLOADS)
    found: list[str] = []
    seen: set[str] = set()
    for token in read_lines(path):
        if _is_ip(token) or "/" in token:
            fail(f"{token!r}: в списке закачки нужны домены")
        name = parse_domain(token)
        if name not in seen:
            seen.add(name)
            found.append(name)
    return found


def load_domains(path: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for token in read_lines(path):
        if _is_ip(token) or "/" in token:
            fail(f"{token!r}: в списке целей нужны домены. IP клиент и так набирает напрямую, DNS тут не участвует")
        name = parse_domain(token)
        if name not in seen:
            seen.add(name)
            found.append(name)
    if not found:
        fail(f"В {path} нет доменов. Добавьте хотя бы одно имя.")
    return found


def load_same_port(path: str) -> list[str] | None:
    """None — файла нет, остаются встроенные зоны приставки. Пустой файл — таких зон нет."""
    if not os.path.isfile(path):
        return None
    found: list[str] = []
    seen: set[str] = set()
    for token in read_lines(path):
        if _is_ip(token) or "/" in token:
            fail(f"{token!r}: в списке общего порта нужны домены")
        name = parse_domain(token)
        if name not in seen:
            seen.add(name)
            found.append(name)
    return found


def same_port_zones(settings: Settings) -> set[str]:
    if settings.same_port is None:
        return set(SAME_PORT_ZONES)
    return set(settings.same_port)


def same_port_preset() -> str:
    lines = [
        "# Зоны, которые остаются на порту 443.",
        "# Остальные зоны из списка «через прокси» получают отдельные порты.",
        *sorted(SAME_PORT_ZONES),
    ]
    return "\n".join(lines) + "\n"


def https_client_port(settings: Settings, name: str) -> int:
    if not settings.split_https:
        return 0
    base = match_base(name, settings.domains, settings.depth)
    if not base or base in same_port_zones(settings):
        return 0
    return settings.name_ports.assign(ascii_name(name), base)


def is_connectivity_probe(name: str) -> bool:
    try:
        text = ascii_name(name)
    except ConfigError:
        return False
    return any(text == probe or text.endswith("." + probe) for probe in CONNECTIVITY_PROBES)


def connectivity_addresses(name: str, qtype: int) -> list[str] | None:
    """Фиксированный ответ только для dns.msftncsi.com. Остальные пробы указывают на VPS."""
    try:
        text = ascii_name(name)
    except ConfigError:
        return None
    if text != "dns.msftncsi.com":
        return None
    if qtype == QTYPE_A:
        return [NCSI_IPV4]
    if qtype == QTYPE_AAAA:
        return [NCSI_IPV6]
    return []


def is_ipv6_capability_name(name: str) -> bool:
    try:
        return ascii_name(name) == IPV6_CAPABILITY
    except ConfigError:
        return False


def is_nxdomain(packet: bytes) -> bool:
    return len(packet) >= 12 and (packet[3] & 0x0F) == 3


def is_fixed_ncsi(name: str) -> bool:
    try:
        return ascii_name(name) == "dns.msftncsi.com"
    except ConfigError:
        return False


def connect_test_response(host: str, head: bytes) -> bytes | None:
    try:
        text = ascii_name(host)
    except ConfigError:
        return None
    if not is_connectivity_probe(text) or text == "dns.msftncsi.com":
        return None
    path = b"/"
    request = head.split(b"\r\n", 1)[0].split()
    if len(request) >= 2:
        path = request[1].split(b"?", 1)[0]
    if path == b"/connecttest.txt":
        body = CONNECT_TEST_BODY
        status = b"200 OK"
    else:
        body = b""
        status = b"404 Not Found"
    length = str(len(body)).encode("ascii")
    return (
        b"HTTP/1.1 "
        + status
        + b"\r\nContent-Type: text/plain\r\nContent-Length: "
        + length
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )


def is_direct_download(name: str, names: list[str], depth: int) -> bool:
    return bool(names) and domain_matches(name, names, depth)


def match_base(name: str, domains: list[str], depth: int) -> str | None:
    try:
        labels = ascii_name(name).split(".")
    except ConfigError:
        return None
    found: str | None = None
    for base in domains:
        base_labels = base.split(".")
        matched = labels == base_labels or (
            len(labels) > len(base_labels)
            and labels[-len(base_labels) :] == base_labels
            and 1 <= len(labels) - len(base_labels) <= depth
        )
        if matched and (found is None or len(base) < len(found)):
            found = base
    return found


def domain_matches(name: str, domains: list[str], depth: int) -> bool:
    return match_base(name, domains, depth) is not None


def _is_ip(token: str) -> bool:
    bare = token[1:-1] if token.startswith("[") and token.endswith("]") else token
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        return False
    return True


def encode_name(name: str) -> bytes:
    body = b""
    for label in ascii_name(name).split("."):
        raw = label.encode("ascii")
        body += bytes([len(raw)]) + raw
    return body + b"\x00"


def read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[bytes] = []
    hopped = False
    end = offset
    hops = 0
    pos = offset
    while True:
        if pos >= len(packet):
            raise ValueError("обрезанное dns-имя")
        length = packet[pos]
        if length == 0:
            pos += 1
            if not hopped:
                end = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(packet) or hops > 16:
                raise ValueError("некорректный dns-указатель")
            hops += 1
            if not hopped:
                end = pos + 2
                hopped = True
            pos = ((length & 0x3F) << 8) | packet[pos + 1]
            continue
        if length & 0xC0:
            raise ValueError("неподдерживаемая dns-метка")
        pos += 1
        if pos + length > len(packet):
            raise ValueError("обрезанная dns-метка")
        labels.append(packet[pos : pos + length])
        pos += length
    name = ".".join(label.decode("ascii") for label in labels)
    return name, end


def first_question(packet: bytes) -> tuple[str, int, int, int]:
    if len(packet) < 12:
        raise ValueError("короткий dns-пакет")
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount < 1:
        raise ValueError("в dns-пакете нет вопроса")
    name, offset = read_name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("обрезанный dns-вопрос")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return name, qtype, qclass, offset + 4


def parse_answers(packet: bytes) -> tuple[list[tuple[str, int]], str | None]:
    try:
        _, _, _, offset = first_question(packet)
    except ValueError:
        return [], None
    ancount = struct.unpack("!H", packet[6:8])[0]
    found: list[tuple[str, int]] = []
    cname = None
    for _ in range(ancount):
        if offset >= len(packet):
            break
        _, offset = read_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        data_at = offset + 10
        offset = data_at + rdlength
        if offset > len(packet):
            break
        if rtype == QTYPE_A and rdlength == 4:
            found.append((str(ipaddress.IPv4Address(packet[data_at:data_at + 4])), ttl))
        elif rtype == QTYPE_AAAA and rdlength == 16:
            found.append((str(ipaddress.IPv6Address(packet[data_at:data_at + 16])), ttl))
        elif rtype == QTYPE_CNAME and cname is None:
            try:
                cname, _ = read_name(packet, data_at)
            except ValueError:
                cname = None
    return found, cname


def build_query(name: str, qtype: int) -> bytes:
    tid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


def nodata_soa(ttl: int) -> bytes:
    rdata = encode_name("ns.invalid") + encode_name("hostmaster.invalid")
    rdata += struct.pack("!IIIII", 1, 3600, 600, 86400, max(ttl, 0))
    return b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, ttl, len(rdata)) + rdata


def service_binding_rdata(addresses: list[str], port: int = 0) -> bytes:
    # Приставка спрашивает тип HTTPS и без этой записи не открывает TCP.
    # В списке протоколов нет h3, поэтому QUIC мимо прокси не выбирается.
    # Ключи параметров идут по возрастанию: 1 alpn, 3 port, 4 ipv4hint.
    alpn = b"\x02h2\x08http/1.1"
    params = struct.pack("!HH", 1, len(alpn)) + alpn
    if port:
        params += struct.pack("!HHH", 3, 2, port)
    hints = b"".join(ipaddress.IPv4Address(ip).packed for ip in addresses if ":" not in ip)
    if hints:
        params += struct.pack("!HH", 4, len(hints)) + hints
    return struct.pack("!H", 1) + b"\x00" + params


def _skip_rrs(packet: bytes, offset: int, count: int) -> int:
    for _ in range(count):
        _, offset = read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("обрезанная dns-запись")
        rdlength = struct.unpack("!H", packet[offset + 8 : offset + 10])[0]
        offset += 10 + rdlength
        if offset > len(packet):
            raise ValueError("обрезанная dns-запись")
    return offset


def read_opt_fields(packet: bytes) -> tuple[bytes, int, int, bytes] | None:
    """Имя, UDP-размер, TTL и данные первой OPT-записи."""
    if len(packet) < 12:
        return None
    qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", packet[4:12])
    try:
        offset = 12
        for _ in range(qdcount):
            _, offset = read_name(packet, offset)
            offset += 4
            if offset > len(packet):
                return None
        offset = _skip_rrs(packet, offset, ancount + nscount)
        for _ in range(arcount):
            start = offset
            _, offset = read_name(packet, offset)
            if offset + 10 > len(packet):
                return None
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
            end = offset + 10 + rdlength
            if end > len(packet):
                return None
            if rtype == QTYPE_OPT:
                return packet[start:offset], rclass, ttl, packet[offset + 10 : end]
            offset = end
    except (ValueError, struct.error, IndexError):
        return None
    return None


def _rdata_has_cookie(rdata: bytes) -> bool:
    pos = 0
    while pos + 4 <= len(rdata):
        code, length = struct.unpack("!HH", rdata[pos : pos + 4])
        pos += 4 + length
        if pos > len(rdata):
            return False
        if code == 10:
            return True
    return False


def opt_facts(packet: bytes) -> tuple[int, bool, bool]:
    found = read_opt_fields(packet)
    if found is None:
        return 0, False, False
    _name, udp_size, ttl, rdata = found
    return udp_size, bool(ttl & 0x8000), _rdata_has_cookie(rdata)


def extract_opt(packet: bytes) -> bytes | None:
    """OPT из запроса, с выключенным DNSSEC: подписи мы не отдаём."""
    found = read_opt_fields(packet)
    if found is None:
        return None
    name, rclass, ttl, rdata = found
    # Бит DO обещает RRSIG. Его нет, поэтому приставка могла отбрасывать ответ.
    new_ttl = ttl & ~0x8000
    return name + struct.pack("!HHIH", QTYPE_OPT, rclass, new_ttl, len(rdata)) + rdata


def answer_type_names(packet: bytes) -> str:
    if len(packet) < 12:
        return ""
    labels = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 28: "AAAA", 41: "OPT", 64: "SVCB", 65: "HTTPS"}
    try:
        qdcount, ancount, _, _arcount = struct.unpack("!HHHH", packet[4:12])
        offset = 12
        for _ in range(qdcount):
            _, offset = read_name(packet, offset)
            offset += 4
        names: list[str] = []
        for _ in range(ancount):
            _, offset = read_name(packet, offset)
            if offset + 10 > len(packet):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
            offset += 10 + rdlength
            names.append(labels.get(rtype, str(rtype)))
        return ",".join(names)
    except (ValueError, struct.error, IndexError):
        return ""


def dns_trace(query: bytes, response: bytes, client: str, port: int, transport: str) -> str:
    try:
        name, qtype, _, _ = first_question(query)
    except ValueError:
        name, qtype = "?", 0
    qid = int.from_bytes(query[:2], "big") if len(query) >= 2 else 0
    qsize, qdo, qcookie = opt_facts(query)
    qflags = int.from_bytes(query[2:4], "big") if len(query) >= 4 else 0
    qbits: list[str] = []
    if qflags & 0x0100:
        qbits.append("RD")
    if qflags & 0x0010:
        qbits.append("CD")
    if qsize:
        qbits.append(f"edns={qsize}")
    if qdo:
        qbits.append("DO")
    if qcookie:
        qbits.append("cookie")
    if response and len(response) >= 12:
        rflags = int.from_bytes(response[2:4], "big")
        an, ns, ar = struct.unpack("!HHH", response[6:12])
        rbits = [
            label
            for mask, label in (
                (0x8000, "QR"),
                (0x0400, "AA"),
                (0x0100, "RD"),
                (0x0080, "RA"),
                (0x0020, "AD"),
                (0x0010, "CD"),
            )
            if rflags & mask
        ]
        rsize, rdo, rcookie = opt_facts(response)
        redns = ""
        if rsize:
            redns = f" edns={rsize}"
            if rdo:
                redns += "+DO"
            if rcookie:
                redns += "+cookie"
        kinds = answer_type_names(response)
        answer = (
            f"ответ={len(response)}б {'+'.join(rbits)} rcode={rflags & 15} "
            f"an={an}{(':' + kinds) if kinds else ''} ns={ns} ar={ar}{redns}"
        )
    else:
        answer = "ответ=нет"
    asked = " ".join(qbits) or "без-edns"
    return (
        f"DNS пакет {log_text(name)} тип={qtype} id={qid:04x} {transport} {client}:{port} "
        f"запрос={len(query)}б {asked} {answer}"
    )


def synthetic_response(query: bytes, qtype: int, addresses: list[str], ttl: int, port: int = 0) -> bytes:
    _name, _qtype, _qclass, qend = first_question(query)
    question = query[12:qend]
    query_flags = struct.unpack("!H", query[2:4])[0]
    # QR+RA и запрошенные RD/CD. Без бита AA: рекурсивный DNS так не отвечает,
    # и приставка не использует адрес из такого пакета.
    flags = 0x8080 | (query_flags & 0x0100) | (query_flags & 0x0010)
    records: list[bytes] = []
    if qtype in {QTYPE_HTTPS, QTYPE_SVCB}:
        rdata = service_binding_rdata(addresses, port)
        records.append(b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata)
    else:
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if (qtype == QTYPE_A and ip.version != 4) or (qtype == QTYPE_AAAA and ip.version != 6):
                continue
            packed = ip.packed
            records.append(b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(packed)) + packed)
    body = b"".join(records)
    authority = b"" if records else nodata_soa(ttl)
    opt = extract_opt(query) or b""
    header = struct.pack(
        "!HHHHHH",
        struct.unpack("!H", query[:2])[0],
        flags,
        1,
        len(records),
        0 if records else 1,
        1 if opt else 0,
    )
    return header + question + body + authority + opt


def refused_response(query: bytes, rcode: int) -> bytes:
    tid = struct.unpack("!H", query[:2])[0] if len(query) >= 2 else 0
    question = b""
    qd = 0
    try:
        _, _, _, qend = first_question(query)
        question = query[12:qend]
        qd = 1
    except ValueError:
        pass
    flags = 0x8080 | (rcode & 0x0F)
    return struct.pack("!HHHHHH", tid, flags, qd, 0, 0, 0) + question


def extract_sni(data: bytes) -> str | None:
    if not data:
        raise NeedMore()
    if data[0] != 22:
        return None
    if len(data) < 5:
        raise NeedMore()
    record_len = int.from_bytes(data[3:5], "big")
    if len(data) < 5 + record_len:
        raise NeedMore()
    hs = data[5 : 5 + record_len]
    if len(hs) < 42 or hs[0] != 1:
        return None
    pos = 4 + 2 + 32
    if pos >= len(hs):
        return None
    session_len = hs[pos]
    pos += 1 + session_len
    if pos + 2 > len(hs):
        return None
    cipher_len = int.from_bytes(hs[pos : pos + 2], "big")
    pos += 2 + cipher_len
    if pos >= len(hs):
        return None
    comp_len = hs[pos]
    pos += 1 + comp_len
    if pos + 2 > len(hs):
        return None
    ext_len = int.from_bytes(hs[pos : pos + 2], "big")
    pos += 2
    ext_end = min(len(hs), pos + ext_len)
    while pos + 4 <= ext_end:
        etype = int.from_bytes(hs[pos : pos + 2], "big")
        elen = int.from_bytes(hs[pos + 2 : pos + 4], "big")
        pos += 4
        payload = hs[pos : pos + elen]
        pos += elen
        if etype != 0 or len(payload) < 5:
            continue
        name_type = payload[2]
        name_len = int.from_bytes(payload[3:5], "big")
        if name_type == 0 and 5 + name_len <= len(payload):
            return payload[5 : 5 + name_len].decode("ascii", "ignore")
    return None


def extract_host(data: bytes) -> str | None:
    if not data:
        raise NeedMore()
    if data[0] == 22 or not (65 <= data[0] <= 90):
        return None
    if b"\r\n\r\n" not in data:
        if len(data) < 8192:
            raise NeedMore()
        return None
    head = data.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"host:"):
            host = line.split(b":", 1)[1].strip().decode("latin1")
            if host.startswith("["):
                host = host[1:].split("]", 1)[0]
            else:
                host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            return host.strip() or None
    return None


def parse_allow(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    found = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "/" in token:
                found.append(ipaddress.ip_network(token, strict=False))
            else:
                ip = ipaddress.ip_address(token)
                found.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))
        except ValueError:
            fail(f"ALLOW_CLIENTS содержит {token!r}")
    return found


def local_ips() -> set[str]:
    import subprocess

    try:
        output = subprocess.check_output(["ip", "-o", "addr", "show"], text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"Не удалось прочитать адреса интерфейсов: {exc}")
    found: set[str] = set()
    for line in output.splitlines():
        parts = line.split()
        kind = "inet" if "inet" in parts else "inet6" if "inet6" in parts else ""
        if not kind:
            continue
        addr = parts[parts.index(kind) + 1].split("/")[0].split("%")[0]
        found.add(str(ipaddress.ip_address(addr)))
    return found


def primary_ipv6() -> str | None:
    import subprocess

    try:
        output = subprocess.check_output(
            ["ip", "-6", "route", "get", "2001:4860:4860::8888"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    match = re.search(r"\bsrc\s+(\S+)", output)
    if not match:
        return None
    ip = ipaddress.ip_address(match.group(1).split("%", 1)[0])
    if ip.version != 6 or not ip.is_global:
        return None
    return str(ip)


def primary_ipv4() -> str:
    import subprocess

    try:
        output = subprocess.check_output(["ip", "-4", "route", "get", "1.1.1.1"], text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"Не удалось определить основной IPv4: {exc}")
    match = re.search(r"\bsrc\s+(\S+)", output)
    if not match:
        fail("В маршруте по умолчанию нет адреса источника")
    ip = ipaddress.ip_address(match.group(1))
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified:
        fail(f"Основной адрес {ip} не подходит")
    return str(ip)


def acceptable_origin(address: str, own_ips: set[str]) -> bool:
    """Цель соединения только из интернета. Внутренние и учебные адреса не подходят."""
    ip = ipaddress.ip_address(address)
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if not ip.is_global or str(ip) in own_ips or address in own_ips:
        return False
    return True


def client_allowed(settings: Settings, address: str) -> bool:
    if not settings.allow:
        return True
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip.is_loopback:
        return True
    return any(ip in network for network in settings.allow)


async def udp_exchange(upstream: str, payload: bytes, timeout: float = 2.5) -> bytes:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes] = loop.create_future()

    class Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr) -> None:
            if not future.done():
                future.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not future.done():
                future.set_exception(exc)

    transport, _ = await loop.create_datagram_endpoint(Proto, remote_addr=(upstream, 53))
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(future, timeout)
    finally:
        transport.close()


async def tcp_exchange(upstream: str, payload: bytes, timeout: float = 4) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(upstream, 53), timeout)
    try:
        writer.write(struct.pack("!H", len(payload)) + payload)
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(2), timeout)
        size = struct.unpack("!H", header)[0]
        return await asyncio.wait_for(reader.readexactly(size), timeout)
    finally:
        writer.close()
        await writer.wait_closed()


async def query_upstream(settings: Settings, name: str, qtype: int) -> bytes:
    query = build_query(name, qtype)
    last: Exception | None = None
    for upstream in settings.upstreams:
        try:
            response = await udp_exchange(upstream, query)
            if len(response) >= 12 and response[2] & 0x02:
                response = await tcp_exchange(upstream, query)
            if len(response) >= 12 and response[:2] == query[:2]:
                return response
        except Exception as exc:
            last = exc
    fail(f"Апстрим-DNS не ответил на {name}: {last}")
    return b""


async def resolve_origin(settings: Settings, name: str) -> list[str]:
    loop = asyncio.get_running_loop()
    cached = settings.origin_cache.get(name)
    if cached and cached[0] > loop.time():
        return cached[1]
    current = ascii_name(name)
    found: list[str] = []
    for _ in range(5):
        packet = await query_upstream(settings, current, QTYPE_A)
        records, cname = parse_answers(packet)
        ips = [
            ip
            for ip, _ttl in records
            if acceptable_origin(ip, settings.own_ips) and (settings.ipv6 or ":" not in ip)
        ]
        if ips:
            found.extend(ips)
            break
        if cname and ascii_name(cname) != current:
            current = ascii_name(cname)
            continue
        break
    if settings.ipv6:
        try:
            packet = await query_upstream(settings, current, QTYPE_AAAA)
            records, cname = parse_answers(packet)
            if not records and cname:
                packet = await query_upstream(settings, ascii_name(cname), QTYPE_AAAA)
                records, _cname = parse_answers(packet)
            found.extend(
                ip
                for ip, _ttl in records
                if acceptable_origin(ip, settings.own_ips) and ":" in ip
            )
        except ConfigError:
            pass
    if found:
        settings.origin_cache[name] = (loop.time() + 60, found)
        return found
    fail(f"У {name} нет внешнего адреса, до которого можно дойти с VPS")
    return []


async def forward_query(settings: Settings, payload: bytes, name: str = "") -> bytes:
    last: Exception | None = None
    for upstream in settings.upstreams:
        try:
            response = await udp_exchange(upstream, payload)
            if len(response) >= 12 and response[2] & 0x02:
                response = await tcp_exchange(upstream, payload)
            if len(response) >= 2 and payload[:2] == response[:2]:
                return response
        except Exception as exc:
            last = exc
    detail = str(last).strip() if last is not None else ""
    print(f"DNS апстрим недоступен {name}: {detail or 'таймаут'}", file=sys.stderr)
    return refused_response(payload, 2)


async def name_missing(settings: Settings, name: str) -> bool:
    """Имени нет у внешнего DNS. Такой ответ нельзя подменять адресом VPS."""
    try:
        text = ascii_name(name)
    except ConfigError:
        return False
    now = asyncio.get_running_loop().time()
    cached = settings.nx_cache.get(text)
    if cached and cached[0] > now:
        return cached[1]
    try:
        packet = await query_upstream(settings, text, QTYPE_A)
    except ConfigError:
        return False
    missing = is_nxdomain(packet)
    settings.nx_cache[text] = (now + 60, missing)
    return missing


def log_public_dns(response: bytes, name: str, kind: str, client_ip: str) -> None:
    found, _cname = parse_answers(response)
    shown = ", ".join(ip for ip, _ttl in found) or "без адреса"
    print(
        f"DNS {log_text(name)} {kind} -> {shown} проверка связи, адрес Microsoft клиент={client_ip}"
    )


def answer_query(settings: Settings, payload: bytes) -> bytes | None:
    try:
        name, qtype, qclass, _end = first_question(payload)
    except ValueError:
        return None
    if (
        qclass != 1
        or is_fixed_ncsi(name)
        or is_ipv6_capability_name(name)
        or is_direct_download(name, settings.direct, settings.depth)
    ):
        return None
    listed = domain_matches(name, settings.domains, settings.depth)
    if not listed and not is_connectivity_probe(name):
        return None
    if qtype not in HIJACK_TYPES and qtype != QTYPE_CNAME:
        return None
    if qtype in {QTYPE_A, QTYPE_HTTPS, QTYPE_SVCB}:
        addresses = settings.exits_v4
    elif qtype == QTYPE_AAAA:
        addresses = settings.exits_v6
    else:
        addresses = []
    port = https_client_port(settings, name) if qtype in {QTYPE_HTTPS, QTYPE_SVCB} else 0
    return synthetic_response(payload, qtype, addresses, settings.ttl, port)


async def handle_dns(settings: Settings, payload: bytes, client_ip: str) -> bytes | None:
    settings.count("dns_queries")
    if not client_allowed(settings, client_ip):
        settings.count("dns_refused")
        print(f"Отказ DNS клиенту {client_ip}: адреса нет в ALLOW_CLIENTS")
        return None
    try:
        asked_name, asked_type, _, _ = first_question(payload)
    except ValueError:
        asked_name, asked_type = "", 0
    kind = {QTYPE_A: "A", QTYPE_AAAA: "AAAA", QTYPE_HTTPS: "HTTPS", QTYPE_SVCB: "SVCB"}.get(
        asked_type, str(asked_type)
    )
    probe = connectivity_addresses(asked_name, asked_type)
    if probe is not None:
        print(f"DNS {log_text(asked_name)} {kind} -> {', '.join(probe) or 'пусто'} проверка связи клиент={client_ip}")
        return synthetic_response(payload, asked_type, probe, settings.ttl)
    if is_direct_download(asked_name, settings.direct, settings.depth):
        settings.count("dns_direct")
        print(
            f"DNS {log_text(asked_name)} {kind} закачка напрямую, адрес сети доставки клиент={client_ip}"
        )
        return await forward_query(settings, payload, asked_name)
    if is_ipv6_capability_name(asked_name):
        response = await forward_query(settings, payload, asked_name)
        log_public_dns(response, asked_name, kind, client_ip)
        return response
    listed = domain_matches(asked_name, settings.domains, settings.depth)
    if listed and await name_missing(settings, asked_name):
        print(f"DNS {log_text(asked_name)} нет такого имени, ответ DNS без подмены клиент={client_ip}")
        return await forward_query(settings, payload, asked_name)
    if (
        asked_type == QTYPE_AAAA
        and not settings.ipv6
        and (listed or is_connectivity_probe(asked_name))
    ):
        print(f"DNS {log_text(asked_name)} AAAA -> пусто, через прокси IPv6 нет клиент={client_ip}")
        return synthetic_response(payload, QTYPE_AAAA, [], settings.ttl)
    local = answer_query(settings, payload)
    if local is not None:
        settings.count("dns_hijacked")
        try:
            name, qtype, _, _ = first_question(payload)
        except ValueError:
            name, qtype = "?", 0
        labels = {QTYPE_A: "A", QTYPE_AAAA: "AAAA", QTYPE_HTTPS: "HTTPS", QTYPE_SVCB: "SVCB"}
        if qtype in labels:
            shown = settings.exits_v6 if qtype == QTYPE_AAAA else settings.exits_v4
            alias = ""
            if qtype in {QTYPE_HTTPS, QTYPE_SVCB}:
                try:
                    number = settings.name_ports.port_of(ascii_name(name))
                except ConfigError:
                    number = 0
                if number:
                    alias = f" порт={number}"
            print(
                f"DNS {log_text(name)} {labels[qtype]} -> {', '.join(shown) or 'пусто'}{alias} клиент={client_ip}"
            )
        return local
    settings.count("dns_forwarded")
    return await forward_query(settings, payload, asked_name)


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def read_hello(reader: asyncio.StreamReader) -> tuple[bytes, str | None]:
    buf = b""
    while len(buf) < 16384:
        try:
            chunk = await asyncio.wait_for(reader.read(16384 - len(buf)), 8)
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
        try:
            if buf[0] == 22:
                return buf, extract_sni(buf)
            host = extract_host(buf)
            if host is not None or b"\r\n\r\n" in buf:
                return buf, host
        except NeedMore:
            continue
    return buf, None


def source_for(settings: Settings, address: str) -> str | None:
    version = ipaddress.ip_address(address).version
    pool = settings.exits_v6 if version == 6 else settings.exits_v4
    if not pool:
        return None
    return random.choice(pool)


async def connect_origin(settings: Settings, ips: list[str], port: int, prefer_v6: bool):
    def rank(address: str) -> int:
        return 0 if (":" in address) == prefer_v6 else 1

    last: Exception | None = None
    for address in sorted(ips, key=rank):
        source = source_for(settings, address)
        if source is None:
            continue
        try:
            conn = await asyncio.wait_for(
                asyncio.open_connection(address, port, local_addr=(source, 0)),
                10,
            )
            return conn, source
        except (OSError, TimeoutError) as exc:
            last = exc
    raise OSError(last or "нет соединения")


async def handle_proxy(settings: Settings, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    sockname = writer.get_extra_info("sockname") or ("", 0)
    client_ip = str(peer[0])
    peer_port = int(peer[1]) if len(peer) > 1 else 0
    port = int(sockname[1] or 0)
    print(f"TCP входящий порт={port} клиент={client_ip}:{peer_port}")
    settings.count("tcp_accepted")
    if settings.proxy_inflight >= MAX_PROXY_CONNECTIONS:
        settings.count("proxy_overflow")
        note_full("Прокси", f"{client_ip}:{peer_port}")
        writer.close()
        return
    settings.proxy_inflight += 1
    try:
        if not client_allowed(settings, client_ip):
            settings.count("proxy_refused")
            print(f"Отказ прокси клиенту {client_ip}: адреса нет в ALLOW_CLIENTS")
            writer.close()
            return
        if not settings.ipv6 and ":" in client_ip:
            print(f"Прокси не берёт IPv6-клиента {client_ip}")
            writer.close()
            return
        try:
            head, host = await read_hello(reader)
            if port == 80 and host:
                reply = connect_test_response(host, head)
                if reply is not None:
                    print(f"Проверка связи HTTP {ascii_name(host)} клиент={client_ip}")
                    writer.write(reply)
                    await writer.drain()
                    writer.close()
                    return
            if not host or not domain_matches(host, settings.domains, settings.depth):
                settings.count("proxy_no_name")
                sample = head[:16].hex() if head else "-"
                print(
                    f"Прокси закрыл соединение без подходящего имени, клиент={client_ip}:{peer_port} "
                    f"порт={port} имя={log_text(host) if host else '-'} байт={len(head)} начало={sample}"
                )
                writer.close()
                return
            host = ascii_name(host)
            origins = await resolve_origin(settings, host)
            prefer_v6 = ":" in str(sockname[0])
            (remote_reader, remote_writer), source = await connect_origin(
                settings, origins, origin_port(port), prefer_v6
            )
            if head:
                remote_writer.write(head)
                await remote_writer.drain()
        except Exception as exc:
            settings.count("proxy_errors")
            print(f"Прокси ошибка клиент={client_ip} порт={port}: {log_text(str(exc))}", file=sys.stderr)
            writer.close()
            return
        settings.count("proxy_ok")
        print(f"Прокси {host}:{port} -> {origins[0]} с адреса {source or 'по маршруту'} клиент={client_ip}")
        left = asyncio.create_task(pipe(reader, remote_writer))
        right = asyncio.create_task(pipe(remote_reader, writer))
        _done, pending = await asyncio.wait({left, right}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for stream in (writer, remote_writer):
            try:
                stream.close()
            except OSError:
                pass
    finally:
        settings.proxy_inflight = max(0, settings.proxy_inflight - 1)


class DnsUdp(asyncio.DatagramProtocol):
    def __init__(self, settings: Settings):
        self.settings = settings
        self.transport: asyncio.DatagramTransport | None = None
        self.tasks: set[asyncio.Task] = set()

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if self.settings.dns_inflight >= MAX_DNS_INFLIGHT:
            note_full("DNS", f"{addr[0]}:{addr[1]}")
            return
        self.settings.dns_inflight += 1
        task = asyncio.create_task(self.reply(data, addr))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def reply(self, data: bytes, addr) -> None:
        client = str(addr[0])
        port = int(addr[1]) if len(addr) > 1 else 0
        try:
            try:
                response = await handle_dns(self.settings, data, client)
            except Exception as exc:
                print(f"DNS ошибка {client}: {log_text(str(exc))}", file=sys.stderr)
                response = refused_response(data, 2)
            print(dns_trace(data, response or b"", client, port, "udp"))
            if not response or self.transport is None:
                print(f"DNS сокет не отправил {client}:{port}")
                return
            try:
                self.transport.sendto(response[:4096], addr)
            except OSError as exc:
                print(f"DNS сокет не отправил {client}:{port}: {exc}", file=sys.stderr)
        finally:
            self.settings.dns_inflight = max(0, self.settings.dns_inflight - 1)


async def handle_dns_tcp(settings: Settings, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    client = str(peer[0])
    if settings.dns_inflight >= MAX_DNS_INFLIGHT:
        note_full("DNS", client)
        writer.close()
        return
    settings.dns_inflight += 1
    try:
        while True:
            header = await reader.readexactly(2)
            size = struct.unpack("!H", header)[0]
            payload = await reader.readexactly(size)
            response = await handle_dns(settings, payload, client)
            peer_port = int(peer[1]) if len(peer) > 1 else 0
            print(dns_trace(payload, response or b"", client, peer_port, "tcp"))
            if response is None:
                break
            writer.write(struct.pack("!H", len(response)) + response)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        settings.dns_inflight = max(0, settings.dns_inflight - 1)
        writer.close()


MAX_PROXY_PORTS = 256


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    seen: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            left, right = token.split("-", 1)
            try:
                start, end = int(left), int(right)
            except ValueError:
                fail(f"Диапазон портов {token} записан не числами")
            if not 1 <= start <= end <= 65535:
                fail(f"Диапазон портов {token} вне 1-65535")
            expanded = range(start, end + 1)
        else:
            try:
                start = int(token)
            except ValueError:
                fail(f"Порт {token} не число")
            if not 1 <= start <= 65535:
                fail(f"Порт {start} вне диапазона")
            expanded = (start,)
        for port in expanded:
            if port in seen:
                continue
            seen.add(port)
            ports.append(port)
            if len(ports) > MAX_PROXY_PORTS:
                fail(f"PROXY_PORTS содержит больше {MAX_PROXY_PORTS} портов")
    if not ports:
        fail("PROXY_PORTS пуст")
    return ports


def format_ports(ports: list[int]) -> str:
    ordered = sorted(set(ports))
    if not ordered:
        return ""
    chunks: list[str] = []
    start = previous = ordered[0]
    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        chunks.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    chunks.append(str(start) if start == previous else f"{start}-{previous}")
    return ", ".join(chunks)


async def load_exit_addresses(path: str, upstreams: list[str], own: set[str]) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    seen: set[str] = set()
    settings = Settings([], [], [], own, "0.0.0.0", 53, [], upstreams, [], 4, 60)

    def push(address: str, origin: str) -> None:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
            fail(f"Адрес {ip} ({origin}) нельзя отдавать клиентам")
        if own and str(ip) not in own:
            fail(f"Адрес {ip} ({origin}) не назначен интерфейсу этого сервера")
        if ip.is_private:
            print(f"Предупреждение: {ip} частный. Устройства из интернета до него не дойдут.", file=sys.stderr)
        text = str(ip)
        if text in seen:
            return
        seen.add(text)
        (v4 if ip.version == 4 else v6).append(text)

    for token in read_lines(path):
        if token == "auto":
            push(primary_ipv4(), "auto")
            address_v6 = primary_ipv6()
            if address_v6:
                push(address_v6, "auto")
            continue
        bare = token[1:-1] if token.startswith("[") and token.endswith("]") else token
        if _is_ip(bare):
            push(bare, bare)
            continue
        name = ascii_name(token)
        records, _cname = parse_answers(await query_upstream(settings, name, QTYPE_A))
        if not records:
            fail(f"{name} не резолвится в адрес этого VPS")
        for address, _ttl in records:
            push(address, name)
    if not v4 and not v6:
        fail(f"В {path} нет исходящих адресов")
    return v4, v6


def env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip() or default


ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_env_text(text: str) -> dict[str, str]:
    """Строки KEY=VALUE как в EnvironmentFile systemd и env_file docker compose."""
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not ENV_KEY_RE.fullmatch(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        found[key] = value
    return found


def apply_env_file(path: str, required: bool) -> None:
    """Значения из файла важнее окружения процесса: этот файл правит Web UI."""
    if not os.path.isfile(path):
        if required:
            fail(f"Нет файла {path}")
        return
    with open(path, encoding="utf-8-sig") as handle:
        os.environ.update(parse_env_text(handle.read()))


async def load_settings() -> Settings:
    domains = load_domains(env("DESTINATIONS_FILE", "/etc/egress-proxy/allow-destinations.txt"))
    direct = load_direct(env("DIRECT_FILE", "/etc/egress-proxy/direct-destinations.txt"))
    upstreams = [token.strip() for token in env("DNS_UPSTREAM", "1.1.1.1,8.8.8.8").split(",") if token.strip()]
    for address in upstreams:
        ipaddress.ip_address(address)
    own = local_ips()
    v4, v6 = await load_exit_addresses(env("EXIT_IPS_FILE", "/etc/egress-proxy/exit-ips.txt"), upstreams, own)
    depth = int(env("MAX_WILDCARD_DEPTH", "4"))
    if depth < 0 or depth > 20:
        fail("MAX_WILDCARD_DEPTH должен быть от 0 до 20")
    ttl = int(env("ANSWER_TTL", "60"))
    ipv6 = env("IPV6", "1").lower() in {"1", "true", "yes", "on"}
    if not ipv6:
        v6 = []
    split_https = env("SPLIT_HTTPS", "1").lower() in {"1", "true", "yes", "on"}
    same_port = load_same_port(env("SAME_PORT_FILE", "/etc/egress-proxy/same-port-destinations.txt"))
    return Settings(
        domains=domains,
        exits_v4=v4,
        exits_v6=v6,
        own_ips=own | set(v4) | set(v6),
        listen_ip=env("LISTEN_IP", "0.0.0.0"),
        dns_port=int(env("DNS_PORT", "53")),
        proxy_ports=parse_ports(env("PROXY_PORTS", "80,443")),
        upstreams=upstreams,
        allow=parse_allow(env("ALLOW_CLIENTS", "")),
        depth=depth,
        ttl=ttl,
        ipv6=ipv6,
        direct=direct,
        split_https=split_https,
        same_port=same_port,
    )


def plan_dict(settings: Settings) -> dict:
    return {
        "domains": settings.domains,
        "direct": settings.direct,
        "exits_v4": settings.exits_v4,
        "exits_v6": settings.exits_v6,
        "listen_ip": settings.listen_ip,
        "dns_port": settings.dns_port,
        "proxy_ports": format_ports(settings.proxy_ports),
        "upstreams": settings.upstreams,
        "allow": [str(item) for item in settings.allow],
        "depth": settings.depth,
        "ttl": settings.ttl,
        "ipv6": settings.ipv6,
    }


def write_status(path: str, settings: Settings, started: float) -> None:
    data = {
        "pid": os.getpid(),
        "started_at": started,
        "updated_at": time.time(),
        "counters": dict(settings.stats),
        "dns_inflight": settings.dns_inflight,
        "proxy_inflight": settings.proxy_inflight,
        "plan": plan_dict(settings),
    }
    folder = os.path.dirname(path) or "."
    tmp = os.path.join(folder, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False)
    os.replace(tmp, path)


async def status_loop(path: str, settings: Settings, interval: float = 5.0) -> None:
    started = time.time()
    warned = False
    while True:
        try:
            write_status(path, settings, started)
        except OSError as exc:
            if not warned:
                print(f"Не удалось записать статус в {path}: {exc}", file=sys.stderr)
                warned = True
        await asyncio.sleep(interval)


def print_plan(settings: Settings) -> None:
    print("Домены в списке:")
    for name in settings.domains:
        print(f"  {name} и поддомены глубиной до {settings.depth}")
    published = ", ".join(settings.exits_v4 + settings.exits_v6)
    print(f"DNS отдаёт клиентам из списка: {published}")
    print(
        f"Слушаем {settings.listen_ip}:{settings.dns_port}, "
        f"прокси порты {format_ports(settings.proxy_ports)}"
    )
    if settings.allow:
        print("Пускать только: " + ", ".join(str(item) for item in settings.allow))
    else:
        print("ALLOW_CLIENTS пуст: обращаться может любой адрес.")
    if settings.ipv6 and settings.exits_v6:
        print("Домены из списка идут и по IPv4, и по IPv6.")
    elif settings.ipv6:
        print("IPv6 включён, но у VPS нет глобального IPv6. AAAA для списка останется пустым.")
    else:
        print("Домены из списка идут только по IPv4. IPv6 им не отдаётся и не проксируется.")
    print("Отладка: в журнале каждый DNS-ответ, каждый входящий TCP и UDP на портах прокси.")
    print(f"Одновременно не больше {MAX_DNS_INFLIGHT} DNS-запросов и {MAX_PROXY_CONNECTIONS} TCP-соединений.")
    if settings.direct:
        print("Закачка идёт напрямую с адреса клиента, не через VPS:")
        for name in settings.direct:
            print(f"  {name}")
    print("Проверка www.msftconnecttest.com отвечает сам VPS текстом Microsoft Connect Test.")
    print("xbox.ipv6.microsoft.com уходит на адреса Microsoft, приставка открывает его сама.")
    print("Имени нет в DNS — приставке уходит этот ответ, адрес VPS не подставляется.")
    print(f"dns.msftncsi.com остаётся адресом Microsoft, по IPv6: {NCSI_IPV6}")
    print(f"Остальные имена уходят на {', '.join(settings.upstreams)}")
    if settings.split_https:
        zones = ", ".join(sorted(same_port_zones(settings))) or "нет"
        print(
            f"Имена одной зоны, кроме www, получают порт {alias_port_range()}, чтобы браузер не склеивал HTTP/2. "
            f"На 443 остаются: {zones}. Диапазон должен быть открыт в файрволе."
        )
    else:
        print("SPLIT_HTTPS выключен: все имена открываются на 443.")


class UdpNotice(asyncio.DatagramProtocol):
    def __init__(self, port: int):
        self.port = port
        self.seen: dict[str, float] = {}

    def datagram_received(self, data: bytes, addr) -> None:
        now = asyncio.get_running_loop().time()
        key = f"{addr[0]}:{addr[1]}"
        if now - self.seen.get(key, 0) < 2:
            return
        self.seen[key] = now
        if len(self.seen) > 200:
            self.seen.clear()
        print(
            f"UDP входящий порт={self.port} клиент={addr[0]}:{addr[1]} "
            f"байт={len(data)} начало={data[:16].hex() or '-'}"
        )


async def serve(check_only: bool, as_json: bool = False) -> None:
    settings = await load_settings()
    if as_json:
        print(json.dumps({"ok": True, "plan": plan_dict(settings)}, ensure_ascii=False))
    else:
        print_plan(settings)
    if check_only:
        return
    loop = asyncio.get_running_loop()
    try:
        dns_udp, _dns_proto = await loop.create_datagram_endpoint(
            lambda: DnsUdp(settings),
            local_addr=(settings.listen_ip, settings.dns_port),
        )
        dns_tcp = await asyncio.start_server(
            lambda r, w: handle_dns_tcp(settings, r, w),
            settings.listen_ip,
            settings.dns_port,
        )
        if settings.ipv6 and settings.exits_v6:
            v6_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            v6_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            v6_sock.bind(("::", settings.dns_port))
            v6_sock.setblocking(False)
            await loop.create_datagram_endpoint(lambda: DnsUdp(settings), sock=v6_sock)
            v6_tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            v6_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            v6_tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            v6_tcp.bind(("::", settings.dns_port))
            v6_tcp.setblocking(False)
            await asyncio.start_server(lambda r, w: handle_dns_tcp(settings, r, w), sock=v6_tcp)
    except OSError as exc:
        owners = ""
        try:
            import subprocess

            owners = subprocess.check_output(
                ["ss", "-Htulpn", f"sport = :{settings.dns_port}"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError):
            owners = ""
        fail(
            f"Не удалось занять DNS-порт {settings.dns_port}: {exc}. "
            "Кто слушает порт:\n"
            + (owners.strip() or "ss ничего не показал")
        )
    proxies = []
    for port in settings.proxy_ports:
        try:
            proxies.append(
                await asyncio.start_server(
                    lambda r, w: handle_proxy(settings, r, w),
                    settings.listen_ip,
                    port,
                )
            )
        except OSError as exc:
            print(f"Порт {port} занят, прокси на нём не запущен: {exc}", file=sys.stderr)
        try:
            await loop.create_datagram_endpoint(lambda p=port: UdpNotice(p), local_addr=(settings.listen_ip, port))
        except OSError as exc:
            print(f"UDP-порт {port} не слушается: {exc}", file=sys.stderr)
        if not settings.ipv6 or not settings.exits_v6:
            continue
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(("::", port))
            sock.setblocking(False)
            proxies.append(await asyncio.start_server(lambda r, w: handle_proxy(settings, r, w), sock=sock))
        except OSError as exc:
            print(f"IPv6-порт {port} не слушается: {exc}", file=sys.stderr)
    if settings.split_https:
        for port in alias_listen_ports(settings.proxy_ports):
            try:
                proxies.append(
                    await asyncio.start_server(
                        lambda r, w: handle_proxy(settings, r, w),
                        settings.listen_ip,
                        port,
                    )
                )
            except OSError as exc:
                print(f"Порт {port} занят, прокси на нём не запущен: {exc}", file=sys.stderr)
            if not settings.ipv6 or not settings.exits_v6:
                continue
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(("::", port))
                sock.setblocking(False)
                proxies.append(await asyncio.start_server(lambda r, w: handle_proxy(settings, r, w), sock=sock))
            except OSError as exc:
                print(f"IPv6-порт {port} не слушается: {exc}", file=sys.stderr)
    print("Сервис запущен")
    status_path = os.environ.get("STATUS_FILE", "").strip()
    status_task = asyncio.create_task(status_loop(status_path, settings)) if status_path else None
    while True:
        await asyncio.sleep(3600)
        if status_task is not None and status_task.done():
            status_task = asyncio.create_task(status_loop(status_path, settings))


def healthcheck() -> int:
    host = "127.0.0.1"
    ports = [int(env("DNS_PORT", "53"))]
    ports.extend(parse_ports(env("PROXY_PORTS", "80,443")))
    for port in ports:
        try:
            with socket.create_connection((host, port), 3):
                pass
        except OSError as exc:
            print(f"Порт {port} недоступен: {exc}", file=sys.stderr)
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DNS и прокси доменов через VPS")
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true", help="вывод --check-config в JSON")
    parser.add_argument("--env-file", help="файл KEY=VALUE, по умолчанию из EGRESS_ENV_FILE")
    args = parser.parse_args(argv)
    try:
        if args.env_file:
            apply_env_file(args.env_file, required=True)
        elif os.environ.get("EGRESS_ENV_FILE", "").strip():
            apply_env_file(os.environ["EGRESS_ENV_FILE"].strip(), required=False)
        if args.check:
            return healthcheck()
        asyncio.run(serve(args.check_config, args.json and args.check_config))
    except ConfigError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        print(f"Ошибка конфигурации: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        print(f"Ошибка конфигурации: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
