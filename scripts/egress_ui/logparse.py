"""Разбор строк журнала egress-proxy в события."""

from __future__ import annotations

import re
from collections import Counter

KINDS = ("dns", "proxy", "direct", "refused", "error", "tcp", "trace", "other")

CLIENT_RE = re.compile(r"клиент[ау]?[= ]([0-9A-Fa-f:.]+)")
REFUSED_RE = re.compile(r"^Отказ (DNS|прокси) клиенту (\S+): ")
PROXY_RE = re.compile(r"^Прокси (\S+):(\d+) -> (\S+) с адреса (\S+)")
DNS_RE = re.compile(r"^DNS (\S+) (\S+)")
TCP_RE = re.compile(r"^TCP входящий порт=(\d+)")
NONAME_RE = re.compile(r"порт=(\d+) имя=(\S+)")


def _client(message: str, with_port: bool = False) -> str:
    """with_port: служба дописала к адресу :порт, его надо срезать и у IPv6."""
    match = CLIENT_RE.search(message)
    if not match:
        return ""
    value = match.group(1).rstrip(":.")
    if with_port and ":" in value:
        return value.rsplit(":", 1)[0]
    if value.count(":") == 1 and "." in value:
        return value.split(":", 1)[0]
    return value


def parse_line(message: str) -> dict:
    event = {"kind": "other", "client": "", "domain": "", "port": None}
    text = message.strip()
    refused = REFUSED_RE.match(text)
    if refused:
        event.update(kind="refused", client=refused.group(2), what=refused.group(1))
        return event
    if text.startswith(("Ошибка конфигурации", "DNS апстрим недоступен", "DNS ошибка", "Прокси ошибка")) or " очередь полная" in text:
        event["kind"] = "error"
        event["client"] = _client(text)
        port = re.search(r"порт=(\d+)", text)
        if port:
            event["port"] = int(port.group(1))
        return event
    proxy = PROXY_RE.match(text)
    if proxy:
        event.update(kind="proxy", domain=proxy.group(1), port=int(proxy.group(2)), client=_client(text))
        return event
    if text.startswith("Прокси закрыл соединение"):
        event.update(kind="error", client=_client(text, with_port=True))
        extra = NONAME_RE.search(text)
        if extra:
            event["port"] = int(extra.group(1))
            event["domain"] = "" if extra.group(2) == "-" else extra.group(2)
        return event
    if text.startswith("DNS пакет"):
        event["kind"] = "trace"
        peer = re.search(r" (?:udp|tcp) ([0-9A-Fa-f:.]+):\d+ ", text)
        event["client"] = peer.group(1) if peer else ""
        name = re.match(r"^DNS пакет (\S+)", text)
        if name:
            event["domain"] = name.group(1)
        return event
    dns = DNS_RE.match(text)
    if dns:
        event["domain"] = dns.group(1)
        event["client"] = _client(text)
        event["kind"] = "direct" if "закачка напрямую" in text else "dns"
        return event
    tcp = TCP_RE.match(text)
    if tcp or text.startswith("UDP входящий"):
        event["kind"] = "tcp"
        event["client"] = _client(text, with_port=True)
        port = re.search(r"порт=(\d+)", text)
        if port:
            event["port"] = int(port.group(1))
        return event
    if text.startswith("Проверка связи"):
        event.update(kind="dns", client=_client(text))
    return event


def enrich(entry: dict) -> dict:
    event = parse_line(entry.get("msg", ""))
    if entry.get("prio", 6) <= 3 and event["kind"] in ("other", "tcp"):
        event["kind"] = "error"
    merged = dict(entry)
    merged.update(event)
    return merged


def summarize(entries: list[dict], top: int = 10) -> dict:
    domains: Counter = Counter()
    clients: Counter = Counter()
    ports: Counter = Counter()
    kinds: Counter = Counter()
    refused: dict[str, dict] = {}
    errors: list[dict] = []
    for raw in entries:
        event = raw if "kind" in raw else enrich(raw)
        kinds[event["kind"]] += 1
        if event["kind"] == "proxy":
            domains[event["domain"]] += 1
            if event["port"]:
                ports[event["port"]] += 1
        if event["client"] and event["kind"] in ("proxy", "dns", "direct"):
            clients[event["client"]] += 1
        if event["kind"] == "refused" and event["client"]:
            item = refused.setdefault(event["client"], {"client": event["client"], "count": 0, "last": 0})
            item["count"] += 1
            item["last"] = max(item["last"], event.get("ts", 0))
        if event["kind"] == "error":
            errors.append({"ts": event.get("ts", 0), "msg": event.get("msg", "")})
    return {
        "lines": len(entries),
        "kinds": dict(kinds),
        "top_domains": domains.most_common(top),
        "top_clients": clients.most_common(top),
        "top_ports": ports.most_common(top),
        "refused": sorted(refused.values(), key=lambda item: -item["last"]),
        "errors": errors[-top:],
    }
