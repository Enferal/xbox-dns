"""Чтение и изменение правил ufw."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass

from egress_proxy import ConfigError, parse_allow, parse_ports

from .system import Runner

RULE_RE = re.compile(
    r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s(IN|OUT|FWD))?\s+(.+?)(?:\s+#\s?(.*))?$"
)
PORT_RE = re.compile(r"^(?:(\S+)\s+)?(\d+(?::\d+)?(?:,\d+(?::\d+)?)*)(?:/(tcp|udp))?$")
COMMENT_RE = re.compile(r"^[\w .,:-]{0,64}$")
ACTIONS = {"allow", "deny", "reject", "limit"}
APP_PORTS = {"openssh": "22", "ssh": "22"}
COMMENT = "egress-ui"


class FirewallError(Exception):
    pass


@dataclass
class Rule:
    num: int
    to: str
    action: str
    direction: str
    source: str
    comment: str
    v6: bool
    port: str
    proto: str
    raw: str

    @property
    def anywhere(self) -> bool:
        return self.source.startswith("Anywhere")

    def covers(self, port: str, proto: str) -> bool:
        return self.port == port and self.proto in (proto, "any")


def parse_rule(line: str) -> Rule | None:
    match = RULE_RE.match(line.rstrip())
    if not match:
        return None
    num, to, action, direction, source, comment = match.groups()
    v6 = "(v6)" in to or "(v6)" in source
    target = to.replace("(v6)", "").strip()
    port, proto = "", "any"
    app = APP_PORTS.get(target.lower())
    if app:
        port, proto = app, "tcp"
    else:
        found = PORT_RE.match(target)
        if found:
            port = found.group(2)
            proto = found.group(3) or "any"
    return Rule(
        num=int(num),
        to=to.strip(),
        action=action,
        direction=direction or "IN",
        source=source.strip(),
        comment=(comment or "").strip(),
        v6=v6,
        port=port,
        proto=proto,
        raw=line.strip(),
    )


def parse_status(numbered: str, verbose: str = "") -> dict:
    active = None
    for line in (numbered + "\n" + verbose).splitlines():
        if line.startswith("Status:"):
            active = line.split(":", 1)[1].strip() == "active"
            break
    defaults = ""
    for line in verbose.splitlines():
        if line.startswith("Default:"):
            defaults = line.split(":", 1)[1].strip()
    rules = [rule for rule in (parse_rule(line) for line in numbered.splitlines()) if rule is not None]
    return {"active": active, "defaults": defaults, "rules": rules}


def ufw_port(token: str) -> str:
    token = token.strip().replace(":", "-")
    if "-" in token:
        left, right = token.split("-", 1)
        return f"{int(left)}:{int(right)}"
    return str(int(token))


def service_ports(dns_port: str, proxy_ports: str) -> list[tuple[str, str]]:
    parse_ports(proxy_ports)
    found: list[tuple[str, str]] = [(str(int(dns_port)), "tcp"), (str(int(dns_port)), "udp")]
    for token in proxy_ports.split(","):
        if token.strip():
            item = (ufw_port(token), "tcp")
            if item not in found:
                found.append(item)
    return found


def normalize_source(value: str) -> str:
    value = (value or "").strip()
    if value.lower() in {"", "any", "anywhere"}:
        return "any"
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise FirewallError(f"{value!r} не IP-адрес и не сеть") from exc
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def same_source(rule: Rule, source: str) -> bool:
    if source == "any":
        return rule.anywhere
    shown = rule.source.replace("(v6)", "").split(" on ")[0].strip()
    try:
        return ipaddress.ip_network(shown, strict=False) == ipaddress.ip_network(source, strict=False)
    except ValueError:
        return False


def rule_argv(action: str, port: str, proto: str, source: str, comment: str = COMMENT) -> list[str]:
    if action not in ACTIONS:
        raise FirewallError("Действие: allow, deny, reject или limit")
    if proto not in {"tcp", "udp", "any"}:
        raise FirewallError("Протокол: tcp, udp или any")
    try:
        spec = ",".join(ufw_port(part) for part in port.split(",") if part.strip())
    except ValueError as exc:
        raise FirewallError(f"Порт {port!r} записан неверно") from exc
    if not spec:
        raise FirewallError("Нужен порт")
    for part in spec.replace(":", ",").split(","):
        if not 1 <= int(part) <= 65535:
            raise FirewallError(f"Порт {part} вне 1-65535")
    if (":" in spec or "," in spec) and proto == "any":
        raise FirewallError("Для диапазона или списка портов нужен протокол tcp или udp")
    if not COMMENT_RE.fullmatch(comment):
        raise FirewallError("Комментарий: до 64 букв, цифр, пробелов и знаков .,:-")
    argv = ["ufw", action, "from", normalize_source(source), "to", "any", "port", spec]
    if proto != "any":
        argv += ["proto", proto]
    if comment:
        argv += ["comment", comment]
    return argv


class Ufw:
    def __init__(self, runner: Runner, protected_ports: list[str]):
        self.runner = runner
        self.protected = set(protected_ports)

    def available(self) -> bool:
        return self.runner.run(["ufw", "version"], timeout=10).ok

    def read(self) -> dict:
        numbered = self.runner.run(["ufw", "status", "numbered"], timeout=20)
        if numbered.code == 127:
            return {"available": False, "error": "ufw не установлен"}
        if not numbered.ok:
            return {"available": False, "error": numbered.text}
        verbose = self.runner.run(["ufw", "status", "verbose"], timeout=20)
        status = parse_status(numbered.out, verbose.out if verbose.ok else "")
        status["available"] = True
        return status

    def snapshot(self) -> dict:
        status = self.read()
        if status.get("available"):
            status["rules"] = [dict(asdict(rule), protected=self.is_protected(rule)) for rule in status["rules"]]
        status["protected_ports"] = sorted(self.protected, key=lambda item: int(item.split(":")[0]))
        return status

    def is_protected(self, rule: Rule) -> bool:
        if rule.action not in ("ALLOW", "LIMIT"):
            return False
        for port in rule.port.split(","):
            if ":" in port:
                low, high = (int(part) for part in port.split(":"))
                if any(low <= int(item) <= high for item in self.protected):
                    return True
            elif port in self.protected:
                return True
        return False

    def _rules(self) -> list[Rule]:
        status = self.read()
        if not status.get("available"):
            raise FirewallError(status.get("error") or "ufw недоступен")
        return status["rules"]

    def add(self, action: str, port: str, proto: str, source: str, comment: str = COMMENT) -> dict:
        argv = rule_argv(action, port, proto, source, comment)
        result = self.runner.run(argv, timeout=30)
        return {"ok": result.ok, "command": " ".join(argv), "output": result.text}

    def delete(self, num: int, expect: str) -> dict:
        rules = {rule.num: rule for rule in self._rules()}
        rule = rules.get(int(num))
        if rule is None or rule.raw != expect.strip():
            raise FirewallError("Правила изменились. Обновите список и повторите.")
        if self.is_protected(rule):
            raise FirewallError(f"Правило для порта SSH или Web UI ({rule.to}) UI не удаляет")
        result = self.runner.run(["ufw", "--force", "delete", str(rule.num)], timeout=30)
        return {"ok": result.ok, "command": f"ufw --force delete {rule.num}", "output": result.text}

    def enable(self, ssh_ports: list[str]) -> dict:
        commands = [["ufw", "allow", "OpenSSH"]]
        for port in ssh_ports:
            if port != "22":
                commands.append(["ufw", "allow", f"{int(port)}/tcp"])
        commands.append(["ufw", "--force", "enable"])
        return self._run_all(commands)

    def _run_all(self, commands: list[list[str]]) -> dict:
        log = []
        for argv in commands:
            result = self.runner.run(argv, timeout=60)
            log.append({"command": " ".join(argv), "ok": result.ok, "output": result.text})
            if not result.ok:
                return {"ok": False, "steps": log}
        return {"ok": True, "steps": log}

    def plan(self, mode: str, dns_port: str, proxy_ports: str, clients: str, rules: list[Rule] | None = None) -> dict:
        """Что сделать, чтобы порты службы были открыты для всех или только для клиентов."""
        if mode not in {"all", "clients"}:
            raise FirewallError("Режим: all или clients")
        try:
            ports = service_ports(dns_port, proxy_ports)
            networks = [str(item) for item in parse_allow(clients)]
        except (ConfigError, ValueError) as exc:
            raise FirewallError(str(exc)) from exc
        if mode == "clients" and not networks:
            raise FirewallError("ALLOW_CLIENTS пуст: режим «только клиенты» закрыл бы порты для всех")
        rules = self._rules() if rules is None else rules
        sources = ["any"] if mode == "all" else [normalize_source(item) for item in networks]
        add: list[list[str]] = []
        for port, proto in ports:
            for source in sources:
                version = None if source == "any" else ipaddress.ip_network(source, strict=False).version
                exists = any(
                    rule.action == "ALLOW"
                    and rule.covers(port, proto)
                    and same_source(rule, source)
                    and (version is None or rule.v6 == (version == 6))
                    for rule in rules
                )
                if not exists:
                    add.append(rule_argv("allow", port, proto, source))
        delete = self._stale(rules, ports, sources)
        return {
            "mode": mode,
            "add": [" ".join(argv) for argv in add],
            "add_argv": add,
            "delete": [{"num": rule.num, "rule": rule.raw} for rule in delete],
        }

    def _stale(self, rules: list[Rule], ports: list[tuple[str, str]], sources: list[str]) -> list[Rule]:
        stale = []
        for rule in rules:
            if rule.action != "ALLOW" or self.is_protected(rule):
                continue
            if not any(rule.covers(port, proto) for port, proto in ports):
                continue
            if any(same_source(rule, source) for source in sources):
                continue
            stale.append(rule)
        return sorted(stale, key=lambda rule: -rule.num)

    def apply_mode(self, mode: str, dns_port: str, proxy_ports: str, clients: str) -> dict:
        plan = self.plan(mode, dns_port, proxy_ports, clients)
        steps = []
        for argv in plan["add_argv"]:
            result = self.runner.run(argv, timeout=60)
            steps.append({"command": " ".join(argv), "ok": result.ok, "output": result.text})
            if not result.ok:
                return {"ok": False, "steps": steps}
        rules = self._rules()
        sources = ["any"] if mode == "all" else [normalize_source(str(item)) for item in parse_allow(clients)]
        for rule in self._stale(rules, service_ports(dns_port, proxy_ports), sources):
            result = self.runner.run(["ufw", "--force", "delete", str(rule.num)], timeout=60)
            steps.append({"command": f"ufw --force delete {rule.num}  # {rule.raw}", "ok": result.ok, "output": result.text})
            if not result.ok:
                return {"ok": False, "steps": steps}
        return {"ok": True, "steps": steps}
