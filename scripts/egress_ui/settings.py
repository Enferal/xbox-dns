"""Настройки самого UI: /etc/egress-proxy-ui/ui.env и переменные окружения."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

from egress_proxy import parse_allow, parse_env_text

DEFAULT_UI_ENV = "/etc/egress-proxy-ui/ui.env"
HOST_RE = re.compile(r"^[A-Za-z0-9.:-]{1,253}$")


class UiConfigError(Exception):
    pass


@dataclass
class UiConfig:
    listen: str = "0.0.0.0"
    port: int = 8443
    tls_cert: str = "/etc/egress-proxy-ui/tls.crt"
    tls_key: str = "/etc/egress-proxy-ui/tls.key"
    insecure_http: bool = False
    password_hash: str = ""
    allow_clients: list = field(default_factory=list)
    session_hours: float = 12.0
    ui_env_file: str = DEFAULT_UI_ENV
    config_dir: str = "/etc/egress-proxy"
    env_file: str = "/etc/egress-proxy/egress.env"
    destinations_file: str = "/etc/egress-proxy/allow-destinations.txt"
    direct_file: str = "/etc/egress-proxy/direct-destinations.txt"
    same_port_file: str = "/etc/egress-proxy/same-port-destinations.txt"
    exit_ips_file: str = "/etc/egress-proxy/exit-ips.txt"
    status_file: str = "/run/egress-proxy/status.json"
    state_dir: str = "/var/lib/egress-proxy-ui"
    proxy_script: str = "/usr/local/lib/egress-proxy/egress_proxy.py"
    repo_dir: str = "/opt/egress-proxy"
    presets_dir: str = ""
    service_backend: str = "systemd"
    service_name: str = "egress-proxy"
    ui_service_name: str = "egress-proxy-ui"
    docker_socket: str = "/var/run/docker.sock"
    docker_container: str = "egress-proxy"
    firewall_backend: str = "ufw"
    config_group: str = "egress-proxy"
    public_host: str = ""
    ssh_port: int = 0

    @property
    def tls(self) -> bool:
        return not self.insecure_http

    @property
    def tunnel(self) -> bool:
        """Без TLS UI слушает только loopback, снаружи до него доходят через SSH-туннель."""
        return self.insecure_http

    @property
    def presets(self) -> str:
        return self.presets_dir or os.path.join(self.repo_dir, "config")

    def files(self) -> dict[str, str]:
        return {
            "env": self.env_file,
            "proxy": self.destinations_file,
            "direct": self.direct_file,
            "sameport": self.same_port_file,
            "exits": self.exit_ips_file,
        }


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_ui_config(path: str | None = None, environ: dict[str, str] | None = None) -> UiConfig:
    environ = dict(os.environ if environ is None else environ)
    path = path or environ.get("UI_ENV_FILE") or DEFAULT_UI_ENV
    values: dict[str, str] = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8-sig") as handle:
            values.update(parse_env_text(handle.read()))
    values.update({key: value for key, value in environ.items() if key.startswith(("UI_", "EGRESS_"))})

    def get(key: str, default: str) -> str:
        return values.get(key, "").strip() or default

    cfg = UiConfig(ui_env_file=path)
    cfg.listen = get("UI_LISTEN", cfg.listen)
    try:
        cfg.port = int(get("UI_PORT", str(cfg.port)))
        cfg.session_hours = float(get("UI_SESSION_HOURS", str(cfg.session_hours)))
        cfg.ssh_port = int(get("UI_SSH_PORT", "0"))
    except ValueError as exc:
        raise UiConfigError(f"Число в настройках UI записано неверно: {exc}") from exc
    if not 1 <= cfg.port <= 65535:
        raise UiConfigError("UI_PORT вне 1-65535")
    if not 0 <= cfg.ssh_port <= 65535:
        raise UiConfigError("UI_SSH_PORT вне 1-65535")
    cfg.public_host = get("UI_PUBLIC_HOST", "")
    if cfg.public_host and not HOST_RE.fullmatch(cfg.public_host):
        raise UiConfigError("UI_PUBLIC_HOST: нужен IP-адрес или имя хоста")
    try:
        ipaddress.ip_address(cfg.listen)
    except ValueError as exc:
        raise UiConfigError(f"UI_LISTEN {cfg.listen!r} не IP-адрес") from exc
    cfg.tls_cert = get("UI_TLS_CERT", cfg.tls_cert)
    cfg.tls_key = get("UI_TLS_KEY", cfg.tls_key)
    cfg.insecure_http = _bool(get("UI_INSECURE_HTTP", "0"))
    cfg.password_hash = get("UI_PASSWORD_HASH", "")
    try:
        cfg.allow_clients = parse_allow(get("UI_ALLOW_CLIENTS", ""))
    except Exception as exc:
        raise UiConfigError(f"UI_ALLOW_CLIENTS: {exc}") from exc
    cfg.config_dir = get("EGRESS_CONFIG_DIR", cfg.config_dir)
    cfg.env_file = get("EGRESS_ENV_FILE", os.path.join(cfg.config_dir, "egress.env"))
    cfg.destinations_file = get("UI_DESTINATIONS_FILE", os.path.join(cfg.config_dir, "allow-destinations.txt"))
    cfg.direct_file = get("UI_DIRECT_FILE", os.path.join(cfg.config_dir, "direct-destinations.txt"))
    cfg.same_port_file = get("UI_SAME_PORT_FILE", os.path.join(cfg.config_dir, "same-port-destinations.txt"))
    cfg.exit_ips_file = get("UI_EXIT_IPS_FILE", os.path.join(cfg.config_dir, "exit-ips.txt"))
    cfg.status_file = get("UI_STATUS_FILE", cfg.status_file)
    cfg.state_dir = get("UI_STATE_DIR", cfg.state_dir)
    cfg.proxy_script = get("UI_PROXY_SCRIPT", cfg.proxy_script)
    cfg.repo_dir = get("UI_REPO_DIR", cfg.repo_dir)
    cfg.presets_dir = get("UI_PRESETS_DIR", "")
    cfg.service_backend = get("UI_SERVICE_BACKEND", cfg.service_backend)
    cfg.service_name = get("UI_SERVICE_NAME", cfg.service_name)
    cfg.ui_service_name = get("UI_SELF_SERVICE", cfg.ui_service_name)
    cfg.docker_socket = get("UI_DOCKER_SOCKET", cfg.docker_socket)
    cfg.docker_container = get("UI_DOCKER_CONTAINER", cfg.docker_container)
    cfg.firewall_backend = get("UI_FIREWALL_BACKEND", "none" if cfg.service_backend == "docker" else cfg.firewall_backend)
    cfg.config_group = get("UI_CONFIG_GROUP", cfg.config_group)
    if cfg.service_backend not in {"systemd", "docker", "none"}:
        raise UiConfigError("UI_SERVICE_BACKEND: systemd, docker или none")
    if cfg.firewall_backend not in {"ufw", "none"}:
        raise UiConfigError("UI_FIREWALL_BACKEND: ufw или none")
    if cfg.insecure_http and not ipaddress.ip_address(cfg.listen).is_loopback:
        raise UiConfigError(
            "HTTP без TLS разрешён только на 127.0.0.1 или ::1 (доступ через SSH-туннель). "
            "Для внешнего адреса нужен сертификат UI_TLS_CERT и UI_TLS_KEY."
        )
    return cfg


def set_ui_value(path: str, key: str, value: str) -> None:
    """Меняет одну строку KEY=VALUE в ui.env, остальное оставляет как есть."""
    if "\n" in value or "\r" in value:
        raise UiConfigError("Перевод строки в значении недопустим")
    lines: list[str] = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8-sig") as handle:
            lines = handle.read().splitlines()
    replaced = False
    for index, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[index] = f"{key}={value}"
            replaced = True
    if not replaced:
        lines.append(f"{key}={value}")
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
