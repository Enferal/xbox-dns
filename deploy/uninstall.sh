#!/bin/sh
# Удаление egress-proxy и Web UI с сервера: службы, файлы, пользователь, правила ufw, настройка systemd-resolved.
# Запуск из каталога проекта: sh deploy/uninstall.sh
# Без вопросов: UNINSTALL_UFW=1 sh deploy/uninstall.sh  (без UNINSTALL_UFW правила ufw остаются)
# Пакеты (python3, ufw, git, openssl…) и сам каталог проекта не удаляются.
grep -q "$(printf '\r')" "$0" && sed -i 's/\r$//' "$0" && exec /bin/sh "$0" "$@" #
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ENV_FILE=/etc/egress-proxy/egress.env
UI_ENV=/etc/egress-proxy-ui/ui.env
RESOLVED_CONF=/etc/systemd/resolved.conf.d/egress-proxy.conf

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите скрипт от root: sh deploy/uninstall.sh" >&2
  exit 1
fi

interactive=0
if ( : < /dev/tty ) 2>/dev/null; then
  interactive=1
fi

confirm() {
  # confirm "вопрос" ОТВЕТ_БЕЗ_ТЕРМИНАЛА; Enter — да
  if [ "$interactive" -eq 0 ]; then
    [ "$2" = "1" ]
    return
  fi
  printf '%s' "$1"
  IFS= read -r reply < /dev/tty || reply=
  case "$reply" in
    ''|y|Y|yes|YES|д|Д|да|ДА) return 0 ;;
    *) return 1 ;;
  esac
}

file_value() {
  # file_value ФАЙЛ КЛЮЧ ПО_УМОЛЧАНИЮ
  value=
  if [ -f "$1" ]; then
    value=$(grep "^$2=" "$1" | tail -n 1 | cut -d= -f2- | tr -d '\r' || true)
  fi
  printf '%s' "${value:-$3}"
}

echo "Удаление egress-proxy и Web UI."
if [ "$interactive" -eq 1 ]; then
  if ! confirm "Остановить службы и удалить установленные файлы? [Y/n]: " 1; then
    echo "Ничего не меняю."
    exit 0
  fi
fi

dns_port=$(file_value "$ENV_FILE" DNS_PORT 53)
proxy_ports=$(file_value "$ENV_FILE" PROXY_PORTS 80,443)
ui_port=$(file_value "$UI_ENV" UI_PORT 8443)

stamp=$(date +%Y%m%d-%H%M%S)
backup=/root/egress-proxy-config-$stamp.tar.gz
saved=""
for dir in /etc/egress-proxy /etc/egress-proxy-ui; do
  if [ -d "$dir" ]; then
    saved="$saved ${dir#/}"
  fi
done
if [ -n "$saved" ]; then
  # shellcheck disable=SC2086
  tar -czf "$backup" -C / $saved
  chmod 0600 "$backup"
  echo "Копия настроек: $backup"
fi

for unit in egress-proxy-update.service egress-proxy-ui.service egress-proxy.service; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || systemctl stop "$unit" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/egress-proxy.service /etc/systemd/system/egress-proxy-ui.service
systemctl daemon-reload
systemctl reset-failed egress-proxy.service egress-proxy-ui.service egress-proxy-update.service >/dev/null 2>&1 || true
echo "Службы egress-proxy и egress-proxy-ui остановлены и удалены."

ssh_ports=22
session_port=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $4}')
case "$session_port" in
  ''|*[!0-9]*) ;;
  *) ssh_ports="$ssh_ports $session_port" ;;
esac
for port in $(ss -Htlpn 2>/dev/null | awk '/sshd/ {n=split($4, a, ":"); print a[n]}'); do
  ssh_ports="$ssh_ports $port"
done

service_ports="$dns_port $ui_port"
old_ifs=$IFS
IFS=,
for token in $proxy_ports; do
  token=$(printf '%s' "$token" | tr -d '[:space:]')
  [ -n "$token" ] || continue
  service_ports="$service_ports $(printf '%s' "$token" | tr '-' ':')"
done
IFS=$old_ifs

in_list() {
  # in_list ЗНАЧЕНИЕ СПИСОК
  for item in $2; do
    [ "$item" = "$1" ] && return 0
  done
  return 1
}

ufw_rule_numbers() {
  ufw status numbered 2>/dev/null | while IFS= read -r line; do
    num=$(printf '%s\n' "$line" | sed -n 's/^\[ *\([0-9][0-9]*\)\].*/\1/p')
    [ -n "$num" ] || continue
    target=$(printf '%s\n' "$line" | sed -n 's/^\[ *[0-9][0-9]*\] *\([^ ]*\).*/\1/p')
    port=${target%%/*}
    case "$target" in
      OpenSSH|ssh|SSH) continue ;;
    esac
    if in_list "$port" "$ssh_ports"; then
      continue
    fi
    if in_list "$port" "$service_ports" || printf '%s\n' "$line" | grep -q '# egress-ui'; then
      printf '%s\n' "$num"
    fi
  done | sort -nru
}

if command -v ufw >/dev/null 2>&1; then
  nums=$(ufw_rule_numbers)
  if [ -n "$nums" ]; then
    echo
    echo "Правила ufw для портов службы ($service_ports) и панели:"
    for n in $nums; do
      ufw status numbered | grep -E "^\[ *$n\]" | sed 's/^/  /' || true
    done
    echo "Правила для SSH ($ssh_ports) не трогаю."
    if confirm "Удалить эти правила? Если порты нужны другим программам, ответьте n. [Y/n]: " "${UNINSTALL_UFW:-0}"; then
      for n in $nums; do
        ufw --force delete "$n" >/dev/null
      done
      echo "Правила ufw удалены. ufw остаётся включённым."
    else
      echo "Правила ufw оставляю. Удалить позже: ufw status numbered, затем ufw delete НОМЕР"
    fi
  else
    echo "Правил ufw для портов службы нет."
  fi
fi

if [ -f "$RESOLVED_CONF" ]; then
  rm -f "$RESOLVED_CONF"
  if [ -L /etc/resolv.conf ] && [ "$(readlink /etc/resolv.conf)" = /run/systemd/resolve/resolv.conf ]; then
    ln -sfn ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
  fi
  systemctl restart systemd-resolved || true
  echo "systemd-resolved снова слушает 127.0.0.53:53, /etc/resolv.conf указывает на него."
fi

rm -rf /usr/local/lib/egress-proxy /etc/egress-proxy /etc/egress-proxy-ui /var/lib/egress-proxy-ui /run/egress-proxy
rm -f /etc/sysctl.d/99-egress-proxy-ipv6.conf
echo "Удалены /usr/local/lib/egress-proxy, /etc/egress-proxy, /etc/egress-proxy-ui, /var/lib/egress-proxy-ui."

if getent passwd egress-proxy >/dev/null 2>&1; then
  userdel egress-proxy || true
fi
if getent group egress-proxy >/dev/null 2>&1; then
  groupdel egress-proxy || true
fi
echo "Пользователь и группа egress-proxy удалены."

echo
echo "Готово. Остались: пакеты, каталог проекта $ROOT и журнал systemd."
if [ -n "$saved" ]; then
  echo "Вернуть прежние настройки: tar -xzf $backup -C /"
fi
echo "Удалить каталог проекта: cd / && rm -rf $ROOT"
if [ -f "$ROOT/docker-compose.yml" ] && command -v docker >/dev/null 2>&1; then
  echo "Если служба запускалась в Docker: cd $ROOT && docker compose --profile ui down -v --rmi local"
fi
