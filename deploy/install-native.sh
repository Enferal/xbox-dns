#!/bin/sh
# Полная установка и обновление на Ubuntu 22.04/24.04.
# Запуск из каталога проекта: sh deploy/install-native.sh
grep -q "$(printf '\r')" "$0" && sed -i 's/\r$//' "$0" && exec /bin/sh "$0" "$@" #
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите скрипт от root: sh deploy/install-native.sh" >&2
  exit 1
fi

echo "Установщик egress-proxy. Пустой ALLOW_CLIENTS пускает всех. Дальше будут вопросы, и только потом проверка пакетов."

ENV_FILE=/etc/egress-proxy/egress.env
reset=0
interactive=0
if ( : < /dev/tty ) 2>/dev/null; then
  interactive=1
fi

apply_answer() {
  case "$1" in
    LISTEN_IP) LISTEN_IP=$2 ;;
    DNS_PORT) DNS_PORT=$2 ;;
    PROXY_PORTS) PROXY_PORTS=$2 ;;
    DNS_UPSTREAM) DNS_UPSTREAM=$2 ;;
    MAX_WILDCARD_DEPTH) MAX_WILDCARD_DEPTH=$2 ;;
    ANSWER_TTL) ANSWER_TTL=$2 ;;
    IPV6) IPV6=$2 ;;
    ALLOW_CLIENTS) ALLOW_CLIENTS=$2 ;;
  esac
}

ask_value() {
  name=$1
  hint=$2
  example=$3
  fallback=$4
  kind=$5
  from_vps=${6:-}
  file_value=
  has_file=0
  if [ -f "$ENV_FILE" ] && grep -q "^${name}=" "$ENV_FILE"; then
    has_file=1
    file_value=$(grep "^${name}=" "$ENV_FILE" | tail -n 1 | cut -d= -f2-)
  fi
  if [ "$from_vps" = "vps" ]; then
    picked=$fallback
  elif [ "$reset" -eq 0 ] && [ "$has_file" -eq 1 ]; then
    picked=$file_value
  else
    picked=$fallback
  fi
  if [ "$interactive" -eq 0 ]; then
    apply_answer "$name" "$picked"
    return
  fi
  while true; do
    echo
    echo "$name — $hint"
    if [ "$from_vps" = "vps" ]; then
      if [ "$vps_dns_from_host" -eq 1 ]; then
        echo "DNS этого VPS: $fallback"
        echo "Enter подставит DNS этого VPS."
      else
        echo "На VPS своих DNS нет. По умолчанию: $fallback"
        echo "Enter подставит этот список."
      fi
      if [ "$has_file" -eq 1 ] && [ "$file_value" != "$fallback" ]; then
        echo "В файле сейчас: $file_value"
      fi
      printf 'Новое значение или Enter — взять этот список: '
    else
      echo "Пример: $example"
      if [ -n "$picked" ]; then
        label=$picked
      elif [ "$kind" = "allow" ]; then
        label="пусто, обратиться может любой адрес"
      else
        label="пусто"
      fi
      if [ "$reset" -eq 1 ]; then
        echo "Enter оставит: $label"
      else
        echo "Сейчас: $label"
      fi
      if [ "$kind" = "allow" ]; then
        printf 'Новое значение, Enter — оставить, «-» — пустить всех: '
      else
        printf 'Новое значение или Enter — оставить: '
      fi
    fi
    IFS= read -r entered < /dev/tty || entered=
    if [ -z "$entered" ]; then
      value=$picked
    elif [ "$entered" = "-" ] && [ "$kind" = "allow" ]; then
      value=
    else
      value=$entered
    fi
    case "$kind" in
      number)
        case "$value" in
          ''|*[!0-9]*)
            echo "Нужно целое число. Пример: $example"
            continue
            ;;
        esac
        ;;
      text)
        if [ -z "$value" ]; then
          echo "Пустое значение не подходит. Пример: $example"
          continue
        fi
        ;;
      bit)
        case "$value" in
          0|1) ;;
          *)
            echo "Нужно 0 или 1. Пример: $example"
            continue
            ;;
        esac
        ;;
    esac
    apply_answer "$name" "$value"
    break
  done
}

has_old=0
for cfg in "$ENV_FILE" /etc/egress-proxy/exit-ips.txt /etc/egress-proxy/allow-destinations.txt /etc/egress-proxy/direct-destinations.txt; do
  if [ -f "$cfg" ]; then
    has_old=1
  fi
done

if [ "$has_old" -eq 1 ] && [ "$interactive" -eq 1 ]; then
  echo "Найдены прошлые настройки в /etc/egress-proxy."
  echo "Это egress.env, список доменов, список закачки и exit-ips.txt."
  printf 'Удалить прошлые настройки? [y/N]: '
  IFS= read -r reply < /dev/tty || reply=
  case "$reply" in
    y|Y|yes|YES|д|Д|да|ДА) reset=1 ;;
    *) reset=0 ;;
  esac
elif [ "$has_old" -eq 1 ]; then
  echo "Терминала нет: прошлые настройки сохраняю."
fi

vps_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' || true)
vps_dns=""
add_dns() {
  addr=${1%%%*}
  case "$addr" in
    ''|127.*|0.0.0.0|::1|localhost|fe80:*) return ;;
  esac
  if [ -n "$vps_ip" ] && [ "$addr" = "$vps_ip" ]; then
    return
  fi
  case ",$vps_dns," in
    *,"$addr",*) return ;;
  esac
  if [ -z "$vps_dns" ]; then
    vps_dns=$addr
  else
    vps_dns=$vps_dns,$addr
  fi
}
read_dns_file() {
  if [ ! -f "$1" ]; then
    return
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    key=${line%% *}
    if [ "$key" != "nameserver" ]; then
      continue
    fi
    rest=${line#* }
    add_dns "${rest%% *}"
  done < "$1"
}
read_dns_file /run/systemd/resolve/resolv.conf
if [ -z "$vps_dns" ]; then
  read_dns_file /etc/resolv.conf
fi
vps_dns_from_host=0
if [ -n "$vps_dns" ]; then
  vps_dns_from_host=1
else
  vps_dns="1.1.1.1,8.8.8.8"
fi
vps_dns_spaces=$(printf '%s' "$vps_dns" | tr ',' ' ')
ssh_client=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $1}')
case "$ssh_client" in
  ''|*[!0-9a-fA-F:.]* ) ssh_client= ;;
esac

if [ "$reset" -eq 1 ]; then
  echo "Прошлые настройки будут удалены. Ниже можно задать переменные заново."
elif [ "$has_old" -eq 1 ]; then
  echo "Прошлые настройки сохраняются. Ниже можно поменять переменные."
else
  echo "Задайте настройки. Enter оставляет значение из строки «Сейчас»."
fi
if [ -n "$vps_ip" ]; then
  echo "Адрес этого VPS: $vps_ip"
fi
if [ "$vps_dns_from_host" -eq 1 ]; then
  echo "DNS этого VPS: $vps_dns"
else
  echo "На VPS не нашлось своего DNS, для запросов наружу взяты $vps_dns"
fi

listen_hint="Адрес, на котором принимать клиентов. 0.0.0.0 — все интерфейсы сервера."
if [ -n "$vps_ip" ]; then
  listen_hint="Адрес, на котором принимать клиентов. У этого VPS адрес $vps_ip. 0.0.0.0 принимает на всех интерфейсах, в том числе на нём."
fi
if [ "$vps_dns_from_host" -eq 1 ]; then
  dns_hint="Куда сервер спрашивает настоящие адреса сайтов. Список взят из DNS этого VPS."
else
  dns_hint="Куда сервер спрашивает настоящие адреса сайтов. На VPS своих DNS не нашлось, оставлены публичные."
fi
allow_example="203.0.113.8,198.51.100.0/24"
allow_hint="Кто может обращаться к этому DNS. Пусто — может любой адрес. Несколько адресов или сетей через запятую."
if [ -n "$ssh_client" ]; then
  allow_example=$ssh_client
  allow_hint="Кто может обращаться к этому DNS. Пусто — может любой адрес. Сейчас вы подключены к этому VPS с $ssh_client."
fi

ask_value LISTEN_IP "$listen_hint" "0.0.0.0" "0.0.0.0" text
ask_value DNS_PORT \
  "Порт DNS, который указывают на устройстве." \
  "53" "53" number
ask_value PROXY_PORTS \
  "Порты, через которые открывается сайт. Несколько значений через запятую, диапазон пишется как 15000-15099." \
  "80,443" "80,443" text
ask_value DNS_UPSTREAM "$dns_hint" "$vps_dns" "$vps_dns" text vps
ask_value MAX_WILDCARD_DEPTH \
  "Сколько меток поддомена покрывает имя из списка. 4 — это a.b.c.d.example.com." \
  "4" "4" number
ask_value ANSWER_TTL \
  "Сколько секунд устройство помнит ответ DNS." \
  "60" "60" number
ask_value IPV6 \
  "IPv6 для доменов из списка. 1 — отдавать IPv6-адрес VPS и проксировать его. 0 — только IPv4. Интернет самого VPS не меняется." \
  "1" "1" bit
ask_value ALLOW_CLIENTS "$allow_hint" "$allow_example" "" allow

# python3 запускает службу. iproute2 даёт ip и ss. dig берётся из bind9-dnsutils.
# ca-certificates нужен apt и git по HTTPS. ufw: SSH открывается всегда,
# а 53 и порты из PROXY_PORTS — только если правил ещё нет или так выбран ответ. git нужен для git pull.
ensure_requirements() {
  if [ ! -r /etc/os-release ] || ! command -v apt-get >/dev/null 2>&1; then
    echo "Нужна Ubuntu 22.04 или 24.04 с apt." >&2
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu) ;;
    *)
      echo "Нужна Ubuntu. Сейчас: ${PRETTY_NAME:-неизвестная система}." >&2
      exit 1
      ;;
  esac
  case "${VERSION_ID:-}" in
    22.04|24.04) ;;
    *)
      echo "Скрипт проверен на Ubuntu 22.04 и 24.04. Сейчас: ${PRETTY_NAME:-$VERSION_ID}." >&2
      exit 1
      ;;
  esac
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "Нужен systemd: команды systemctl нет." >&2
    exit 1
  fi
  echo "Проверка пакетов на ${PRETTY_NAME}."
  missing=""
  for pkg in python3 iproute2 ca-certificates bind9-dnsutils ufw git; do
    status=$(dpkg-query -W -f '${Status}' "$pkg" 2>/dev/null || true)
    case "$status" in
      "install ok installed")
        echo "Уже стоит: $pkg"
        ;;
      *)
        echo "Нет пакета: $pkg"
        missing="$missing $pkg"
        ;;
    esac
  done
  if [ -n "$missing" ]; then
    echo "Ставлю недостающее:$missing"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # shellcheck disable=SC2086
    apt-get install -y --no-install-recommends $missing
  else
    echo "Все нужные пакеты уже стоят. apt не запускаю."
  fi
}

ensure_requirements

# systemd-resolved слушает только 127.0.0.53 и 127.0.0.54.
# Это локальная заглушка. Из-за неё нельзя занять 0.0.0.0:53.
# Сами DNS-серверы VPS не меняем: программы ходят в интернет через systemd-resolved.
# Если /etc/resolv.conf смотрит на 127.0.0.53, до отключения заглушки
# переключаем его на файл с настоящими DNS, иначе пропадут имена.
resolv_points_at_stub() {
  if [ -L /etc/resolv.conf ]; then
    case "$(readlink /etc/resolv.conf)" in
      *stub-resolv.conf*) return 0 ;;
    esac
  fi
  if [ -f /etc/resolv.conf ] && grep -q '127\.0\.0\.53' /etc/resolv.conf; then
    return 0
  fi
  return 1
}
has_public_nameserver() {
  if [ ! -f "$1" ]; then
    return 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    key=${line%% *}
    if [ "$key" != "nameserver" ]; then
      continue
    fi
    rest=${line#* }
    addr=${rest%% *}
    case "$addr" in
      ''|127.*|0.0.0.0|::1|localhost|fe80:*) continue ;;
      *) return 0 ;;
    esac
  done < "$1"
  return 1
}
rm -f /etc/sysctl.d/99-egress-proxy-ipv6.conf
systemctl stop egress-proxy.service 2>/dev/null || true
if ss -Htulpn 'sport = :53' 2>/dev/null | grep -q systemd-resolve; then
  if resolv_points_at_stub; then
    if has_public_nameserver /run/systemd/resolve/resolv.conf; then
      ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
    else
      echo "Заглушка 127.0.0.53 заняла порт 53, но настоящего DNS для сервера не нашлось."
      echo "Заглушку не отключаю, чтобы не пропал интернет на VPS."
      exit 1
    fi
  fi
  install -d /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/egress-proxy.conf << 'EOF'
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved
fi
if ss -Htulpn 'sport = :53' 2>/dev/null | grep -q ':53'; then
  echo "Порт 53 занят, служба не сможет его занять:"
  ss -Htulpn 'sport = :53' || true
  exit 1
fi

if ! getent group egress-proxy >/dev/null 2>&1; then
  groupadd --system egress-proxy
fi
if ! getent passwd egress-proxy >/dev/null 2>&1; then
  useradd --system --gid egress-proxy --home-dir /nonexistent --shell /usr/sbin/nologin egress-proxy
fi

install -d -m 0755 /usr/local/lib/egress-proxy
install -d -m 0750 -o root -g egress-proxy /etc/egress-proxy
install -m 0755 "$ROOT/scripts/egress_proxy.py" /usr/local/lib/egress-proxy/egress_proxy.py
install -m 0644 "$ROOT/deploy/egress-proxy.service" /etc/systemd/system/egress-proxy.service

if [ "$reset" -eq 1 ]; then
  rm -f "$ENV_FILE" /etc/egress-proxy/exit-ips.txt /etc/egress-proxy/allow-destinations.txt /etc/egress-proxy/direct-destinations.txt
fi
if [ ! -f /etc/egress-proxy/exit-ips.txt ]; then
  install -m 0644 "$ROOT/config/exit-ips.txt" /etc/egress-proxy/exit-ips.txt
fi

need_domains=0
if [ ! -f /etc/egress-proxy/allow-destinations.txt ]; then
  need_domains=1
elif ! grep -Eqv '^[[:space:]]*(#|$)' /etc/egress-proxy/allow-destinations.txt; then
  need_domains=1
fi
if [ "$need_domains" -eq 1 ]; then
  install -m 0644 "$ROOT/config/allow-destinations.xbox.txt" /etc/egress-proxy/allow-destinations.txt
fi
if [ ! -f /etc/egress-proxy/direct-destinations.txt ]; then
  install -m 0644 "$ROOT/config/direct-destinations.txt" /etc/egress-proxy/direct-destinations.txt
fi

{
  printf '%s\n' '# Настройки egress-proxy. Меняются при запуске sh deploy/install-native.sh'
  printf '%s\n' '# LISTEN_IP — пример: 0.0.0.0'
  printf 'LISTEN_IP=%s\n' "$LISTEN_IP"
  printf '%s\n' '# DNS_PORT — пример: 53'
  printf 'DNS_PORT=%s\n' "$DNS_PORT"
  printf '%s\n' '# PROXY_PORTS — пример: 80,443 или 80,443,42130,44326,15000-15099'
  printf 'PROXY_PORTS=%s\n' "$PROXY_PORTS"
  printf '%s\n' "# DNS_UPSTREAM — по умолчанию DNS этого VPS: $vps_dns"
  printf 'DNS_UPSTREAM=%s\n' "$DNS_UPSTREAM"
  printf '%s\n' '# MAX_WILDCARD_DEPTH — пример: 4'
  printf 'MAX_WILDCARD_DEPTH=%s\n' "$MAX_WILDCARD_DEPTH"
  printf '%s\n' '# ANSWER_TTL — пример: 60'
  printf 'ANSWER_TTL=%s\n' "$ANSWER_TTL"
  printf '%s\n' '# IPV6 — 0 выключен, 1 включён'
  printf 'IPV6=%s\n' "$IPV6"
  printf '%s\n' '# ALLOW_CLIENTS — пусто пускает всех. Пример: 203.0.113.8,198.51.100.0/24'
  printf 'ALLOW_CLIENTS=%s\n' "$ALLOW_CLIENTS"
} > "$ENV_FILE"

sed -i 's/\r$//' \
  /usr/local/lib/egress-proxy/egress_proxy.py \
  /etc/systemd/system/egress-proxy.service \
  /etc/egress-proxy/exit-ips.txt \
  /etc/egress-proxy/allow-destinations.txt \
  /etc/egress-proxy/direct-destinations.txt \
  "$ENV_FILE"

chown root:egress-proxy /etc/egress-proxy
chmod 0750 /etc/egress-proxy
for cfg in /etc/egress-proxy/*; do
  if [ -f "$cfg" ]; then
    chown root:egress-proxy "$cfg"
    chmod 0640 "$cfg"
  fi
done

export LISTEN_IP DNS_PORT PROXY_PORTS DNS_UPSTREAM MAX_WILDCARD_DEPTH ANSWER_TTL IPV6 ALLOW_CLIENTS
export EXIT_IPS_FILE=/etc/egress-proxy/exit-ips.txt
export DESTINATIONS_FILE=/etc/egress-proxy/allow-destinations.txt
export DIRECT_FILE=/etc/egress-proxy/direct-destinations.txt

python3 /usr/local/lib/egress-proxy/egress_proxy.py --check-config

ufw_service_lines() {
  ufw status numbered 2>/dev/null | grep -E '^\[[[:space:]]*[0-9]+\][[:space:]]+(53|80|443)(/tcp|/udp)?([[:space:]]|\()' || true
}

ufw_rule_numbers() {
  kind=$1
  ufw_service_lines | while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$kind" in
      open)
        if ! printf '%s\n' "$line" | grep -q 'Anywhere'; then
          continue
        fi
        ;;
      limited)
        if printf '%s\n' "$line" | grep -q 'Anywhere'; then
          continue
        fi
        ;;
      all) ;;
      *) continue ;;
    esac
    printf '%s\n' "$line" | sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p'
  done
}

ufw_delete_kind() {
  nums=$(ufw_rule_numbers "$1" | sort -nr)
  for n in $nums; do
    ufw --force delete "$n"
  done
}

ufw_open_service() {
  ufw allow 53/tcp
  ufw allow 53/udp
  old_ifs=$IFS
  IFS=,
  for token in $PROXY_PORTS; do
    IFS=$old_ifs
    token=$(printf '%s' "$token" | tr -d '[:space:]')
    [ -n "$token" ] || continue
    case "$token" in
      *-*)
        ufw allow "${token%%-*}:${token#*-}/tcp"
        ;;
      *)
        ufw allow "$token/tcp"
        ;;
    esac
    IFS=,
  done
  IFS=$old_ifs
}

configure_service_firewall() {
  lines=$(ufw_service_lines)
  if [ -z "$lines" ]; then
    echo "Правил для 53, 80 и 443 нет. Открываю DNS и порты из PROXY_PORTS для всех."
    ufw_open_service
    return
  fi
  echo
  echo "В файрволе уже есть правила для 53, 80 и 443:"
  printf '%s\n' "$lines" | sed 's/^/  /'
  limited=$(ufw_rule_numbers limited)
  open=$(ufw_rule_numbers open)
  if [ -n "$limited" ] && [ -n "$open" ]; then
    echo "Есть и ограничение по адресу, и разрешение для всех."
    echo "Разрешение для всех пускает чужой адрес, ограничение его не закрывает."
  elif [ -n "$limited" ]; then
    echo "Эти порты пускают только указанные адреса."
  else
    echo "Эти порты открыты для всех."
  fi
  if [ "$interactive" -eq 0 ]; then
    echo "Терминала нет: правила файрвола не меняю."
    return
  fi
  echo "Enter — оставить правила как есть."
  if [ -n "$limited" ]; then
    echo "адреса — убрать разрешения для всех и оставить только правила с адресом."
  fi
  echo "все — удалить эти правила и открыть 53 и порты из PROXY_PORTS для всех."
  printf 'Что сделать: '
  IFS= read -r entered < /dev/tty || entered=
  case "$entered" in
    ''|y|Y|yes|YES|д|Д|да|ДА)
      echo "Правила файрвола оставляю."
      ;;
    адреса|Адреса)
      if [ -z "$limited" ]; then
        echo "Правил с адресом нет. Ничего не меняю, иначе порты закроются для всех."
      elif [ -z "$open" ]; then
        echo "Общих разрешений нет. Правила оставляю."
      else
        ufw_delete_kind open
        echo "Общие разрешения для 53, 80 и 443 удалены."
      fi
      ;;
    все|Все)
      ufw_delete_kind all
      ufw_open_service
      echo "Порты 53 и список PROXY_PORTS открыты для всех."
      ;;
    *)
      echo "Не понял ответ. Правила файрвола оставляю."
      ;;
  esac
}

ssh_port=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $4}')
ufw allow OpenSSH
if [ -n "$ssh_port" ] && [ "$ssh_port" != "22" ]; then
  ufw allow "${ssh_port}/tcp"
fi
configure_service_firewall
ufw --force enable

systemctl daemon-reload
systemctl enable egress-proxy.service
systemctl restart egress-proxy.service

if [ -z "$vps_ip" ]; then
  vps_ip=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
fi
echo
answer=""
i=0
while [ "$i" -lt 15 ]; do
  if systemctl is-active --quiet egress-proxy.service; then
    answer=$(dig +time=1 +tries=1 +short @127.0.0.1 user.auth.xboxlive.com A 2>/dev/null || true)
    case "$answer" in
      ''|*[!0-9.]*) answer= ;;
    esac
    if [ -n "$answer" ]; then
      break
    fi
  fi
  i=$((i + 1))
  sleep 1
done

if [ -z "$answer" ]; then
  echo "DNS на 127.0.0.1:53 не ответил. Кто слушает порты:"
  ss -tulpn 'sport = :53 or sport = :80 or sport = :443' || true
  echo "Журнал службы:"
  journalctl -u egress-proxy -n 40 --no-pager || true
  exit 1
fi

echo "Служба egress-proxy запущена."
echo "Проверка: dig +short @127.0.0.1 user.auth.xboxlive.com A"
printf '%s\n' "$answer"
echo "В ответе выше должен быть ${vps_ip}."
if [ -z "${ALLOW_CLIENTS:-}" ]; then
  echo "ALLOW_CLIENTS пуст: к DNS может обратиться любой адрес."
  echo "Чтобы пускать только свои устройства, впишите их в /etc/egress-proxy/egress.env и выполните systemctl restart egress-proxy"
else
  echo "К DNS пускает только: ${ALLOW_CLIENTS}"
fi
echo "На устройстве укажите DNS: ${vps_ip}"
echo "Логи: journalctl -u egress-proxy -f"
