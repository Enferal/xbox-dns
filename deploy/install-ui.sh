#!/bin/sh
# Установка Web UI egress-proxy на Ubuntu 22.04/24.04. Можно запускать отдельно и повторно.
# Запуск из каталога проекта: sh deploy/install-ui.sh
# Без вопросов: UI_MODE=https|ssh-tunnel EGRESS_UI_PASSWORD=... sh deploy/install-ui.sh
grep -q "$(printf '\r')" "$0" && sed -i 's/\r$//' "$0" && exec /bin/sh "$0" "$@" #
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
LIB=/usr/local/lib/egress-proxy
UI_DIR=/etc/egress-proxy-ui
UI_ENV=$UI_DIR/ui.env

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите скрипт от root: sh deploy/install-ui.sh" >&2
  exit 1
fi

interactive=0
if ( : < /dev/tty ) 2>/dev/null; then
  interactive=1
fi

ask() {
  # ask "вопрос" "ответ по умолчанию"; без терминала берётся ответ по умолчанию
  if [ "$interactive" -eq 0 ]; then
    answer=$2
    return
  fi
  printf '%s' "$1"
  IFS= read -r answer < /dev/tty || answer=
  if [ -z "$answer" ]; then
    answer=$2
  fi
}

yes_answer() {
  case "$1" in
    y|Y|yes|YES|д|Д|да|ДА) return 0 ;;
    *) return 1 ;;
  esac
}

echo "Установка Web UI egress-proxy."

missing=""
for pkg in python3 openssl iproute2; do
  status=$(dpkg-query -W -f '${Status}' "$pkg" 2>/dev/null || true)
  if [ "$status" != "install ok installed" ]; then
    missing="$missing $pkg"
  fi
done
if [ -n "$missing" ]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Нет пакетов:$missing, а apt-get не найден." >&2
    exit 1
  fi
  echo "Ставлю недостающее:$missing"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # shellcheck disable=SC2086
  apt-get install -y --no-install-recommends $missing
fi

if ! getent group egress-proxy >/dev/null 2>&1; then
  groupadd --system egress-proxy
fi

install -d -m 0755 "$LIB"
proxy_changed=0
if ! cmp -s "$ROOT/scripts/egress_proxy.py" "$LIB/egress_proxy.py" 2>/dev/null; then
  proxy_changed=1
fi
install -m 0755 "$ROOT/scripts/egress_proxy.py" "$LIB/egress_proxy.py"
sed -i 's/\r$//' "$LIB/egress_proxy.py"

rm -rf "$LIB/egress_ui.new"
cp -R "$ROOT/scripts/egress_ui" "$LIB/egress_ui.new"
find "$LIB/egress_ui.new" -name __pycache__ -type d -prune -exec rm -rf {} +
find "$LIB/egress_ui.new" -type f -exec sed -i 's/\r$//' {} +
find "$LIB/egress_ui.new" -type d -exec chmod 0755 {} +
find "$LIB/egress_ui.new" -type f -exec chmod 0644 {} +
rm -rf "$LIB/egress_ui.old"
if [ -d "$LIB/egress_ui" ]; then
  mv "$LIB/egress_ui" "$LIB/egress_ui.old"
fi
mv "$LIB/egress_ui.new" "$LIB/egress_ui"
rm -rf "$LIB/egress_ui.old"

unit_changed=0
for unit in egress-proxy.service egress-proxy-ui.service; do
  if ! cmp -s "$ROOT/deploy/$unit" "/etc/systemd/system/$unit" 2>/dev/null; then
    unit_changed=1
  fi
  install -m 0644 "$ROOT/deploy/$unit" "/etc/systemd/system/$unit"
  sed -i 's/\r$//' "/etc/systemd/system/$unit"
done

install -d -m 0700 "$UI_DIR"
if [ ! -f "$UI_ENV" ]; then
  umask 077
  {
    printf '%s\n' '# Настройки Web UI egress-proxy. После правки: systemctl restart egress-proxy-ui'
    printf '%s\n' '# Порт панели. Не должен совпадать с PROXY_PORTS.'
    printf '%s\n' 'UI_PORT=8443'
    printf '%s\n' '# Режим задаёт sh deploy/install-ui.sh: HTTPS на 0.0.0.0 или HTTP на 127.0.0.1 через SSH-туннель.'
    printf '%s\n' 'UI_LISTEN=0.0.0.0'
    printf '%s\n' 'UI_INSECURE_HTTP=0'
    printf '%s\n' '# Кто видит страницу входа. Пусто — любой адрес, доступ ограничивает ufw.'
    printf '%s\n' 'UI_ALLOW_CLIENTS='
    printf '%s\n' '# Свой сертификат (например, Let'"'"'s Encrypt) — пути к fullchain и ключу.'
    printf '%s\n' "UI_TLS_CERT=$UI_DIR/tls.crt"
    printf '%s\n' "UI_TLS_KEY=$UI_DIR/tls.key"
    printf '%s\n' '# Каталог git-клона для обновления из панели.'
    printf '%s\n' "UI_REPO_DIR=$ROOT"
  } > "$UI_ENV"
  umask 022
  echo "Создан $UI_ENV"
  had_env=0
else
  sed -i 's/\r$//' "$UI_ENV"
  echo "Настройки $UI_ENV сохраняются."
  had_env=1
fi
chmod 0600 "$UI_ENV"
chown root:root "$UI_DIR" "$UI_ENV"

ui_value() {
  grep "^$1=" "$UI_ENV" | tail -n 1 | cut -d= -f2- || true
}

set_value() {
  # set_value КЛЮЧ ЗНАЧЕНИЕ — значения тут только IP, числа и пути без «|»
  if grep -q "^$1=" "$UI_ENV"; then
    sed -i "s|^$1=.*|$1=$2|" "$UI_ENV"
  else
    printf '%s=%s\n' "$1" "$2" >> "$UI_ENV"
  fi
}

if [ -z "$(ui_value UI_REPO_DIR)" ]; then
  set_value UI_REPO_DIR "$ROOT"
fi

ui_port=$(ui_value UI_PORT)
ui_port=${ui_port:-8443}
case "$ui_port" in
  ''|*[!0-9]*)
    echo "UI_PORT в $UI_ENV не число: $ui_port" >&2
    exit 1
    ;;
esac

vps_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' || true)
ssh_client=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $1}')
case "$ssh_client" in
  ''|*[!0-9a-fA-F:.]*) ssh_client= ;;
esac
ssh_port=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $4}')
case "$ssh_port" in
  ''|*[!0-9]*) ssh_port=$(ui_value UI_SSH_PORT) ;;
esac
ssh_port=${ssh_port:-22}
if [ -n "$vps_ip" ]; then
  set_value UI_PUBLIC_HOST "$vps_ip"
fi
set_value UI_SSH_PORT "$ssh_port"

current_mode=https
case "$(ui_value UI_INSECURE_HTTP)" in
  1|true|yes|on) current_mode=ssh-tunnel ;;
esac
mode=${UI_MODE:-}
if [ -z "$mode" ]; then
  if [ "$had_env" -eq 1 ]; then
    default_mode=$current_mode
  else
    default_mode=https
  fi
  if [ "$interactive" -eq 1 ]; then
    echo
    echo "Как открывать панель:"
    echo "  1 — HTTPS на внешнем адресе VPS (самоподписанный сертификат, порт $ui_port в ufw только для вас)"
    echo "  2 — без HTTPS, только через SSH-туннель (UI слушает 127.0.0.1, порт наружу не открывается)"
    if [ "$default_mode" = "ssh-tunnel" ]; then default_num=2; else default_num=1; fi
    ask "Выбор [$default_num]: " "$default_num"
    case "$answer" in
      2|ssh|ssh-tunnel|туннель) mode=ssh-tunnel ;;
      *) mode=https ;;
    esac
  else
    mode=$default_mode
  fi
fi
case "$mode" in
  https|ssh-tunnel) ;;
  *)
    echo "UI_MODE: https или ssh-tunnel, сейчас $mode" >&2
    exit 1
    ;;
esac
if [ "$mode" != "$current_mode" ] && [ "$had_env" -eq 1 ]; then
  echo "Режим доступа меняется: $current_mode -> $mode"
fi

ui() {
  PYTHONPATH="$LIB" UI_ENV_FILE="$UI_ENV" python3 -m egress_ui "$@"
}

ufw_ui_rules() {
  # Номера правил ufw для порта UI с комментарием egress-ui, по убыванию
  ufw status numbered 2>/dev/null \
    | grep -E "^\[ *[0-9]+\] +$ui_port(/tcp)?( \(v6\))? .*# egress-ui" \
    | sed -n 's/^\[ *\([0-9][0-9]*\)\].*/\1/p' \
    | sort -nr || true
}

if [ "$mode" = "ssh-tunnel" ]; then
  set_value UI_LISTEN 127.0.0.1
  set_value UI_INSECURE_HTTP 1
  echo "Режим SSH-туннеля: UI слушает 127.0.0.1:$ui_port без HTTPS, сертификат не нужен."
  if command -v ufw >/dev/null 2>&1; then
    nums=$(ufw_ui_rules)
    if [ -n "$nums" ]; then
      echo "В ufw остались правила egress-ui для порта $ui_port:"
      ufw status numbered | grep -E "^\[ *[0-9]+\] +$ui_port(/tcp)?( \(v6\))? .*# egress-ui" | sed 's/^/  /' || true
      if [ "$interactive" -eq 1 ]; then
        ask "Удалить их? В режиме туннеля порт снаружи не нужен. [Y/n]: " "y"
      else
        answer=n
      fi
      if yes_answer "$answer"; then
        for n in $nums; do
          ufw --force delete "$n"
        done
      else
        echo "Правила оставляю. Удалить: ufw status numbered, затем ufw delete НОМЕР"
      fi
    fi
  fi
else
  listen=$(ui_value UI_LISTEN)
  case "$listen" in
    ''|127.0.0.1|::1) set_value UI_LISTEN 0.0.0.0 ;;
  esac
  set_value UI_INSECURE_HTTP 0
  tls_cert=$(ui_value UI_TLS_CERT)
  tls_cert=${tls_cert:-$UI_DIR/tls.crt}
  if [ ! -f "$tls_cert" ]; then
    echo "Создаю самоподписанный сертификат $tls_cert"
    ui gen-cert
  fi
  if command -v ufw >/dev/null 2>&1; then
    if [ -n "$ssh_client" ]; then
      ask "Открыть порт $ui_port в ufw только для вашего адреса $ssh_client? [Y/n]: " "y"
      if yes_answer "$answer"; then
        ufw allow from "$ssh_client" to any port "$ui_port" proto tcp comment egress-ui
      else
        echo "Порт $ui_port в ufw не открываю."
      fi
    elif [ "$interactive" -eq 1 ]; then
      echo "Адрес вашей SSH-сессии неизвестен."
      ask "С какого адреса открыть порт $ui_port (IP или сеть; any — для всех; Enter — не открывать): " ""
      case "$answer" in
        '') echo "Порт $ui_port в ufw не открываю. Открыть: ufw allow from АДРЕС to any port $ui_port proto tcp" ;;
        any) ufw allow "$ui_port/tcp" comment egress-ui ;;
        *) ufw allow from "$answer" to any port "$ui_port" proto tcp comment egress-ui ;;
      esac
    else
      echo "Порт $ui_port в ufw не открываю. Открыть: ufw allow from АДРЕС to any port $ui_port proto tcp"
    fi
  fi
fi

if grep -q '^UI_PASSWORD_HASH=..*' "$UI_ENV"; then
  echo "Пароль Web UI уже задан. Сменить: PYTHONPATH=$LIB python3 -m egress_ui set-password"
elif [ -n "${EGRESS_UI_PASSWORD:-}" ]; then
  printf '%s\n' "$EGRESS_UI_PASSWORD" | ui set-password --stdin
elif [ "$interactive" -eq 1 ]; then
  echo "Задайте пароль входа в Web UI. Не короче 10 символов."
  tries=0
  until ui set-password < /dev/tty; do
    tries=$((tries + 1))
    if [ "$tries" -ge 3 ]; then
      echo "Пароль не задан. Позже: PYTHONPATH=$LIB python3 -m egress_ui set-password" >&2
      break
    fi
  done
else
  echo "Терминала нет и EGRESS_UI_PASSWORD не задан: пароль не задан."
fi

systemctl daemon-reload
if [ "$unit_changed" -eq 1 ] || [ "$proxy_changed" -eq 1 ]; then
  if systemctl is-active --quiet egress-proxy.service; then
    echo "Перезапускаю egress-proxy: обновлён код или юнит."
    systemctl restart egress-proxy.service
  fi
fi

systemctl enable egress-proxy-ui.service
if ! grep -q '^UI_PASSWORD_HASH=..*' "$UI_ENV"; then
  systemctl stop egress-proxy-ui.service 2>/dev/null || true
  echo "Web UI установлен, но не запущен: нет пароля."
  echo "Задайте пароль и запустите: PYTHONPATH=$LIB python3 -m egress_ui set-password && systemctl restart egress-proxy-ui"
  exit 0
fi

systemctl restart egress-proxy-ui.service
i=0
while [ "$i" -lt 10 ]; do
  if systemctl is-active --quiet egress-proxy-ui.service; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
sleep 1
if ! systemctl is-active --quiet egress-proxy-ui.service; then
  echo "Web UI не запустился. Журнал:"
  journalctl -u egress-proxy-ui -n 30 --no-pager || true
  exit 1
fi

host=${vps_ip:-АДРЕС_VPS}
port_flag=
if [ "$ssh_port" != "22" ]; then
  port_flag=" -p $ssh_port"
fi
tunnel="ssh -N -L $ui_port:127.0.0.1:$ui_port$port_flag root@$host"
echo
if [ "$mode" = "ssh-tunnel" ]; then
  echo "Web UI запущен без HTTPS на 127.0.0.1:$ui_port этого VPS."
  echo "На своём компьютере выполните и не закрывайте окно:"
  echo "  $tunnel"
  echo "Затем откройте в браузере: http://127.0.0.1:$ui_port/"
  echo "PuTTY: Session — $host, порт $ssh_port. Connection → SSH → Tunnels: Source port $ui_port, Destination 127.0.0.1:$ui_port, Add, затем Open."
  echo "Включить HTTPS: sh deploy/install-ui.sh и выбрать 1."
else
  fingerprint=$(ui fingerprint 2>/dev/null || true)
  echo "Web UI запущен: https://$host:$ui_port/"
  if [ -n "$fingerprint" ]; then
    echo "Отпечаток сертификата SHA-256: $fingerprint"
    echo "Браузер предупредит о самоподписанном сертификате. Сверьте отпечаток и только тогда продолжайте."
  fi
  echo "Если порт закрыт: $tunnel, затем https://127.0.0.1:$ui_port/"
fi
echo "Журнал UI: journalctl -u egress-proxy-ui -f"
