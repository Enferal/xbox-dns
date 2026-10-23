#!/bin/sh
# Обновление без вопросов: git pull, проверка нового кода, установка, перезапуск с откатом.
# Запуск: sh deploy/update.sh. Web UI запускает его через systemd-run.
grep -q "$(printf '\r')" "$0" && sed -i 's/\r$//' "$0" && exec /bin/sh "$0" "$@" #
set -eu

REPO=${REPO:-$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)}
LIB=/usr/local/lib/egress-proxy
UNITS=/etc/systemd/system
ENV_FILE=/etc/egress-proxy/egress.env

fail() {
  echo "$*" >&2
  echo "Обновление не удалось"
  exit 1
}

if [ -z "${EGRESS_UPDATE_PULLED:-}" ]; then
  echo "Обновление egress-proxy: начало, каталог $REPO"
fi
if [ "$(id -u)" -ne 0 ]; then
  fail "Нужен root: sh deploy/update.sh"
fi
[ -d "$REPO/.git" ] || fail "$REPO не git-репозиторий. Укажите каталог: REPO=/путь sh deploy/update.sh"

git_repo() {
  git -c safe.directory="$REPO" -C "$REPO" "$@"
}

if [ -z "${EGRESS_UPDATE_PULLED:-}" ]; then
  before=$(git_repo rev-parse --short HEAD)
  git_repo pull --ff-only || fail "git pull --ff-only не прошёл. Локальные правки или история разошлась: git -C $REPO status"
  after=$(git_repo rev-parse --short HEAD)
  if [ "$before" = "$after" ]; then
    echo "Новых коммитов нет ($after). Переустанавливаю текущую версию."
  else
    echo "Код обновлён: $before -> $after"
    git_repo log --format='  %h %s' "$before..$after" | head -n 30 || true
  fi
  # Дальше работает уже новая версия этого скрипта.
  EGRESS_UPDATE_PULLED=1 REPO=$REPO exec /bin/sh "$REPO/deploy/update.sh"
fi

work=$(mktemp -d /var/tmp/egress-update.XXXXXX)
backup=$work/backup
stage=$work/stage
mkdir -p "$backup" "$stage"

ui_installed=0
if [ -f "$UNITS/egress-proxy-ui.service" ] || [ -d "$LIB/egress_ui" ]; then
  ui_installed=1
fi

cp "$REPO/scripts/egress_proxy.py" "$stage/egress_proxy.py"
cp -R "$REPO/scripts/egress_ui" "$stage/egress_ui"
find "$stage" -name __pycache__ -type d -prune -exec rm -rf {} +
find "$stage" -type f -exec sed -i 's/\r$//' {} +
find "$stage/egress_ui" -type d -exec chmod 0755 {} +
find "$stage/egress_ui" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/egress_proxy.py"
for unit in egress-proxy.service egress-proxy-ui.service; do
  cp "$REPO/deploy/$unit" "$stage/$unit"
  sed -i 's/\r$//' "$stage/$unit"
done

echo "Проверка нового кода на текущих настройках"
(
  export EXIT_IPS_FILE=/etc/egress-proxy/exit-ips.txt
  export DESTINATIONS_FILE=/etc/egress-proxy/allow-destinations.txt
  export DIRECT_FILE=/etc/egress-proxy/direct-destinations.txt
  if [ -f "$ENV_FILE" ]; then
    python3 "$stage/egress_proxy.py" --check-config --env-file "$ENV_FILE" > /dev/null
  else
    python3 "$stage/egress_proxy.py" --check-config > /dev/null
  fi
) || {
  rm -rf "$work"
  fail "Новый код не принял настройки. Установленные файлы не тронуты."
}
if [ "$ui_installed" -eq 1 ]; then
  PYTHONPATH="$stage" python3 -c "import egress_ui.server, egress_ui.__main__" || {
    rm -rf "$work"
    fail "Новый код Web UI не импортируется. Установленные файлы не тронуты."
  }
fi

[ -f "$LIB/egress_proxy.py" ] && cp -p "$LIB/egress_proxy.py" "$backup/egress_proxy.py"
[ -d "$LIB/egress_ui" ] && cp -Rp "$LIB/egress_ui" "$backup/egress_ui"
for unit in egress-proxy.service egress-proxy-ui.service; do
  [ -f "$UNITS/$unit" ] && cp -p "$UNITS/$unit" "$backup/$unit"
done

install_ui_files() {
  # install_ui_files КАТАЛОГ — ставит egress_ui из каталога
  rm -rf "$LIB/egress_ui.new" "$LIB/egress_ui.old"
  cp -Rp "$1/egress_ui" "$LIB/egress_ui.new"
  if [ -d "$LIB/egress_ui" ]; then
    mv "$LIB/egress_ui" "$LIB/egress_ui.old"
  fi
  mv "$LIB/egress_ui.new" "$LIB/egress_ui"
  rm -rf "$LIB/egress_ui.old"
}

restore() {
  echo "Возвращаю прежние файлы"
  if [ -f "$backup/egress_proxy.py" ]; then
    install -m 0755 "$backup/egress_proxy.py" "$LIB/egress_proxy.py"
  fi
  if [ -d "$backup/egress_ui" ]; then
    install_ui_files "$backup"
  fi
  for unit in egress-proxy.service egress-proxy-ui.service; do
    if [ -f "$backup/$unit" ]; then
      install -m 0644 "$backup/$unit" "$UNITS/$unit"
    fi
  done
  systemctl daemon-reload
}

proxy_ok() {
  # Служба активна и не перезапускалась за время ожидания.
  first=$(systemctl show -p NRestarts --value egress-proxy.service 2>/dev/null || echo 0)
  i=0
  while [ "$i" -lt 8 ]; do
    sleep 1
    if ! systemctl is-active --quiet egress-proxy.service; then
      return 1
    fi
    i=$((i + 1))
  done
  last=$(systemctl show -p NRestarts --value egress-proxy.service 2>/dev/null || echo 0)
  [ "$first" = "$last" ]
}

ui_ok() {
  i=0
  while [ "$i" -lt 6 ]; do
    sleep 1
    if ! systemctl is-active --quiet egress-proxy-ui.service; then
      return 1
    fi
    i=$((i + 1))
  done
  return 0
}

echo "Установка в $LIB"
install -d -m 0755 "$LIB"
install -m 0755 "$stage/egress_proxy.py" "$LIB/egress_proxy.py"
install -m 0644 "$stage/egress-proxy.service" "$UNITS/egress-proxy.service"
if [ "$ui_installed" -eq 1 ]; then
  install_ui_files "$stage"
  install -m 0644 "$stage/egress-proxy-ui.service" "$UNITS/egress-proxy-ui.service"
fi
systemctl daemon-reload

echo "Перезапуск egress-proxy"
if ! systemctl restart egress-proxy.service || ! proxy_ok; then
  journalctl -u egress-proxy -n 20 --no-pager || true
  restore
  systemctl restart egress-proxy.service || true
  rm -rf "$work"
  fail "Служба не поднялась с новым кодом. Прежний код возвращён."
fi
echo "egress-proxy работает"

if [ "$ui_installed" -eq 1 ] && systemctl is-enabled --quiet egress-proxy-ui.service 2>/dev/null; then
  echo "Перезапуск egress-proxy-ui. Панель попросит войти снова."
  if ! systemctl restart egress-proxy-ui.service || ! ui_ok; then
    journalctl -u egress-proxy-ui -n 20 --no-pager || true
    if [ -d "$backup/egress_ui" ]; then
      install_ui_files "$backup"
      if [ -f "$backup/egress-proxy-ui.service" ]; then
        install -m 0644 "$backup/egress-proxy-ui.service" "$UNITS/egress-proxy-ui.service"
      fi
      systemctl daemon-reload
      systemctl restart egress-proxy-ui.service || true
    fi
    rm -rf "$work"
    fail "Web UI не поднялся с новым кодом. Служба egress-proxy обновлена, прежний Web UI возвращён."
  fi
fi

rm -rf "$work"
echo "Версия: $(git_repo log -1 --format='%h %s')"
echo "Обновление завершено"
