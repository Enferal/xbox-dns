# Домашний роутер и свой VPS

Репозиторий: https://github.com/Enferal/xbox-dns

На приставке или компьютере меняется только DNS: туда пишется адрес VPS. Прокси на устройстве не нужен. Имена из списка VPS отдаёт как свои и принимает TCP 80 и 443. Сайт видит адрес VPS. UDP, в том числе QUIC на 443, через сервис не идёт.

В журнале VPS рабочая строка выглядит так:

```text
Прокси xsts.auth.xboxlive.com:443 -> 20.201.192.52 с адреса 203.0.113.10 клиент=198.51.100.20
```

`203.0.113.10` в примере — адрес VPS. `198.51.100.20` — белый адрес дома, его показывает сайт «мой IP». Локальный адрес приставки `192.168.x.x` в этот журнал не попадает.

После смены DNS выдерните приставку из розетки на 10 секунд. Иначе она помнит старые ответы.

## 1. Обычный роутер

Подойдёт любой: от провайдера, Keenetic, Asus, MikroTik. nft, zapret и tcpdump тут не нужны.

В DNS устройства впишите адрес VPS. Второй DNS оставьте пустым. Если роутер или приставка сами включают прокси, VPN или «безопасный DNS», для этого устройства выключите.

До VPS должны проходить три вещи:

- DNS, UDP и TCP, порт 53
- TCP, порт 80
- TCP, порт 443

Этого хватает, когда роутер ничего не перехватывает. Перехват прячет соединение: DNS до VPS доходит, а TCP 443 нет. Так делают родительский контроль, подмена DNS, прозрачный прокси, VPN на всю сеть и правило «это устройство выпускать через другой сервер». Для приставки такое выключите.

Проверка с компьютера в той же сети:

```bash
nslookup user.auth.xboxlive.com АДРЕС_VPS
```

В ответе должен быть адрес VPS.

Дальше журнал на VPS, команда в разделе 3. Есть строки `DNS`, а следом нет `TCP входящий` и `Прокси` — имя приставка получила, TCP до сервера не дошёл. На роутере ищите подмену DNS, прокси или VPN для этого устройства.

## 2. Роутер на OpenWrt

Команды этого раздела — на роутере. Приглашение `root@OpenWrt`. На VPS этих файлов нет: цепочка `XRAY` и каталог `/opt/zapret` только на роутере.

Сначала раздел 1: DNS устройства — адрес VPS, в журнале VPS виден белый адрес дома. Строк `Прокси` нет — причина на роутере. Ниже проверки по порядку. Файрвол, zapret, Xray и bytetube во время проверки не перезапускайте. Перезапуск стирает таблицу соединений, и роутер сам рвёт уже открытый TCP.

Ошибка `0x800704c6` значит, что до сети Xbox приставка не дошла. Часто DNS уже отвечает адресом VPS, а TCP 443 роутер забирает себе.

Пакеты ставятся через `apk`, если `opkg` нет:

```bash
apk update
apk add tcpdump-mini
```

Адрес приставки и её MAC:

```bash
grep -i xbox /tmp/dhcp.leases
```

Интерфейс локальной сети берите из маршрута. Имя `br-lan` само не подставляйте:

```bash
DEV=$(ip -4 route get АДРЕС_ПРИСТАВКИ | sed -n 's/.* dev \([^ ]*\).*/\1/p')
echo "LAN=$DEV"
tcpdump -n -i "$DEV" 'host АДРЕС_ПРИСТАВКИ and tcp port 443'
```

На этом экране успех такой: сначала `Flags [S]` от приставки к VPS, следом `Flags [S.]` от VPS к приставке. Одни `[S]` — ответное рукопожатие до приставки не дошло.

В ту же минуту на VPS:

```bash
tcpdump -n -i any 'host БЕЛЫЙ_АДРЕС_ДОМА and tcp port 443'
```

На VPS фильтруйте белый адрес. На самом PPPoE адрес часто из сети `100.64.0.0/10`. Это внутренний адрес провайдера, VPS его не видит. Интерфейс в интернет: `ip -4 route get АДРЕС_VPS`. Часто это `pppoe-wan`.

### Zapret

Правила: `/etc/config/zapret` и `/opt/zapret/config`.

UDP 443 у zapret уже может быть закрыт отказом `icmp port-unreachable`. Так и оставьте. Приставка получит отказ и перейдёт на TCP. Второй запрет UDP 443 не добавляйте: QUIC сервис всё равно не обслуживает.

TCP 443 zapret портит, пока адрес назначения не лежит в наборе `nozapret` таблицы `inet zapret`. Проверка:

```bash
nft get element inet zapret nozapret '{ АДРЕС_VPS }'
```

Команда пишет, что элемента нет — добавьте адрес в живой набор и в файл, из которого набор собирается заново:

```bash
grep -qx АДРЕС_VPS /opt/zapret/ipset/zapret-ip-user-exclude.txt || echo АДРЕС_VPS >> /opt/zapret/ipset/zapret-ip-user-exclude.txt
nft add element inet zapret nozapret '{ АДРЕС_VPS }'
nft get element inet zapret nozapret '{ АДРЕС_VPS }'
```

Живой набор пропадает, когда zapret или файрвол перезапускаются. Строка в файле нужна, чтобы адрес вернулся сам.

### Flow offload

```bash
uci get firewall.@defaults[0].flow_offloading
uci get firewall.@defaults[0].flow_offloading_hw
```

Оба значения должны быть `0`. Единица уводит часть TCP мимо обычных правил, и SYN до интернета не доходит. Менять это можно только вместе с перезапуском файрвола. После перезапуска снова добавьте адрес VPS в `nozapret`, как в блоке zapret выше.

### Bytetube

Цепочка `inet bytetube prerouting` метит TCP к адресам из набора `yt4` и уводит его в туннель `ytb0`. Адрес VPS:

```bash
nft get element inet bytetube yt4 '{ АДРЕС_VPS }'
```

Ответ `No such file or directory` значит, что адреса в наборе нет и bytetube его не забирает. Элемент находится — SYN к VPS уходит в туннель. Уберите адрес из источника списка `yt4` и пересоберите набор средствами bytetube. Весь bytetube из-за одного адреса удалять не нужно. Пока VPS в `yt4` не входит, туннель этот трафик не трогает.

### Старый Xray

Остаток старой установки забирает весь TCP одного устройства на локальный прокси. На роутере:

```bash
iptables -t mangle -S XRAY
```

Плохая строка выглядит так:

```text
-A XRAY -p tcp -m mac --mac-source MAC_ПРИСТАВКИ -j TPROXY --on-port 12345 --on-ip 127.0.0.1 --tproxy-mark 0x1/0xffffffff
```

MAC в ней совпадает с приставкой из `dhcp.leases`. Весь её TCP уходит на `127.0.0.1`. На WAN и на VPS пусто, а DNS живой: правило только для TCP. Сообщение `No chain/target/match by that name` значит, что цепочки нет и этот перехват выключен.

Снимите живое правило той же строкой, только `-A` замените на `-D`. Порт и mark копируйте из своей строки `-S`:

```bash
iptables -t mangle -D XRAY -p tcp -m mac --mac-source MAC_ПРИСТАВКИ -j TPROXY --on-port 12345 --on-ip 127.0.0.1 --tproxy-mark 0x1/0xffffffff
iptables -t mangle -S XRAY
```

Для перезагрузки этого мало. Правило заново создаёт скрипт, который файрвол подключает при каждой загрузке. Ищите так:

```bash
grep -r -l "XRAY" /etc /root 2>/dev/null
grep -n "xraytproxy" /etc/config/firewall
```

Чаще всего это `/etc/firewall.xraytproxy`, а в `/etc/config/firewall` у него есть `option path`. Выключите включение, файл не удаляйте:

```bash
line=$(uci show firewall | grep "path='/etc/firewall.xraytproxy'")
echo "$line"
sec=${line%%.path=*}
uci set "${sec}.enabled=0"
uci commit firewall
uci show "$sec"
```

В выводе должно быть `enabled='0'`. Пока нет `uci commit`, перезагрузка роутера снова включит `TPROXY`. Файрвол ради этой записи не перезапускайте. Текущее правило уже снято командой `-D`, а `enabled='0'` заработает при следующей загрузке.

### После перезагрузки роутера

```bash
echo '===== INCLUDE ====='
uci show firewall.@include[0]
echo '===== XRAY ====='
iptables -t mangle -S XRAY
echo '===== EXCLUDE ====='
grep АДРЕС_VPS /opt/zapret/ipset/zapret-ip-user-exclude.txt
nft get element inet zapret nozapret '{ АДРЕС_VPS }'
```

Так выглядит рабочий результат:

- `enabled='0'` у включения с путём `firewall.xraytproxy`. Такого включения нет — строки `XRAY` в файрволе тоже нет.
- Цепочки `XRAY` нет, либо в ней нет `TPROXY` с MAC приставки.
- `grep` печатает адрес VPS.
- `nft get element` показывает этот адрес в `elements`.

Дальше выдерните питание приставки на 10 секунд и откройте магазин. На VPS в журнале нужна строка `Прокси` с белым адресом дома.

### Куда делся SYN

| Что видно | Где режется |
| --- | --- |
| На LAN есть `[S]`, на VPS пусто, на `pppoe-wan` тоже пусто | Роутер не выпускает пакет. Смотрите zapret, flow offload, bytetube и Xray |
| На `pppoe-wan` есть `[S]`, на VPS пусто | Пакет вышел с роутера и потерялся дальше |
| В журнале VPS есть `Прокси ... клиент=БЕЛЫЙ_АДРЕС` | Путь рабочий |

`tcpdump-mini` на `pppoe-wan` иногда пишет `UNSUPPORTED` и шестнадцатеричный дамп. Для обычной проверки хватает захвата на LAN и журнала VPS.

## 3. Что поставить на свой VPS

Нужны Ubuntu 22.04 или 24.04, вход root, systemd и свободные порты 53, 80 и 443. Пакеты: `python3`, `iproute2` (команды `ip` и `ss`), `ca-certificates`, `bind9-dnsutils` (команда `dig`), `ufw`, `git`. После вопросов установщик проверяет список и ставит только то, чего нет. На экране будет `Ставлю недостающее` или `Все нужные пакеты уже стоят`. Другую систему он не ставит. Входящие SSH, 53/tcp, 53/udp, 80/tcp и 443/tcp открывает установщик. Исходящий интернет самого VPS он не трогает. `git` в команде ниже нужен раньше скрипта, чтобы скачать репозиторий.

Зайдите на сервер и посмотрите порты:

```bash
ssh root@АДРЕС_VPS
ss -tulpn 'sport = :53 or sport = :80 or sport = :443'
```

`127.0.0.53:53` установке не мешает. `*:443` или `0.0.0.0:443` — порт занят другой программой. DNS поднимется, а сайты через VPS не откроются, пока она работает.

Скачайте проект и поставьте службу:

```bash
apt-get update
apt-get install -y git
git clone https://github.com/Enferal/xbox-dns.git /opt/egress-proxy
cd /opt/egress-proxy
sh deploy/install-native.sh
```

Первая строка установщика: `Установщик egress-proxy. Пустой ALLOW_CLIENTS пускает всех.` Дальше вопросы.

- Прошлые настройки: Enter оставляет список доменов, адреса выхода и `/etc/egress-proxy/egress.env`. `y` стирает эти три файла.
- Остальные вопросы показывают пример и строку «Сейчас». Enter оставляет текущее.
- `DNS_UPSTREAM`: Enter берёт DNS самого VPS. Адреса `127.0.0.53` и адрес самого VPS в этот список не входят. Своих DNS нет — остаётся `1.1.1.1,8.8.8.8`.
- `ALLOW_CLIENTS`: пустой ответ пускает всех. Знак `-` тоже. Адреса вписывайте, только когда нужно ограничить доступ.
- `LISTEN_IP`: оставьте `0.0.0.0`, иначе `dig` на самом сервере не сработает.

В конце строка `На устройстве укажите DNS:` и адрес VPS. Его и вписывайте в DNS устройства.

Проверка на сервере:

```bash
dig +short @127.0.0.1 user.auth.xboxlive.com A
```

В ответе один адрес — адрес этого VPS.

Журнал:

```bash
journalctl -u egress-proxy -n 50 --no-pager
```

Новые строки сразу: `journalctl -u egress-proxy -f`. Выход: `Ctrl+C`.

Обновить программу и не отвечать на вопросы заново:

```bash
cd /opt/egress-proxy
git pull
install -m 0755 scripts/egress_proxy.py /usr/local/lib/egress-proxy/egress_proxy.py
systemctl restart egress-proxy
```

Полная переустановка снова задаёт вопросы: `sh deploy/install-native.sh` из `/opt/egress-proxy`.

Имена Xbox лежат в `/etc/egress-proxy/allow-destinations.txt`. Строка `xboxlive.com` покрывает само имя и поддомены. Туда же входят общие зоны `microsoft.com`, `bing.com`, `live.com`, `akamai.net` и `akamaized.net`: через VPS пойдёт любой сайт на этих именах, кроме закачки.

Закачка перечислена в `/etc/egress-proxy/direct-destinations.txt`: `dl.delivery.mp.microsoft.com`, `dlassets.xboxlive.com` и `assets1.xboxlive.com`–`assets5.xboxlive.com`. Для них DNS отдаёт настоящий адрес, файл качается с IP приставки. Файла на сервере нет — тот же список уже встроен в программу. После правки: `systemctl restart egress-proxy`. Выдерните питание приставки на 10 секунд, иначе она помнит старый адрес VPS для этих имён.

## 4. Что прислать для сравнения

Два куска: с VPS и с роутера OpenWrt. Файлы `network` и `wireless` не присылайте, там пароль интернета и пароль Wi‑Fi. Файрвол и zapret перед снятием не перезапускайте.

На VPS:

```bash
echo '===== ENV ====='
cat /etc/egress-proxy/egress.env
echo '===== DESTINATIONS ====='
cat /etc/egress-proxy/allow-destinations.txt
echo '===== EXIT ====='
cat /etc/egress-proxy/exit-ips.txt
echo '===== LISTEN ====='
ss -tulpn 'sport = :53 or sport = :80 or sport = :443'
echo '===== DIG ====='
dig +short @127.0.0.1 user.auth.xboxlive.com A
```

На роутере OpenWrt:

```bash
echo '===== LEASE ====='
grep -i xbox /tmp/dhcp.leases
echo '===== FLOW ====='
uci get firewall.@defaults[0].flow_offloading
uci get firewall.@defaults[0].flow_offloading_hw
echo '===== ZAPRET CONFIG ====='
cat /etc/config/zapret
echo '===== ZAPRET OPT ====='
grep -n "NFQWS_\|MODE_\|FLOWOFFLOAD" /opt/zapret/config
echo '===== ZAPRET EXCLUDE ====='
cat /opt/zapret/ipset/zapret-ip-user-exclude.txt
echo '===== NOZAPRET ====='
nft list set inet zapret nozapret
echo '===== BYTETUBE ====='
nft list chain inet bytetube prerouting
echo '===== XRAY ====='
iptables -t mangle -S PREROUTING
iptables -t mangle -S XRAY
echo '===== XRAY INCLUDE ====='
uci show firewall | grep xraytproxy
echo '===== MANGLE ====='
nft list chain ip mangle PREROUTING
```

Какой-то команды в системе нет — она напишет ошибку. Ошибку тоже присылайте: по ней видно, что этой программы на роутере нет.
