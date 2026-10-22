# Когда приставка не доходит до сервера

Проект: https://github.com/Enferal/xbox-dns

На приставке меняется только DNS: туда пишется адрес сервера. Прокси на приставке не нужен. Сервер принимает TCP и открывает сайт уже от своего адреса. Для Xbox это порты 80 и 443. Для UFC 5 к ним добавляются 42130, 44326 и 15000–15099, раздел «UFC 5» в [README.md](README.md). UDP, в том числе голос и QUIC на 443, через службу не идёт.

Готовая настройка роутера OpenWrt: [OPENWRT.md](OPENWRT.md). Этот файл — что проверить, когда настройка уже сделана, а соединения всё равно нет.

В журнале сервера рабочая строка выглядит так:

```text
Прокси xsts.auth.xboxlive.com:443 -> 20.201.192.52 с адреса 203.0.113.10 клиент=198.51.100.20
```

`203.0.113.10` в примере — адрес сервера. `198.51.100.20` — белый адрес дома, его показывает сайт «мой IP». Домашний адрес приставки `192.168.x.x` в этот журнал не попадает.

После смены DNS выдерните питание приставки на 10 секунд. Иначе она помнит старые ответы.

## 1. Обычный роутер

Подойдёт роутер провайдера, Keenetic, Asus, MikroTik. Команды nft и zapret здесь не нужны.

В DNS приставки впишите адрес сервера. Второй DNS оставьте пустым. Родительский контроль, свой DNS, прозрачный прокси и VPN для этой приставки выключите. Иначе роутер отвечает на DNS сам, а до сервера доходит только часть пакетов.

До сервера должны проходить:

- DNS, UDP и TCP, порт 53
- TCP, порт 80
- TCP, порт 443

Проверка с компьютера в той же сети:

```bash
nslookup user.auth.xboxlive.com АДРЕС_VPS
```

В ответе должен быть адрес сервера.

Дальше смотрите журнал на сервере, команда в конце этого файла. Есть строки `DNS`, а следом нет `TCP входящий` и `Прокси` — имя приставка получила, само соединение до сервера не дошло.

## 2. Роутер OpenWrt

Сначала [OPENWRT.md](OPENWRT.md): переадресация DNS, исключение zapret и правило для flow offload. Ниже проверка, когда пакет всё равно пропадает.

Команды этого раздела — на роутере, приглашение `root@OpenWrt`. На сервере нет цепочки `XRAY` и каталога `/opt/zapret`.

Ошибка `0x800704c6` значит, что приставка до сети Xbox не дошла. Часто DNS уже отвечает адресом сервера, а TCP 443 роутер забирает себе. Ошибка `0x80a40401` значит, что соединение дошло, но Xbox увидел домашний адрес. Тогда на роутере не хватает строк для `user.auth.xboxlive.com` и `xsts.auth.xboxlive.com` из [OPENWRT.md](OPENWRT.md).

Пока ищете пакет, файрвол, zapret, Xray и bytetube не перезапускайте. Перезапуск стирает таблицу соединений, и роутер сам рвёт уже открытый TCP.

Пакет для захвата, если `opkg` нет:

```bash
apk update
apk add tcpdump-mini
```

Адрес приставки и её MAC:

```bash
grep -i xbox /tmp/dhcp.leases
```

Интерфейс домашней сети возьмите из маршрута. Имя `br-lan` само не подставляйте, оно бывает другим:

```bash
DEV=$(ip -4 route get АДРЕС_ПРИСТАВКИ | sed -n 's/.* dev \([^ ]*\).*/\1/p')
echo "LAN=$DEV"
tcpdump -n -i "$DEV" 'host АДРЕС_ПРИСТАВКИ and tcp port 443'
```

Успех на этом экране: сначала `Flags [S]` от приставки к серверу, следом `Flags [S.]` от сервера к приставке. Одни `[S]` без `[S.]` значат, что ответ до приставки не дошёл.

В ту же минуту на сервере:

```bash
tcpdump -n -i any 'host БЕЛЫЙ_АДРЕС_ДОМА and tcp port 443'
```

На сервере фильтруйте белый адрес дома. Адрес на самом PPPoE часто из сети `100.64.0.0/10`. Это внутренний адрес провайдера, сервер его не видит. Интерфейс роутера в интернет: `ip -4 route get АДРЕС_VPS`. Часто это `pppoe-wan`.

### Zapret

Правила лежат в `/etc/config/zapret` и `/opt/zapret/config`.

UDP 443 zapret может закрывать отказом `icmp port-unreachable`. Оставьте так: приставка получит отказ и перейдёт на TCP. Второй запрет UDP 443 не добавляйте.

TCP 443 проходит, когда адрес сервера лежит в наборе `nozapret`:

```bash
nft get element inet zapret nozapret '{ АДРЕС_VPS }'
```

Если элемента нет:

```bash
grep -qx АДРЕС_VPS /opt/zapret/ipset/zapret-ip-user-exclude.txt || echo АДРЕС_VPS >> /opt/zapret/ipset/zapret-ip-user-exclude.txt
nft add element inet zapret nozapret '{ АДРЕС_VPS }'
nft get element inet zapret nozapret '{ АДРЕС_VPS }'
```

Живой набор пропадает, когда zapret или файрвол перезапускаются. Строка в файле нужна, чтобы адрес вернулся сам. Как устроено исключение целиком, написано в [OPENWRT.md](OPENWRT.md).

### Flow offload

```bash
uci get firewall.@defaults[0].flow_offloading
uci get firewall.@defaults[0].flow_offloading_hw
```

Значение `1` оставляет ускорение включённым. Выключать его в `0` не нужно. Скрипт, который проводит только адрес сервера до правила `flow add`, лежит в [OPENWRT.md](OPENWRT.md). После перезапуска файрвола снова проверьте `nozapret`.

### Bytetube

Цепочка `inet bytetube prerouting` метит TCP к адресам из набора `yt4` и уводит его в туннель `ytb0`.

```bash
nft get element inet bytetube yt4 '{ АДРЕС_VPS }'
```

Ответ `No such file or directory` значит, что адреса в наборе нет и bytetube его не забирает. Если элемент есть, уберите адрес сервера из источника списка `yt4` и пересоберите набор. Весь bytetube из-за одного адреса удалять не нужно.

### Старый Xray

Остаток старой установки забирает весь TCP одного устройства на локальный прокси. На роутере:

```bash
iptables -t mangle -S XRAY
```

Плохая строка выглядит так:

```text
-A XRAY -p tcp -m mac --mac-source MAC_ПРИСТАВКИ -j TPROXY --on-port 12345 --on-ip 127.0.0.1 --tproxy-mark 0x1/0xffffffff
```

MAC в ней совпадает с приставкой из `dhcp.leases`. Весь её TCP уходит на `127.0.0.1`. На выходе в интернет и на сервере пусто, а DNS живой: правило только для TCP. Сообщение `No chain/target/match by that name` значит, что цепочки нет и этот перехват выключен.

Снимите правило той же строкой. `-A` замените на `-D`. Порт и mark копируйте из своей строки, числа ниже только пример:

```bash
iptables -t mangle -D XRAY -p tcp -m mac --mac-source MAC_ПРИСТАВКИ -j TPROXY --on-port 12345 --on-ip 127.0.0.1 --tproxy-mark 0x1/0xffffffff
iptables -t mangle -S XRAY
```

Этого хватает до перезагрузки. Правило заново создаёт скрипт, который файрвол подключает при каждой загрузке. Ищите его так:

```bash
grep -r -l "XRAY" /etc /root 2>/dev/null
grep -n "xraytproxy" /etc/config/firewall
```

Чаще всего это `/etc/firewall.xraytproxy`, а в `/etc/config/firewall` у него есть `option path`. Выключите включение, сам файл оставьте:

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

Рабочий результат:

- у включения с путём `firewall.xraytproxy` стоит `enabled='0'`, либо такого включения нет
- цепочки `XRAY` нет, либо в ней нет `TPROXY` с MAC приставки
- `grep` печатает адрес сервера
- `nft get element` показывает этот адрес в `elements`

Дальше выдерните питание приставки на 10 секунд и откройте магазин. На сервере в журнале нужна строка `Прокси` с белым адресом дома.

### Куда делся первый пакет

| Что видно | Где искать |
| --- | --- |
| На домашней сети есть `[S]`, на сервере пусто и на `pppoe-wan` пусто | Роутер не выпускает пакет. Смотрите zapret, flow offload, bytetube и Xray |
| На `pppoe-wan` есть `[S]`, на сервере пусто | Пакет вышел с роутера и потерялся дальше |
| В журнале сервера есть `Прокси ... клиент=БЕЛЫЙ_АДРЕС` | Путь рабочий |

`tcpdump-mini` на `pppoe-wan` иногда пишет `UNSUPPORTED` и шестнадцатеричный дамп. Для обычной проверки хватает захвата на домашней сети и журнала сервера.

## 3. Что стоит на сервере

Подробная установка: [README.md](README.md). Коротко, на сервере:

```bash
ssh root@АДРЕС_VPS
ss -tulpn 'sport = :53 or sport = :80 or sport = :443'
```

Строка `127.0.0.53:53` установке не мешает. `*:443` или `0.0.0.0:443` — порт занят другой программой.

```bash
apt-get update
apt-get install -y git
git clone https://github.com/Enferal/xbox-dns.git /opt/egress-proxy
cd /opt/egress-proxy
sh deploy/install-native.sh
```

На вопросы жмите Enter, если ставите в первый раз. В конце строка `На устройстве укажите DNS:` и адрес сервера.

Проверка:

```bash
dig +short @127.0.0.1 user.auth.xboxlive.com A
journalctl -u egress-proxy -n 50 --no-pager
```

В ответе `dig` один адрес — адрес этого сервера. Живой журнал: `journalctl -u egress-proxy -f`, выход `Ctrl+C`.

Обновить программу и не отвечать на вопросы заново:

```bash
cd /opt/egress-proxy
git pull
install -m 0755 scripts/egress_proxy.py /usr/local/lib/egress-proxy/egress_proxy.py
systemctl restart egress-proxy
```

Имена Xbox лежат в `/etc/egress-proxy/allow-destinations.txt`. Закачка игр перечислена в `/etc/egress-proxy/direct-destinations.txt` и идёт с адреса приставки. После правки списка: `systemctl restart egress-proxy` и питание приставки на 10 секунд.

## 4. Что прислать, если сами не нашли

Два куска: с сервера и с роутера OpenWrt. Файлы `network` и `wireless` не присылайте, там пароль интернета и пароль Wi‑Fi. Файрвол и zapret перед снятием не перезапускайте.

На сервере:

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

На роутере:

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
