# Роутер на OpenWrt

Проект: https://github.com/Enferal/xbox-dns

Этот файл выполняется на роутере. Приглашение там `root@OpenWrt`. На сервере этих файлов нет: каталог `/opt/zapret` и правила `fw4` живут только на роутере.

Сначала служба уже стоит на сервере, а в DNS приставки указан адрес сервера. Как поставить службу: [README.md](README.md). Если приставка адрес получает, а сайт всё равно не открывается, разбор пакетов: [ROUTER.md](ROUTER.md).

`АДРЕС_VPS` — адрес сервера из строки установщика `На устройстве укажите DNS`. `АДРЕС_ДОМА` — белый адрес дома, в журнале сервера он после `клиент=`.

На роутере обычно мешают три вещи.

1. Роутер сам отвечает на имена Xbox адресом провайдера. Приставка идёт в Xbox с дома, и появляется `0x80a40401`.
2. Zapret портит TCP до сервера, пока адрес сервера не внесён в исключения.
3. Ускорение flow offload забирает соединение с сервером себе. Выключать ускорение не нужно: ниже есть правило только для адреса сервера.

Порты UFC 5 (42130, 44326, 15000–15099) открываются на сервере, в разделе «UFC 5» файла [README.md](README.md). На роутере их прописывать не надо. Zapret и flow offload смотрят на весь адрес сервера, поэтому эти порты проходят вместе с 443.

## Имена, которые роутер должен отдавать сам

В переадресации DNS строка выглядит так: `/имя/адрес`. Роутер на вопрос об этом имени отвечает адресом сервера и дальше никого не спрашивает.

Вход в Xbox заработал на двух строках:

```text
/user.auth.xboxlive.com/АДРЕС_VPS
/xsts.auth.xboxlive.com/АДРЕС_VPS
```

Для синхронизации UFC 5 добавьте ещё две. Имена вроде `spring18` и `ext-…blaze` каждый раз новые, поэтому берётся вся зона `ea.com`. Сохранения лежат на `titlestorage….blob.core.windows.net`, регион в имени тоже меняется.

```text
/ea.com/АДРЕС_VPS
/blob.core.windows.net/АДРЕС_VPS
```

Те же четыре строки командами:

```bash
uci add_list dhcp.@dnsmasq[0].address='/user.auth.xboxlive.com/АДРЕС_VPS'
uci add_list dhcp.@dnsmasq[0].address='/xsts.auth.xboxlive.com/АДРЕС_VPS'
uci add_list dhcp.@dnsmasq[0].address='/ea.com/АДРЕС_VPS'
uci add_list dhcp.@dnsmasq[0].address='/blob.core.windows.net/АДРЕС_VPS'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

Строка нужна, когда во время входа журнал сервера молчит, а приставка показывает ошибку региона. Ответ тогда дал роутер, мимо сервера. Если в журнале уже есть `DNS xsts.auth.xboxlive.com A -> АДРЕС_VPS`, эта строка на роутере уже не требуется.

Зоны целиком `xboxlive.com` и `microsoft.com` в переадресацию не добавляйте. Внутри них закачка игр: `assets1.xboxlive.com` … `assets5.xboxlive.com`, `dlassets.xboxlive.com`, `dlassets2.xboxlive.com` и `dl.delivery.mp.microsoft.com`. Такая строка погонит большие файлы через сервер.

Три имени оставьте как есть, без адреса сервера:

- `xbox.ipv6.microsoft.com` открывается только по настоящему адресу Microsoft
- `dns.msftncsi.com` — это адрес `131.107.255.255`, соединения туда нет
- `pti.store.microsoft.com` в DNS не существует

После правки выдерните питание приставки на 10 секунд, чтобы она забыла старые ответы.

Запрос, на который ответил роутер, в журнал сервера не попадает. Пустая строка `AAAA -> пусто` на сервере при этом нормальна: IPv6 у сервера нет, приставка берёт адрес из строки роутера.

## Zapret

Zapret меняет пакеты к части серверов в интернете. Пока адреса вашего сервера нет в исключениях, до него ломается и обычный TCP.

Проверка на роутере:

```bash
nft get element inet zapret nozapret '{ АДРЕС_VPS }'
```

Если элемента нет, добавьте адрес в файл и в работающий набор:

```bash
grep -qx АДРЕС_VPS /opt/zapret/ipset/zapret-ip-user-exclude.txt || echo АДРЕС_VPS >> /opt/zapret/ipset/zapret-ip-user-exclude.txt
nft add element inet zapret nozapret '{ АДРЕС_VPS }'
nft get element inet zapret nozapret '{ АДРЕС_VPS }'
```

Файл нужен потому, что живой набор пропадает при перезапуске zapret или файрвола. Из файла адрес возвращается сам.

UDP 443 zapret может закрывать отказом `icmp port-unreachable`. Так и оставьте. Служба принимает только TCP, приставка переходит на него сама.

## Flow offload

Проверка:

```bash
uci get firewall.@defaults[0].flow_offloading
uci get firewall.@defaults[0].flow_offloading_hw
```

Оба значения могут быть `1`. Так и оставьте: выключать ускорение в `0` не нужно.

Ускорение после нескольких пакетов перестаёт смотреть на обычные правила, и соединение с сервером замирает. Два правила в начале цепочки `forward` говорят: пакеты к серверу и от него проводить сразу, до строки `flow add`.

Создайте файл `/etc/firewall.vps-no-offload.sh` с таким текстом. Вместо `АДРЕС_VPS` подставьте адрес сервера:

```bash
#!/bin/sh
nft insert rule inet fw4 forward ip saddr АДРЕС_VPS ct state established,related accept
nft insert rule inet fw4 forward ip daddr АДРЕС_VPS accept
```

Подключите его к файрволу и перезапустите файрвол:

```bash
chmod 755 /etc/firewall.vps-no-offload.sh
uci set firewall.vps_no_offload=include
uci set firewall.vps_no_offload.type='script'
uci set firewall.vps_no_offload.path='/etc/firewall.vps-no-offload.sh'
uci set firewall.vps_no_offload.fw4_compatible='1'
uci commit firewall
/etc/init.d/firewall restart
```

Перезапуск файрвола рвёт текущие соединения. Сразу после него правила должны стоять выше `flow add`:

```bash
nft list chain inet fw4 forward | head
```

В начале видны две строки с адресом сервера и `accept`, и только потом `flow add`. Затем ещё раз проверьте zapret из предыдущего раздела: перезапуск мог убрать адрес из живого набора, файл его вернёт после перезапуска zapret.

## Если пакет всё ещё уходит не туда

Bytetube забирает часть TCP в туннель `ytb0`, когда адрес лежит в наборе `yt4`:

```bash
nft get element inet bytetube yt4 '{ АДРЕС_VPS }'
```

Ответ `No such file or directory` значит, что этого адреса в наборе нет и туннель его не трогает. Если элемент есть, уберите адрес сервера из списка, из которого собирается `yt4`, и соберите набор снова. Весь bytetube из-за одного адреса удалять не нужно.

Старый Xray с правилом `TPROXY` забирает весь TCP приставки на `127.0.0.1`. Как снять это правило и выключить его возврат после загрузки, написано в [ROUTER.md](ROUTER.md), раздел «Старый Xray».
