<img src="icon.svg" width="96" alt="Nyampy" />

# Nyampy

Ещё один Android-клиент для VLESS и других — в Material Design 3 Expressive и на ядре
Mihomo.

*English version: [README.md](README.md)*

> **Альфа-версия.** Всё ещё в разработке. Если она зависнет — а оно может — пиши в
> [Issues](https://github.com/y4zwa/Nyampy/issues).

## Требования

Android 8.0 (API 26) или новее.

## Протоколы

VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, WireGuard (включая AmneziaWG),
Hysteria2.

XHTTP сохраняет `extra` из ссылки, включая раздельную загрузку: Xray-овский
`downloadSettings` переводится в плоский `download-settings` ядра. В режиме
`stream-one` пара выбрасывается — ядро её не принимает (`xhttp mode "stream-one" cannot
be used with download-settings`), и весь сервер не поднялся бы.

## IPv6

Туннель получает IPv6-адрес и маршрут, но ядро работает с `ipv6: false`, а DNS — с
`dns.ipv6: false`: AAAA-запросы не отправляются, и v6 не утекает мимо прокси. Это
защита от утечки, а не туннелирование v6 — сайты, доступные только по v6, работать
не будут.

Счётчики трафика считают весь туннель, включая DIRECT.

## Сборка

```shell
./gradlew :app:assembleRelease
```

При первой сборке готовый AAR ядра скачивается из пришпиленного релиза
`core-1.19.34-5` в `app/libs/`, с проверкой sha256. Без сети положи `nyampycore.aar`
туда руками — совпадение дайджеста всё равно решает, можно ли его использовать.

## Спасибо

- [Mihomo](https://github.com/MetaCubeX/mihomo) — ядро
- [Chumpy](https://github.com/ChumpyXray/Chumpy) — клиент, от которого форкнулись
- [v2rayNG](https://github.com/2dust/v2rayNG) — парсеры ссылок (порт из его `fmt/`)
- [zxing](https://github.com/zxing/zxing) — QR-сканер
- [Material Symbols](https://fonts.google.com/material) — иконки
- [Twemoji](https://github.com/jdecked/twemoji) — флаги (CC-BY 4.0)

## Лицензия

GPL-3.0 — см. [LICENSE](LICENSE). Форк линкует ядро Mihomo под GPL-3.0; оригинальный
Chumpy был под MIT, его уведомление сохранено в [NOTICE](NOTICE).
