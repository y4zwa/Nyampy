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

При первой сборке готовый AAR ядра скачивается из релиза `core` в `app/libs/`. Без
сети положи `nyampycore.aar` туда руками — если файл уже есть, Gradle ничего не качает.

## Спасибо

- [Mihomo](https://github.com/MetaCubeX/mihomo) — ядро
- [Chumpy](https://github.com/ChumpyXray/Chumpy) — клиент, от которого форкнулись
- [v2rayNG](https://github.com/2dust/v2rayNG) — парсеры ссылок (порт из его `fmt/`)
- [zxing](https://github.com/zxing/zxing) — QR-сканер
- [Material Symbols](https://fonts.google.com/material) — иконки
- [Twemoji](https://github.com/jdecked/twemoji) — флаги (CC-BY 4.0)

## Лицензия

GPL-3.0 — см. [LICENSE](LICENSE). Форк линкует ядро Mihomo под GPL-3.0; оригинальный
Chumpy был под MIT.
