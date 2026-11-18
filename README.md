<img src="icon.svg" width="96" alt="Nyampy" />

# Nyampy

Another Android client for VLESS and others — dressed in Material Design 3 Expressive,
running on the Mihomo core.

*Русская версия: [README.ru.md](README.ru.md)*

> **Alpha.** Still under development. If it hangs on you — and it might — please report
> it in the [Issues tab](https://github.com/y4zwa/Nyampy/issues).

## Requirements

Android 8.0 (API 26) or newer.

## Protocols

VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, WireGuard (AmneziaWG included),
Hysteria2.

XHTTP keeps the share link's `extra`, split download included: Xray's `downloadSettings`
is rewritten into the core's own flat `download-settings`. In `stream-one` mode the pair
is dropped — the core refuses it (`xhttp mode "stream-one" cannot be used with
download-settings`) and the whole server would fail to start.

## IPv6

The tunnel carries an IPv6 address and route, but the core runs with `ipv6: false` and
DNS with `dns.ipv6: false`: AAAA answers are never requested, so v6 traffic cannot
escape around the proxy. That is leak prevention, not v6 tunnelling — v6-only services
will not work.

Traffic counters cover the whole tunnel, DIRECT included.

## Building

```shell
./gradlew :app:assembleRelease
```

The first build downloads the prebuilt core AAR from the pinned `core-1.19.34-3`
GitHub release (sha256-checked) into `app/libs/`. Without network, put
`nyampycore.aar` there by hand — the digest still decides whether it may be used.

## Thanks to

- [Mihomo](https://github.com/MetaCubeX/mihomo) — the engine
- [Chumpy](https://github.com/ChumpyXray/Chumpy) — the client this forked from
- [v2rayNG](https://github.com/2dust/v2rayNG) — the share-link parsers, ported from its `fmt/`
- [zxing](https://github.com/zxing/zxing) — QR scanning
- [Material Symbols](https://fonts.google.com/material) — the icons
- [Twemoji](https://github.com/jdecked/twemoji) — the flags (CC-BY 4.0)

## License

GPL-3.0 - see [LICENSE](LICENSE). The fork links the Mihomo core, which is GPL-3.0;
upstream Chumpy was MIT, and its notice is kept in [NOTICE](NOTICE).
