<img src="icon.svg" width="72" align="right" alt="Nyampy">

# Nyampy

An Android client for the protocols supported by the mihomo core: VLESS, VMess, Trojan, Shadowsocks, WireGuard, Hysteria2 and others. The interface follows Material 3 Expressive. Colors can be taken from your wallpaper, there is a pure black theme for AMOLED screens, and you can choose your own accent color.

Requires Android 8.0 or newer. [Download the APK](https://github.com/y4zwa/Nyampy/releases/latest)

The app is still in alpha. If something doesn't work correctly, please report it in [issues](https://github.com/y4zwa/Nyampy/issues).

[Русский](README.ru.md)

## Features

**Server sources.** You can add servers from a subscription link, a Clash/mihomo YAML file (anchors and aliases are supported), a ready-made config, a file, or a QR code. A subscription is refreshed when you ask for it. Groups can be pinned, and servers you add manually are shown alongside them.

**WARP.** One tap creates a Cloudflare account and adds a group of WARP endpoints.

**Routing.** You can send all traffic through the tunnel, or have traffic to your own region go directly. Supported regions are RU, CN, IR, AF, ID, TR and BR. A separate list sets which apps bypass the tunnel.

**Latency and traffic.** Latency is measured the same way the core's `url-test` measures it. The counters include all tunnel traffic, DIRECT connections too.

**Switching without a reconnect.** Changing the server or the mode does not recreate the tunnel: the core receives the new config, and the TUN interface stays in place.

## Supported protocols

`VLESS` `VMess` `Trojan` `Shadowsocks` `SOCKS` `HTTP` `WireGuard` / `AmneziaWG` `Hysteria2` `TUIC` `AnyTLS` `Snell` `Mieru` `Sudoku` `ShadowQuic` `TrustTunnel` `Masque`

For XHTTP, the `extra` parameter from the link is kept, including split download. In `stream-one` mode the `download-settings` parameter is dropped: the core does not accept it, and it would prevent the whole server from starting.

## How the tunnel works

The tunnel is IPv4 only. The interface address is `172.19.0.1/30`, the core is set to `ipv6: false`, and DNS returns no AAAA records. This is done because, when a second address family was available, some apps concluded that there was no connection even though the browser kept working over IPv4.

DNS runs in fake-IP mode, and the core handles the queries.

## Building

You need JDK 17 and the Android SDK with `compileSdk 37`.

```
./gradlew :app:assembleRelease
```

The finished APKs, one for each architecture, will be in `app/build/outputs/apk/release/`.

On the first build, the core library (AAR) is downloaded from the `core-1.19.34-6` release and its sha256 checksum is verified. If you have no network access, place the `nyampycore.aar` file in `app/libs/` yourself. The checksum is still verified, and a file with a different checksum will not be accepted.

## Credits

- Core: [mihomo](https://github.com/MetaCubeX/mihomo)
- The project grew out of [Chumpy](https://github.com/ChumpyXray/Chumpy)
- Link parsing was ported from [v2rayNG](https://github.com/2dust/v2rayNG)
- QR code scanner: [zxing](https://github.com/zxing/zxing)
- Icons: [Material Symbols](https://fonts.google.com/material)
- Flags: [Twemoji](https://github.com/jdecked/twemoji) (CC-BY 4.0)

## License

GPL-3.0, see the [LICENSE](LICENSE) file. The app links against the mihomo core, which is distributed under GPL-3.0. The original Chumpy was under the MIT license, and its notice is kept in the [NOTICE](NOTICE) file.
