# nyampy-core

Минимальный [gomobile](https://pkg.go.dev/golang.org/x/mobile)-мост к ядру
[mihomo](https://github.com/MetaCubeX/mihomo), из которого собирается
`nyampycore.aar` для Android-клиента Nyampy.

Зачем отдельный проект: у mihomo нет готового AAR в релизах (только бинарники), а
Clash Meta for Android собирает своё ядро через собственный C/JNI-мост. Здесь — тонкая
обёртка только над теми вызовами, которые нужны клиенту.

## API (из Kotlin)

```kotlin
Nyampycore.setHome(dir)          // куда mihomo складывает geodata/cache
Nyampycore.setLogLevel("info")
Nyampycore.subscribe()           // начать собирать лог в кольцо
Nyampycore.configure(path)       // загрузить config.yaml
Nyampycore.startTun(fd, mtu, "gvisor", "172.19.0.1/30", "", "any")
Nyampycore.stopTun()
Nyampycore.upTotal()             // байты на отправку, кумулятивно
Nyampycore.downTotal()           // байты на приём, кумулятивно
Nyampycore.upNow()               // байты/с на отправку
Nyampycore.downNow()             // байты/с на приём
Nyampycore.resetStats()          // обнулить счётчики
Nyampycore.closeConnections()    // закрыть все трекаемые соединения
Nyampycore.logs()                // хвост лога ядра
Nyampycore.version()             // версия ядра
```

TUN-устройство создаёт сам `VpnService` (как и раньше); ядро только подхватывает fd.
Счётчики трафика — по всему туннелю, включая DIRECT: это «трафик туннеля», а не
только прокси.

## Сборка

Нужно: Go 1.27+, JDK 17, Android NDK r27+, `ANDROID_NDK_HOME`, `gomobile`.

```powershell
go install golang.org/x/mobile/cmd/gomobile@latest
go get -tool golang.org/x/mobile/cmd/gobind@latest
gomobile init
gomobile bind "-target=android/arm64,android/arm,android/amd64" `
  "-androidapi=26" "-tags=with_gvisor,cmfa" "-ldflags=-s -w" "-o=nyampycore.aar" "."
```

Оба тега обязательны. `with_gvisor` даёт sing_tun gvisor-стек. `cmfa` переключает
ядро на сокеты и пакеты, которые ему отдаёт `VpnService`; без него TUN пытается
прочитать `/data/system/packages.xml` для Android-правил и падает с
`permission denied` — туннель не поднимается.

Готовый `nyampycore.aar` кладётся в `../app/libs/` и заливается ассетом в релиз
`core` на GitHub; в git он не хранится, Gradle скачивает его при первой сборке.

## Лицензия

⚠️ mihomo распространяется под **GPL-3.0** (в теге v1.19.34 — GPL, ветка `main`
перелицензирована в MIT, но релизы собираются не с неё). AAR линкует mihomo, поэтому
приложение, которое его использует и распространяется, обязано быть GPL-3.0.
Для личного использования без распространения обязательств не возникает.
