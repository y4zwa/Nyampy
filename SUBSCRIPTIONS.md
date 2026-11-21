# Интеграция подписок с Nyampy

## Открытие подписки по ссылке

Nyampy поддерживает одну команду своей схемы:

```text
nyampy://add/https://sub.example.com/example-token?format=xray
```

После `nyampy://add/` вставьте полный HTTP(S)-адрес подписки. Параметры после `?` сохраняются. Целиком кодировать вложенный URL не нужно. Nyampy покажет окно подтверждения, а затем запросит подписку.

Для сайта можно использовать обычную ссылку. В HTML экранируйте амперсанды в параметрах как `&amp;`.

```html
<a href="nyampy://add/https://sub.example.com/example-token?format=xray&amp;lang=ru">
  Открыть в Nyampy
</a>
```

В Remnawave тип кнопки — `subscriptionLink`, значение — `nyampy://add/{{SUBSCRIPTION_LINK}}` (старый `nyampy://add/...` тоже работает).

## Что Nyampy отправляет серверу

Nyampy запрашивает подписку методом `GET`. Обычный User-Agent:

```text
Nyampy/1.0 (Android) v2rayNG/1.10
```

При включённой совместимости с Happ формат меняется:

```text
Happ/<версия Happ>/<платформа>/Nyampy/<версия приложения>/<идентификатор клиента>
```

В этом режиме также передаются `x-device-locale`, `x-hwid`, `x-device-os`, `x-ver-os` и `x-device-model`. Для правила, которое должно совпадать с обоими режимами, проверяйте, что User-Agent содержит `Nyampy/`.

## Какие заголовки читает Nyampy

| Заголовок ответа | Значение |
| --- | --- |
| `profile-title` | Название подписки. Обычный текст, URL-кодированный текст или `base64:<UTF-8 в Base64>`. |
| `content-disposition` | Имя файла используется как запасное название, если `profile-title` не задан. |
| `subscription-userinfo` | Трафик в байтах и срок действия в секундах Unix. Например, `upload=0; download=12345; total=1073741824; expire=1893456000`. |
| `profile-update-interval` | Интервал автообновления в часах, если оно включено. |
| `profile-logo` | URL иконки подписки. |
| `profile-web-page-url` | HTTP(S)-ссылка на сайт подписки. |
| `support-url` | HTTP(S)-ссылка на поддержку. |
| `announce` | Текст объявления в карточке подписки. Допускается `base64:<UTF-8 в Base64>`. Для кириллицы в HTTP-заголовке используйте Base64. |
| `routing` | Из формата Happ Nyampy сохраняет ссылки на базы `Geoipurl` и `Geositeurl`, но не скачивает их: правила маршрутизации приходят в теле подписки, а geodata лежит внутри APK. Заголовок необязателен. |

Те же поля, кроме `content-disposition`, можно передать строками в теле подписки. Это работает и для списка, целиком закодированного в Base64. Непустой HTTP-заголовок имеет приоритет над одноимённой строкой тела.

```text
#profile-title: Example VPN
#profile-logo: https://cdn.example.com/logo.png
#support-url: https://t.me/example_support
#announce: Тарифы и продление — в личном кабинете.
```

После этих строк разместите обычные ссылки на серверы.

## Иконка подписки в клиенте (`profile-logo`)

Передайте URL изображения в заголовке ответа сервера подписки:

```http
profile-logo: https://cdn.example.com/logo.png
```

Nyampy скачивает и кеширует иконку при добавлении или обновлении подписки. Подойдут PNG и SVG до 2 МиБ по обычному HTTP(S)-адресу. В значении должен быть URL, по которому сервер отдаёт саму картинку.

Если поле отсутствует или значение не подходит, отображается стандартная иконка. Если загрузка по корректному адресу временно не удалась, Nyampy сохраняет предыдущую иконку, если она есть.

### Remnawave для всех клиентов

Откройте **Подписка → Настройки → Заголовки ответа** и добавьте пару `profile-logo` и `https://cdn.example.com/logo.png`. В JSON эта настройка выглядит так:

```json
{
  "profile-logo": "https://cdn.example.com/logo.png"
}
```

### Только для Nyampy

В разделе **Подписка → Правила ответов** добавьте `profile-logo` в правило, которое обслуживает Nyampy. Если создаёте отдельное правило, поставьте его выше общего правила и выберите тот же формат ответа, который уже получает клиент. В примере ниже используется `XRAY_BASE64`. Remnawave останавливается на первом совпавшем правиле. [Документация правил ответов](https://docs.rw/learn-en/routing-rules/)

```json
{
  "name": "Nyampy icon",
  "enabled": true,
  "operator": "AND",
  "conditions": [
    {
      "headerName": "user-agent",
      "operator": "CONTAINS",
      "value": "Nyampy/",
      "caseSensitive": false
    }
  ],
  "responseType": "XRAY_BASE64",
  "responseModifications": {
    "applyHeadersToEnd": true,
    "headers": [
      { "key": "profile-logo", "value": "https://cdn.example.com/logo.png" }
    ]
  }
}
```

### Разные иконки для внешних сквадов

Откройте **Users → External Squads**, выберите сквад и добавьте `profile-logo` в его заголовки ответа. Для каждого сквада можно указать свой URL. Если правило ответа задаёт этот же заголовок с `applyHeadersToEnd: true`, оно может переопределить значение сквада. [Документация внешних сквадов](https://github.com/remnawave/panel/blob/main/_panel-docs/help-articles/en/PAGE_EXTERNAL_SQUADS.md)

### Через API Remnawave

Получите UUID настроек и текущие заголовки запросом `GET /api/subscription-settings`. Используйте API-токен панели в переменной `REMNA_TOKEN`.

```bash
curl -fsS 'https://panel.example.com/api/subscription-settings' \
  -H "Authorization: Bearer ${REMNA_TOKEN}"
```

Передайте в `customResponseHeaders` все заголовки, которые хотите сохранить, вместе с новым `profile-logo`. В примере ниже он единственный.

```bash
curl -fsS -X PATCH 'https://panel.example.com/api/subscription-settings' \
  -H "Authorization: Bearer ${REMNA_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{
    "uuid": "<settings-uuid>",
    "customResponseHeaders": {
      "profile-logo": "https://cdn.example.com/logo.png"
    }
  }'
```

### Проверка

Выполните обычный `GET` с User-Agent Nyampy. Команда выводит заголовки, а тело подписки отбрасывает.

```bash
curl -fsSL -D - -o /dev/null \
  -A 'Nyampy/1.0 (Android) v2rayNG/1.10' \
  'https://sub.example.com/example-token' | grep -i '^profile-logo:'
```

Если сервер вернул `profile-logo: https://…`, обновите подписку в Nyampy и проверьте иконку на карточке.
