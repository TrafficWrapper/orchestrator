# Контракт воркер ↔ оркестратор

Здесь описан сетевой контракт между агентом воркера
(`TrafficWrapper/worker`) и оркестратором в том виде, в каком он реализован в
этом репозитории. Источник истины — код: если страница и код расходятся,
прав код, а расхождение на странице считается ошибкой.

English version: [CONTRACT.md](CONTRACT.md).

## Правила совместимости

- Воркеры и оркестратор обновляются независимо и в любом порядке.
- Все поля, добавленные после первого релиза, необязательны. Отсутствие
  поля означает прежнее поведение, неизвестное поле игнорируется. Ни одна
  сторона не отвергает payload из-за незнакомых полей (строгого разбора на
  межкомпонентных payload нет).
- Более новый формат используется только после того, как партнёр его
  объявил: воркер — через capabilities (`self_describe.capabilities`,
  `worker_capabilities`), оркестратор — через `orchestrator_capabilities`,
  а для чанков APK — самим наличием `update_ref`.
- Тексты ошибок, по которым ориентируются старые воркеры, не меняются;
  рядом с ними добавляется структурированное поле `code`.

## Транспорт

Все вызовы `/w/v1/*`, кроме `handshake/start`, — сообщения Noise_XK поверх
HTTPS. Воркер пинит статический Noise-ключ оркестратора; оркестратор
узнаёт воркера по статическому ключу рукопожатия и на каждом вызове сверяет
его с записью воркера (иначе `worker identity mismatch`).

| Эндпоинт | Назначение |
| --- | --- |
| `POST /w/v1/handshake/start` | Начало рукопожатия Noise. Может нести `cookie` (см. ниже). |
| `/w/v1/enroll` | Однократная регистрация по токену. |
| `/w/v1/config/pull` | Получение подписанных бандлов воркера и клиента, APK и discovery-фида. |
| `/w/v1/nudge/wait` | Long poll (до ~25 с) нового desired seq; заодно heartbeat. |
| `/w/v1/ack` | Отчёт о применённом seq, self-check, трафике и self_describe. |
| `/w/v1/telemetry` | Пересылка одного подписанного события телеметрии устройства. |
| `/w/v1/apk/chunk` | Чтение одного диапазона текущего APK (см. ниже). |

После любого аутентифицированного вызова `/w/` одобренный воркер получает
`cookie` в открытом конверте ответа (`v1.<worker_id>.<expiry_unix>.<mac>`,
действует час). Если прислать его в теле следующего `handshake/start`,
рукопожатие пойдёт в резерв, выделенный для воркеров. Cookie не
аутентифицирует.

## Время платформы: `server_time`

Noise-ответы enroll, pull, nudge, ack, telemetry и apk/chunk (включая отказы)
несут `server_time` — часы оркестратора в Unix-миллисекундах. Воркер может держать смещение
относительно `server_time` для решений о свежести; без поля он живёт по своим
часам.

## self_describe

`self_describe` приходит в enroll, nudge и ack. Это недоверенный ввод:
оркестратор санитизирует его один раз при приёме и хранит только очищенную
копию.

Разрешённые ключи верхнего уровня:

`schema` (строка), `hostname`, `egress_ip`, `orch_url`, `agent_url`,
`distributor_url`, `standalone` (bool), `dialect_id`, `capacity` (число),
`protocols` ([]string), `reality`, `reality_profiles`, `awg`, `awg_profiles`,
`health`, `orchestrator`, `distributed_apk`, `capabilities` ([]string).

- Неизвестные ключи отбрасываются без отказа воркеру. `priority`, `weight`,
  `label` и `region` — настройки оператора, от воркера они не принимаются.
- Строки — не длиннее 256 байт, списки профилей — не больше 32 элементов,
  весь объект — не больше 64 KiB (больший отчёт игнорируется, действует
  предыдущий).
- Публичные ключи REALITY — 32 байта в base64 (RawURL или с паддингом),
  ключи AWG — 32 байта в стандартном base64, порты 1..65535, адрес — имя
  хоста или IP. `egress_ip`, если задан, должен быть IP. Некорректное поле
  сохраняется и попадает в отчёт (`self_describe_issues` в админке), а не
  молча выкидывает маршрут. Неожиданный хост или схема `distributor_url`
  только отмечается в отчёте.
- В `reality` может быть `address_v6`. `fingerprint` в `reality`
  принимается, но для клиентских маршрутов оркестратор применяет свою
  политику fingerprint.
- `distributed_apk` = `{apk_sha256, version_code, version_name, apk_name,
  seq?}` — APK, который воркер раздаёт сейчас.
- Ключ, похожий на секрет (`private_key`, `privatekey`, `psk2`,
  `internal_ip`, `internalip`, `server_private_key`), на любой глубине
  вырезается, а воркер исключается из клиентских бандлов и discovery, пока
  не пришлёт чистое описание. Остальные воркеры не затрагиваются.

## Capabilities

Известные значения capabilities воркера:

| Значение | Смысл |
| --- | --- |
| `reality_flow` | Воркер настраивает REALITY flow (Vision) для каждого устройства. |
| `desired_state_enabled` | Воркер соблюдает `desired_state.*.enabled` и пустой список устройств. |
| `revoked_status` | Воркер понимает отказ `revoked`; отзыв однофазный. |
| `apk_fetch_v1` | Воркер забирает APK через `update_ref` и `/w/v1/apk/chunk`. |

Они передаются в двух местах:

- `self_describe.capabilities` хранится вместе с очищенным self_describe
  (не больше 32 значений до 64 байт). Описывает воркера по последнему
  отчёту и используется, когда значения из запроса нет.
- `worker_capabilities` в запросе pull (необязательное) — то, что умеет
  запущенный бинарь. Решения для этого pull (например, `update_ref` вместо
  inline `update`, однофазный отзыв) принимаются по нему, если оно есть.
  Оркестратор хранит последнее значение в записи воркера, оставив только
  известные значения из таблицы (обрезка пробелов, без дублей, не больше 32
  входных значений до 64 байт), и показывает его в списке воркеров админки
  как `pull_capabilities` рядом с `capabilities`. Запись перезаписывается
  только при изменении значения; pull без поля его очищает.

Неизвестные значения везде игнорируются. Воркер без capabilities получает
поведение первого релиза.

### `orchestrator_capabilities`

Ответы pull, nudge и ack несут `orchestrator_capabilities` ([]string).
Текущее значение:

- `usage_source_awg_v1`: в `ack.usage[]` можно указывать `source: "awg"`
  вместе с `device_id`. Без него воркер обязан слать AWG-трафик без `source`,
  по `awg_public_key`.

Поддержка чанков APK здесь не объявляется: её признак — `update_ref` в
ответе pull. Отсутствие поля означает «ничего нового».

## Статусы воркера и отказы

`status` — одно из `pending`, `approved`, `active`, `inactive`, `revoked`.
`revoked` — терминальный. `disabled` — отдельный флаг оператора, не статус.

Любой отказ — `{ok: false, error, ...}`; `code` (строка) необязателен и
добавляется там, где указано ниже. Тексты `error` стабильны.

| Ситуация | Ответ |
| --- | --- |
| pending-воркер, pull | `{ok:false, status:"pending", error:"owner approval required"}` |
| pending-воркер, nudge / ack / telemetry / apk chunk | `{ok:false, status:"pending", error:"owner approval required", code:"worker_pending"}` |
| отозванный воркер | `{ok:false, status:"revoked", error:"worker revoked", code:"worker_revoked"}` |
| enroll с отозванным статическим ключом | как для отозванного, отказ до траты токена |

Отзыв:

- Воркер с `revoked_status` получает отказ сразу.
- Остальные сначала получают подписанный бандл воркера со всеми
  протоколами выключенными, `approved_devices: []` и новым seq. После ack
  этого seq или через 10 минут все вызовы получают отказ `worker_revoked`.

Отключённый (disabled) воркер продолжает делать pull. В его бандле
`reality.enabled=false`, `awg.enabled=false` и `approved_devices: []`; его
трафик и телеметрия принимаются, но не учитываются.

### Коды телеметрии

`/w/v1/telemetry` принимает `{worker_id, payload_base64, headers,
received_at}` и отвечает `{ok}` или отказом. Коды отказа: `stale_timestamp`,
`replay`, `bad_signature`, `unknown_device`, `device_not_approved`,
`invalid_payload`, `worker_revoked`, `worker_pending`. Текст
`device is not approved` сохранён для старых воркеров. `received_at` —
только диагностика; время события оркестратор берёт по своим часам.

## Бандл воркера: `desired_state`

Бандл воркера (`schema: 1`, `ns: "worker-config-v1"`) подписан minisign
по точной строке `config_json`. Поля: `schema`, `ns`, `seq` (desired seq
воркера), `worker_id`, `issued_at`, `desired_state`.

`desired_state`:

- `reality.enabled`, `awg.enabled` (bool) — обслуживает ли протокол
  устройства. false для отключённых и отозванных воркеров и для протоколов,
  выключенных оператором. Отсутствие значения означает `true`.
- `reality.public`, `awg.public` — собственный раздел воркера из его отчёта.
- `approved_devices` ([]object) — устройства, которые воркер обязан
  обслуживать: `device_id`, `reality_uuid`, `awg_public_key`,
  `internal_ip`, `psk2`, `status` и, если заданы, `awg_profiles`,
  `reality_flow`, `limits`, `expires_at`. Пустой список — корректный ввод
  (отключён, отозван или устройств нет), и при валидной подписи его нельзя
  считать сбоем синхронизации.
- `revoked_short_ids` ([]string) — REALITY short ID, которые больше не
  принимаются.
- `egress_policy` (сейчас всегда `direct`) и `client_artifacts` (пути
  публикуемых клиентских файлов).

Воркеру следует проверять, что `worker_id` равен его ID, а `schema` — 1.

Ответ pull также несёт `desired_seq`, `not_modified` (если `have_seq`
актуален) и `client_bundle` — общий подписанный бандл `client-config-v1`,
который воркер публикует клиентам. Его `seq` никогда не уменьшается; воркер
применяет его, если seq не меньше последнего применённого.

## ack

Запрос `/w/v1/ack`: `worker_id`, `applied_version`, `self_check`,
`egress_ip_observed`, необязательные `self_describe`, `usage[]` и
`client_applied_seq`.

- `usage[]` = `{device_id, awg_public_key, source?, rx_bytes, tx_bytes}` с
  кумулятивными счётчиками. Первый отчёт по ключу — базовая линия;
  уменьшение — новая базовая линия без начисления. `source` — `reality` или
  `awg` (`awg` только после `usage_source_awg_v1`). За один ack учитывается
  не больше 32768 отчётов.
- `client_applied_seq` учитывается только в ограниченном окне над счётчиком
  оркестратора.

Ответ: `ok`, `desired_seq`, `applied_seq`, `egress_ip_probe`,
`egress_match`, `quota_blocks`, `orchestrator_capabilities`, `server_time`.

### `egress_ip_seen`

Оркестратор запоминает адрес источника каждого аутентифицированного ack как
`egress_ip_seen` и сравнивает с ним заявленный воркером egress (или со своей
пробой, если источник — не публичный адрес). Результат — `match`,
`mismatch` или `n/a`; в админ-API это `egress_seen` / `egress_check`, а
`egress_match` в ответе ack равен false только при `mismatch`. Воркеру для
этого ничего слать не нужно; расхождение даёт алерт оператору и не меняет
клиентские маршруты.

## Доставка APK

### `update_ref`

Если есть новый релиз и `worker_capabilities` этого pull содержит
`apk_fetch_v1`, ответ pull несёт `update_ref` вместо inline `update`:

```
update_ref = {
  apk_seq int64, apk_name string, apk_sha256 string (64 hex, нижний регистр),
  apk_size int64, manifest_json string, manifest_minisig string
}
```

Воркеры без этой capability получают inline `update` (`manifest_json`,
`manifest_minisig`, `apk_name`, `apk_sha256`, `apk_base64`), только пока APK
укладывается в `ORCH_APK_INLINE_MAX_BYTES` (по умолчанию 40 MiB, максимум
64 MiB). Иначе поля нет и доставляется только конфиг. Воркер, который после
inline-отправки снова и снова приходит с тем же `have_seq`, перестаёт
получать APK на растущий интервал.

Релиз считается применённым, если `distributed_apk.seq` и
`distributed_apk.apk_sha256` совпадают с ним, а для воркеров без seq — по
подтверждённому ack seq того pull, который его вёз.

### `/w/v1/apk/chunk`

Запрос: `{worker_id, apk_seq, apk_sha256, offset, length}`, где
`0 ≤ offset < apk_size` и `0 < length ≤ 4 MiB`.

Ответ: `{ok, code?, error?, total_size, data_base64}`.

| Код | Смысл |
| --- | --- |
| `release_superseded` | sha256 больше не совпадает с текущим релизом (или seq новее него). Начать заново со следующего pull. Переподписанный манифест того же APK загрузку не прерывает. |
| `bad_range` | offset или length вне допустимого; возвращается `total_size`. |
| `worker_revoked`, `worker_pending` | как выше. |

Воркер пишет чанки во временный файл, проверяет sha256, переименовывает файл
на место и только потом пишет манифест. Если такой sha256 уже опубликован,
он заменяет только манифест и подпись.

## `discovery_bundle`

Ответы pull несут `discovery_bundle = {endpoints_json,
endpoints_json_minisig}`, если оркестратор может его собрать: тот же
подписанный discovery-фид (rendezvous-v1), что публикует оркестратор, одно
подписанное содержимое на один discovery seq. Воркер раздаёт его без
изменений как `/tw/endpoints.json` и `/tw/endpoints.json.minisig`. Воркеры
получают новый seq конфига при смене seq фида и до истечения половины его
срока жизни. Воркеры получают ровно фид настроенного режима
`ORCH_DISCOVERY_PUBLIC` (по умолчанию `reduced`: только AWG-записи и пустой
`endpoints.reality`); в режиме `off` публичный эндпоинт оркестратора ничего
не отдаёт, и фид публикуют только воркеры.
