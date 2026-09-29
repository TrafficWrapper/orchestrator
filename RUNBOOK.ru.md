# Runbook владельца

🇬🇧 English: [RUNBOOK.md](RUNBOOK.md)

Этот runbook описывает owner operations. В tickets и notes используйте
placeholders; никогда не публикуйте реальные keys, tokens, domains, IP
addresses, bootstrap payloads или state files.

## Корни доверия

TrafficWrapper разделяет четыре trust roots:

1. config-signing minisign key;
2. update minisign key;
3. Android APK signing certificate;
4. orchestrator Noise static key.

Бэкапьте каждый root отдельно. Храните private material offline или в
owner-controlled secret storage. Не коммитьте `.env`, `orch-state/`,
`worker-state/`, release keystores или minisign private keys.

## Переход на изолированный signer

Релизы, где `docker-compose.yml` использует `./signer-state`, при первом старте
signer автоматически переносят config-signing key из `./orch-state`
(`ORCH_SIGNER_LEGACY_KEY_PATH`); публичный ключ, закреплённый у workers и
клиентов, не меняется. Перед обновлением сделайте бэкап `./orch-state`. После
первого старта проверьте, что `./signer-state/orch-config.key` есть, а
`./orch-state/orch-config.key` удалён, и добавьте `./signer-state` в бэкапы.
Если signer не стартует, потому что ключи есть в обоих местах и различаются,
оставьте тот, чей public key совпадает с развёрнутыми конфигами. Контейнеры
теперь работают от uid `10001`; entrypoint сам меняет владельца state-каталогов,
но seed APK в `./seed` должен быть доступен на чтение всем.

Проверка legacy-ключа одноразовая. После успешного переноса, а также если
legacy-ключа не было, signer пишет маркер
`./signer-state/orch-config.key.legacy-migrated` и дальше `./orch-state` не
читает и не меняет: файл, появившийся там позже, только логируется
(`signer=legacy_key_ignored`) и не мешает старту. Пока маркера нет, расхождение
ключей по-прежнему останавливает signer — это решение за оператором.
`docker-compose.yml` монтирует `./orch-state` в signer на запись только ради
этого переноса и оставлен без изменений, чтобы обновление со старых релизов
работало. Когда маркер уже есть, монтирование `./orch-state:/orch-state` у
сервиса `signer` можно сделать `:ro` или убрать вместе с
`ORCH_SIGNER_LEGACY_KEY_PATH`: при наличии маркера entrypoint не меняет
владельца каталога legacy-ключа. Без маркера оставляйте монтирование на
запись — перенос удаляет legacy-копию.

## Более строгий разбор конфигурации

`serve` больше не стартует при неверных значениях окружения и перечисляет их
все в логе (`invalid configuration: ...`). `ORCH_TLS` принимает `1/0`,
`true/false`, `yes/no`, `on/off`: раньше любое значение кроме `0` оставляло TLS
включённым, поэтому старое `ORCH_TLS=false` теперь действительно выключает
встроенный TLS (предупреждение при loopback `ORCH_LISTEN`, иначе `ERROR`; см.
«Plain HTTP на публичном адресе»). `ORCH_PUBLIC_URL` должен быть
абсолютным http(s) URL. Ошибки admin API теперь JSON
`{"ok":false,"error":"..."}`, отсутствующий worker или device даёт 404, а
неверный метод — 405 до проверки авторизации.

## Plain HTTP на публичном адресе

При `ORCH_TLS=0` оркестратор отдаёт plain HTTP. Это штатная схема за
TLS-прокси на том же хосте с `ORCH_LISTEN=127.0.0.1:9091` (только
предупреждение при старте). Если `ORCH_LISTEN` — любой другой адрес
(default `:9091` слушает все интерфейсы), при старте в логе
`ERROR: built-in TLS is disabled ... on non-loopback listen address`, в
админке красный баннер, а `/admin/v1/status` начинается со строки
`warning=plaintext_public_listener`. Оркестратор при этом стартует, чтобы не
ломать развёртывания, где прокси уже стоит. Исправление: `ORCH_TLS=1` или
перенос listener на loopback за прокси. `ORCH_TLS_STRICT=1` превращает этот
случай в ошибку старта; включите его после настройки прокси, чтобы
последующая правка конфига не открыла plain HTTP незаметно.

## Web UI и журнал аудита

Вход в web UI — `/login`; без сессии `/` отвечает 404, как любой неизвестный
путь, а страницы без аутентификации не называют продукт. Пути admin API не
изменились. Страницы админки работают под Content-Security-Policy с nonce,
все ответы — `Cache-Control: no-store`.

`audit.log` в каталоге состояния ротируется по `ORCH_AUDIT_MAX_BYTES`
(64 MiB), хранятся `ORCH_AUDIT_KEEP` (5) старых файлов `audit.log.1` ...;
каждый новый файл начинается с записи `audit_log_rotated`, продолжающей
hash-цепочку, а проверка при старте идёт по всем хранимым файлам и сообщает
все разрывы. Запросы во время блокировки логина пишутся раз в минуту на
адрес, затем итоговая запись со счётчиком `repeats`. Если нужна более
длинная история, сохраняйте ротированные файлы в бэкап до их удаления.

## Обновление формата зашифрованных записей

Начиная с релиза, который привязывает зашифрованные записи к их ключам, при
первом старте все зашифрованные записи в `orchestrator.db` перезаписываются в
новый формат (в логе `store: bound N legacy sealed records`). Старые бинарники
новый формат не читают, поэтому перед обновлением сделайте бэкап
`./orch-state`; откат возможен только восстановлением этого бэкапа.

Мастер-ключ (`orch-state/master.key`) и база данных неразделимы:

- Если `master.key` отсутствует, а в базе есть зашифрованные записи,
  orchestrator не стартует и не создаёт новый ключ. Восстановите ключ из того
  же бэкапа, что и базу. `ORCH_ALLOW_NEW_MASTER_KEY=1` запускает с новым
  ключом, и все существующие зашифрованные записи становятся нечитаемыми.
- Если `master.key` не расшифровывает базу (не тот бэкап), старт падает.
  `ORCH_STORE_ALLOW_UNREADABLE=1` запускает всё равно, не запечатывая формат,
  чтобы правильный ключ можно было вернуть позже.
- Если старый бинарник уже запечатал формат с неверным ключом, остановите
  orchestrator, верните правильный `master.key`, выполните
  `orchestrator store-clear-sealed-marker` и запустите снова: legacy-записи
  будут мигрированы правильным ключом.

## Ротация config-signing key

Config-signing key хранится signer process и доступен через
`ORCH_SIGNER_SOCKET`.

Процедура:

1. Остановите config publication и не approve'ьте новых workers/devices во время
   rotation window.
2. Сделайте backup текущего orchestrator state.
3. Сгенерируйте или установите новый signer key в signer state location.
   При остановленном orchestrator выполните `orchestrator signer-accept-key`,
   чтобы он закрепил новый ключ, а не отверг его.
4. Перезапустите `signer` и `orchestrator`.
5. Опубликуйте свежие `worker-config-v1` и `client-config-v1`.
6. Re-issue client config/bootstrap material, чтобы devices pin'или новый config
   public key.
7. Храните старый backup, пока все ожидаемые devices не подтверждены migrated.

Impact: devices, pin'ящие старый config public key, отклонят config, подписанный
новым key, пока не будут re-enrolled или иначе не получат новый trusted pin.

## Ротация update minisign key

Update key подписывает APK update manifests. Предпочтителен offline
owner-controlled key.

Процедура:

1. Сгенерируйте новый update minisign keypair offline.
2. Храните private key вне repository и по возможности вне public servers.
3. Обновите orchestrator/bootstrap update public key для новых enrollments.
4. Опубликуйте transition app/config plan для existing devices.
5. Подписывайте future manifests новым private key только после того, как
   clients доверяют новому public key.

Impact: devices отклоняют update manifests, подписанные key, который не
соответствует их pinned update public key.

## Ротация APK signing certificate

Android APK signing certificate привязан к Android package lineage.

Процедура:

1. Создайте новый release keystore offline.
2. Соберите новую APK lineage намеренно.
3. Публикуйте её как new install path, а не как seamless in-place update со
   старого certificate.
4. Сообщите, что users должны установить новую APK lineage и re-bootstrap при
   необходимости.

Impact: Android не будет считать APK, подписанный другим certificate, обычным
update для существующего package. Планируйте reinstall или separate package
lineage.

## Ротация orchestrator Noise static key

Workers pin'ят `ORCH_STATIC_PUBLIC_KEY`; device bootstrap payloads pin'ят
`orch_noise_public`.

Процедура:

1. Запланируйте downtime или maintenance window.
2. Сделайте backup orchestrator state.
3. Сгенерируйте новый orchestrator Noise static key.
4. Перезапустите orchestrator services.
5. Обновите `ORCH_STATIC_PUBLIC_KEY` на каждом worker.
6. Re-bootstrap devices, чтобы они получили новый `orch_noise_public`.

Impact: старые workers и devices отклонят orchestrator, пока их pins не
обновлены.

## Seq клиентского конфига после restore или отката

Seq клиентского бандла — персистентный счётчик в хранилище, он не выводится
из seq воркеров. Приложения отвергают seq ниже уже виденного, поэтому он
никогда не должен уменьшаться:

- Первый старт после обновления ставит его в максимальный seq воркера +
  1000000 (или `ORCH_CLIENT_SEQ_FLOOR`, если он выше).
- Каждая публикация поднимает seq конфига каждого обслуживающего воркера не
  ниже счётчика. Поэтому откаченный бинарь (который выводит client seq из seq
  воркеров) всё равно не опубликует seq ниже виденного клиентами.
- После восстановления старой БД воркеры, сообщающие более высокий
  применённый client seq (в пределах 10000), сами сдвигают счётчик вперёд.
  Для большего разрыва поднимите его явно, со step-up:
  `POST /admin/v1/client-seq/floor {"floor": N, "current_secret": ..., "totp_code": ...}`
  (или задайте `ORCH_CLIENT_SEQ_FLOOR` перед первым стартом на восстановленной
  БД).
- Воркеры, у которых после restore seq конфига опережает оркестратор,
  автоматически сдвигаются дальше на следующем pull, nudge или ack.

## Открытость discovery-фида

`ORCH_DISCOVERY_PUBLIC` управляет неаутентифицированным discovery-фидом
(`/discovery/endpoints.json`):

- `reduced` (по умолчанию): только AWG-записи (`priority`, `endpoint`,
  `server_public_key`, `awg_preset`, `egress_ip`, `worker_id`); `reality` —
  пустой список, ключи REALITY и short ID не публикуются.
- `off`: публичный эндпоинт отвечает 404. Клиенты по-прежнему получают фид
  через туннель: воркеры получают его в каждом pull (`discovery_bundle`) и
  раздают как `/tw/endpoints.json`. Включать `off` только после того, как этот
  файл раздают все воркеры.
- `full`: прежний формат с REALITY-записями, только по явному выбору.

Полностью перечисление инфраструктуры закрывает только `off`. До него
остаточный риск `reduced` принят: AWG endpoint, `awg_preset` и priority
остаются публичными, потому что старым app нужна полная AWG-запись. Фид
переотправляется воркерам при каждой смене seq и не реже раза в 5 часов, задолго
до 12-часового `expires_at`.

## Политика signer и discovery-ключ

Signer подписывает config-ключом только документы `client-config-v1` и
`worker-config-v1`, а отдельным discovery-ключом (`discovery.key` рядом с
config-ключом) — только фиды `rendezvous-v1`. Для каждого потока (client
config, конфиг каждого воркера, discovery-фид) seq может вырасти не больше чем
на 10 000 000 относительно наибольшего подписанного; эти значения хранятся в
`sign-policy.json` рядом с ключами. Одноразовый миграционный скачок client seq
в этот шаг укладывается. Поднимать floor client seq больше чем на шаг — в
несколько приёмов.

Чтобы перевести discovery с update-ключа, задайте `ORCH_DISCOVERY_SIGNER=1` и
перезапустите. Client bundle объявляет новый `discovery_pubkey`, и фид
подписывается им в том же изменении, поэтому app, получившие новый бандл,
принимают фид. App, которые до этого офлайн, отвергают новые фиды, пока не
получат бандл; делайте это только после внедрения монотонного client seq,
плановым действием оператора.
## Ротация TLS-сертификата оркестратора

QR-коды bootstrap несут `orch_tls_spki_sha256` — SHA-256 открытого ключа
сертификата; app проверяет его только при первичном enrollment в пределах
срока токена. Re-enroll установленных app это не затрагивает. Чтобы ротация
не сломала выданные QR, либо продлевайте сертификат с тем же ключом
(`certbot renew --reuse-key` или аналог), либо заранее добавьте пин
следующего ключа как резервный в `ORCH_PUBLIC_TLS_SPKI_SHA256` и дождитесь
истечения старых токенов.

Self-signed сертификат, который создаёт `ORCH_TLS=1`, теперь использует
нейтральное имя `localhost` (при старте пишется предупреждение, что он
self-signed). Сертификаты прежних релизов содержали имя продукта; они
остаются как есть, а при старте пишется предупреждение со ссылкой сюда.
Чтобы заменить такой сертификат, выполните шаги выше для его пина, затем
остановите оркестратор, удалите `tls.crt` и `tls.key` из каталога состояния и
запустите снова.

## Компрометация worker

1. Отзовите worker: `POST /admin/v1/workers/revoke {"id": ..., "current_secret": ..., "totp_code": ...}`
   (step-up: текущий admin secret, код TOTP при включённом 2FA и
   подтверждение владельца в Telegram, если бот настроен). Отзыв
   окончательный: ключ получает отказ на всех вызовах и не может заново
   пройти enroll даже с новым токеном. Переустановленный worker приходит с
   новым ключом.
2. Что видит worker. Worker с capability `revoked_status` получает отказ
   сразу (`code: worker_revoked`). Старый worker сначала получает ещё один
   подписанный конфиг со всеми выключенными протоколами и пустым списком
   устройств; его обычный путь применения удаляет все учётки. После ack этого
   конфига (или через 10 минут) он тоже получает отказ. Живые сессии на
   старом worker остаются до переподключения, а все REALITY UUID, которые он
   обслуживал, ему известны.
3. Ротируйте затронутый per-device transport material: заново проведите
   enroll устройств этого worker, чтобы сменились REALITY UUID и учётки AWG.
4. Уберите worker из seed workers.
5. Сохраните logs/state приватно для incident analysis.

Отключение (вместо отзыва) обратимо: отключённый worker продолжает pull, но
получает все протоколы выключенными и пустой список устройств, а новый
конфиг — только при включении или отключении. Учёт трафика и телеметрия от
него игнорируются. На старых worker отключение удаляет учётки, но уже
открытые сессии не рвёт.

Не подключайте devices к worker, которому вы операционно не доверяете.

## Смена admin password

Используйте admin UI или `/admin/v1/password/change`. Если running server
недоступен и вы работаете с local state, используйте documented safe CLI path
через stdin. Не кладите реальные passwords в committed files или public logs.

## Потерян signer key

Если config signer private key потерян:

1. Восстановите его из private backup, если он есть. Signer никогда не
   заменяет потерянный ключ сам: если рядом с файлом ключа есть
   `<key>.initialized`, отсутствие ключа останавливает signer.
2. Если backup отсутствует, удалите `<key>.initialized`, чтобы signer создал
   новый config-signing key, затем остановите orchestrator и выполните
   `orchestrator signer-accept-key`: orchestrator закрепляет публичный ключ
   signer и отказывается подписывать другим, пока закрепление не снято.
3. Рассматривайте это как config key rotation.
4. Re-enroll или re-bootstrap devices, pin'ившие старый config public key.

Без старого key вы не сможете выпускать config, принимаемый clients, которые
доверяют только старому config public key.
