# TrafficWrapper Orchestrator

[![CI](https://github.com/TrafficWrapper/orchestrator/actions/workflows/ci.yml/badge.svg)](https://github.com/TrafficWrapper/orchestrator/actions/workflows/ci.yml)

[English](README.md)

TrafficWrapper — open-source self-hosted платформа private transport для
небольших operator deployments и transport-obfuscation research. Она
разделяет control plane, worker data plane и Android client, чтобы operator
владел deployment keys, worker endpoints, bootstrap payloads и update policy.

Этот репозиторий — control plane. Orchestrator approve'ит workers, enroll'ит
устройства, подписывает client-config, отдаёт web-админку владельца, хранит APK
update artifacts и опционально запускает owner-only Telegram-бота. Android app
не является Android VPN: она поднимает local SOCKS front-end и использует signed
deployment config для выбора user-space transports.

TrafficWrapper разделён на три репозитория:

- [orchestrator](https://github.com/TrafficWrapper/orchestrator) — control plane.
- [worker](https://github.com/TrafficWrapper/worker) — REALITY + AmneziaWG data plane nodes.
- [app](https://github.com/TrafficWrapper/app) — Android public client.

Обычный workflow: запустить orchestrator, подключить один или несколько workers,
затем собрать/установить app и импортировать bootstrap payload из orchestrator.

Архитектура и threat model описаны в [ARCHITECTURE.md](ARCHITECTURE.ru.md) и
[THREAT_MODEL.md](THREAT_MODEL.ru.md).

Операционные и contributor guides: [FAQ.ru.md](FAQ.ru.md),
[TROUBLESHOOTING.ru.md](TROUBLESHOOTING.ru.md) и [RUNBOOK.ru.md](RUNBOOK.ru.md).
Заметки по local development stand находятся в organization
[CONTRIBUTING.ru.md](https://github.com/TrafficWrapper/.github/blob/main/CONTRIBUTING.ru.md#local-development-stand).

## Форма проекта

Эта таблица — ориентир для operators, а не ranking. Другие проекты закрывают
другие deployment models и меняются со временем; перед operational choice
сверяйтесь с их upstream документацией.

| Проект | Модель | Transport / mimicry | Client mode | Key ownership | Update / config distribution | Reproducible build | License |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TrafficWrapper | Self-hosted control plane + worker data plane + Android client | REALITY и AmneziaWG routes из signed config | Local SOCKS front-end; не Android `VpnService` | Operator-owned config, update, APK, Noise и worker keys | Signed client config и APK artifacts раздаются через `/tw/` внутри туннеля | Документированная source build + `app/build/verify-release.sh` | MIT |
| Amnezia | Self-hosted VPN/client tooling | Varies by deployment; включает AmneziaWG-oriented workflows | Обычно VPN-style clients | Operator/server owner, зависит от setup | Varies | См. upstream | См. upstream |
| Marzban | Self-hosted proxy management panel | Varies; часто Xray-profile based | Зависит от external clients | Operator controls panel/server keys | Varies | См. upstream | См. upstream |
| 3x-ui / Hiddify | Self-hosted proxy panels | Varies by panel/profile | Зависит от external clients | Operator controls panel/server keys | Varies | См. upstream | См. upstream |
| Outline | Self-hosted access server + client ecosystem | Shadowsocks-oriented access model | Обычно VPN-style client apps | Operator controls server access keys | Varies | См. upstream | См. upstream |

## Quickstart (5 минут)

Это самый короткий путь к local development stand. Полный
[сквозной сценарий](#начните-здесь-сквозной-сценарий) ниже и organization
[Local development stand](https://github.com/TrafficWrapper/.github/blob/main/CONTRIBUTING.ru.md#local-development-stand)
объясняют каждый шаг и production differences.

1. Запустите orchestrator:

   ```sh
   git clone https://github.com/TrafficWrapper/orchestrator.git
   cd orchestrator
   cp .env.example .env
   docker compose up -d --build signer orchestrator
   docker compose logs orchestrator | grep -i 'initial admin password'
   docker compose exec -T orchestrator orchestrator public-key
   ```

2. Откройте `https://127.0.0.1:9091`, смените initial admin password и создайте
   worker enrollment token в admin UI.
3. Запустите worker из worker repository с
   `ORCH_URL=https://host.docker.internal:9091`,
   `ORCH_STATIC_PUBLIC_KEY=<public-key>`, `ENROLL_TOKEN=<token>`,
   `ORCH_INSECURE_TLS=1` для этого self-signed dev stand и реальным
   `CAMOUFLAGE_DOMAIN`.
4. Approve pending worker в admin UI.
5. Откройте **Устройства** -> **+ Новое устройство**, создайте one-time
   bootstrap, установите APK из app release channel или свою сборку,
   импортируйте bootstrap, подтвердите его и подключитесь.

## Начните здесь: сквозной сценарий

1. Запустите orchestrator через Docker Compose и откройте admin UI по
   `ORCH_PUBLIC_URL`.
2. Скопируйте public key orchestrator командой
   `docker compose exec orchestrator orchestrator public-key`, затем создайте
   worker enrollment token в admin UI или через `/admin/v1/token/create`.
3. Запустите worker с `ORCH_STATIC_PUBLIC_KEY=<orchestrator public-key>`,
   `ENROLL_TOKEN=<worker token>`, `ORCH_URL=<orchestrator URL>` и
   `ORCH_INSECURE_TLS=1` только для self-signed dev TLS. До запуска REALITY
   задайте реальный `CAMOUFLAGE_DOMAIN`.
4. Approve pending worker в admin UI orchestrator.
5. Откройте **Устройства** -> **+ Новое устройство** и создайте one-time device
   bootstrap payload. Сохраните QR, Base64 или JSON с этой страницы.
6. Установите Android APK из release channel репозитория app или свою
   подписанную сборку.
7. Импортируйте bootstrap payload в приложении и подтвердите распарсенные
   `orchestrator_url` и `config_pubkey_pin`.
8. Подключитесь. Приложение загрузит signed client config и автоматически
   выберет worker и route.

## Требования

- Linux host с Docker и Docker Compose.
- HTTPS URL, доступный устройствам и workers.
- Go 1.23+ только для локальной сборки вне Docker.
- Минимум для запуска: 1 CPU и 1 GB RAM. На серверах с 1 GB добавьте swap;
  сборки и pull Docker images стабильнее с 2 GB+ RAM.

Установка Docker на чистом host:

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"
```

## Быстрый старт

```sh
git clone https://github.com/TrafficWrapper/orchestrator.git
cd orchestrator
cp .env.example .env
docker compose up -d --build signer orchestrator
docker compose logs orchestrator | grep -i 'initial admin password'
docker compose exec orchestrator orchestrator public-key
```

Откройте web UI по `ORCH_PUBLIC_URL`, войдите с initial password из лога
контейнера и сразу смените пароль. Initial password хранится только как hash и
не создаёт полноценную admin session до смены.

Чтобы подключить телефон через web UI, сначала approve хотя бы один worker,
затем откройте **Устройства** -> **+ Новое устройство**. Страница создаёт
one-time bootstrap payload и показывает QR, Base64 и pretty JSON. В Android app
импортируйте его вставкой Base64-строки, открытием скачанного `.json` файла или
через Android «Поделиться» -> TrafficWrapper.

Для headless-настройки при запущенном server используйте HTTP admin API. Если
включён встроенный self-signed TLS, добавьте `-k` к `curl` или сначала поставьте
свой TLS-сертификат. Admin API принимает bearer session token; CSRF нужен только
для cookie-сессии браузера.

```sh
ORCH_URL=https://127.0.0.1:9091
INITIAL_PASSWORD='<password from docker compose logs orchestrator>'
NEW_PASSWORD='<new owner password>'

LOGIN_JSON=$(curl -ksS -H 'content-type: application/json' \
  --data "{\"secret\":\"$INITIAL_PASSWORD\"}" \
  "$ORCH_URL/admin/v1/login")
SESSION_TOKEN=$(printf '%s' "$LOGIN_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')

CHANGE_JSON=$(curl -ksS -H "authorization: Bearer $SESSION_TOKEN" \
  -H 'content-type: application/json' \
  --data "{\"current_secret\":\"$INITIAL_PASSWORD\",\"new_secret\":\"$NEW_PASSWORD\"}" \
  "$ORCH_URL/admin/v1/password/change")
SESSION_TOKEN=$(printf '%s' "$CHANGE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')

WORKER_TOKEN=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
curl -ksS -H "authorization: Bearer $SESSION_TOKEN" \
  -H 'content-type: application/json' \
  --data "{\"id\":\"worker-1\",\"value\":\"$WORKER_TOKEN\",\"ttl\":\"48h\"}" \
  "$ORCH_URL/admin/v1/token/create"

EXPIRES=$(date -u -d '+24 hours' +%Y-%m-%dT%H:%M:%SZ)
curl -ksS -H "authorization: Bearer $SESSION_TOKEN" \
  -H 'content-type: application/json' \
  --data "{\"limits\":{},\"expires\":\"$EXPIRES\"}" \
  "$ORCH_URL/admin/v1/bootstrap-token/create"
```

`WORKER_TOKEN` используйте как worker `ENROLL_TOKEN`. Если orchestrator server
остановлен и вы работаете напрямую с local state, остаётся безопасный CLI-путь:

```sh
read -r -s ORCH_NEW_ADMIN_PASSWORD
printf '%s\n' "$ORCH_NEW_ADMIN_PASSWORD" | docker compose run --rm orchestrator \
  orchestrator admin set-password --stdin
unset ORCH_NEW_ADMIN_PASSWORD
```

## Переменные окружения

Эти переменные реально читаются orchestrator-кодом или поставляемым Compose:

| Переменная | Назначение | Обязательна | Дефолт | Пример / как получить |
| --- | --- | --- | --- | --- |
| `ORCH_LISTEN` | HTTP(S) listen address. | Опц. | `:9091` | Оставьте default для host-network Compose или задайте `127.0.0.1:9091` за reverse proxy. |
| `ORCH_STATE_DIR` | Local state directory для bbolt DB, generated keys, APK artifacts и bot/admin secrets. | Опц. | `./orch-state` | В Compose используется `/orch-state`, смонтированный из `./orch-state`. |
| `ORCH_SIGNER_SOCKET` | Unix socket для config signer sidecar. | Опц. | `./orch-state/signer.sock` | В Compose используется `/orch-state/signer.sock`. |
| `ORCH_PUBLIC_URL` | Public URL, попадает в bootstrap payloads и используется workers/devices. | Обяз. для реального deploy | `https://127.0.0.1:9091` | `https://orch.example.com` или LAN URL для dev. |
| `ORCH_EGRESS_PROBE_URL` | Optional worker egress probe URL. | Опц. | empty | Обычно `http://127.0.0.1:9090/self-describe` в local dev. |
| `ORCH_ADMIN_SECRET` | Optional seed для first-run admin password. Лучше использовать generated initial password или safe CLI input. | Опц. | empty | Если нужен, передавайте через secret manager/env, не коммитьте. |
| `ORCH_ADMIN_SESSION_TOKEN` | Optional bearer session token для local CLI admin requests при запущенном сервере. | Опц. | empty | Получите из `/admin/v1/login`; не кладите в shell history или git. |
| `ORCH_UPDATE_PUBKEY` | Public minisign key для APK update manifests. | Опц. | empty | Для управляемого update-канала задайте свой offline `update.pub` до первого старта. Empty разрешает seed-on-first-run сгенерировать demo key в local state. |
| `ORCH_TLS` | Включает built-in self-signed TLS listener, если не `0`. | Опц. | `1` | `0` только для local dev за доверенным транспортом. |
| `SEED_APK_PATH` | Путь к APK для seed-on-first-run. | Опц. | `./seed/app.apk` | Compose монтирует `./seed` и ставит `/seed/app.apk`. |
| `SEED_APK_VERSION_CODE` | Version code в generated seed update manifest. | Опц. | `1` | Должен совпадать с seed APK version code. |
| `SEED_APK_VERSION_NAME` | Version name в generated seed update manifest. | Опц. | `seed` | Например `0.1.0`. |

Config-signing key генерируется и хранится signer-процессом в
`ORCH_STATE_DIR`; orchestrator обращается к нему через `ORCH_SIGNER_SOCKET`.
Для APK updates задайте `ORCH_UPDATE_PUBKEY` от своего offline minisign update
key, если планируете публиковать будущие обновления. Seed-on-first-run может
сгенерировать update key в local state для первого demo APK, но дальнейшая
публикация APK должна использовать manifests, подписанные настроенным update
public key. Private keys и `orch-state/` нельзя коммитить.

## Production TLS

`ORCH_TLS=1` запускает встроенный self-signed TLS listener. Это удобно для
локального dogfooding, но в production лучше использовать настоящий сертификат
для `ORCH_PUBLIC_URL`, чтобы Android, workers и браузеры подключались без
insecure-TLS override.

Рекомендуемый вариант:

1. Запустить orchestrator на loopback без встроенного TLS:
   `ORCH_LISTEN=127.0.0.1:9091`, `ORCH_TLS=0`.
2. Поставить Caddy, nginx или другой reverse proxy перед orchestrator.
3. Выпустить Let's Encrypt certificate для вашего `ORCH_PUBLIC_URL`.
4. Проксировать HTTPS на `http://127.0.0.1:9091`.

Для тестов с дефолтным self-signed listener workers должны ставить
`ORCH_INSECURE_TLS=1`. Не используйте это в production.

## Опциональный seed APK

Если при первом старте существует `./seed/app.apk`, orchestrator генерирует
update minisign key в `orch-state/`, подписывает update manifest этого APK и
публикует его как update `seq=1`. Приватный update key не хранится в Git.

Настройка:

```env
SEED_APK_PATH=/seed/app.apk
SEED_APK_VERSION_CODE=1
SEED_APK_VERSION_NAME=seed
```

Сгенерированный public update key попадает в bootstrap payload, если
`ORCH_UPDATE_PUBKEY` не задан явно. Используйте это только для demo/first-run
bootstrap. Для управляемого владельцем update-канала сгенерируйте offline
minisign key сами и задайте `ORCH_UPDATE_PUBKEY` до первого старта.

## Как опубликовать APK

Есть два штатных способа опубликовать Android update через платформу:

- **Web-админка:** откройте admin UI, загрузите подписанный APK и signed update
  manifest. Если `orch-state/update.key` существует и совпадает с configured
  update public key, UI может сам собрать и minisign'ить manifest. Для лучшей
  изоляции key держите update key offline, используйте UI для draft manifest,
  подпишите его externally и вставьте minisig. APK signing key в обоих режимах
  остаётся вне orchestrator.
- **Seed при первом старте:** положите APK в `seed/app.apk` до первого запуска.
  Orchestrator сгенерирует свой update minisign key в local state, подпишет
  manifest для этого APK и опубликует его как `seq=1`. Это только demo/initial
  bootstrap; для последующих APK от владельца стартуйте со своим offline update
  key и `ORCH_UPDATE_PUBKEY`.

Готовый публичный APK доступен в release channel репозитория app:
<https://github.com/TrafficWrapper/app/releases/latest>. App README и release
assets считаются source of truth для текущего имени APK, version code, SHA-256 и
fingerprint signing certificate.

## Проверка APK build

В app repository есть минимальный verifier:
[`build/verify-release.sh`](https://github.com/TrafficWrapper/app/blob/master/build/verify-release.sh).
Используйте его, чтобы проверить SHA-256 скачанного APK, SHA-256 signing
certificate APK, optional minisign update manifest и optional rebuild из git
tag. Текущий hash public APK и certificate fingerprint документированы в
[app README](https://github.com/TrafficWrapper/app#prebuilt-apk). Byte-for-byte
reproduction APK требует тот же signing keystore и build inputs; operators со
своим keystore могут тем же способом проверять свой channel.

## Telegram-бот

Бот опционален. Создайте своего бота через BotFather, затем задайте token и owner
Telegram ID в web-админке на странице Settings. Token шифруется в
`orch-state/orchestrator.db` и больше не показывается.

Headless-вариант:

```sh
read -r -s TW_BOT_TOKEN
printf '%s\n' "$TW_BOT_TOKEN" | docker compose exec -T orchestrator \
  orchestrator bot set-token --stdin --owner-id 123456789
unset TW_BOT_TOKEN
```

## Безопасность

- Не коммитьте `.env`, `orch-state/`, TLS keys, minisign private keys, APK и
  generated update keys.
- Config signing key держит отдельный signer process.
- Admin secrets можно передавать через stdin, env или файл; открытые `--value` и
  `--token` deprecated, потому что светятся в shell history и process list.
- Orchestrator хранит секреты в local state DB, зашифрованные AEAD.

## 💚 Поддержать проект

Проект бесплатный и развивается на энтузиазме. Если он вам помогает — спасибо за
любую поддержку!

- **Bitcoin (BTC):** `bc1qdlqer9rtej6tpzdjzljdwltj7vxr4h6tv9eucp`
- **Ethereum (ETH):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **USDT (ERC-20):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **TRON (TRX):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`
- **USDT (TRC-20):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`

С благодарностью за вашу поддержку! 🙏

## Лицензия

MIT. См. `LICENSE`.
