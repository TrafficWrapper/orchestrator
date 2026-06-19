# FAQ

🇬🇧 English: [FAQ.md](FAQ.md)

## Что такое TrafficWrapper?

TrafficWrapper — публичная self-hosted private transport platform. Она
состоит из orchestrator control plane, worker data-plane nodes и Android public
client.

## Чем это не является?

Это не Android VPN service. Android app открывает local SOCKS front-end и
переносит выбранный traffic через user-space transports, настроенные signed
deployment config.

Это не hosted anonymity service. Operators сами выбирают и обслуживают свою
infrastructure.

## Законно ли это запускать?

TrafficWrapper не даёт юридических консультаций. Self-hosters и contributors
сами отвечают за local law, hosting-provider terms, sanctions/export rules и
operational risk в своей jurisdiction.

## Зачем два bundles?

`worker-config-v1` приватен для workers и содержит material, нужный для
применения per-device transport state. `client-config-v1` публичен для enrolled
devices и содержит active workers, routes и update/distributor metadata.

Оба подписываются, чтобы workers и devices могли проверить точную строку
`config_json` перед применением.

## Зачем подписывать config?

Config signing защищает devices от принятия unsigned или modified deployment
state. Signer process держит config minisign key за `ORCH_SIGNER_SOCKET`;
web/admin process не хранит private signing key в памяти.

## Почему worker должен быть доверенным?

Worker является exit node и decryption point. AWG завершается на worker, поэтому
worker может видеть decrypted egress traffic после tunnel termination. Не
подключайте devices к workers, которым вы операционно не доверяете.

## Можно ли запустить один worker?

Да. Одного worker достаточно для малого deployment или development stand.
Несколько workers улучшают redundancy и route choices, но также увеличивают
operational surface.

## Поддерживаются ли iOS или desktop?

Нет. Scope public app — Android плюс общий Go transport core. iOS и desktop
clients вне scope, если contributors не спроектируют и не возьмут их поддержку.

## Чем это отличается от обычного VPN или Amnezia?

TrafficWrapper не является system VPN profile. Он использует local SOCKS
front-end и signed per-deployment config для выбора REALITY или AmneziaWG
routes. Platform также включает owner approval, per-device bootstrap, signed
config и in-tunnel update/distributor paths.

## Как работают updates?

Owner публикует APK metadata и signed update manifest. App принимает update
только когда manifest verifies, APK signing certificate совпадает с pinned
SHA-256 fingerprint, а version новее установленного app.

## TrafficWrapper собирает telemetry?

Telemetry opt-in. App и worker paths устроены так, чтобы deployment owners могли
работать без публикации real infrastructure details в public channels.
