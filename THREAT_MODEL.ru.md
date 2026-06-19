# Модель угроз TrafficWrapper

[English](THREAT_MODEL.md)

TrafficWrapper является self-hosted. Operators контролируют собственный выбор
инфраструктуры и должны избегать публикации deployment-specific identifiers в
public issues, pull requests, logs, screenshots или examples.

## Что раскрывает self-hoster

Реальный deployment может раскрывать:

- public IP address worker'а и открытые REALITY/AWG ports;
- domain или SNI values, используемые для camouflage;
- факт, что host запускает anti-censorship infrastructure;
- timing и traffic-volume patterns, видимые hosting providers или networks;
- связи между public support/donation addresses и deployment identity, если
  operator переиспользует public identifiers.

TrafficWrapper снижает casual discovery, но не делает hosting анонимным.

## Роли доверия

- **Owner/admin:** approve'ит workers и devices, публикует config и управляет
  APK update metadata.
- **Orchestrator:** source of truth для approved workers/devices и signed
  bundles. Компрометация может enroll или удалить infrastructure и опубликовать
  malicious config.
- **Config signer:** single point of failure для `client-config-v1`. Если signer
  private key или signer socket скомпрометированы, attacker может перенаправить
  все devices, доверяющие этому config key.
- **Worker:** exit node и decryption point. После termination AWG на worker'е
  worker может видеть decrypted traffic, выходящий из tunnel. Не подключайтесь к
  untrusted workers.
- **Worker agent:** имеет доступ к `docker.sock`, чтобы restart/materialize
  Xray и AWG state. Считайте его privileged host-adjacent code.
- **Android app:** обеспечивает bootstrap confirmation, minisign config/update
  verification, APK certificate pinning и local route selection.

## Noise Pinning

Workers задают `ORCH_STATIC_PUBLIC_KEY`. Device bootstrap payloads содержат
`orch_noise_public`. Оба pin'ят orchestrator Noise static public key перед
Noise_XK exchanges over HTTPS. TLS является carrier; authenticity orchestrator'а
идёт от pinned Noise key.

Noise envelope определён в `orchestrator/internal/protocol/protocol.go`:
prologue `TrafficWrapper orchestrator worker v1`, DH25519, ChaChaPoly, SHA256 и
encrypted framed JSON. Pinning не позволяет network attacker заменить
orchestrator во время worker или device enrollment, если он также не
контролирует pinned Noise private key или bootstrap material.

## Корни ключей

TrafficWrapper намеренно разделяет четыре key roots:

1. **Config-signing minisign key:** generated and held by signer process,
   доступен через `ORCH_SIGNER_SOCKET`; подписывает `client-config-v1` и
   `worker-config-v1`.
2. **Update minisign key:** owner-controlled offline key для APK update
   manifests; seed-on-first-run keys предназначены только для demo/bootstrap.
3. **Android APK signing certificate:** offline release keystore. Devices
   принимают updates только когда APK certificate совпадает с pinned SHA-256
   fingerprint.
4. **Noise static keys:** orchestrator, worker и device keys, используемые для
   enrollment и authenticated encrypted envelopes.

Держите эти roots изолированными. Не переиспользуйте update key как config key.
Не храните release keystores, minisign private keys, `.env`, `orch-state/` или
`worker-state/` в Git.

## Tradeoff'ы доверенного времени update-канала

- **Fallback trusted time на системные часы устройства.** Проверки manifest
  expiry и timestamp предпочитают trusted time из SNTP плюс monotonic anchor.
  Если SNTP недоступен и у fresh install ещё нет monotonic anchor, клиент
  сознательно fallback'ится на системные часы устройства. Это выбор в пользу
  availability: иначе fresh client за NTP-blocking не смог бы обновиться вообще.
  Tradeoff: устройство с подделанными системными часами и заблокированным NTP
  может обойти manifest expiry или future-time checks. Mitigations остаются в
  силе: updates всё равно требуют valid minisign signature от pinned update key,
  anti-rollback по sequence number и совпадение APK signing certificate;
  time validation является дополнительным слоем, а не единственным барьером.
- **Подписанные manifest timestamps могут двигать trusted anchor вперёд.**
  Trusted time вычисляется как максимум сохранённого monotonic anchor и
  issued/timestamp value из verified manifest. Поэтому validly signed manifest
  может сдвинуть anchor вперёд. Mitigations: учитываются только
  cryptographically verified manifests, а future guard отклоняет timestamps
  больше чем на 24 часа впереди current trusted time.

## Небезопасные defaults

`example.com`, `example.org`, generated seed update keys, default local
passwords, self-signed dev TLS и copied example AWG dialects не являются
production settings. Worker agent отказывается от placeholder
`CAMOUFLAGE_DOMAIN` values; operators всё равно должны выбрать реальный TLS 1.3
camouflage domain, подходящий их deployment и jurisdiction.

## Юрисдикция

Operators и contributors отвечают за понимание local laws, hosting provider
terms и export или sanctions restrictions, применимых к их собственному
использованию. Project не может оценивать законность конкретного deployment.
