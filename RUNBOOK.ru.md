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

## Ротация config-signing key

Config-signing key хранится signer process и доступен через
`ORCH_SIGNER_SOCKET`.

Процедура:

1. Остановите config publication и не approve'ьте новых workers/devices во время
   rotation window.
2. Сделайте backup текущего orchestrator state.
3. Сгенерируйте или установите новый signer key в signer state location.
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

## Компрометация worker

1. Disable или revoke worker в orchestrator.
2. Rotate affected per-device transport material через re-issuing config.
3. Уберите worker из seed workers и client bundles.
4. Сохраните logs/state приватно для incident analysis.
5. Пересоберите worker из clean state перед re-approval.

Не подключайте devices к worker, которому вы операционно не доверяете.

## Смена admin password

Используйте admin UI или `/admin/v1/password/change`. Если running server
недоступен и вы работаете с local state, используйте documented safe CLI path
через stdin. Не кладите реальные passwords в committed files или public logs.

## Потерян signer key

Если config signer private key потерян:

1. Восстановите его из private backup, если он есть.
2. Если backup отсутствует, создайте новый config-signing key.
3. Рассматривайте это как config key rotation.
4. Re-enroll или re-bootstrap devices, pin'ившие старый config public key.

Без старого key вы не сможете выпускать config, принимаемый clients, которые
доверяют только старому config public key.
