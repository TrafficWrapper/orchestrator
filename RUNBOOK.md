# Owner Runbook

🇷🇺 Русская версия: [RUNBOOK.ru.md](RUNBOOK.ru.md)

This runbook describes owner operations. Use placeholders in tickets and notes;
never publish real keys, tokens, domains, IP addresses, bootstrap payloads, or
state files.

## Trust roots

TrafficWrapper separates four trust roots:

1. config-signing minisign key;
2. update minisign key;
3. Android APK signing certificate;
4. orchestrator Noise static key.

Back up each root separately. Store private material offline or in
owner-controlled secret storage. Do not commit `.env`, `orch-state/`,
`worker-state/`, release keystores, or minisign private keys.

## Rotate the config-signing key

The config-signing key is held by the signer process and reached through
`ORCH_SIGNER_SOCKET`.

Procedure:

1. Stop config publication and avoid approving new workers/devices during the
   rotation window.
2. Back up current orchestrator state.
3. Generate or install the new signer key in the signer state location.
4. Restart `signer` and `orchestrator`.
5. Publish fresh `worker-config-v1` and `client-config-v1`.
6. Re-issue client config/bootstrap material so devices pin the new config
   public key.
7. Keep the old backup until all expected devices are confirmed migrated.

Impact: devices that pin the old config public key will reject config signed by
the new key until they are re-enrolled or otherwise receive the new trusted pin.

## Rotate the update minisign key

The update key signs APK update manifests. Prefer an offline owner-controlled
key.

Procedure:

1. Generate a new update minisign keypair offline.
2. Store the private key outside the repository and outside public servers when
   possible.
3. Update the orchestrator/bootstrap update public key for new enrollments.
4. Publish a transition app/config plan for existing devices.
5. Sign future manifests with the new private key only after clients trust the
   new public key.

Impact: devices reject update manifests signed by a key that does not match
their pinned update public key.

## Rotate the APK signing certificate

The Android APK signing certificate is tied to the Android package lineage.

Procedure:

1. Create a new release keystore offline.
2. Build a new APK lineage intentionally.
3. Publish it as a new install path, not as a seamless in-place update from the
   old certificate.
4. Communicate that users must install the new APK lineage and re-bootstrap if
   required.

Impact: Android will not treat an APK signed by a different certificate as a
normal update for the existing package. Plan for reinstall or a separate package
lineage.

## Rotate the orchestrator Noise static key

Workers pin `ORCH_STATIC_PUBLIC_KEY`; device bootstrap payloads pin
`orch_noise_public`.

Procedure:

1. Schedule downtime or a maintenance window.
2. Back up orchestrator state.
3. Generate the new orchestrator Noise static key.
4. Restart orchestrator services.
5. Update every worker `ORCH_STATIC_PUBLIC_KEY`.
6. Re-bootstrap devices so they receive the new `orch_noise_public`.

Impact: old workers and devices reject the orchestrator until their pins are
updated.

## Worker compromise

1. Disable or revoke the worker in the orchestrator.
2. Rotate affected per-device transport material by re-issuing config.
3. Remove the worker from seed workers and client bundles.
4. Preserve logs/state privately for incident analysis.
5. Rebuild the worker from clean state before re-approval.

Do not connect devices to a worker you do not operationally trust.

## Change the admin password

Use the admin UI or `/admin/v1/password/change`. If the running server is not
available and you operate on local state, use the documented safe CLI path with
stdin. Do not put real passwords into committed files or public logs.

## Lost signer key

If the config signer private key is lost:

1. Restore from a private backup if available.
2. If no backup exists, create a new config-signing key.
3. Treat this as config key rotation.
4. Re-enroll or re-bootstrap devices that pinned the old config public key.

Without the old key, you cannot produce config accepted by clients that trust
only the old config public key.
