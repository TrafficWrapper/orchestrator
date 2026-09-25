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

## Upgrading to the isolated signer layout

Releases that ship `docker-compose.yml` with `./signer-state` move the
config-signing key out of `./orch-state` automatically on the first signer
start (`ORCH_SIGNER_LEGACY_KEY_PATH`); the public key workers and clients pin
does not change. Before upgrading, back up `./orch-state`. After the first
start, confirm `./signer-state/orch-config.key` exists and
`./orch-state/orch-config.key` is gone, then include `./signer-state` in
backups. If the signer refuses to start because keys exist in both places with
different contents, keep the one whose public key matches deployed configs.
Containers now run as uid `10001`; the entrypoint re-owns the state
directories, but a seed APK under `./seed` must be world-readable.

## Stricter configuration parsing

`serve` now refuses to start on malformed environment values and lists them
all in the log (`invalid configuration: ...`). `ORCH_TLS` accepts
`1/0`, `true/false`, `yes/no`, `on/off`: previously any value other than `0`
kept TLS on, so an old `ORCH_TLS=false` now really disables built-in TLS
(a warning is logged). `ORCH_PUBLIC_URL` must be an absolute http(s) URL.
Admin API errors are JSON `{"ok":false,"error":"..."}`, missing workers or
devices answer 404, and a wrong method answers 405 before authentication.

## Sealed record format upgrade

Starting with the release that binds sealed records to their keys, the first
start rewrites every encrypted record in `orchestrator.db` into the new format
(logged as `store: bound N legacy sealed records`). Older binaries cannot read
the new format, so back up `./orch-state` before upgrading; rolling back means
restoring that backup.

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

## Client config seq after restore or rollback

The client bundle seq is a persistent counter stored in the orchestrator
DB, not derived from worker seqs. Apps reject a seq
below what they have seen, so it must never go backwards:

- First start after the upgrade sets it to the highest worker seq + 1000000
  (or `ORCH_CLIENT_SEQ_FLOOR` if higher).
- Every publish also raises each serving worker's config seq to at least the
  counter. A rolled-back binary (which derives the client seq from worker
  seqs) therefore still never publishes a seq below what clients have seen.
- After restoring an older DB, workers that report a higher applied client
  seq (within 10000) move the counter forward by themselves. For larger
  gaps, raise it explicitly with step-up:
  `POST /admin/v1/client-seq/floor {"floor": N, "current_secret": ..., "totp_code": ...}`
  (or set `ORCH_CLIENT_SEQ_FLOOR` before the first start on the restored DB).
- Workers that are ahead of their config seq after a restore are moved past
  it automatically on their next pull, nudge or ack.

## Worker compromise

1. Revoke the worker: `POST /admin/v1/workers/revoke {"id": ..., "current_secret": ..., "totp_code": ...}`
   (step-up: the current admin secret, the TOTP code when 2FA is on, and
   owner approval in Telegram when the bot is set up). Revocation is
   terminal: the key is refused on every call and can never re-enroll, even
   with a fresh token. A reinstalled worker must come back with a new key.
2. What the worker sees. A worker that declares `revoked_status` is refused
   at once (`code: worker_revoked`). An older worker first gets one more
   signed config with every protocol off and no devices, which drops all
   accounts on its normal apply path; after it acks that config (or after 10
   minutes) it is refused too. Live sessions on an old worker survive until
   they reconnect, and the worker still knows every REALITY UUID it served.
3. Rotate affected per-device transport material: re-enroll the devices the
   worker served so their REALITY UUIDs and AWG credentials change.
4. Remove the worker from seed workers.
5. Preserve logs/state privately for incident analysis.

Disabling (instead of revoking) is reversible: a disabled worker keeps
pulling but gets every protocol off and an empty device list, and only gets
a new config when it is enabled or disabled again. Usage and telemetry it
relays are ignored. On old workers disabling removes accounts but does not
cut sessions that are already open.

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
