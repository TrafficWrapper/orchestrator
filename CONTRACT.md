# Worker ↔ Orchestrator Contract

This document describes the wire contract between the worker agent
(`TrafficWrapper/worker`) and the orchestrator as implemented in this
repository. The code is the source of truth; when this page and the code
disagree, the code wins and this page is a bug.

Russian version: [CONTRACT.ru.md](CONTRACT.ru.md).

## Compatibility rules

- Workers and the orchestrator are upgraded independently and in any order.
- Every field added after the first release is optional. A missing field
  means the previous behaviour; an unknown field is ignored. Neither side
  rejects a payload for carrying fields it does not know (no strict
  decoding on worker-facing payloads).
- A newer format is only used when the partner has announced it: the worker
  through capabilities (`self_describe.capabilities`, `worker_capabilities`),
  the orchestrator through `orchestrator_capabilities`, or, for APK chunks,
  through the presence of `update_ref`.
- Error texts that older workers match on are kept verbatim; structured
  `code` values are added next to them.

## Transport

All `/w/v1/*` calls except `handshake/start` are Noise_XK messages over
HTTPS. The worker pins the orchestrator's static Noise key; the orchestrator
identifies the worker by the static key of the handshake and checks it
against the stored worker record on every call (`worker identity mismatch`
otherwise).

| Endpoint | Purpose |
| --- | --- |
| `POST /w/v1/handshake/start` | Starts the Noise handshake. May carry the `cookie` described below. |
| `/w/v1/enroll` | One-time enrollment with a token. |
| `/w/v1/config/pull` | Fetch signed worker and client bundles, APK and discovery feed. |
| `/w/v1/nudge/wait` | Long poll (up to ~25 s) for a new desired seq; also a heartbeat. |
| `/w/v1/ack` | Report the applied seq, self-check, usage and self_describe. |
| `/w/v1/telemetry` | Relay one signed device telemetry event. |
| `/w/v1/apk/chunk` | Read one range of the current APK (see below). |

After any authenticated `/w/` call an approved worker receives `cookie` in the
plaintext envelope (`v1.<worker_id>.<expiry_unix>.<mac>`, valid for one hour).
Sending it back in the next `handshake/start` body lets the handshake use the
capacity reserved for workers. The cookie grants no authentication.

## Platform time: `server_time`

Noise responses of enroll, pull, nudge, ack and telemetry (including their
refusals) carry `server_time`: the orchestrator clock as Unix milliseconds.
The `/w/v1/apk/chunk` response declares the field but does not fill it yet,
so workers must not rely on it there. Workers may keep an offset to it for freshness
decisions; without the field they use their own clock.

## self_describe

`self_describe` is sent in enroll, nudge and ack. It is untrusted input: the
orchestrator sanitizes it once on intake and stores only the sanitized copy.

Allowed top-level keys:

`schema` (string), `hostname`, `egress_ip`, `orch_url`, `agent_url`,
`distributor_url`, `standalone` (bool), `dialect_id`, `capacity` (number),
`protocols` ([]string), `reality`, `reality_profiles`, `awg`, `awg_profiles`,
`health`, `orchestrator`, `distributed_apk`, `capabilities` ([]string).

- Unknown keys are dropped without rejecting the worker. `priority`,
  `weight`, `label` and `region` are operator settings and are never taken
  from a worker.
- Strings are at most 256 bytes, profile lists at most 32 entries, the whole
  object at most 64 KiB (a larger report is ignored and the previous one
  stays in effect).
- REALITY public keys are 32 bytes of base64 (RawURL or padded), AWG keys 32
  bytes of standard base64, ports 1..65535, addresses a hostname or an IP.
  `egress_ip`, when set, must parse as an IP. A malformed field is kept and
  reported (admin `self_describe_issues`) instead of silently dropping a
  route. An unexpected `distributor_url` host or scheme is only reported.
- `reality` may carry `address_v6`. A `fingerprint` in `reality` is accepted
  but the orchestrator applies its own fingerprint policy to client routes.
- `distributed_apk` = `{apk_sha256, version_code, version_name, apk_name,
  seq?}` describes the APK the worker currently serves.
- A secret-looking key (`private_key`, `privatekey`, `psk2`, `internal_ip`,
  `internalip`, `server_private_key`) anywhere is stripped and keeps that
  worker out of client bundles and discovery until it reports a clean
  description. Other workers are not affected.

## Capabilities

Known worker capability values:

| Value | Meaning |
| --- | --- |
| `reality_flow` | The worker configures a per-device REALITY flow (Vision). |
| `desired_state_enabled` | The worker honours `desired_state.*.enabled` and an empty device list. |
| `revoked_status` | The worker understands the `revoked` refusal; revocation is single-phase. |
| `apk_fetch_v1` | The worker fetches the APK through `update_ref` and `/w/v1/apk/chunk`. |

They are sent in two places:

- `self_describe.capabilities`: stored with the sanitized self_describe
  (at most 32 entries of up to 64 bytes). It describes the worker as last
  reported and is used when no request-level value exists.
- `worker_capabilities` in the pull request (optional): what the running
  binary supports. Decisions for that pull (for example `update_ref`
  instead of inline `update`, single-phase revoke) use this value when it is
  present. The orchestrator keeps the last value, reduced to the known values
  above (trimmed, deduplicated, at most 32 input entries of up to 64 bytes),
  on the worker record and shows it as `pull_capabilities` in the admin
  worker list next to `capabilities`. The record is only rewritten when the
  value changes; a pull without the field clears it.

Unknown values are ignored everywhere. A worker without capabilities gets the
behaviour of the first release.

### `orchestrator_capabilities`

Pull, nudge and ack responses carry `orchestrator_capabilities` ([]string).
Current value:

- `usage_source_awg_v1`: `ack.usage[]` may use `source: "awg"` together with
  `device_id`. Without it a worker must send AWG usage without `source`,
  keyed by `awg_public_key`.

Support for APK chunks is not announced here: it is signalled by
`update_ref` in the pull response. A missing field means none.

## Worker statuses and refusals

`status` is one of `pending`, `approved`, `active`, `inactive`, `revoked`.
`revoked` is terminal. `disabled` is a separate operator flag, not a status.

Every refusal is `{ok: false, error, ...}`; `code` (string) is optional and
added to refusals where listed below. `error` texts are stable.

| Situation | Response |
| --- | --- |
| pending worker, pull | `{ok:false, status:"pending", error:"owner approval required"}` |
| pending worker, nudge / ack / telemetry / apk chunk | `{ok:false, status:"pending", error:"owner approval required", code:"worker_pending"}` |
| revoked worker | `{ok:false, status:"revoked", error:"worker revoked", code:"worker_revoked"}` |
| enroll with a revoked static key | same as revoked, refused before the token is used |

Revocation:

- A worker that declares `revoked_status` is refused at once.
- Other workers first get a signed worker bundle with every protocol off,
  `approved_devices: []` and a new seq. Once they ack that seq, or after a
  grace period of 10 minutes, every call is refused with `worker_revoked`.

Disabled workers keep pulling. Their worker bundle has
`reality.enabled=false`, `awg.enabled=false` and `approved_devices: []`;
their usage and telemetry are accepted but not accounted.

### Telemetry codes

`/w/v1/telemetry` takes `{worker_id, payload_base64, headers, received_at}`
and answers `{ok}` or a refusal. Refusal codes: `stale_timestamp`, `replay`,
`bad_signature`, `unknown_device`, `device_not_approved`,
`invalid_payload`, `worker_revoked`, `worker_pending`. The text
`device is not approved` is kept for older workers. `received_at` is
diagnostic only; the orchestrator dates events by its own clock.

## Worker bundle: `desired_state`

The worker bundle (`schema: 1`, `ns: "worker-config-v1"`) is minisign-signed
over the exact `config_json` string. Fields: `schema`, `ns`, `seq` (the
worker's desired seq), `worker_id`, `issued_at`, `desired_state`.

`desired_state`:

- `reality.enabled`, `awg.enabled` (bool): whether the protocol serves
  devices. False for disabled and revoked workers and for protocols the
  operator switched off. A missing value means `true`.
- `reality.public`, `awg.public`: the worker's own reported section, echoed.
- `approved_devices` ([]object): the devices the worker must serve, each with
  `device_id`, `reality_uuid`, `awg_public_key`, `internal_ip`, `psk2`,
  `status` and, when set, `awg_profiles`, `reality_flow`, `limits`,
  `expires_at`. An empty list is valid input (disabled, revoked, or no
  devices) and must not be treated as a failed sync when the bundle
  verifies.
- `revoked_short_ids` ([]string): REALITY short IDs to stop accepting.
- `egress_policy` (currently always `direct`) and `client_artifacts`
  (paths of the published client files).

A worker should check that `worker_id` equals its own ID and `schema` is 1.

The pull response also carries `desired_seq`, `not_modified` (when
`have_seq` is current) and `client_bundle`: the shared, signed
`client-config-v1` bundle the worker publishes to clients. Its `seq` never
goes backwards; the worker applies it when its seq is at least the last one
it applied.

## ack

`/w/v1/ack` request: `worker_id`, `applied_version`, `self_check`,
`egress_ip_observed`, optional `self_describe`, optional `usage[]`, optional
`client_applied_seq`.

- `usage[]` = `{device_id, awg_public_key, source?, rx_bytes, tx_bytes}` with
  cumulative counters. The first report per key is a baseline; a decrease
  rebaselines without accounting. `source` is `reality` or `awg`
  (`awg` only after `usage_source_awg_v1`). At most 32768 reports per ack
  are accounted.
- `client_applied_seq` is followed only within a bounded window above the
  orchestrator's counter.

Response: `ok`, `desired_seq`, `applied_seq`, `egress_ip_probe`,
`egress_match`, `quota_blocks`, `orchestrator_capabilities`, `server_time`.

### `egress_ip_seen`

The orchestrator records the source address of each authenticated ack as
`egress_ip_seen` and compares the worker's declared egress with it (or with
the orchestrator's own probe when the source is not a public address). The
result is `match`, `mismatch` or `n/a`, shown in the admin API as
`egress_seen` / `egress_check`; `egress_match` in the ack response is false
only for `mismatch`. The worker sends nothing new for this; a mismatch
raises an operator alert and does not change client routes.

## APK delivery

### `update_ref`

When a new release exists and the pull's `worker_capabilities` contains
`apk_fetch_v1`, the pull response carries `update_ref` instead of inline
`update`:

```
update_ref = {
  apk_seq int64, apk_name string, apk_sha256 string (64 lower-case hex),
  apk_size int64, manifest_json string, manifest_minisig string
}
```

Workers without the capability receive the inline `update`
(`manifest_json`, `manifest_minisig`, `apk_name`, `apk_sha256`,
`apk_base64`) only while the APK fits `ORCH_APK_INLINE_MAX_BYTES`
(default 40 MiB, at most 64 MiB). Otherwise the field is absent and only the
config is delivered. A worker that repeatedly pulls with the same `have_seq`
after an inline shipment stops getting the APK for a growing backoff.

A release counts as applied when `distributed_apk.seq` and
`distributed_apk.apk_sha256` match it, or, for workers that report no seq,
by the acked seq of the pull that carried it.

### `/w/v1/apk/chunk`

Request: `{worker_id, apk_seq, apk_sha256, offset, length}` with
`0 ≤ offset < apk_size` and `0 < length ≤ 4 MiB`.

Response: `{ok, code?, error?, total_size, data_base64}`.

| Code | Meaning |
| --- | --- |
| `release_superseded` | The sha256 no longer matches the current release (or the seq is newer than it). Start over from the next pull. A re-signed manifest for the same APK does not interrupt a download. |
| `bad_range` | Offset or length out of range; `total_size` is returned. |
| `worker_revoked`, `worker_pending` | As above. |

The worker writes chunks to a temporary file, checks sha256, renames it into
place, and only then writes the manifest. If the sha256 is already
published it only replaces the manifest and signature.

## `discovery_bundle`

Pull responses carry `discovery_bundle = {endpoints_json,
endpoints_json_minisig}` when the orchestrator can build it: the same signed
discovery feed (rendezvous-v1) the orchestrator publishes, one signed content
per discovery seq. The worker serves it as `/tw/endpoints.json` and
`/tw/endpoints.json.minisig` without modification. Workers are sent a new
config seq when the feed's seq changes and before half of its lifetime has
passed. Workers receive exactly the feed of the configured
`ORCH_DISCOVERY_PUBLIC` mode (`reduced` by default: AWG entries only and an
empty `endpoints.reality`); in `off` mode the orchestrator's public endpoint
serves nothing and workers are the only place the feed is published.
