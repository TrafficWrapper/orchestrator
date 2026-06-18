# Troubleshooting

🇷🇺 Русская версия: [TROUBLESHOOTING.ru.md](TROUBLESHOOTING.ru.md)

This is the canonical troubleshooting guide for the full TrafficWrapper flow:
orchestrator -> worker -> device bootstrap -> Android app -> tunnel.

Do not paste real domains, IP addresses, SNI values, tokens, keys, bootstrap
payloads, worker state, or device credentials into public issues.

## Orchestrator does not start

Check:

- `docker compose ps`
- `docker compose logs signer orchestrator`
- `.env` exists and `ORCH_STATE_DIR` is writable
- `ORCH_SIGNER_SOCKET` points to the same path for `signer` and `orchestrator`
- `ORCH_LISTEN` is not already used by another process

For local development, the default self-signed TLS listener is expected:

```sh
ORCH_TLS=1
ORCH_PUBLIC_URL=https://127.0.0.1:9091
```

Use `curl -k` for local admin API checks. Do not use `-k` as a production habit.

## Worker cannot enroll

Verify these values on the worker:

- `ORCH_URL` points to the orchestrator URL reachable from the worker container.
- `ORCH_STATIC_PUBLIC_KEY` exactly matches `orchestrator public-key`.
- `ENROLL_TOKEN` is the one-time worker token created by the owner.
- `ORCH_INSECURE_TLS=1` is set only when the orchestrator uses self-signed dev
  TLS.
- system clocks are close enough for token expiry checks.

Same-host Docker development usually uses:

```sh
ORCH_URL=https://host.docker.internal:9091
ORCH_INSECURE_TLS=1
```

If enrollment fails after a partial attempt, create a fresh token and check the
orchestrator logs for the rejected reason.

## Worker remains pending

Enrollment only creates a pending worker. The owner must approve it in the admin
UI or admin API before the worker receives signed config.

Check the worker list in the orchestrator admin UI. Approving a worker bumps the
desired config sequence; the worker should pull config and ack shortly after.

## Worker refuses `CAMOUFLAGE_DOMAIN`

The worker fails closed when `CAMOUFLAGE_DOMAIN` is empty, `example.com`, or
`example.org`. Set a real TLS 1.3 domain that fits your deployment.

Do not copy a public example value into production. The camouflage domain is part
of the deployment fingerprint.

## Device bootstrap is invalid or expired

Bootstrap payloads are one-time and time-limited. If import or enrollment fails:

- create a new bootstrap from **Devices** -> **+ New device**;
- verify the app asks for confirmation and shows the expected
  `orchestrator_url` and `config_pubkey_pin`;
- confirm the device can reach `orchestrator_url`;
- check that the device clock is not far from real time.

Do not reuse an old QR, Base64, or JSON bootstrap after a failed enrollment.

## App says there is no route or does not connect

Check the platform in this order:

1. Worker is approved and active in the orchestrator.
2. Worker ack time is recent.
3. Client config is signed and fetched by the app.
4. The app has at least one route whose policy matches the requested traffic.
5. REALITY and AWG public ports are reachable from the device network.
6. Worker `/tw/` distributor is reachable inside the tunnel.

If REALITY is unhealthy, AWG should remain available as a fallback when the
worker and device materialization are current.

## Egress probe mismatch

The orchestrator may compare advertised worker egress with the worker
self-description/probe result. Mismatch usually means:

- `PUBLIC_ADDRESS` or `EGRESS_IP` is wrong;
- the host has multiple outbound interfaces;
- NAT or provider routing changes the observed source address;
- `ORCH_EGRESS_PROBE_URL` points to the wrong worker.

Set an explicit `EGRESS_IP` on the worker when auto-detection is wrong.

## Distributor `/tw/` is unavailable

The distributor is intentionally reachable only inside the tunnel. It should not
be exposed as a public clearnet website.

Check:

- `distributor` container is running;
- `worker-state/distributor` exists and is mounted read-only into nginx;
- AWG gateway is healthy;
- Xray REALITY fallback destination can reach the distributor path;
- the app is testing `/tw/` through the selected tunnel route, not directly from
  clearnet.

## APK update is not visible

Check:

- APK metadata is published in the orchestrator.
- The app can fetch signed client config through the tunnel.
- The update manifest minisign key matches the update public key pinned during
  bootstrap/enrollment.
- The APK is signed by the pinned Android signing certificate.
- `versionCode` is higher than the installed version.

Publishing config or APK metadata does not bypass signature checks on the app.
