# TrafficWrapper Orchestrator

[![CI](https://github.com/TrafficWrapper/orchestrator/actions/workflows/ci.yml/badge.svg)](https://github.com/TrafficWrapper/orchestrator/actions/workflows/ci.yml)

[Русский](README.ru.md)

Control plane for the TrafficWrapper platform. It approves workers, enrolls
devices, signs client configuration, hosts the owner admin UI, stores APK update
artifacts, and optionally runs an owner-only Telegram admin bot.

TrafficWrapper is split into three repositories:

- [orchestrator](https://github.com/TrafficWrapper/orchestrator) — the control plane.
- [worker](https://github.com/TrafficWrapper/worker) — REALITY + AmneziaWG data plane nodes.
- [app](https://github.com/TrafficWrapper/app) — Android public client.

The normal workflow is: start the orchestrator, enroll one or more workers, then
build/install the app and import a bootstrap payload from the orchestrator.

Architecture and threat-model notes live in [ARCHITECTURE.md](ARCHITECTURE.md)
and [THREAT_MODEL.md](THREAT_MODEL.md).

## Start Here: End-to-End Flow

1. Start the orchestrator with Docker Compose and open the admin UI at
   `ORCH_PUBLIC_URL`.
2. Copy the orchestrator public key with
   `docker compose exec orchestrator orchestrator public-key`, then create a
   worker enrollment token in the admin UI or with `/admin/v1/token/create`.
3. Start a worker with `ORCH_STATIC_PUBLIC_KEY=<orchestrator public-key>`,
   `ENROLL_TOKEN=<worker token>`, `ORCH_URL=<orchestrator URL>`, and
   `ORCH_INSECURE_TLS=1` only for self-signed development TLS. Set a real
   `CAMOUFLAGE_DOMAIN` before starting REALITY.
4. Approve the pending worker in the orchestrator admin UI.
5. Open **Devices** -> **+ New device** and create a one-time device bootstrap
   payload. Save the QR, Base64, or JSON shown on that page.
6. Install the Android APK from the app repository release channel or your own
   signed build.
7. Import the bootstrap payload in the app and confirm the parsed
   `orchestrator_url` and `config_pubkey_pin`.
8. Connect. The app fetches the signed client config and automatically selects a
   worker and route.

## Requirements

- Linux host with Docker and Docker Compose.
- A reachable HTTPS URL for devices and workers.
- Go 1.23+ only if you build locally outside Docker.
- Minimum for running: 1 CPU and 1 GB RAM. Add swap on 1 GB servers; builds and
  image pulls are more reliable with 2 GB+ RAM.

Install Docker on a fresh host:

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"
```

## Quick Start

```sh
git clone https://github.com/TrafficWrapper/orchestrator.git
cd orchestrator
cp .env.example .env
docker compose up -d --build signer orchestrator
docker compose logs orchestrator | grep -i 'initial admin password'
docker compose exec orchestrator orchestrator public-key
```

Open the web UI at `ORCH_PUBLIC_URL`, log in with the initial password from the
container log, and change it immediately. The initial password is stored only as
a hash and cannot create a full admin session until it is changed.

To enroll a phone from the web UI, approve at least one worker, then open
**Devices** -> **+ New device**. The page creates a one-time bootstrap payload
and shows QR, Base64, and pretty JSON. In the Android app, import it by pasting
the Base64 string, opening the downloaded `.json` file, or using Android Share
-> TrafficWrapper.

For headless setup while the server is running, use the HTTP admin API. With the
built-in self-signed TLS listener, add `-k` to `curl` or install your own TLS
certificate first. Admin API requests use a bearer session token; CSRF is only
needed for cookie-based browser sessions.

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

Use `WORKER_TOKEN` as the worker `ENROLL_TOKEN`. If the orchestrator server is
stopped and you are operating directly on local state, the safe CLI path is also
available:

```sh
read -r -s ORCH_NEW_ADMIN_PASSWORD
printf '%s\n' "$ORCH_NEW_ADMIN_PASSWORD" | docker compose run --rm orchestrator \
  orchestrator admin set-password --stdin
unset ORCH_NEW_ADMIN_PASSWORD
```

## Environment Variables

These are the environment variables read by the orchestrator code or the
provided Compose file:

| Variable | Purpose | Required | Default | Example / how to get it |
| --- | --- | --- | --- | --- |
| `ORCH_LISTEN` | HTTP(S) listen address. | Optional | `:9091` | Keep the default for host-network Compose, or set `127.0.0.1:9091` behind a reverse proxy. |
| `ORCH_STATE_DIR` | Local state directory for bbolt DB, generated keys, APK artifacts and bot/admin secrets. | Optional | `./orch-state` | Compose uses `/orch-state` mounted from `./orch-state`. |
| `ORCH_SIGNER_SOCKET` | Unix socket used by the config signer sidecar. | Optional | `./orch-state/signer.sock` | Compose uses `/orch-state/signer.sock`. |
| `ORCH_PUBLIC_URL` | Public URL embedded into bootstrap payloads and used by workers/devices. | Required for real deployments | `https://127.0.0.1:9091` | `https://orch.example.com` or your LAN URL for dev. |
| `ORCH_EGRESS_PROBE_URL` | Optional worker egress probe URL. | Optional | empty | Usually `http://127.0.0.1:9090/self-describe` in local dev. |
| `ORCH_ADMIN_SECRET` | Optional first-run admin password seed. Prefer the generated initial password or safe CLI input. | Optional | empty | If used, pass via a secret manager/env, never commit it. |
| `ORCH_ADMIN_SESSION_TOKEN` | Optional bearer session token used by local CLI admin requests while the server is running. | Optional | empty | Get it from `/admin/v1/login`; do not put it in shell history or git. |
| `ORCH_UPDATE_PUBKEY` | Update minisign public key for APK update manifests. | Optional | empty | For a managed update channel, set this from your offline `update.pub` before the first start. Leaving it empty lets seed-on-first-run generate a demo key in local state. |
| `ORCH_TLS` | Enables the built-in self-signed TLS listener unless set to `0`. | Optional | `1` | Use `0` only for local dev behind trusted transport. |
| `SEED_APK_PATH` | APK path used by seed-on-first-run. | Optional | `./seed/app.apk` | Compose mounts `./seed` and defaults to `/seed/app.apk`. |
| `SEED_APK_VERSION_CODE` | Version code written into the generated seed update manifest. | Optional | `1` | Match the seed APK version code. |
| `SEED_APK_VERSION_NAME` | Version name written into the generated seed update manifest. | Optional | `seed` | Example: `0.1.0`. |

The config-signing key is generated and held by the signer process in
`ORCH_STATE_DIR`; the orchestrator talks to it through `ORCH_SIGNER_SOCKET`.
For APK updates, provide `ORCH_UPDATE_PUBKEY` from your own offline minisign
update key if you plan to publish future updates. Seed-on-first-run can generate
an update key in local state for a first demo APK, but later APK publishing must
use manifests signed by the configured update public key. Private keys and
`orch-state/` must not be committed.

## Production TLS

`ORCH_TLS=1` starts the built-in self-signed TLS listener. This is convenient for
local dogfooding, but production deployments should use a real certificate for
`ORCH_PUBLIC_URL` so Android, workers, and browsers can connect without
insecure-TLS overrides.

Recommended setup:

1. Run the orchestrator on loopback without built-in TLS:
   `ORCH_LISTEN=127.0.0.1:9091`, `ORCH_TLS=0`.
2. Put Caddy, nginx, or another reverse proxy in front of it.
3. Issue a Let's Encrypt certificate for your `ORCH_PUBLIC_URL`.
4. Proxy HTTPS traffic to `http://127.0.0.1:9091`.

For tests with the default self-signed listener, workers must set
`ORCH_INSECURE_TLS=1`. Do not use that setting for production.

## Optional Seed APK

If `./seed/app.apk` exists on first start, the orchestrator generates an update
minisign key in `orch-state/`, signs an update manifest for that APK, and
publishes it as update `seq=1`. No update private key is stored in Git.

Configure with:

```env
SEED_APK_PATH=/seed/app.apk
SEED_APK_VERSION_CODE=1
SEED_APK_VERSION_NAME=seed
```

The generated public update key is included in bootstrap payloads unless
`ORCH_UPDATE_PUBKEY` is explicitly set. Use this only for demo/first-run
bootstrap. For an owner-managed update channel, generate an offline minisign key
yourself and set `ORCH_UPDATE_PUBKEY` before the first start.

## Publishing the APK

There are two supported ways to publish an Android app update through the
platform:

- **Web admin UI:** open the admin UI, upload a signed APK and the signed update
  manifest. The APK signing key stays outside the orchestrator; the orchestrator
  stores and distributes the already signed artifacts.
- **Seed on first run:** put an APK at `seed/app.apk` before the first start.
  The orchestrator generates its own update minisign key in local state, signs
  a manifest for that APK, and publishes it as `seq=1`. This is for a demo or
  initial bootstrap only; for later owner-published APKs, start with your own
  offline update key and `ORCH_UPDATE_PUBKEY`.

A ready-to-install public APK is available from the app repository release
channel: <https://github.com/TrafficWrapper/app/releases/latest>. Treat the app
README and the release assets as the source of truth for the current APK file
name, version code, SHA-256, and signing certificate fingerprint.

## Telegram Bot

The bot is optional. Create a bot through BotFather, then set the token and owner
Telegram ID in the web admin Settings page. The token is encrypted in
`orch-state/orchestrator.db` and is never shown again.

Headless setup is also supported:

```sh
read -r -s TW_BOT_TOKEN
printf '%s\n' "$TW_BOT_TOKEN" | docker compose exec -T orchestrator \
  orchestrator bot set-token --stdin --owner-id 123456789
unset TW_BOT_TOKEN
```

## Security Notes

- Never commit `.env`, `orch-state/`, TLS keys, minisign private keys, APKs, or
  generated update keys.
- The config signing key is held by the signer process.
- Admin secrets can be supplied through stdin, env, or file; open `--value` and
  `--token` arguments are deprecated because they leak via shell history and
  process lists.
- The orchestrator stores secrets encrypted with AEAD in the local state DB.

## 💚 Support the project

This project is free and developed in spare time. If it helps you, any support is
appreciated — thank you!

- **Bitcoin (BTC):** `bc1qdlqer9rtej6tpzdjzljdwltj7vxr4h6tv9eucp`
- **Ethereum (ETH):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **USDT (ERC-20):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **TRON (TRX):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`
- **USDT (TRC-20):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`

Thank you for your support! 🙏

## License

MIT. See `LICENSE`.
