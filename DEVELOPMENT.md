# Development

🇷🇺 Русская версия: [DEVELOPMENT.ru.md](DEVELOPMENT.ru.md)

This guide is for a local development stand on one machine. It is not a
production deployment guide. For the owner-facing flow, start with the
end-to-end section in [README.md](README.md#start-here-end-to-end-flow).

## Layout

Use a parent workspace with all three public repositories:

```sh
mkdir -p tw-dev
cd tw-dev
git clone https://github.com/TrafficWrapper/orchestrator.git
git clone https://github.com/TrafficWrapper/worker.git
git clone https://github.com/TrafficWrapper/app.git
```

## Start the orchestrator

```sh
cd orchestrator
cp .env.example .env
docker compose up -d --build signer orchestrator
docker compose logs orchestrator | grep -i 'initial admin password'
docker compose exec orchestrator orchestrator public-key
```

The default local stand uses self-signed TLS:

```sh
ORCH_TLS=1
ORCH_PUBLIC_URL=https://127.0.0.1:9091
```

Use `curl -k` for local API calls against this self-signed listener.

## Create a worker token with the admin API

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
  --data "{\"id\":\"worker-dev\",\"value\":\"$WORKER_TOKEN\",\"ttl\":\"48h\"}" \
  "$ORCH_URL/admin/v1/token/create"
```

Keep `WORKER_TOKEN` in your shell history only for disposable local stands.

## Start a same-host worker

```sh
cd ../worker
cp .env.example .env
```

Set at least:

```sh
ORCH_URL=https://host.docker.internal:9091
ORCH_STATIC_PUBLIC_KEY=<output of orchestrator public-key>
ORCH_INSECURE_TLS=1
ENROLL_TOKEN=<WORKER_TOKEN>
PUBLIC_ADDRESS=127.0.0.1
CAMOUFLAGE_DOMAIN=<real TLS 1.3 domain for dev testing>
APPLY_NFT=0
```

Then start:

```sh
docker compose up -d --build
```

Approve the pending worker in the orchestrator admin UI. Keep `APPLY_NFT=0` for
local development unless you have reviewed the generated firewall/NAT rules.

## Create and import a device bootstrap

Use **Devices** -> **+ New device** in the admin UI, or call the admin API:

```sh
EXPIRES=$(date -u -d '+24 hours' +%Y-%m-%dT%H:%M:%SZ)
curl -ksS -H "authorization: Bearer $SESSION_TOKEN" \
  -H 'content-type: application/json' \
  --data "{\"limits\":{},\"expires\":\"$EXPIRES\"}" \
  "$ORCH_URL/admin/v1/bootstrap-token/create"
```

Transfer the QR, Base64, or JSON bootstrap to the Android app and confirm the
parsed `orchestrator_url` and `config_pubkey_pin`.

## Build the Android debug app

```sh
cd ../app
./build/build-apk.sh
```

Install the debug APK on a test device or emulator, import the bootstrap, and
try a request through the local SOCKS front-end or an app integration that uses
it.

## Test commands

```sh
# orchestrator
go test ./...

# worker
(cd agent && go test ./...)
(cd awg-gw && go test ./...)
(cd awg-smoke && go test ./...)
(cd core && go test ./...)

# app
(cd core && go test ./...)
(cd client && ./gradlew :app:testPublicDebugUnitTest)
```

## Development vs production

- `ORCH_INSECURE_TLS=1` is for self-signed local TLS only.
- `ORCH_PUBLIC_URL=https://127.0.0.1:9091` is not reachable by real remote
  devices.
- `PUBLIC_ADDRESS=127.0.0.1` is only useful for same-host experiments.
- `APPLY_NFT=0` avoids automatic firewall/NAT changes during development.
- Production workers need real public ports, a real `CAMOUFLAGE_DOMAIN`, and
  deployment-specific keys.
