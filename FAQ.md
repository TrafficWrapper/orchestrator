# FAQ

🇷🇺 Русская версия: [FAQ.ru.md](FAQ.ru.md)

## What is TrafficWrapper?

TrafficWrapper is a public, self-hosted anti-censorship tunnel platform. It has
an orchestrator control plane, worker data-plane nodes, and an Android public
client.

## What is it not?

It is not an Android VPN service. The Android app exposes a local SOCKS
front-end and carries selected traffic through user-space transports configured
by signed deployment config.

It is not a hosted anonymity service. Operators choose and operate their own
infrastructure.

## Is it legal to run?

TrafficWrapper cannot give legal advice. Self-hosters and contributors are
responsible for local law, hosting-provider terms, sanctions/export rules, and
operational risk in their own jurisdiction.

## Why are there two bundles?

`worker-config-v1` is private to workers and contains material needed to apply
per-device transport state. `client-config-v1` is public to enrolled devices and
contains active workers, routes, and update/distributor metadata.

Both are signed so workers and devices can verify exact `config_json` before
applying it.

## Why is config signed?

Config signing protects devices from accepting unsigned or modified deployment
state. The signer process holds the config minisign key behind
`ORCH_SIGNER_SOCKET`; the web/admin process does not keep the private signing key
in memory.

## Why must I trust workers?

A worker is an exit node and a decryption point. AWG terminates on the worker,
so the worker can observe decrypted egress traffic after tunnel termination. Do
not attach devices to workers you do not trust operationally.

## Can I run only one worker?

Yes. A single worker is enough for a small deployment or development stand. More
workers improve redundancy and route choices but also increase operational
surface.

## Is iOS or desktop supported?

No. The public app scope is Android plus the shared Go transport core. iOS and
desktop clients are out of scope unless contributors design and maintain them.

## How is this different from a normal VPN or Amnezia?

TrafficWrapper is not a system VPN profile. It uses a local SOCKS front-end and
signed per-deployment config to select REALITY or AmneziaWG routes. The platform
also includes owner approval, per-device bootstrap, signed config, and
in-tunnel update/distributor paths.

## How do updates work?

The owner publishes APK metadata and a signed update manifest. The app accepts an
update only when the manifest verifies, the APK signing certificate matches the
pinned SHA-256 fingerprint, and the version is newer than the installed app.

## Does TrafficWrapper collect telemetry?

Telemetry is opt-in. The app and worker paths are designed so deployment owners
can operate without publishing real infrastructure details in public channels.
