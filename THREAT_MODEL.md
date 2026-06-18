# TrafficWrapper Threat Model

[Русский](THREAT_MODEL.ru.md)

TrafficWrapper is self-hosted. Operators control their infrastructure choices and
must avoid publishing deployment-specific identifiers in public issues, pull
requests, logs, screenshots, or examples.

## What a Self-Hoster Exposes

A real deployment can expose:

- the worker's public IP address and open REALITY/AWG ports;
- the domain or SNI values used for camouflage;
- the fact that the host is running anti-censorship infrastructure;
- timing and traffic-volume patterns visible to hosting providers or networks;
- links between public support/donation addresses and deployment identity if the
  operator reuses public identifiers.

TrafficWrapper reduces casual discovery, but it does not make hosting anonymous.

## Trust Roles

- **Owner/admin:** approves workers and devices, publishes config, and controls
  APK update metadata.
- **Orchestrator:** source of truth for approved workers/devices and signed
  bundles. Compromise can enroll or remove infrastructure and publish malicious
  config.
- **Config signer:** single point of failure for `client-config-v1`. If the
  signer private key or signer socket is compromised, an attacker can redirect
  all devices that trust that config key.
- **Worker:** exit node and decryption point. After AWG terminates on the worker,
  the worker can observe decrypted traffic leaving the tunnel. Do not connect to
  untrusted workers.
- **Worker agent:** has access to `docker.sock` so it can restart/materialize
  Xray and AWG state. Treat it as privileged host-adjacent code.
- **Android app:** enforces bootstrap confirmation, minisign config/update
  verification, APK certificate pinning, and local route selection.

## Noise Pinning

Workers set `ORCH_STATIC_PUBLIC_KEY`. Device bootstrap payloads include
`orch_noise_public`. Both pin the orchestrator Noise static public key before
Noise_XK exchanges over HTTPS. TLS provides a carrier; orchestrator authenticity
comes from the pinned Noise key.

The Noise envelope is defined in `orchestrator/internal/protocol/protocol.go`:
prologue `TrafficWrapper orchestrator worker v1`, DH25519, ChaChaPoly, SHA256,
and encrypted framed JSON. Pinning prevents a network attacker from replacing
the orchestrator during worker or device enrollment unless they also control the
pinned Noise private key or the bootstrap material.

## Key Roots

TrafficWrapper intentionally separates four key roots:

1. **Config-signing minisign key:** generated and held by the signer process,
   reached through `ORCH_SIGNER_SOCKET`; signs `client-config-v1` and
   `worker-config-v1`.
2. **Update minisign key:** owner-controlled offline key for APK update
   manifests; seed-on-first-run keys are demo/bootstrap only.
3. **Android APK signing certificate:** offline release keystore. Devices accept
   updates only when the APK certificate matches the pinned SHA-256 fingerprint.
4. **Noise static keys:** orchestrator, worker, and device keys used for
   enrollment and authenticated encrypted envelopes.

Keep these roots isolated. Do not reuse the update key as a config key. Do not
store release keystores, minisign private keys, `.env`, `orch-state/`, or
`worker-state/` in Git.

## Unsafe Defaults

`example.com`, `example.org`, generated seed update keys, default local
passwords, self-signed dev TLS, and copied example AWG dialects are not
production settings. The worker agent refuses placeholder `CAMOUFLAGE_DOMAIN`
values; operators still need to choose a real TLS 1.3 camouflage domain that
fits their deployment and jurisdiction.

## Jurisdiction

Operators and contributors are responsible for understanding local laws, hosting
provider terms, and export or sanctions restrictions that apply to their own
use. The project cannot evaluate the legality of a specific deployment.
