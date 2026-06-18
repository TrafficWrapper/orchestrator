# Changelog

🇬🇧 English: [CHANGELOG.md](CHANGELOG.md)

Все заметные изменения этого repository документируются здесь.

Формат основан на [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), а
project следует [Semantic Versioning](https://semver.org/spec/v2.0.0.html) для
public releases.

## [Unreleased]

### Added

- Канонические troubleshooting, FAQ, development и owner runbook docs.
- Secret-scan workflow для contributor PR hygiene.

## [0.1.0] - 2026-06-18

### Added

- Initial public orchestrator split с owner admin UI, worker approval,
  per-device bootstrap, Noise_XK enroll/pull, minisign-signed client config,
  APK publication metadata, optional Telegram bot и isolated signer process.
- Contributor onboarding docs, architecture notes, threat model, security
  policy references и CI workflow.
- Русские documentation mirrors для существующих public docs.

### Changed

- APK publishing docs теперь указывают на app release channel вместо stale APK
  version/checksum в orchestrator docs.
