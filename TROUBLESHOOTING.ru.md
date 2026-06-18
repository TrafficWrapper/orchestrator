# Устранение неполадок

🇬🇧 English: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

Это канонический troubleshooting guide для полного flow TrafficWrapper:
orchestrator -> worker -> device bootstrap -> Android app -> tunnel.

Не вставляйте реальные domains, IP addresses, SNI values, tokens, keys,
bootstrap payloads, worker state или device credentials в public issues.

## Orchestrator не стартует

Проверьте:

- `docker compose ps`
- `docker compose logs signer orchestrator`
- `.env` существует и `ORCH_STATE_DIR` writable
- `ORCH_SIGNER_SOCKET` указывает на один и тот же path для `signer` и
  `orchestrator`
- `ORCH_LISTEN` не занят другим process

Для local development ожидается дефолтный self-signed TLS listener:

```sh
ORCH_TLS=1
ORCH_PUBLIC_URL=https://127.0.0.1:9091
```

Для local admin API checks используйте `curl -k`. Не превращайте `-k` в
production привычку.

## Worker не enroll'ится

Проверьте эти значения на worker:

- `ORCH_URL` указывает на orchestrator URL, доступный из worker container.
- `ORCH_STATIC_PUBLIC_KEY` точно совпадает с `orchestrator public-key`.
- `ENROLL_TOKEN` — одноразовый worker token, созданный owner'ом.
- `ORCH_INSECURE_TLS=1` задан только когда orchestrator использует self-signed
  dev TLS.
- system clocks достаточно близки для token expiry checks.

Same-host Docker development обычно использует:

```sh
ORCH_URL=https://host.docker.internal:9091
ORCH_INSECURE_TLS=1
```

Если enrollment падает после partial attempt, создайте fresh token и проверьте
orchestrator logs на rejected reason.

## Worker остаётся pending

Enrollment только создаёт pending worker. Owner должен approve'ить его в admin
UI или admin API, прежде чем worker получит signed config.

Проверьте worker list в orchestrator admin UI. Approval worker'а повышает
desired config sequence; worker вскоре должен pull config и отправить ack.

## Worker отклоняет `CAMOUFLAGE_DOMAIN`

Worker fails closed, когда `CAMOUFLAGE_DOMAIN` пустой, `example.com` или
`example.org`. Задайте реальный TLS 1.3 domain, подходящий вашему deployment.

Не копируйте public example value в production. Camouflage domain является
частью deployment fingerprint.

## Device bootstrap invalid или expired

Bootstrap payloads одноразовые и time-limited. Если import или enrollment
падает:

- создайте новый bootstrap через **Devices** -> **+ New device**;
- проверьте, что app просит confirmation и показывает ожидаемые
  `orchestrator_url` и `config_pubkey_pin`;
- убедитесь, что device может reach `orchestrator_url`;
- проверьте, что device clock не сильно отличается от реального времени.

Не переиспользуйте старый QR, Base64 или JSON bootstrap после failed enrollment.

## App пишет, что нет route, или не подключается

Проверяйте platform в таком порядке:

1. Worker approved и active в orchestrator.
2. Worker ack time свежий.
3. Client config signed и загружен app.
4. App имеет хотя бы один route, policy которого matches requested traffic.
5. Public ports REALITY и AWG доступны из сети device.
6. Worker `/tw/` distributor доступен внутри tunnel.

Если REALITY unhealthy, AWG должен оставаться fallback, когда worker и device
materialization актуальны.

## Egress probe mismatch

Orchestrator может сравнивать advertised worker egress с worker
self-description/probe result. Mismatch обычно означает:

- `PUBLIC_ADDRESS` или `EGRESS_IP` неверен;
- host имеет несколько outbound interfaces;
- NAT или provider routing меняет observed source address;
- `ORCH_EGRESS_PROBE_URL` указывает не на тот worker.

Задайте явный `EGRESS_IP` на worker, если auto-detection ошибается.

## Distributor `/tw/` недоступен

Distributor намеренно доступен только внутри tunnel. Он не должен быть exposed
как public clearnet website.

Проверьте:

- container `distributor` запущен;
- `worker-state/distributor` существует и mounted read-only в nginx;
- AWG gateway healthy;
- Xray REALITY fallback destination может reach distributor path;
- app проверяет `/tw/` через selected tunnel route, а не напрямую из clearnet.

## APK update не виден

Проверьте:

- APK metadata опубликованы в orchestrator.
- App может fetch signed client config через tunnel.
- Update manifest minisign key совпадает с update public key, pinned во время
  bootstrap/enrollment.
- APK подписан pinned Android signing certificate.
- `versionCode` выше installed version.

Публикация config или APK metadata не обходит signature checks в app.
