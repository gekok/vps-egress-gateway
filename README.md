# VPS Egress Gateway - MVP local

Private CONNECT egress gateway: many PCs -> gateway -> third-party proxy -> destination.
TLS content stays end-to-end. Single upstream. Fail-closed. Local MVP only.

Out of scope: User-Agent editing, TLS interception, provider API translation,
prompt/token accounting, whole-PC proxying, proxy rotation, DB, production deploy.

## Build

```sh
go build ./...
```

## Configure

Copy `config.example.json` to `config.json`, set secrets only via env:

```sh
export GATEWAY_CLIENT_PC_01_SECRET='pc-01-secret'
export GATEWAY_CLIENT_PC_02_SECRET='pc-02-secret'
export GATEWAY_UPSTREAM_USER='upstream-user'
export GATEWAY_UPSTREAM_PASS='upstream-pass'
./gateway --config config.json
```

Default listen is loopback only (`127.0.0.1:8080`). Config fails startup on:
bad listener, missing client/env secret, duplicate client, empty allowlist,
unsupported upstream protocol, bad limits/timeouts, unreadable CA file.

## Client use

```sh
curl -x http://pc-01:$GATEWAY_CLIENT_PC_01_SECRET@127.0.0.1:8080 https://example.com
```

Only allowlisted hostnames and allowed ports are accepted. DNS is resolved at
the gateway and pinned to a public IP. Private/loopback/link-local/metadata
addresses fail closed. No direct fallback to destination.

## Run tests

```sh
go test ./...
go test -race ./internal/... ./tests/...
go vet ./...
gofmt -l .
```

Tests use loopback fake HTTP/HTTPS/SOCKS5 upstreams and TLS echo targets.
No provider key or Internet required.

## Local runbook

1. Build: `go build -o gateway ./cmd/gateway`.
2. Start fake upstream for smoke (example: local forward proxy on 127.0.0.1:3128).
3. Create `config.json` from example, export env secrets, start `./gateway --config config.json`.
4. Test: `curl -x http://<id>:<secret>@127.0.0.1:8080 https://<allowlisted-host>`.
5. Troubleshoot: 407 means client auth failed; 403 means host/port/DNS policy
rejected; 502/504 means upstream failed; 429/503 means limits; check redacted
gateway logs without secrets.
6. Stop with SIGINT/SIGTERM; server drains tunnels then force-closes leftovers.

Local success does not prove Internet IP masking. Multi-PC Internet
verification is deferred to M2 after M1 acceptance and infra decisions.
