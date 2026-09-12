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
unsupported upstream protocol, bad limits/timeouts, unreadable CA file,
`default_port` missing from `allowed_ports` (every portless CONNECT would 403),
an `upstream.host` or allowlist entry that is not a bare hostname or IP (no
brackets, no port), and a negative `max_pending_handshakes`.

## Client use

```sh
curl -x http://pc-01:$GATEWAY_CLIENT_PC_01_SECRET@127.0.0.1:8080 https://example.com
```

Only allowlisted hostnames and allowed ports are accepted. DNS is resolved at
the gateway and pinned to a public IP. Private/loopback/link-local/metadata
addresses fail closed, including the IPv6 transition formats that embed an IPv4
address (6to4, NAT64, IPv4-compatible and IPv4-translated), reserved ranges and
cloud metadata addresses. No direct fallback to destination.

Allowlist entries are hostnames or bare IP literals, IPv4 or IPv6
(`2606:4700:4700::1111`); an entry carrying a port is rejected. An IPv6 target
is written `[addr]:port` in the CONNECT authority.

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
6. `max_pending_handshakes` caps connections accepted but not yet tunnelling, so
unauthenticated peers cannot each pin a header buffer; it defaults to
`4 * max_active` and answers 503 once full.
7. Stop with SIGINT/SIGTERM; the server stops accepting, waits out live tunnels,
then cancels in-flight DNS and upstream dials and force-closes both legs of
whatever is left, so shutdown cannot hang on an idle tunnel or a silent upstream.

Local success does not prove Internet IP masking. Multi-PC Internet
verification is deferred to M2 after M1 acceptance and infra decisions.
