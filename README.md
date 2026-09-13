# VPS Egress Gateway - MVP local

Private CONNECT egress gateway: many PCs -> gateway -> third-party proxy -> destination.
TLS content stays end-to-end. One configured upstream per process. The gateway
fails closed and accepts only loopback connections in M1.

## Project status

The repository default branch is `main`. The current implementation is the
local MVP; VPS and third-party proxy deployment remain deferred until the M1
acceptance gate is complete.

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

Default listen is loopback only (`127.0.0.1:8080`). The JSON schema rejects
unknown keys and trailing values. Config fails startup on: bad listener,
missing client/env secret, duplicate client, empty allowlist, non-ASCII or
non-canonical hostname, unsupported upstream protocol, incomplete upstream
credentials, bad limits/timeouts, invalid CA bundle,
`default_port` missing from `allowed_ports` (every portless CONNECT would 403),
an `upstream.host` or allowlist entry that is not a bare hostname or IP (no
brackets, no port), a client id outside `[A-Za-z0-9._-]{1,64}` (it is echoed to
the log, so it must not be able to forge a log line), and a
`max_pending_handshakes` that is negative or above 1024. Limits also cap active
tunnels at 4096, new tunnels at 10000/s, each relay buffer at 1 MiB and the two
buffers per active tunnel at 256 MiB in total.

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
go test -count=1 -shuffle=on ./...
go test -race -count=1 -shuffle=on ./internal/... ./tests/...
go vet ./...
test -z "$(gofmt -l .)"
```

Tests use loopback fake HTTP/HTTPS/SOCKS5 upstreams and TLS echo targets.
No provider key or Internet required.

## Local runbook

1. Build: `go build -o gateway ./cmd/gateway` (Windows: `gateway.exe`).
2. Start an HTTP, HTTPS, or SOCKS5 forward proxy on loopback for the local smoke.
3. Copy `config.example.json` to `config.json`; set client and upstream secret
   environment variables; then run `./gateway --config config.json`.
4. Test: `curl -x http://<id>:<secret>@127.0.0.1:8080 https://<allowlisted-host>`.
5. Troubleshoot: 407 means client auth failed; 403 means host/port/DNS policy
rejected; 502/504 means upstream failed; 429/503 means limits; check redacted
gateway logs without secrets.
6. `max_pending_handshakes` caps connections accepted but not yet tunnelling;
the listener reserves that slot before it starts a handler. It defaults to
`min(4 * max_active, 1024)`, and answers 503 once full. Kernel backlog, firewall
rate limits, TLS/VPN for PC-to-VPS, log rotation and outbound egress rules are
M2 deployment work.
7. Stop with SIGINT/SIGTERM; the server stops accepting, waits out live tunnels,
then cancels in-flight DNS and upstream dials and force-closes both legs of
whatever is left, so shutdown cannot hang on an idle tunnel or a silent upstream.
   A TCP half-close is propagated when the transport supports it, so a destination
   can still return a response after the client finishes its upload.

Local success does not prove Internet IP masking. Multi-PC Internet
verification is deferred to M2 after M1 acceptance and infra decisions.
