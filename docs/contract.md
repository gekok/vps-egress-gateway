# Module contract (Foundation - #2)

Flow: create -> relay -> cleanup.

```
client CONNECT -> access.Authenticate -> access.Policy.AuthorizeTarget
  -> gateway limiter.acquire -> upstream.Dialer.Dial (pinned IP only)
  -> 200 to client -> relayTunnel opaque bytes -> cleanup + limiter.release
```

Ownership:
- internal/config owns Config schema and validation; secrets only via env.
- internal/access owns auth, allowlist, DNS resolve + pin, fail-closed policy.
- internal/upstream owns HTTP/HTTPS/SOCKS5 dialers; sockets only to upstream.
- internal/gateway owns listener, limits, relay, shutdown, redacted logs.
- internal/testutil + tests/integration own fakes and regression matrix.

Rules:
- No direct dial to destination; pinned IP from policy is the only dial target,
  and every upstream socket is pinned to the configured upstream address.
- A destination address must be public under the reserved-range table in
  internal/access, which covers IPv6 formats that embed an IPv4 address.
- Client credential never goes upstream; upstream credential never enters tunnel/log.
- 200 only after upstream success; after 200, close tunnel instead of HTTP/JSON.
- Every acquire has exactly one release; every conn closed; no secret in logs.
- Early bytes the upstream packs in with its CONNECT response are handed to the
  caller exactly once; the tunnel must never replay them.
- Every upstream handshake runs under a deadline, and every conn (client and
  upstream leg) is tracked so shutdown can force-close it.
- Request line and header reads are byte-capped, so a peer that never sends a
  newline cannot grow a buffer without bound.
- TLS content stays opaque; gateway never terminates client TLS.
