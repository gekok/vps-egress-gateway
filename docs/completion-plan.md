# M1 completion plan

Branch: `feat/complete-gateway`, based on PR #18 head `4c9c9e6` plus local
Windows test fix `24e88b8`. The owner's request authorizes completing M1 code;
real infrastructure and multi-PC Internet acceptance remain M2 (#15, #16).

## Scope and impact (L3)

- Config -> access -> upstream -> gateway -> CLI: validate before opening a
  listener, bound allocations and time conversions, retain the existing schema.
- Gateway: admission before spawning handlers, shared bidirectional idle timeout,
  half-close, cancellation and deterministic cleanup; keep CONNECT data opaque.
- Transport: cancel blocked CONNECT I/O promptly and retain buffered bytes once.
- Tests/fixtures: assert cleanup, per-client separation, authenticated three-proxy
  matrix, TLS/SSE/WSS, failures, limits and real CLI exit codes.
- CI/docs: executable checks, reproducible local commands and explicit acceptance
  evidence. No automatic merge, issue closure, infrastructure deployment or
  changes to user agent/provider API/account configuration.

## Traces and affected callers

`config.Load -> Config.Validate -> gateway.Serve -> New -> NewWithDeps`;
tests also call `NewWithDeps` with injected policy/dialer. Constructors must not
bypass limits. `access.Policy.AuthorizeTarget` produces the pinned target used by
all three upstream adapters. `ServeListener -> handleConn -> relayTunnel` owns
pending slots, limiter reservations and both sockets. All these modules and
their existing tests were read, along with PR #18 history and issues #1-#16.

## Implementation sequence

1. Bound and validate config; reject malformed authority and header inputs.
2. Correct admission/relay and upstream cancellation; add failure regressions.
3. Make fixtures close all connections and wait for handlers; extend real
   transport and CLI tests without provider credentials or external destinations.
4. Update executable CI checks, README and operational/acceptance documentation.
5. Independent agent self-review, full feature/security review, formatting/vet,
   race, integration and CLI checks. Fix blocking findings before handoff.

## Risks and verification

Explicitly reject configurations exceeding documented hard ceilings; defaults
and example configuration remain valid. Half-close must preserve the remaining
response and not keep idle sockets forever. Admission rejection cannot promise
delivery of an HTTP status to a peer concurrently writing unread bytes. Test the
observable rejection, cleanup and recovery, not a TCP scheduling assumption.

Run `go test -count=1 -timeout 3m ./...`, race checks, regression repeats for
changed concurrency paths, `go vet`, enforced gofmt/hygiene, and built-binary
checks. Record actual commands/exit codes and unverified requirements separately.
Live Codex/provider smoke (#12) and M2 require suitable endpoint/access; local
mock or TLS tests do not establish Internet IP hiding or provider compatibility.
