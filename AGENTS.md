# AGENTS.md - VPS Egress Gateway (MVP local)

Scope: M1 local only. No VPS/proxy deployment, no Internet IP verification in this change.

Ownership: cmd/gateway + internal/gateway (Core), internal/config (Config), internal/access (Security), internal/upstream (Transport), internal/testutil + tests/integration (QA), .github/workflows + docs (DevEx).

Rules:
- One issue, one owner; PR references Closes #N and dependencies.
- Do not modify shared files outside scope without owner coordination.
- No User-Agent editing, TLS interception, API translation, DB, proxy rotation, or whole-PC proxying.
- No secrets, real chat content, or personal data in issues/PRs/artifacts.
- Close only with review + merge + acceptance evidence: commands, outputs, exit codes, or CI links.
- Local tests do not prove Internet IP masking; M2 has a separate multi-PC verification.
