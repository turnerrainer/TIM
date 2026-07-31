# SECURITY

## Reporting a vulnerability

**Please do not open a public issue.** Report privately via one of:

1. **GitHub private security advisories** (preferred) — click "Report
   a vulnerability" on the repository's Security tab.
2. **Email** — `rainer.turner@gmail.com`. Encrypt with the maintainer's
   public key if the finding is sensitive.

## Response commitments

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Triage decision (accept / reject / need info) | 7 business days |
| Fix + advisory for CRITICAL / HIGH | 30 days |
| Fix + advisory for MEDIUM | 90 days |
| LOW / hardening suggestions | Best effort, batched into next release |

If a fix requires a coordinated disclosure across dependent projects
we will negotiate a longer embargo with the reporter.

## Supported versions

Only the latest minor version receives security patches. Older
versions are considered end-of-life.

| Version | Status |
|---|---|
| 0.1.x | Supported |
| < 0.1.0 | Not applicable — pre-release history |

## Supply-chain posture

CI (see `.github/workflows/security.yml`) enforces on every push,
PR, and daily 06:00 UTC cron:

- `cargo audit --deny warnings` — advisory database + explicit
  exception list at `.cargo/audit.toml` (mirrored to `deny.toml`),
  every exception carries a rationale and a review date.
- `cargo deny check all` — license allow-list (no GPL / AGPL /
  SSPL), no wildcards, warn on duplicate versions, crates.io-only
  sources.

Release publish (see `.github/workflows/publish.yml`) enforces:

- Trivy vulnerability scan on the built image before signing —
  HIGH / CRITICAL fixed CVEs block the release.
- Cosign keyless signing via GitHub OIDC on both Docker Hub and
  GHCR digests.
- Provenance (`mode=max`) and SBOM (SPDX) attestations attached.
- Reproducible layer timestamps (`SOURCE_DATE_EPOCH` from commit
  time; `rewrite-timestamp=true` on Buildx).
- Multi-arch smoke test (`linux/amd64` + `linux/arm64`) before
  signing.

Container runtime posture (see `docker-compose.yml`):

- Non-root uid 1000.
- `cap_drop: ALL`, `no-new-privileges: true`.
- `read_only: true` root filesystem, `tmpfs: /tmp:64M` for scratch.
- Resource limits (2 CPU, 512M memory).

## Out of scope

TIM is a token / identity issuer. It does **not** provide:

- Secret storage — mount your private key and database URL from
  your secret manager.
- Rate limiting — deploy behind an ingress that provides it.
- Persistent sessions across pods — MVP session storage is
  in-process (see STANDARDS §Project-specific extras).
- Password authentication — no local user database.
