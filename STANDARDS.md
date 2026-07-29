# STANDARDS

TIM-on-Rust follows every rule in
[`../DEV-REQUIREMENTS.md`](../DEV-REQUIREMENTS.md) — the authoritative
Buerostack Rust ruleset, compiled from Ruuter-on-Rust and XTR
experience. Read that file front-to-back before touching this repo.

This file lists the small set of project-specific extras and
codifies where TIM-on-Rust deviates (with justification) from the
generic ruleset.

## Project-specific extras

### 1. Database is Postgres — real, not mocked

Per DEV-REQUIREMENTS §3, integration tests must not mock the
database. TIM-on-Rust integration tests connect to a real Postgres
instance. Locally this is `docker compose up postgres`; in CI it is
a service container (see `.github/workflows/tests.yml`).

If you find yourself reaching for a mock, stop — the whole point of
the rule is that mock/prod divergence eventually causes an outage.

### 2. RSA private key is loaded once, at startup

The JWT signing key is loaded from a PKCS#8 PEM file at startup and
never re-read. To rotate:

1. Deploy a new instance with the new key path.
2. Verify JWKS at `/jwt/keys/public` shows the new `kid`.
3. Drain traffic from the old instance.

The old key's `kid` will disappear from JWKS. Downstream services
that cache JWKS with a TTL keep validating tokens signed with the
old key until the TTL expires. There is no in-process rotation
endpoint — this is deliberate; see DEV-REQUIREMENTS §5.3
("no admin HTTP endpoints").

### 3. Session storage is in-process (MVP)

The OAuth2 module's session cache is an in-process `DashMap`. This
is **explicitly not** production-grade for multi-instance deploys —
sessions do not survive process restart and do not span pods. The
Postgres-backed session store is tracked as a backlog task; until it
lands, deploy TIM-on-Rust behind a session-affinity load balancer
or as a single replica.

This constraint is documented in `book/src/oauth2.md` and in
`tim.yaml` next to the `session_store: "memory"` field.

## Deviations from DEV-REQUIREMENTS

None currently. Every `Deviation:` line in commit history is
enumerated here as it lands, per §0.

## Verification set

Every one of these MUST exit 0 before a release. See
`HANDOFF.md` for the exact one-liner.

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo test --no-fail-fast
cargo audit --deny warnings
cargo deny check all
( cd book && mdbook build )
docker build .
```
