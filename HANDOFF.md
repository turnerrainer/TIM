# HANDOFF

**Written**: 2026-07-30
**Last verified green**: 2026-07-30 — `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo build --release`, `cargo test --no-fail-fast` (25/0/0: 13 unit + 12 integration), `cargo audit --deny warnings` (1 documented exception in `.cargo/audit.toml`), `cargo deny check all`, `mdbook build book` (linkcheck error-strict), `docker build .`, `docker compose up -d` → `/health` responded in 2s, real JWT issued end-to-end. All exit 0.
**Branch**: `dev` (initial state; nothing pushed to remote yet)
**Release**: `v0.1.0-alpha.1` (Cargo.toml + CHANGELOG + VERSION) — not yet tagged / published.

This file is the entry point for the next contributor (human or agent). Read this, run the verification set, then dive into the specific files it points at.

## First-run checklist

1. **Open a fresh shell** in `/home/rainer/Desktop/Buerostack/TIM-on-Rust`.
2. **Bring up Postgres** — required for integration tests and local runs:
   ```bash
   docker compose up -d postgres
   ```
3. **Run the verification set** (release gate):
   ```bash
   export TIM_DATABASE_URL=postgres://tim:changeme@localhost:5432/tim
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo build --release
   cargo test --no-fail-fast
   cargo audit --deny warnings
   cargo deny check all
   ( cd book && mdbook build )
   ```
4. **Smoke test the container** end-to-end:
   ```bash
   docker compose up -d --build
   curl -sf http://localhost:8085/health
   ```

## Release state at handoff

- **Cargo.toml `version = "0.1.0-alpha.1"`**, CHANGELOG `[0.1.0-alpha.1] - 2026-07-30`, `VERSION` = `0.1.0-alpha.1`, `docker-compose.yml image: tim:0.1.0-alpha.1`. All aligned.
- Not yet tagged. First publish is a manual step by the maintainer:
  1. `gh repo create turnerrainer/tim --public --source .`
  2. Enable Pages: `gh api repos/turnerrainer/tim/pages -X POST -f 'build_type=workflow'`
  3. Workflow permissions Read+Write:
     `gh api repos/turnerrainer/tim/actions/permissions/workflow -X PUT -F 'default_workflow_permissions=write' -F 'can_approve_pull_request_reviews=false'`
  4. Create Docker Hub repo at <https://hub.docker.com/repositories/turnerrainer> → New repository → `tim` → Public.
  5. Generate a repo-scoped Docker Hub PAT (Read + Write + Delete on `turnerrainer/tim` only).
  6. Set secrets:
     ```bash
     gh secret set DOCKERHUB_USERNAME --repo turnerrainer/tim --body 'turnerrainer'
     echo -n '<token>' | gh secret set DOCKERHUB_TOKEN --repo turnerrainer/tim
     ```
  7. Push branch + tag:
     ```bash
     git push -u origin dev
     git tag -a v0.1.0-alpha.1 -m "TIM v0.1.0-alpha.1 — first alpha release"
     git push origin v0.1.0-alpha.1
     ```
  8. After first publish, link GHCR package to the repo with **Write**
     role — see DEV-REQUIREMENTS §9.1 step 7.

## What this repo IS today

Working REST API in Rust for JWT / OAuth2 / introspection, packaged
as a multi-stage container image. Feature-parity with the JVM TIM
2.0 across the endpoints enumerated in [`docs/DESIGN.md`](./docs/DESIGN.md).

- **`POST /jwt/custom/generate`** — RS256-signed JWT with custom
  claims, optional audience, configurable expiration. Persists
  metadata to `custom_jwt.jwt_metadata`; chain root =
  `original_jwt_uuid = jti`.
- **`POST /jwt/custom/validate`** — signature + expiration +
  denylist + optional audience/issuer.
- **`POST /jwt/custom/validate/boolean`** — same, `true` / `false`.
- **`POST /jwt/custom/extend`** — new token with preserved claims,
  old token denylisted, chain linkage recorded.
- **`POST /jwt/custom/revoke`** — single-token denylist.
- **`POST /jwt/custom/revoke/bulk`** — up to 100 per request,
  configurable via `jwt.bulk_revoke_max`.
- **`POST /jwt/custom/list/me`** — paginated caller-token listing
  (bearer JWT in `Authorization`).
- **`GET /jwt/keys/public`** — JWKS with the signing public key.
- **`POST /introspect`** (form + JSON) + **`GET /introspect/types`** —
  RFC 7662 shape.
- **`GET /auth/providers`**, **`GET /auth/login/{provider_id}`**,
  **`GET /auth/callback/{provider_id}`**, session validate /
  profile / logout — OAuth2/OIDC MVP (session storage in-process).
- **`GET /health`** — `{"status":"ok"}`.

## Verification set

Every command MUST exit 0:

```bash
export TIM_DATABASE_URL=postgres://tim:changeme@localhost:5432/tim
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release --bin tim
cargo test --no-fail-fast
cargo audit --deny warnings
cargo deny check all
( cd book && mdbook build )
```

Live smoke:

```bash
docker compose up -d --build
sleep 5
curl -sf http://localhost:8085/health
```

## Roadmap

See `tasks/backlog/` for full detail. Immediate next work items:

| Task | What |
|---|---|
| 002 | Postgres-backed OAuth2 session store (replaces MVP in-process DashMap) |
| 003 | PKCE flow completion (columns exist; end-to-end wiring pending) |
| 004 | Prometheus metrics endpoint |
| 005 | JWKS caching layer for introspection of externally-issued tokens |

## For the next Claude session

Read, in order:

1. **[`../DEV-REQUIREMENTS.md`](../DEV-REQUIREMENTS.md)** — the
   ruleset. Non-negotiable unless a deviation is justified in
   the commit message.
2. **[`./STANDARDS.md`](./STANDARDS.md)** — project-specific extras.
3. **[`./docs/DESIGN.md`](./docs/DESIGN.md)** — domain model +
   endpoint catalog + DB schema.
4. **This HANDOFF.md** — release state + roadmap.

Common questions answered by files in this repo:

| Question | See |
|---|---|
| How is `Cargo.toml` structured? | `Cargo.toml` |
| What are the CI workflows? | `.github/workflows/` |
| How is the container built? | `Dockerfile` + `docker-compose.yml` |
| What DB schema does TIM use? | `migrations/` + `docs/DESIGN.md` §4 |
| How is a task file structured? | any file under `tasks/done/` |
| Where does the book live? | `book/src/` |

## Where to look for more detail

| Topic | File |
|---|---|
| Cross-project ruleset (authoritative) | [`../DEV-REQUIREMENTS.md`](../DEV-REQUIREMENTS.md) |
| Domain design (TIM-specific) | [`./docs/DESIGN.md`](./docs/DESIGN.md) |
| Project-specific standards addendum | [`./STANDARDS.md`](./STANDARDS.md) |
| Full change history | [`./CHANGELOG.md`](./CHANGELOG.md) |
| Private security disclosure | [`./SECURITY.md`](./SECURITY.md) |
| CI workflows | [`.github/workflows/`](./.github/workflows/) |
| Public docs | `https://turnerrainer.github.io/TIM/` (once published) |
