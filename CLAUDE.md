# CLAUDE.md

Instructions for LLM agents working on this repo. User-facing docs
live in `README.md` and the book at `book/src/`.

## What TIM is

Token Identity Manager — Rust reimplementation of `buerokratt/TIM`.
Custom JWT lifecycle (generate / validate / extend / revoke / list)
+ OAuth2/OIDC multi-provider authentication + RFC 7662 token
introspection, backed by PostgreSQL.

- **Current version:** `0.3.0-alpha` (see `Cargo.toml`, `CHANGELOG.md`).
- **Last tag:** `v0.2.1-alpha` — v0.3.0-alpha is staged on branch
  `release/0.3.0-alpha` and not yet pushed as a tag.
- **Docs:** the mdBook under `book/src/` is authoritative for
  operator-facing behaviour. `CHANGELOG.md` (top-level) is the
  canonical release log; `book/src/reference/changelog.md` is a
  manually-maintained mirror — copy the top-level file over the
  book copy when cutting a release (the two are byte-identical
  as of 0.3.0-alpha). No auto-regeneration hook wired up.

## Breaking / behaviour changes since v0.2.1-alpha

Read `CHANGELOG.md` under `## [0.3.0-alpha]` for the full narrative.
The one thing that will bite operators on upgrade:

**OIDC discovery is now fail-closed on plain HTTP.** Both the
configured `discovery_url` and the endpoints *returned inside the
discovery document* (`authorization_endpoint`, `token_endpoint`,
`jwks_uri`) must be `https://` or startup / login refuses. Escape
hatch: `oauth2.providers.<id>.allow_http_discovery: true`.

Find affected configs:

```bash
grep -rnE 'discovery_url:\s*http://' /path/to/tim.yaml /path/to/config/
```

Two soft changes (log-volume alerts, monitoring dashboards keyed
on JWT `reason` strings) — see the CHANGELOG's "Upgrading from
0.2.x" section.

**No schema migration required.** The `pkce_verifier` column has
existed in `migrations/0001_init.sql` since the first alpha.

## Verification loop

Run before + after any code change:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --no-fail-fast -- --test-threads=1
cargo audit --deny warnings
cargo deny check all
```

Integration tests need Postgres reachable via `TIM_DATABASE_URL`.
Locally that's the `tim-postgres` container from `docker-compose.yml`:

```bash
TIM_DATABASE_URL=postgres://tim:timtest@127.0.0.1:5432/tim \
  cargo test --release --test <name> -- --test-threads=1
```

The container's actual `POSTGRES_PASSWORD` differs from the compose
default (`changeme`) — check the running container:

```bash
docker inspect tim-postgres --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -i password
```

**Serial execution matters.** Integration binaries share the same
Postgres schema and coordinate via an advisory lock in
`tests/common/mod.rs`. Always pass `--test-threads=1`.

## Code layout to know before editing

- `src/oauth2/flow.rs` — hot spot; touched by 4 of the last 9
  audit PRs (PKCE, state race, HTTPS-strict discovery, JWKS pin).
  Any change here is likely to conflict with concurrent branches.
- `src/config/mod.rs` — `AppConfig` uses `serde(deny_unknown_fields)`.
  Every nested struct needs full field coverage in test literals
  (no `..Default::default()` for `ProviderConfig`, which doesn't
  derive `Default`). Recent additions to `ProviderConfig`:
  `allow_http_discovery: bool` (v0.3.0-alpha, PR #6) and
  `jwks_uri: Option<String>` (v0.3.0-alpha, PR #10).
- `migrations/` — sqlx-managed, applied at startup when
  `database.auto_migrate: true`. Do **not** edit already-released
  migrations; add new ones instead. (Historically PR #3 got away
  with the `pkce_verifier` column being in 0001 because the column
  was reserved from the first alpha — this is not a pattern to
  repeat.)
- `book/src/` — mdBook. `book/book.toml` runs
  `mdbook-linkcheck` and fails on broken internal links. External
  URLs are skipped (`follow-web-links = false`) to avoid CI flakes.

## PR / branch conventions observed on this repo

- One audit-finding cluster per PR (`fix/h1-*`, `fix/m1-*`,
  `fix/low-*`).
- Each PR gets its own CHANGELOG entry under `[Unreleased]`; the
  release commit rolls them into a dated version header.
- **Cost of the per-PR CHANGELOG convention:** cascading conflicts
  when merging a batch. For the v0.3.0-alpha batch (9 PRs),
  CHANGELOG was the *only* real conflict in 6 of 7 rebase cycles.
  If you're helping plan a future batch, propose deferring CHANGELOG
  entries to a single release-notes PR.
- Base branch: `dev`. `main` is release-only.
- Force-push to PR branches is expected for rebase-on-conflict
  workflows. Use `--force-with-lease` with the current remote SHA.

## Shipping a breaking change

TIM is pre-1.0 (alpha). "Breaking" is a strict category —
anything that requires an operator to touch config, upgrade
downstream callers, or run a manual step. Everything else is
non-breaking, no matter what the release notes say.

### What counts as breaking

- Flipping a default that changes wire behaviour operators may be
  relying on. Example: `introspection.required_client_auth`
  `false → true` (audit FN1, deferred for 0.4.0-alpha) —
  every unauth `/introspect` request begins returning 401.
- Adding, renaming, or removing a field in a
  `#[serde(deny_unknown_fields)]` config struct such that a
  previously-valid `tim.yaml` no longer parses. Renaming should
  keep the old name via `#[serde(alias = "old_name")]` for one
  release before removal.
- Removing an HTTP endpoint, renaming a response body field,
  or flipping a status code for the same input (finding 16:
  `/jwt/custom/validate` went `200 → 401` on invalid tokens for
  JVM parity — breaking for anyone who was reading status).
- A new required env var, or a new config field without a
  `#[serde(default)]`.
- Any migration that alters an already-released schema in place
  (see migration rules below — avoid via additive-then-tighten).

### What does NOT count as breaking

- New endpoint, new response field, new optional config field
  with a default. Log under `### Added` in CHANGELOG.
- Fixing a bug so the wrong status now returns the right one, if
  no external contract was documenting the old behaviour. Log
  under `### Fixed`; not `### Upgrading`.
- Internal refactor with no wire-visible effect.

### Where the version bump happens

Version lives in three tracked files that must move together:

- `Cargo.toml` line 3 (`version = "..."`)
- `Cargo.lock` — regenerate with `cargo build`, do not edit by hand
- `VERSION` — top-level, one line

For an alpha, the bump is `0.X.0-alpha → 0.(X+1).0-alpha`. We do
not do patch bumps during alpha; every batch is a minor.

### CHANGELOG discipline

`CHANGELOG.md` is canonical; `book/src/reference/changelog.md`
mirrors it byte-for-byte (see "Docs" bullet at the top of this
file). Per-PR entries land under `## [Unreleased]` in one of
`### Added`, `### Changed`, `### Removed`, `### Fixed`,
`### Security`. Mark breaking entries with `**BREAKING**` at the
start of the line.

At release cut:

1. Roll `[Unreleased]` into a dated version header
   `## [0.X.0-alpha] — YYYY-MM-DD`.
2. Add `### Upgrading from 0.(X-1).y-alpha` immediately below,
   listing every default that flipped, every config field that
   must change, every migration that must run, every downstream
   that must be re-configured. This section is the operator's
   punch list — it is not optional.
3. Copy the top-level file byte-for-byte over
   `book/src/reference/changelog.md`.

### Migrations

`migrations/` is sqlx-managed and applied at startup when
`database.auto_migrate: true`. **Every already-released migration
is immutable.** Never edit `migrations/0001_init.sql` or any
subsequent released file. Always add a new file with the next
number.

For schema shifts driven by a breaking change:

- Additive first — new column NULLable or with a `DEFAULT` so
  the previous code version can still write to the table.
- Then a code deploy that reads/writes the new shape.
- Then a later migration that tightens (NOT NULL, drop old
  column) once operators have deployed the intermediate version.

Never destructive-in-place in the same migration that adds the
new shape.

### PR + branch shape for a breaking change

- Branch name: `fix/<slug>` for a fix-shaped break (rare —
  usually a security default flip), `feat/<slug>` for a
  feature-shaped break, `breaking/<slug>` when the break itself
  is the point.
- **One breaking change per PR.** Never bundle two breaks; the
  operator's upgrade decision has to be atomic.
- PR body must include an `## Upgrading` section written from
  the operator's point of view. At release time the reviewer
  copy-pastes it into CHANGELOG.md `### Upgrading from …` —
  that copy-paste is the handoff.
- Base branch: `dev`. Do not push the version-bump commit on
  the fix branch itself. Version bumps live on
  `release/X.Y.Z-alpha`, which batches merged fix branches once
  the batch is ready.

### What an LLM must NOT do autonomously

- **Never flip a default without an explicit ask**, even when a
  finding says "flip in the next minor." Version bumps are a
  human decision.
- **Never create a `release/X.Y.Z-alpha` branch or tag** without
  being told. The maintainer cuts releases.
- **Never edit an already-released migration file.** Add a new
  one instead.
- **Never modify `main`.** It is release-only, pushed to by tag
  merges of release branches.
- **Never force-push a branch that has already been merged.**

If a change would require its own `### Upgrading from …` entry
in the CHANGELOG, treat it as breaking. Escalate to the
maintainer instead of shipping it.

## Where to look for context

- `CHANGELOG.md` — canonical history, including 0.3.0-alpha
  upgrade notes.
- `README.md` — user-facing intro + upgrade pointer.
- `book/src/` — mdBook: getting started, configuration, OAuth2/OIDC,
  security hardening, legacy compatibility, failure modes, and the
  API + config reference chapters.
- `STANDARDS.md` — project-specific addendum to Buerostack Rust
  standards (if present in the tree; check before referencing).
- `migrations/` — sqlx-managed SQL schema evolution.

Some maintainer-only governance artefacts (design docs, audit
inputs, handoff notes) may exist locally but are `.gitignore`d and
are not part of the public repo — do not assume the maintainer has
shared them, and do not surface pointers to them in tracked files.
