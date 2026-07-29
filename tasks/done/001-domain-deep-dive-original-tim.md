# 001 — Domain deep-dive: original JVM TIM

## Filed

2026-07-29 — kick-off task for the Rust rewrite. Before writing any
code, produce an authoritative domain map of the JVM TIM 2.0
codebase so the Rust rewrite has a checklist to hit.

## Landed

2026-07-30 — commit `<initial>`. Domain map committed as
[`docs/DESIGN.md`](../../docs/DESIGN.md). Covers: mission, module
layout, complete HTTP API surface (custom JWT + OAuth2 + introspect),
DB schema (custom_jwt + auth), config surface, crypto model, token
lifecycle, OAuth2 flow, introspection dispatcher, security posture
inventory, JVM bugs / gotchas to not repeat, deliberate Rust-side
non-goals.

## Severity

High. Every subsequent task uses `docs/DESIGN.md` as the acceptance
oracle — "does my Rust code do what §N says?"

## Motivation

The JVM TIM has ~50 Java files across 4 Maven modules and 30+
markdown files under `docs/`. Without a distilled reference, the
Rust rewrite will drift out of parity in ways that only surface as
"why doesn't X work like it did in the old TIM?" bug reports post
release. A canonical DESIGN.md up front prevents that.

## Fix / Design

Explore agent produced a comprehensive domain map covering:
- 4 Maven modules and their packages / classes / repositories
- 20+ REST endpoints with request/response shapes
- PostgreSQL schemas (`custom_jwt`, `auth`) with every column +
  index
- application.yml + oauth2-providers.yml configuration surfaces
- Crypto model (RS256, JKS keystore in JVM → PKCS#8 PEM in Rust)
- Token lifecycle including extension-chain modeling
- OAuth2 authorization code flow specifics
- 20 non-obvious gotchas for Rust port (Spring Data magic, AOP,
  Jackson polymorphism, multi-datasource, timezone handling, etc.)

Distilled into a single `docs/DESIGN.md` (~450 lines) organized
per DEV-REQUIREMENTS §4 (structured, tabular where structured,
no prose paragraphs listing tabular info).

## Acceptance

- [x] `docs/DESIGN.md` committed
- [x] Every endpoint the Java TIM exposes appears in DESIGN §3
- [x] Every DB table + column appears in DESIGN §4
- [x] Configuration surface enumerated in DESIGN §5 + full field
      reference in `book/src/configuration.md`
- [x] Section 11 lists JVM bugs / gotchas to NOT repeat
- [x] Section 12 lists deliberate Rust-side non-goals with
      justification

## Estimated effort

0.5 day. Actual: ~4 hours of exploration + drafting.

## Dependencies

None. This is the seed task.

## Non-scope

Any Rust code. This task produces a design doc; task 002 implements
against it.

## Risks

- **Drift**: DESIGN.md and the code diverge as the Rust rewrite
  evolves. Mitigation: every PR that changes an endpoint / schema /
  config field also updates DESIGN.md, verified in review.
- **Java TIM is a moving target**: upstream continues to evolve.
  Mitigation: DESIGN.md is dated at the top of §1; parity is
  measured against the state captured in this task, not
  live-tracked. Sync-up is a periodic backlog task.
