# 004 — Prometheus metrics endpoint

## Filed

2026-07-30 — the JVM TIM has micrometer wired in but does not
expose a `/metrics` endpoint today (Spring Boot Actuator is
present but not turned on). Rust MVP has no metrics at all beyond
`tracing` logs.

## Severity

Low. Not required for correctness. Operators without metrics fly
blind, but they can still infer health from logs + `/health`.

## Motivation

Every production deployment eventually wants:

- Request rate + latency by endpoint
- JWT generation rate + failure rate
- OAuth2 provider callback rate + failure rate by provider
- Postgres pool saturation

Without a Prometheus endpoint, operators write ad-hoc log-based
alerting. Get ahead of the curve.

## Fix / Design

- Add `metrics` + `metrics-exporter-prometheus` crates.
- New endpoint `GET /metrics` — Prometheus text-format.
- New config field `server.metrics_enabled: bool` (default `true`).
- Register counters + histograms per §3.4:
  - `tim_http_requests_total{method,path,status}`
  - `tim_http_request_duration_seconds{method,path}`
  - `tim_jwt_generated_total`
  - `tim_jwt_revoked_total`
  - `tim_oauth2_callback_total{provider_id,status}`
  - `tim_db_pool_idle`, `tim_db_pool_size`

`/metrics` MUST be exposed on the same axum router (no separate
port for MVP; if operators need port isolation add later per
task).

## Acceptance

- [ ] `GET /metrics` returns Prometheus text format when
      `server.metrics_enabled: true`.
- [ ] Instrument every endpoint via `metrics::counter!` +
      `metrics::histogram!`.
- [ ] Configurable label cardinality — reject `path` labels with
      unbounded values (UUIDs in path get bucketed to `/jwt/custom/*`).
- [ ] `book/src/configuration.md` documents `metrics_enabled`.
- [ ] Integration test: hit `/metrics` after generating a JWT,
      assert `tim_jwt_generated_total` incremented.

## Estimated effort

1 day.

## Dependencies

None.

## Non-scope

- OpenTelemetry OTLP export (Ruuter-on-Rust has this; TIM MVP
  scope is Prometheus only).
- Grafana dashboards.

## Risks

- Label cardinality explosion if user-controlled inputs sneak
  into labels — enforce in-code allowlist for label values.
