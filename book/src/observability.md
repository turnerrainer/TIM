# Observability: trace export (OTLP)

TIM always writes one access-log line per request and returns a W3C
`traceparent` + `x-trace-id` on every response (see
[Security hardening](./security-hardening.md#w3c-trace-context--every-response-carries-traceparent)).
On top of that it can export spans to any OpenTelemetry collector or
OTLP-compatible backend.

Export is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set. With it unset,
TIM creates no spans, sends no extra headers and the log output is
identical to a build without this feature.

## Environment variables

| Variable | Effect |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Enables export. gRPC: `http://collector:4317`. HTTP: `http(s)://collector:4318` (TIM appends `/v1/traces`). |
| `OTEL_EXPORTER_OTLP_PROTOCOL` / `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | `grpc` (default) or `http/protobuf`. The per-signal variable wins; other values fall back to `grpc` with a warning. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Exporter headers, e.g. `authorization=Bearer%20<token>`. Values are never logged. |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | Export timeout in milliseconds. |
| `OTEL_SERVICE_NAME` | `service.name` resource attribute. Default `tim`. |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, e.g. `deployment.environment=staging`. `service.name` and `service.version` from TIM win. |

TLS: use `http/protobuf` with an `https://` endpoint. It goes through
TIM's HTTP client (native TLS, system trust store). The gRPC exporter is
plaintext; an `https://` endpoint with `grpc` logs a boot warning and
exports will fail. For a TLS backend over gRPC, run a collector next to
TIM and let it forward.

With export on, TIM stops on SIGTERM / Ctrl-C after in-flight requests
finish and flushes queued spans before exiting. If the collector is
down, requests are unaffected; spans are dropped from the bounded export
queue.

## Spans

**Request span** (kind `SERVER`), one per request:

- name `"{METHOD} {route}"` with the matched route pattern, e.g.
  `GET /auth/callback/:id`. Path parameters and the query string never
  appear;
- attributes `http.request.method`, `http.route`,
  `http.response.status_code`;
- parented on the inbound `traceparent` when present. The response
  `traceparent` then names this span (same trace id, caller's sampling
  flags), so the caller's trace and TIM's spans line up. The access-log
  line then also carries `span_id=<16 hex>` of that span;
- status `ERROR` and `error.type` = status code for 5xx only.

`/health`, `/healthz` and `/auth/health` produce no spans: probes would
dominate the exported data.

**Outbound OIDC calls** (kind `CLIENT`), children of the request span (or
roots when made outside a request, e.g. discovery at boot):

| Name | Call |
|---|---|
| `GET oidc.discovery` | discovery document |
| `GET oidc.jwks` | provider JWKS |
| `POST oidc.token` | authorization-code token exchange |

Attributes: `http.request.method`, `server.address`, `server.port`,
`url.full` (scheme, host, port and path only), `http.response.status_code`,
`tim.operation`. 4xx/5xx and transport failures set status `ERROR`;
`error.type` is the status code or a kind (`timeout`, `connect`, `body`,
`request`), never an error message. Each call carries the client span's
`traceparent` header.

## Never exported

- Request and response bodies, form fields and query strings, so no
  OAuth `code`, `state`, `nonce`, PKCE verifier or `redirect_uri`
  values.
- Header values: `Authorization` (including the token-endpoint Basic
  credentials), cookies, admin and introspection secrets.
- Tokens and their contents: access, ID and refresh tokens, TIM JWTs,
  claims such as `sub`, personal codes, names or e-mail addresses.
- Session ids.
- Log events. Only TIM's own spans are exported; log lines stay in the
  log stream and correlate through `trace_id`. Spans created by
  dependencies (for example `tower_http` request spans at `debug`, which
  carry the raw URI) are not exported either.
