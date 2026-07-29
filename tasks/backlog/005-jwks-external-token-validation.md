# 005 — JWKS caching for external-token introspection

## Filed

2026-07-30 — MVP introspection dispatcher only handles custom JWT
tokens (issued by TIM itself). If the caller submits a token
issued by an OAuth2 provider (e.g. Google, TARA), the dispatcher
returns `{"active": false}` per RFC 7662 §2.2.

## Severity

Low. Not a regression — Java TIM has the same behavior. But
enabling external-token introspection would let TIM be the single
`/introspect` endpoint for all tokens in the ecosystem, which is
useful for downstream Ruuter DSLs.

## Motivation

Ruuter DSL authors currently have to either (a) validate provider
tokens themselves (JWKS fetch + signature verify) or (b) trust
the token without validation. Both are wrong. Making TIM the
canonical introspection point centralizes the JWKS fetch + cache +
validation logic.

## Fix / Design

- Extend `introspect::TokenValidator` registry: on unknown token,
  parse header without validation → extract `kid` + `iss` → look
  up matching provider by `iss` in oauth2 registry → fetch that
  provider's JWKS (moka cache) → validate signature + exp + aud +
  iss.
- If no provider matches `iss`, still return `{"active": false}`
  (do not leak "unknown issuer" — RFC 7662 §2.2).
- Introspection response includes `token_type: "oauth2"` and
  `token_type: "custom_jwt"` accordingly.

## Acceptance

- [ ] `POST /introspect` with a Google-issued ID token returns
      structured active/exp/iat/sub/aud/iss/jti populated from
      the token's claims.
- [ ] JWKS cached per-provider per DEV-REQUIREMENTS OIDC discovery
      TTL.
- [ ] Cache miss on unknown issuer returns `{"active": false}`
      (RFC 7662 §2.2 compliance).
- [ ] Integration test: submit mock-provider-issued token, verify
      active response.
- [ ] `book/src/failure-modes.md` documents introspection dispatch.

## Estimated effort

1.5 days.

## Dependencies

- OAuth2 provider registry must be operational — task 002 has
  more urgency but is not a strict blocker.

## Non-scope

- Token type coercion (returning custom TIM shape for external
  tokens); use the RFC 7662 shape verbatim.

## Risks

- Provider `iss` may not exactly match the discovery URL host
  (e.g. Google's issuer is `https://accounts.google.com` vs.
  discovery at `https://accounts.google.com/.well-known/openid-configuration`).
  Match on the `issuer` field from the discovery document, not
  the URL.
