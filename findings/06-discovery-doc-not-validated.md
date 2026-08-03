# 06 — OIDC discovery document not validated on fetch

**Severity:** MEDIUM
**Area:** OAuth2 discovery
**File:** `src/oauth2/discovery.rs:42-66`

## What happens

`DiscoveryCache::fetch` returns any JSON that deserializes into
`Discovery` (`discovery.rs:10-18`). The struct requires only:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`

Anything else is ignored. There is no check for:

- `grant_types_supported` including `authorization_code`,
- `response_types_supported` including `code`,
- non-empty issuer,
- HTTPS scheme on any endpoint,
- issuer matching the discovery URL host (per OIDC Discovery §4.3
  "the response issuer MUST match the URL that was used").

## Reference — Buerostack Java TIM

`OidcDiscoveryService.validateDiscoveryDocument` at
`.../oauth2/service/OidcDiscoveryService.java:88-118`:

```java
if (discovery.getIssuer() == null || discovery.getIssuer().trim().isEmpty()) { ... }
if (!discovery.getGrantTypesSupported().contains("authorization_code")) { ... }
if (!discovery.getResponseTypesSupported().contains("code")) { ... }
```

## Impact

- Silent misconfiguration: a provider that only supports `implicit`
  flow will be accepted at startup and fail cryptically at first
  callback.
- No defence against a downgrade to `http://` endpoints from a
  compromised discovery doc served over an intermediary. In practice
  the discovery URL is HTTPS-only in most deployments, but nothing in
  the Rust code enforces this.
