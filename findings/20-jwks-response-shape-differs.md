# 20 — `GET /jwt/keys/public` response shape differs from JVM

**Severity:** LOW (compat)
**Area:** JWKS
**Files:**

- `src/router/mod.rs:169-171` (Rust returns bare JWKS)
- Reference: `PublicKeyController.java:1-3` (JVM wraps JWKS)

## What happens

**Java** returns:

```json
{"jwk": "{\"keys\":[{\"kty\":\"RSA\",...}]}"}
```

Note the outer `jwk` key and the JWKS as a *stringified* JSON blob
(from `signer.publicJwkSet()` calling
`new JWKSet(...).toJSONObject().toString()`).

**Rust** returns:

```json
{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"...","n":"...","e":"..."}]}
```

A proper unwrapped RFC 7517 JWK Set. Rust is more correct; but any
client that already parsed the JVM shape (unwrap `jwk` field, then
`JSON.parse` the inner string) now fails.

## Impact

- Client-side breakage for any consumer of the JVM shape. No changelog
  note flagging the break.
- If the intent is to normalise, keep — but document. If parity is
  required, wrap.
