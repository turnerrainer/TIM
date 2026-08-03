# 02 — ID-token nonce check is optional, not mandatory

**Severity:** HIGH (security)
**Area:** OAuth2 / OIDC
**File:** `src/oauth2/flow.rs:224-228`

## What happens

```rust
if let Some(n) = claims.get("nonce").and_then(|v| v.as_str()) {
    if n != expected_nonce {
        return Err(TimError::Unprocessable("id_token nonce mismatch".into()));
    }
}
```

If the ID token **omits** the `nonce` claim, or the claim is not a
string, the check silently passes — even though TIM sent a nonce in the
authorization request (`flow.rs:71`).

## Reference — Buerostack Java TIM

`JwtValidationService.validateIdToken` at `.../oauth2-oidc/.../service/JwtValidationService.java:112-118`:

```java
if (nonce != null) {
    String tokenNonce = claimsSet.getStringClaim("nonce");
    if (!nonce.equals(tokenNonce)) {
        return new JwtValidationResult(false, "Invalid nonce", null);
    }
}
```

The Java version also gates on `if (nonce != null)` (the *stored* nonce,
which is always present because state storage rejects missing nonce),
but the inner `.equals` compares against `getStringClaim("nonce")` which
returns null if the claim is absent — so `null.equals(nonce)` fails
(via `.equals(null)` returning false) → mismatch → reject. The Rust
version's `if let Some(...)` inverts that: absent nonce silently
accepted.

Combined with finding 01 (no signature check), the nonce check is
effectively the only line of defence against ID-token replay in the
Rust rewrite, and it is bypassable by an IdP that just omits the claim.

## Impact

Replay of a captured ID token from an earlier session becomes possible
if the IdP happens to (or is coerced into) omitting the nonce. OIDC
Core §3.1.3.7 step 11 says the client "MUST validate the nonce" when
the authorization request included one; "if not present, an error MUST
be raised" is implied by the MUST.
