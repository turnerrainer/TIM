# 15 — `setCookie` request field silently ignored

**Severity:** MEDIUM (API parity break)
**Area:** Custom JWT
**Files:**

- `src/jwt/api.rs:33-34` (`GenerateRequest.set_cookie`)
- `src/jwt/api.rs:79-80` (`ExtendRequest.set_cookie`)
- Consumers: none. `grep -n "set_cookie\|setCookie\|Set-Cookie" src/` shows
  the fields exist only in the request struct definitions.

## What happens

`setCookie: true` in the request body deserializes into a
`Option<bool>` on both `GenerateRequest` and `ExtendRequest`, but no
handler reads the field. The response contains no `Set-Cookie`
header, and the caller has no way to know the flag was dropped.

## Reference — Buerostack Java TIM

`CustomJwtController.generate` at `.../api/CustomJwtController.java:67-69`:

```java
if (request.getSetCookie()) {
    responseBuilder.header(HttpHeaders.SET_COOKIE,
        request.getJwtName() + "=" + token + "; Path=/; HttpOnly");
}
```

Same in `extend` at line 290-292 (`Set-Cookie: EXTENDED_TOKEN=...`).

## Impact

- Browser-facing clients that relied on the cookie behavior are
  silently broken. They will not see `Set-Cookie` and will fail on
  subsequent same-origin requests that expected the cookie.
- Field parsed but ignored is a footgun — no request-schema warning,
  no server log entry.

## Suggested direction

Either implement the response header (behavior parity) or reject the
field with a helpful error message. Silent no-op is the worst choice.
