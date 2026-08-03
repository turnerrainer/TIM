# 04 — OAuth2 callback rejects IdP error responses as 400 bad-request

**Severity:** MEDIUM
**Area:** OAuth2 flow / router
**File:** `src/router/mod.rs:262-266`

## What happens

```rust
#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}
```

`code` and `state` are both required by serde deserialization. If the
IdP redirects the user to `.../auth/callback/{id}?error=access_denied&error_description=user+cancelled&state=...`
(RFC 6749 §4.1.2.1), serde rejects the query with
`400 Bad Request: missing field 'code'`. The genuine error from the IdP
is lost, and the user sees a nonsensical validation error.

## Reference — Buerostack Java TIM

`AuthController.handleCallback` at `.../oauth2/api/AuthController.java:156-190`
accepts `code`, `state`, `error`, `error_description` all optional, and
special-cases `error != null` to bubble the OAuth2 error back to the
caller with `error` + `message` fields. Rust silently drops the IdP's
error and returns a schema-validation error instead.

## Impact

- Users who cancel or fail to authenticate at the IdP see an unhelpful
  400 from TIM instead of the IdP's actual error.
- Operators debugging failed logins have no signal about what went
  wrong upstream because TIM never logged the `error` param.
- The oauth_state row remains in the DB (no cleanup on error paths)
  until the sweeper picks it up — see also finding 12.
