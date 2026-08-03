# 27 — Session IDs travel in the URL query string

**Severity:** MEDIUM (security posture; parity)
**Area:** OAuth2 / router
**Files:**

- `src/router/mod.rs:283-286, 301-304, 322-326` — `session_id`
  extracted via `Query<...>`.

## What happens

`/auth/session/validate`, `/auth/profile`, and `/auth/logout` all
accept `session_id=<secret>` in the URL. Even for `POST /auth/logout`,
the ID comes from the query string, not the body.

Session IDs are 24-byte random values (`flow.rs:180`). Anything that
leaks the URL — access logs, reverse-proxy logs, referer headers
sent by any resource loaded on the page immediately after login,
browser history sync between devices — leaks the secret.

## Reference — Buerostack Java TIM

`AuthController.java:293-294, 332-333, 371-372` uses
`@RequestParam String session_id` — same behavior. Parity issue,
mutual bug.

## Impact

- Session-ID leak surface. Not immediately exploitable if the
  reverse proxy strips `?session_id=*` from logs, but that's a
  fragile assumption.
- Fix: accept the session ID via `Cookie:` (long-term, tied to the
  `set_cookie` finding) or `Authorization: Bearer sess_...` header
  (short-term, doesn't require cookie plumbing).
