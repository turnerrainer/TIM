# 003 — Complete PKCE authorization code flow

## Filed

2026-07-30 — the JVM TIM `auth.oauth_state` table already has a
`pkce_verifier` column but the flow is not wired end-to-end. Rust
MVP inherits the same shape — column exists, wiring is a
follow-up.

## Severity

Medium. Not exploitable today (state parameter provides CSRF
protection), but modern OAuth2 clients expect PKCE, and public
clients (SPA / mobile) can't safely use the flow without it.

## Motivation

PKCE (RFC 7636) protects the authorization code exchange from
interception when the client cannot safely hold a client secret
(public clients). Even for confidential clients, providers
increasingly require it (Google's browser-based OAuth flow, Azure
AD v2.0, Auth0's SPA guides).

## Fix / Design

1. On `GET /auth/login/{provider_id}`:
   - Generate a 43-character `code_verifier` (base64url of 32
     random bytes, per RFC 7636 §4.1).
   - Compute `code_challenge = base64url(SHA-256(code_verifier))`.
   - Persist `code_verifier` to `auth.oauth_state` alongside
     `state` + `nonce`.
   - Append `code_challenge=...&code_challenge_method=S256` to the
     authorization URL.

2. On `GET /auth/callback/{provider_id}`:
   - Load state row → extract `code_verifier`.
   - Include `code_verifier` in token exchange POST to provider.
   - DELETE the state row (single-use).

3. New config field per provider — `pkce_required: bool` (default
   `true` for public clients, respected for confidential clients
   that request it). If `false`, skip verifier generation entirely
   (backward compatibility for providers that reject PKCE params).

## Acceptance

- [ ] `GET /auth/login/{id}` generates verifier + challenge and
      appends PKCE params to the authorization URL.
- [ ] `auth.oauth_state.pkce_verifier` populated on every
      `pkce_required=true` flow.
- [ ] `GET /auth/callback/{id}` includes `code_verifier` in the
      token POST body.
- [ ] Integration test: end-to-end flow against a mock provider,
      verify `code_verifier` is transmitted and matches the
      persisted verifier.
- [ ] `book/src/oauth2.md` documents PKCE mode.

## Estimated effort

1 day.

## Dependencies

None. Independent of task 002.

## Non-scope

- `plain` challenge method (RFC 7636 allows it but S256 is
  strictly better; plain adds attack surface for nothing).

## Risks

- Some providers may reject unknown query params — mitigated by
  `pkce_required: bool` per-provider config.
