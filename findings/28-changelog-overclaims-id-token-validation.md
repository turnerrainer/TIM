# 28 — CHANGELOG overclaims OAuth2 capabilities

**Severity:** MEDIUM (misleading release notes; feeds finding 01)
**Area:** Docs / release management
**File:** `CHANGELOG.md:47-48`

## What happens

The 0.1.0-alpha.1 changelog entry states:

> `GET /auth/callback/{provider_id}` — exchange `code` → tokens,
> **validate ID token**, create session.

There is no ID-token validation (finding 01). The changelog line is
factually wrong.

The same section characterises the overall release as:

> First alpha release. Full Rust rewrite of TIM ... targeting feature
> parity with the upstream JVM implementation, hardened per
> DEV-REQUIREMENTS.md.

"Feature parity" is not achieved (findings 01, 02, 03, 09, 13, 14,
15, 16, 20, 23). "Hardened" is questionable given findings 01, 03,
09, 13, 26.

## Impact

- Downstream integrators reading the release notes ship code assuming
  TIM verifies ID tokens. They inherit an authentication bypass they
  do not know exists.
- Erodes trust in future changelog entries — once bitten, everything
  needs re-verification.

## Suggested direction

Amend the 0.1.0-alpha.1 entry:

- Move "validate ID token" out of the shipped list into a known-issue
  or roadmap section.
- Replace "feature parity" with "MVP subset; see backlog for gaps."
- Add a "Known limitations" section listing findings 01, 03, 09, 13,
  26 at minimum.
