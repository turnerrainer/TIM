# TIM-on-Rust — Audit findings

Audit performed on 2026-08-04 against:

- **Original TIM (Buerokratt)**: `/home/rainer/Desktop/Buerokratt/GitHub/TIM`
  (Java / Spring Boot; the original Estonian government TIM.)
- **TIM 2.x rewrite (Buerostack)**: `/home/rainer/Desktop/Buerostack/TIM`
  (Java / Spring Boot; multi-provider OIDC rewrite. This is the immediate
  parent TIM-on-Rust is claimed to be at parity with — see commit
  `d4c27c3 feat(001): full Rust rewrite of TIM at parity with JVM 2.0`.)
- **TIM-on-Rust (subject)**: `/home/rainer/Desktop/Buerostack/TIM-on-Rust`
  (Rust / Axum rewrite.)

Findings are numbered sequentially. Each file is standalone: it explains
the issue, references file:line locations in all three code-bases where
relevant, and grades severity. No fixes are applied — this is a survey.

## Severity ladder

- **CRITICAL** — security-relevant, silent data loss, or spec violation
  that produces wrong answers in production.
- **HIGH** — parity gap that a caller can observe (missing endpoint,
  wrong response shape, missing feature the JVM version shipped).
- **MEDIUM** — correctness bug that is unlikely to trigger but real, or
  an ergonomics/robustness regression vs. the JVM version.
- **LOW** — cosmetic, docs drift, dead code, misleading comment.

## Index

See individual `NN-*.md` files below. Index is maintained bottom-up as
findings are discovered — expect additions during the sweep.
