//! Pre-boot environment validator (`tim doctor`).
//!
//! Fleet-strongholds §8.2 — ops teams need to validate a deployment
//! before restarting the running service. `tim doctor` answers "will
//! this config boot cleanly?" without starting the server or holding
//! ports.
//!
//! Distinct from `AppConfig::diagnose()`:
//! - `diagnose()` runs INSIDE the boot path and emits `tracing` INFO /
//!   WARN so operators grep the running log stream.
//! - `doctor` runs OUTSIDE the boot path (subcommand exit) and prints
//!   a structured PASS / WARN / FAIL table to stdout, then exits with
//!   a code CI can act on.
//!
//! Design constraint: doctor MUST NOT touch external systems by
//! default. `--connect` opts into a live Postgres reachability check;
//! everything else is local file / env inspection. This makes doctor
//! safe to run inside a locked-down CI job with no outbound.

use std::fmt;
use std::path::Path;

use crate::config::AppConfig;
use crate::crypto::JwtSigner;

/// Severity of a single doctor check. Ordering matters for the exit-
/// code decision: `Fail > Warn > Pass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Pass => "  OK  ",
            Severity::Warn => " WARN ",
            Severity::Fail => " FAIL ",
        })
    }
}

#[derive(Debug)]
pub struct Check {
    pub severity: Severity,
    pub category: &'static str,
    pub message: String,
}

impl Check {
    fn pass(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Pass,
            category,
            message: message.into(),
        }
    }
    fn warn(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warn,
            category,
            message: message.into(),
        }
    }
    fn fail(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Fail,
            category,
            message: message.into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn push(&mut self, c: Check) {
        self.checks.push(c);
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut pass = 0;
        let mut warn = 0;
        let mut fail = 0;
        for c in &self.checks {
            match c.severity {
                Severity::Pass => pass += 1,
                Severity::Warn => warn += 1,
                Severity::Fail => fail += 1,
            }
        }
        (pass, warn, fail)
    }

    /// Exit code: 0 unless we have any FAIL (or any WARN when strict).
    pub fn exit_code(&self, strict: bool) -> i32 {
        let (_, warn, fail) = self.counts();
        if fail > 0 || (strict && warn > 0) {
            1
        } else {
            0
        }
    }

    pub fn render_to<W: std::io::Write>(&self, out: &mut W) -> std::io::Result<()> {
        for c in &self.checks {
            writeln!(out, "[{}] {}: {}", c.severity, c.category, c.message)?;
        }
        let (pass, warn, fail) = self.counts();
        writeln!(out, "---")?;
        writeln!(
            out,
            "Summary: {pass} pass, {warn} warn, {fail} fail (total {})",
            self.checks.len()
        )?;
        Ok(())
    }
}

/// Run every doctor check. `config_path` is what would have been
/// passed to `AppConfig::load` — same env fallback rules apply.
pub fn run(config_path: Option<&Path>) -> Report {
    let mut r = Report::default();

    // ---- config -----------------------------------------------------
    let config = match AppConfig::load(config_path) {
        Ok(c) => {
            r.push(Check::pass(
                "config",
                match config_path {
                    Some(p) => format!("loaded from {}", p.display()),
                    None => "loaded from default resolution (--config / TIM_CONFIG / ./tim.yaml / built-in)".to_string(),
                },
            ));
            c
        }
        Err(e) => {
            r.push(Check::fail("config", format!("load: {e}")));
            return r;
        }
    };

    if let Err(e) = config.validate() {
        r.push(Check::fail("config", format!("validate: {e}")));
        // Continue — many later checks are still meaningful even when
        // validate() failed. Doctor is diagnostic, not gating.
    } else {
        r.push(Check::pass(
            "config",
            "validate: all cross-field checks pass",
        ));
    }

    // ---- JWT key file ----------------------------------------------
    let key_path = &config.jwt.private_key_path;
    if !key_path.exists() {
        r.push(Check::fail(
            "jwt.private_key",
            format!(
                "file not present at `{}` — provision an RSA PKCS#8 PEM before boot",
                key_path.display()
            ),
        ));
    } else {
        match JwtSigner::load_from_pem(key_path, config.jwt.key_id.clone()) {
            Ok(signer) => r.push(Check::pass(
                "jwt.private_key",
                format!(
                    "parsed OK from {} (kid={})",
                    key_path.display(),
                    signer.kid()
                ),
            )),
            Err(e) => r.push(Check::fail(
                "jwt.private_key",
                format!("parse from {}: {e}", key_path.display()),
            )),
        }
    }

    // ---- database URL env -------------------------------------------
    match std::env::var(&config.database.url_env) {
        Ok(v) if !v.is_empty() => r.push(Check::pass(
            "database.url_env",
            format!(
                "`{}` resolved to a non-empty value",
                config.database.url_env
            ),
        )),
        _ => r.push(Check::fail(
            "database.url_env",
            format!(
                "env var `{}` is unset or empty; startup will refuse",
                config.database.url_env
            ),
        )),
    }

    // ---- admin token env --------------------------------------------
    if config.security.require_admin_token {
        match std::env::var(&config.security.admin_token_env) {
            Ok(v) if !v.is_empty() => r.push(Check::pass(
                "security.admin_token_env",
                format!(
                    "`{}` resolved (require_admin_token = true)",
                    config.security.admin_token_env
                ),
            )),
            _ => r.push(Check::fail(
                "security.admin_token_env",
                format!(
                    "`{}` is unset or empty while require_admin_token = true; startup will refuse",
                    config.security.admin_token_env
                ),
            )),
        }
    } else {
        r.push(Check::warn(
            "security.admin_token_env",
            "require_admin_token = false — privileged endpoints are UNGATED. Do not deploy to production.",
        ));
    }

    // ---- OAuth2 session encryption env (only for postgres store) ----
    if config.oauth2.session_store == "postgres" {
        match std::env::var(&config.oauth2.session_encryption_key_env) {
            Ok(v) if v.len() == 64 => r.push(Check::pass(
                "oauth2.session_encryption_key_env",
                format!(
                    "`{}` resolved (64 hex chars, session_store = postgres)",
                    config.oauth2.session_encryption_key_env
                ),
            )),
            Ok(v) => r.push(Check::fail(
                "oauth2.session_encryption_key_env",
                format!(
                    "`{}` resolved to {} chars; must be 64 hex chars (32 bytes)",
                    config.oauth2.session_encryption_key_env,
                    v.len()
                ),
            )),
            Err(_) => r.push(Check::fail(
                "oauth2.session_encryption_key_env",
                format!(
                    "`{}` is unset while session_store = postgres; startup will refuse",
                    config.oauth2.session_encryption_key_env
                ),
            )),
        }
    }

    // ---- per-provider credential envs -------------------------------
    for (id, p) in &config.oauth2.providers {
        for (name, env) in [
            ("client_id_env", &p.client_id_env),
            ("client_secret_env", &p.client_secret_env),
        ] {
            match std::env::var(env) {
                Ok(v) if !v.is_empty() => r.push(Check::pass(
                    "oauth2.providers",
                    format!("provider[{id}].{name} `{env}` resolved"),
                )),
                _ => r.push(Check::fail(
                    "oauth2.providers",
                    format!("provider[{id}].{name} `{env}` unset or empty"),
                )),
            }
        }
    }

    // ---- introspection client envs ----------------------------------
    if config.introspection.required_client_auth {
        if config.introspection.clients.is_empty() {
            r.push(Check::fail(
                "introspection.clients",
                "required_client_auth = true but clients is empty — startup will refuse",
            ));
        }
        for c in &config.introspection.clients {
            match std::env::var(&c.client_secret_env) {
                Ok(v) if !v.is_empty() => r.push(Check::pass(
                    "introspection.clients",
                    format!(
                        "client[{}].client_secret_env `{}` resolved",
                        c.client_id, c.client_secret_env
                    ),
                )),
                _ => r.push(Check::fail(
                    "introspection.clients",
                    format!(
                        "client[{}].client_secret_env `{}` unset or empty",
                        c.client_id, c.client_secret_env
                    ),
                )),
            }
        }
    } else {
        r.push(Check::warn(
            "introspection",
            "required_client_auth = false — POST /introspect is unauthenticated. RFC 7662 §2.1 recommends client auth on public deployments.",
        ));
    }

    // ---- security posture (mirrors diagnose warnings) ---------------
    if config.oauth2.session_store == "memory" {
        r.push(Check::warn(
            "oauth2.session_store",
            "\"memory\" — sessions do not survive restart or span replicas. Use \"postgres\" for production multi-replica.",
        ));
    }
    if !config.jwt.audience.validation_enabled {
        r.push(Check::warn(
            "jwt.audience",
            "validation_enabled = false — every caller can request any audience.",
        ));
    }
    if config
        .security
        .cors_allowed_origins
        .iter()
        .any(|o| o == "*")
    {
        r.push(Check::warn(
            "security.cors_allowed_origins",
            "contains \"*\" — every unauthenticated read is cross-origin readable.",
        ));
    }
    // Loopback rule mirrors the two-value pattern in `AppConfig::diagnose`.
    // The widened rule (fix/pr-review-nits-v1) supersedes this when both
    // land — kept local so doctor is self-contained on dev.
    let bind = config.server.bind.as_str();
    let bind_is_loopback = bind == "127.0.0.1" || bind == "::1";
    let hsts_has_preload = config
        .security
        .strict_transport_security
        .to_lowercase()
        .contains("preload");
    if !bind_is_loopback && !hsts_has_preload {
        r.push(Check::warn(
            "security.strict_transport_security",
            format!(
                "bind = {} is not loopback AND HSTS lacks `preload` — first-request MITM leaks bearer tokens. Add preload + submit domain to https://hstspreload.org.",
                config.server.bind
            ),
        ));
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_matches_gating() {
        assert!(Severity::Fail > Severity::Warn);
        assert!(Severity::Warn > Severity::Pass);
    }

    #[test]
    fn exit_code_pass_is_zero() {
        let mut r = Report::default();
        r.push(Check::pass("cat", "ok"));
        assert_eq!(r.exit_code(false), 0);
        assert_eq!(r.exit_code(true), 0);
    }

    #[test]
    fn exit_code_warn_gated_by_strict() {
        let mut r = Report::default();
        r.push(Check::pass("cat", "ok"));
        r.push(Check::warn("cat", "eh"));
        assert_eq!(
            r.exit_code(false),
            0,
            "WARN alone is advisory unless --strict"
        );
        assert_eq!(r.exit_code(true), 1, "WARN → 1 with --strict");
    }

    #[test]
    fn exit_code_fail_always_nonzero() {
        let mut r = Report::default();
        r.push(Check::fail("cat", "broken"));
        assert_eq!(r.exit_code(false), 1);
        assert_eq!(r.exit_code(true), 1);
    }

    #[test]
    fn exit_code_counts() {
        let mut r = Report::default();
        r.push(Check::pass("a", "ok"));
        r.push(Check::pass("b", "ok"));
        r.push(Check::warn("c", "eh"));
        r.push(Check::fail("d", "broken"));
        assert_eq!(r.counts(), (2, 1, 1));
    }

    #[test]
    fn render_does_not_panic_and_summary_line_present() {
        let mut r = Report::default();
        r.push(Check::pass("a", "ok"));
        r.push(Check::warn("b", "eh"));
        let mut out = Vec::new();
        r.render_to(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Summary:"));
        assert!(s.contains("1 pass"));
        assert!(s.contains("1 warn"));
    }

    /// Doctor must never install a tracing subscriber, since it prints
    /// its own structured report to stdout. This test is a smoke check
    /// that calling `run` twice in the same process doesn't panic on
    /// "subscriber already set" — proves the code path is safe for
    /// callers that embed doctor (test harnesses, wrapper CLIs).
    #[test]
    fn run_can_be_called_repeatedly() {
        let _ = run(None);
        let _ = run(None);
    }
}
