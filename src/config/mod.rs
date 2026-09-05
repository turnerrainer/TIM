use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, TimError};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub oauth2: OAuth2Config,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
    /// Externally-reachable base URL of this TIM instance. Used to
    /// synthesise the default OAuth2 callback URL when the caller
    /// omits `redirect_uri`. Empty means "reject requests without an
    /// explicit `redirect_uri`."
    #[serde(default)]
    pub public_base_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_url_env")]
    pub url_env: String,
    #[serde(default = "default_min_conn")]
    pub min_connections: u32,
    #[serde(default = "default_max_conn")]
    pub max_connections: u32,
    #[serde(default = "default_auto_migrate")]
    pub auto_migrate: bool,
    #[serde(default = "default_acquire_timeout")]
    pub acquire_timeout_seconds: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_max_lifetime")]
    pub max_lifetime_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    #[serde(default = "default_private_key_path")]
    pub private_key_path: PathBuf,
    #[serde(default = "default_kid")]
    pub key_id: String,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default)]
    pub audience: AudienceConfig,
    #[serde(default = "default_max_claims_bytes")]
    pub max_claims_bytes: usize,
    #[serde(default = "default_bulk_revoke_max")]
    pub bulk_revoke_max: usize,
    /// Cookie name the original Buerokratt TIM DSLs expect. Used by
    /// the compatibility endpoints `/jwt/userinfo`,
    /// `/jwt/custom-jwt-blacklist`, `/jwt/blacklist`, etc.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AudienceConfig {
    #[serde(default)]
    pub validation_enabled: bool,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default = "default_audience_default")]
    pub default: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2Config {
    #[serde(default = "default_session_store")]
    pub session_store: String,
    #[serde(default = "default_discovery_ttl")]
    pub discovery_cache_ttl_seconds: u64,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,
    /// Interval at which the background task deletes expired
    /// sessions + stale `auth.oauth_state` rows. Zero disables the
    /// sweeper (useful in tests). Default 60 s.
    #[serde(default = "default_session_sweep_interval")]
    pub session_sweep_interval_seconds: u64,
    /// Maximum age of an `auth.oauth_state` row before the callback
    /// refuses to consume it. Default 300 s (RFC 6749 §4.1.1 does not
    /// mandate a limit; 5 min matches JVM 2.0).
    #[serde(default = "default_state_max_age")]
    pub state_max_age_seconds: u64,
    /// Environment variable that holds the 32-byte key used to
    /// AEAD-encrypt session token material at rest. Required when
    /// `session_store: "postgres"`.
    #[serde(default = "default_session_key_env")]
    pub session_encryption_key_env: String,
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub name: String,
    pub discovery_url: String,
    pub client_id_env: String,
    pub client_secret_env: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub claim_mappings: HashMap<String, String>,
    #[serde(default)]
    pub token_validation: TokenValidationConfig,
    /// Redirect URIs the caller is allowed to pass via
    /// `?redirect_uri=`. If empty, the *only* accepted redirect URI
    /// is the one synthesised from `server.public_base_url` — any
    /// caller-supplied value is rejected.
    #[serde(default)]
    pub allowed_redirect_uris: Vec<String>,
    /// Allow `discovery_url` and endpoints inside the discovery
    /// document to use plain `http://`. Default false — startup
    /// refuses so an operator who typo'd `http` (or an MITM on the
    /// discovery fetch) cannot silently substitute the JWKS URI and
    /// forge ID tokens. Flip to true only for local dev against a
    /// non-TLS mock IdP.
    #[serde(default)]
    pub allow_http_discovery: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenValidationConfig {
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
    #[serde(default = "default_validation_cache_ttl")]
    pub cache_ttl_seconds: u64,
}

impl Default for TokenValidationConfig {
    fn default() -> Self {
        Self {
            clock_skew_seconds: default_clock_skew(),
            cache_ttl_seconds: default_validation_cache_ttl(),
        }
    }
}

/// HTTP-layer security posture.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Env var name that holds the shared bearer secret required by
    /// privileged endpoints (`/jwt/custom/generate`, `/revoke`,
    /// `/revoke/bulk`, `/extend`). Empty string means "no gate —
    /// endpoints are public" but startup logs a loud warning.
    #[serde(default)]
    pub admin_token_env: String,
    /// If `admin_token_env` is set but unresolved at startup, refuse
    /// to boot. Default true; set false only in test / dev.
    #[serde(default = "default_require_admin_token")]
    pub require_admin_token: bool,
    /// CORS allowed origins. Empty list = no CORS layer (no
    /// `Access-Control-*` headers emitted). `["*"]` = wildcard.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Response header injection. Empty string = header not emitted.
    #[serde(default = "default_csp")]
    pub content_security_policy: String,
    #[serde(default = "default_hsts")]
    pub strict_transport_security: String,
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: String,
    #[serde(default = "default_frame_options")]
    pub x_frame_options: String,
    #[serde(default = "default_content_type_options")]
    pub x_content_type_options: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            admin_token_env: String::new(),
            require_admin_token: default_require_admin_token(),
            cors_allowed_origins: Vec::new(),
            content_security_policy: default_csp(),
            strict_transport_security: default_hsts(),
            referrer_policy: default_referrer_policy(),
            x_frame_options: default_frame_options(),
            x_content_type_options: default_content_type_options(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            max_request_bytes: default_max_request_bytes(),
            request_timeout_seconds: default_request_timeout(),
            public_base_url: String::new(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url_env: default_db_url_env(),
            min_connections: default_min_conn(),
            max_connections: default_max_conn(),
            auto_migrate: default_auto_migrate(),
            acquire_timeout_seconds: default_acquire_timeout(),
            idle_timeout_seconds: default_idle_timeout(),
            max_lifetime_seconds: default_max_lifetime(),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            private_key_path: default_private_key_path(),
            key_id: default_kid(),
            issuer: default_issuer(),
            audience: AudienceConfig::default(),
            max_claims_bytes: default_max_claims_bytes(),
            bulk_revoke_max: default_bulk_revoke_max(),
            cookie_name: default_cookie_name(),
        }
    }
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            session_store: default_session_store(),
            discovery_cache_ttl_seconds: default_discovery_ttl(),
            session_ttl_seconds: default_session_ttl(),
            session_sweep_interval_seconds: default_session_sweep_interval(),
            state_max_age_seconds: default_state_max_age(),
            session_encryption_key_env: default_session_key_env(),
            providers: HashMap::new(),
        }
    }
}

impl AppConfig {
    /// Load config in the standard search order:
    ///   1. Explicit path (from --config or TIM_CONFIG env).
    ///   2. ./tim.yaml or ./tim.yml in current working directory.
    ///   3. Built-in defaults.
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit {
            return Self::from_path(path);
        }
        for candidate in ["tim.yaml", "tim.yml"] {
            let p = Path::new(candidate);
            if p.exists() {
                return Self::from_path(p);
            }
        }
        Ok(Self::default())
    }

    fn from_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| TimError::Config(format!("read {}: {e}", path.display())))?;
        let cfg: AppConfig = serde_yaml_ng::from_str(&raw)
            .map_err(|e| TimError::Config(format!("parse {}: {e}", path.display())))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Cross-field validation applied after YAML parse.
    pub fn validate(&self) -> Result<()> {
        // Enum-shaped string.
        match self.oauth2.session_store.as_str() {
            "memory" | "postgres" => {}
            other => {
                return Err(TimError::Config(format!(
                    "oauth2.session_store must be \"memory\" or \"postgres\", got \"{other}\""
                )));
            }
        }
        if self.oauth2.session_store == "postgres"
            && self.oauth2.session_encryption_key_env.is_empty()
        {
            return Err(TimError::Config(
                "oauth2.session_store=postgres requires oauth2.session_encryption_key_env".into(),
            ));
        }
        // The default redirect_uri synthesised for callbacks needs a
        // public base URL that is not `http://localhost:<port>` in
        // any deployment where the bind is non-loopback.
        if self.server.public_base_url.is_empty() && self.server.bind != "127.0.0.1" {
            tracing::warn!(
                bind = %self.server.bind,
                "server.public_base_url is empty; callers must pass ?redirect_uri= explicitly \
                 (see security-hardening.md)"
            );
        }
        Ok(())
    }

    /// Boot-time diagnostic pass.
    ///
    /// For every field the target reads, emit either INFO (normal),
    /// WARN (deviation from source-of-truth default or non-secure
    /// setting), or ERROR (a value that will produce broken behaviour
    /// downstream). Called once from `main::main` after `load()` +
    /// `validate()`, before the router is built.
    ///
    /// Operators can `grep 'tim::config::diagnose'` to get the full
    /// picture of what TIM sees without hunting through source.
    pub fn diagnose(&self) {
        use tracing::{info, warn};

        // server
        info!(target: "tim::config::diagnose",
            bind = %self.server.bind,
            port = self.server.port,
            max_request_bytes = self.server.max_request_bytes,
            request_timeout_seconds = self.server.request_timeout_seconds,
            public_base_url = %self.server.public_base_url,
            "server");
        if self.server.public_base_url.is_empty() && self.server.bind != "127.0.0.1" {
            warn!(target: "tim::config::diagnose",
                "server.public_base_url is empty on a non-loopback bind — \
                 OAuth2 callbacks that omit ?redirect_uri= will fail. \
                 See docs/book/src/security-hardening.md.");
        }

        // database
        info!(target: "tim::config::diagnose",
            url_env = %self.database.url_env,
            min_connections = self.database.min_connections,
            max_connections = self.database.max_connections,
            auto_migrate = self.database.auto_migrate,
            acquire_timeout_seconds = self.database.acquire_timeout_seconds,
            idle_timeout_seconds = self.database.idle_timeout_seconds,
            max_lifetime_seconds = self.database.max_lifetime_seconds,
            "database");

        // jwt
        info!(target: "tim::config::diagnose",
            private_key_path = %self.jwt.private_key_path.display(),
            key_id = %self.jwt.key_id,
            issuer = %self.jwt.issuer,
            audience_validation_enabled = self.jwt.audience.validation_enabled,
            audience_default = %self.jwt.audience.default,
            max_claims_bytes = self.jwt.max_claims_bytes,
            bulk_revoke_max = self.jwt.bulk_revoke_max,
            cookie_name = %self.jwt.cookie_name,
            "jwt");
        if !self.jwt.audience.validation_enabled {
            warn!(target: "tim::config::diagnose",
                "jwt.audience.validation_enabled = false. Any caller can generate a token \
                 for any audience. Set true + populate jwt.audience.allowed for prod.");
        }
        if self.jwt.issuer == "localhost" {
            warn!(target: "tim::config::diagnose",
                "jwt.issuer = \"localhost\" — downstream introspection will refuse \
                 unless it expects this issuer.");
        }

        // security
        info!(target: "tim::config::diagnose",
            admin_token_env = %self.security.admin_token_env,
            require_admin_token = self.security.require_admin_token,
            cors_allowed_origins = ?self.security.cors_allowed_origins,
            csp = %self.security.content_security_policy,
            hsts = %self.security.strict_transport_security,
            referrer_policy = %self.security.referrer_policy,
            x_frame_options = %self.security.x_frame_options,
            x_content_type_options = %self.security.x_content_type_options,
            "security");
        if !self.security.require_admin_token || self.security.admin_token_env.is_empty() {
            warn!(target: "tim::config::diagnose",
                "security.admin_token_env is unset OR require_admin_token = false — \
                 /jwt/custom/{{generate,revoke,revoke/bulk,extend}} and legacy blacklist \
                 endpoints are UNGATED. Do not deploy to production.");
        }
        if self.security.cors_allowed_origins.is_empty() {
            info!(target: "tim::config::diagnose",
                "security.cors_allowed_origins empty — no CORS layer emitted. \
                 Cross-origin browsers cannot call TIM directly.");
        } else if self.security.cors_allowed_origins.iter().any(|o| o == "*") {
            // M5: wildcard exposes every public read (`/health`,
            // `/auth/providers`, `/introspect/types`, ...) cross-origin.
            warn!(target: "tim::config::diagnose",
                "security.cors_allowed_origins contains \"*\" — wildcard CORS \
                 exposes every unauthenticated read cross-origin. Set an \
                 explicit list for production. RFC 6265 blocks cookie use \
                 with wildcard so admin auth is unaffected, but public \
                 endpoints are readable from any browser.");
        }
        if self.security.content_security_policy.is_empty() {
            warn!(target: "tim::config::diagnose",
                "security.content_security_policy = \"\" — CSP header not emitted.");
        }
        // M4: HSTS + non-loopback bind. HSTS only protects the *second*
        // request the browser makes to the origin, so first-request MITM
        // remains trivial. `preload` in the header + submission to
        // hstspreload.org closes that window.
        let bind_is_loopback = self.server.bind == "127.0.0.1" || self.server.bind == "::1";
        let hsts_has_preload = self
            .security
            .strict_transport_security
            .to_lowercase()
            .contains("preload");
        if !bind_is_loopback && !hsts_has_preload {
            warn!(target: "tim::config::diagnose",
                bind = %self.server.bind,
                hsts = %self.security.strict_transport_security,
                "HSTS header lacks `preload` and bind is not loopback — \
                 first-request MITM against TIM leaks bearer tokens in the \
                 clear. Add `preload` to security.strict_transport_security \
                 AND submit the deployment domain to https://hstspreload.org.");
        }

        // oauth2
        info!(target: "tim::config::diagnose",
            session_store = %self.oauth2.session_store,
            session_ttl_seconds = self.oauth2.session_ttl_seconds,
            session_sweep_interval_seconds = self.oauth2.session_sweep_interval_seconds,
            state_max_age_seconds = self.oauth2.state_max_age_seconds,
            discovery_cache_ttl_seconds = self.oauth2.discovery_cache_ttl_seconds,
            session_encryption_key_env = %self.oauth2.session_encryption_key_env,
            provider_count = self.oauth2.providers.len(),
            "oauth2");
        if self.oauth2.session_store == "memory" {
            warn!(target: "tim::config::diagnose",
                "oauth2.session_store = \"memory\" — sessions do not survive restart or \
                 span replicas. Set \"postgres\" for production multi-replica.");
        }
        if self.oauth2.session_sweep_interval_seconds == 0 {
            warn!(target: "tim::config::diagnose",
                "oauth2.session_sweep_interval_seconds = 0 — sweeper disabled. \
                 Expired sessions + stale oauth_state rows will not be reaped.");
        }

        // per-provider
        for (id, p) in &self.oauth2.providers {
            info!(target: "tim::config::diagnose",
                provider = %id,
                name = %p.name,
                discovery_url = %p.discovery_url,
                client_id_env = %p.client_id_env,
                client_secret_env = %p.client_secret_env,
                scopes = ?p.scopes,
                claim_mapping_count = p.claim_mappings.len(),
                clock_skew_seconds = p.token_validation.clock_skew_seconds,
                cache_ttl_seconds = p.token_validation.cache_ttl_seconds,
                allowed_redirect_uris = ?p.allowed_redirect_uris,
                "provider");
            if p.allowed_redirect_uris.is_empty() && self.server.public_base_url.is_empty() {
                warn!(target: "tim::config::diagnose",
                    provider = %id,
                    "provider has neither allowed_redirect_uris NOR server.public_base_url. \
                     Every login attempt will 400.");
            }
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    8085
}
fn default_max_request_bytes() -> usize {
    1_048_576
}
fn default_request_timeout() -> u64 {
    30
}
fn default_db_url_env() -> String {
    "TIM_DATABASE_URL".into()
}
fn default_min_conn() -> u32 {
    2
}
fn default_max_conn() -> u32 {
    10
}
fn default_auto_migrate() -> bool {
    true
}
fn default_acquire_timeout() -> u64 {
    30
}
fn default_idle_timeout() -> u64 {
    600
}
fn default_max_lifetime() -> u64 {
    1_800
}
fn default_private_key_path() -> PathBuf {
    PathBuf::from("/opt/tim/keys/jwt-private.pem")
}
fn default_kid() -> String {
    "tim-rs-1".into()
}
fn default_issuer() -> String {
    "TIM".into()
}
fn default_audience_default() -> String {
    "tim-service".into()
}
fn default_max_claims_bytes() -> usize {
    32_768
}
fn default_bulk_revoke_max() -> usize {
    100
}
fn default_cookie_name() -> String {
    "jwt".into()
}
fn default_session_store() -> String {
    "memory".into()
}
fn default_discovery_ttl() -> u64 {
    3600
}
fn default_session_ttl() -> u64 {
    86_400
}
fn default_session_sweep_interval() -> u64 {
    60
}
fn default_state_max_age() -> u64 {
    300
}
fn default_session_key_env() -> String {
    "TIM_SESSION_ENCRYPTION_KEY".into()
}
fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}
fn default_clock_skew() -> u64 {
    60
}
fn default_validation_cache_ttl() -> u64 {
    3600
}
fn default_require_admin_token() -> bool {
    true
}
fn default_csp() -> String {
    "default-src 'none'; frame-ancestors 'none'".into()
}
fn default_hsts() -> String {
    "max-age=63072000; includeSubDomains".into()
}
fn default_referrer_policy() -> String {
    "no-referrer".into()
}
fn default_frame_options() -> String {
    "DENY".into()
}
fn default_content_type_options() -> String {
    "nosniff".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = AppConfig::default();
        assert_eq!(c.server.port, 8085);
        assert_eq!(c.database.url_env, "TIM_DATABASE_URL");
        assert_eq!(c.jwt.issuer, "TIM");
        assert_eq!(c.oauth2.session_store, "memory");
        assert!(c.oauth2.providers.is_empty());
        assert!(c.security.require_admin_token);
    }

    #[test]
    fn parses_minimal_yaml() {
        let yaml = r#"
server:
  port: 9000
jwt:
  issuer: "TEST"
"#;
        let c: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(c.server.port, 9000);
        assert_eq!(c.jwt.issuer, "TEST");
        assert_eq!(c.server.bind, "0.0.0.0");
        assert_eq!(c.jwt.key_id, "tim-rs-1");
    }

    #[test]
    fn parses_provider_config() {
        let yaml = r#"
oauth2:
  providers:
    google:
      name: "Google"
      discovery_url: "https://accounts.google.com/.well-known/openid-configuration"
      client_id_env: "GOOG_ID"
      client_secret_env: "GOOG_SECRET"
"#;
        let c: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let p = c.oauth2.providers.get("google").unwrap();
        assert_eq!(p.name, "Google");
        assert_eq!(p.scopes.len(), 3);
        assert_eq!(p.token_validation.clock_skew_seconds, 60);
        assert!(p.allowed_redirect_uris.is_empty());
    }

    #[test]
    fn validate_rejects_unknown_session_store() {
        let mut c = AppConfig::default();
        c.oauth2.session_store = "redis".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_requires_key_env_for_postgres_store() {
        let mut c = AppConfig::default();
        c.oauth2.session_store = "postgres".into();
        c.oauth2.session_encryption_key_env = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_memory_default() {
        let c = AppConfig::default();
        assert!(c.validate().is_ok());
    }
}
