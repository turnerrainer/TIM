//! OAuth2 / OIDC multi-provider authentication.
//!
//! Post-audit posture:
//! - `flow` performs the authorization-code exchange.
//! - `idtoken` validates the ID token against provider JWKS (finding 01/02).
//! - `session` persists sessions via a `SessionStore` trait with
//!   `MemoryStore` and `PostgresStore` implementations (finding 03).
//! - `state_sweeper` reaps expired `auth.oauth_state` rows (finding 10).

pub mod discovery;
pub mod flow;
pub mod idtoken;
pub mod jwks;
pub mod registry;
pub mod session;
pub mod state_sweeper;

pub use registry::ProviderRegistry;
