//! OAuth2 / OIDC multi-provider authentication.
//!
//! MVP scope: authorization code flow, ID-token validation via
//! cached JWKS, in-process session store. Postgres session store is
//! backlog task 002; PKCE is backlog task 003.

pub mod discovery;
pub mod flow;
pub mod registry;
pub mod session;

pub use registry::ProviderRegistry;
