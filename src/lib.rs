//! TIM — Token Identity Manager.
//!
//! Public surface intentionally minimal; integration tests import
//! `crate::router::build_router` and `crate::config::AppConfig`.

pub mod access_log;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod introspect;
pub mod jwt;
pub mod oauth2;
pub mod router;
pub mod security;

pub use error::TimError;
