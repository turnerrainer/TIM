//! Custom JWT lifecycle — generate, validate, extend, revoke, list.
//!
//! Storage layout: `custom_jwt.jwt_metadata` is an immutable
//! audit log (INSERT only). Revocations go to `custom_jwt.denylist`.
//! Extension chains link via `original_jwt_uuid` + `supersedes`.

pub mod api;
pub mod service;

pub use service::JwtService;
