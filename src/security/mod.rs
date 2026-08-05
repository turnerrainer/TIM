//! HTTP-security layer: admin-token gate + session-bearer extractor
//! + response-header middleware. Consolidates findings 25, 26, 27.

pub mod admin;
pub mod headers;
pub mod session_auth;

pub use admin::{AdminAuth, AdminGate};
pub use session_auth::SessionAuth;
