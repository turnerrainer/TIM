//! Session-ID extractor (finding 27).
//!
//! Accepts the session ID via `Authorization: Bearer sess_<id>` OR
//! `X-TIM-Session: <id>` OR, for legacy JVM callers, `?session_id=<id>`
//! in the URL. Handlers get a plain `String` — call sites still hit
//! `SessionStore::get(...)`.

use axum::extract::{FromRequestParts, Query};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use serde::Deserialize;

use crate::error::TimError;

const SESSION_HEADER: &str = "x-tim-session";
const BEARER_SESSION_PREFIX: &str = "sess_";

pub struct SessionAuth {
    pub session_id: String,
    /// True when the ID came from the URL — used by handlers that
    /// want to log or metric this so operators can track migration
    /// off the query-string variant.
    pub via_query: bool,
}

#[derive(Debug, Deserialize)]
struct SessionQuery {
    session_id: Option<String>,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for SessionAuth
where
    S: Send + Sync,
{
    type Rejection = TimError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(v) = parts
            .headers
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            let v = v.trim();
            if !v.is_empty() {
                return Ok(SessionAuth {
                    session_id: v.into(),
                    via_query: false,
                });
            }
        }
        if let Some(v) = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if let Some(rest) = v.strip_prefix("Bearer ") {
                let rest = rest.trim();
                if let Some(id) = rest.strip_prefix(BEARER_SESSION_PREFIX) {
                    if !id.is_empty() {
                        return Ok(SessionAuth {
                            session_id: id.into(),
                            via_query: false,
                        });
                    }
                }
            }
        }
        // Legacy fallback. Elevated to WARN (was DEBUG) so operators
        // grepping their logs can identify callers still on the
        // query-string transport before removing it. Query strings
        // land in access logs, proxy logs, browser history, and
        // Referer headers — the header/Bearer forms don't.
        if let Ok(Query(q)) = Query::<SessionQuery>::try_from_uri(&parts.uri) {
            if let Some(id) = q.session_id {
                let id = id.trim().to_string();
                if !id.is_empty() {
                    tracing::warn!(
                        target: "tim::compat",
                        via_query = true,
                        "session_id supplied via query string (legacy) — \
                         migrate caller to X-TIM-Session header or \
                         Authorization: Bearer sess_<id>"
                    );
                    return Ok(SessionAuth {
                        session_id: id,
                        via_query: true,
                    });
                }
            }
        }
        Err(TimError::Unauthorized)
    }
}
