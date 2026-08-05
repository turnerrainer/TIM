//! Static response headers + CORS layer.
//!
//! Every configured header in `security.*` (CSP, HSTS,
//! Referrer-Policy, X-Frame-Options, X-Content-Type-Options) is
//! emitted on every response including error paths and 404s. CORS
//! is enabled when `security.cors_allowed_origins` is non-empty.

use axum::http::{HeaderName, HeaderValue};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::config::SecurityConfig;

pub struct Layers {
    pub csp: Option<SetResponseHeaderLayer<HeaderValue>>,
    pub hsts: Option<SetResponseHeaderLayer<HeaderValue>>,
    pub referrer: Option<SetResponseHeaderLayer<HeaderValue>>,
    pub frame: Option<SetResponseHeaderLayer<HeaderValue>>,
    pub content_type: Option<SetResponseHeaderLayer<HeaderValue>>,
    pub cors: Option<CorsLayer>,
}

fn header_if_set(name: &'static str, value: &str) -> Option<SetResponseHeaderLayer<HeaderValue>> {
    if value.is_empty() {
        return None;
    }
    let hv = HeaderValue::from_str(value).ok()?;
    Some(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static(name),
        hv,
    ))
}

pub fn build(cfg: &SecurityConfig) -> Layers {
    let cors = if cfg.cors_allowed_origins.is_empty() {
        None
    } else if cfg.cors_allowed_origins.iter().any(|o| o == "*") {
        Some(
            CorsLayer::new()
                .allow_origin(AllowOrigin::any())
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
    } else {
        let list: Vec<HeaderValue> = cfg
            .cors_allowed_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        Some(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(list))
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any)
                .allow_credentials(true),
        )
    };
    Layers {
        csp: header_if_set("content-security-policy", &cfg.content_security_policy),
        hsts: header_if_set("strict-transport-security", &cfg.strict_transport_security),
        referrer: header_if_set("referrer-policy", &cfg.referrer_policy),
        frame: header_if_set("x-frame-options", &cfg.x_frame_options),
        content_type: header_if_set("x-content-type-options", &cfg.x_content_type_options),
        cors,
    }
}
