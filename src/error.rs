use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TimError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("payload too large: max {max} bytes")]
    PayloadTooLarge { max: usize },

    #[error("unsupported media type")]
    UnsupportedMediaType,

    #[error("unprocessable entity: {0}")]
    Unprocessable(String),

    #[error("bad gateway: {0}")]
    BadGateway(String),

    #[error("upstream timeout: {0}")]
    UpstreamTimeout(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl TimError {
    fn status(&self) -> StatusCode {
        match self {
            TimError::BadRequest(_) => StatusCode::BAD_REQUEST,
            TimError::Unauthorized => StatusCode::UNAUTHORIZED,
            TimError::Forbidden => StatusCode::FORBIDDEN,
            TimError::NotFound(_) => StatusCode::NOT_FOUND,
            TimError::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            TimError::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            TimError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            TimError::BadGateway(_) => StatusCode::BAD_GATEWAY,
            TimError::UpstreamTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
            TimError::Database(_) | TimError::Crypto(_) | TimError::Config(_) | TimError::Io(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn code(&self) -> &'static str {
        match self {
            TimError::BadRequest(_) => "bad_request",
            TimError::Unauthorized => "unauthorized",
            TimError::Forbidden => "forbidden",
            TimError::NotFound(_) => "not_found",
            TimError::PayloadTooLarge { .. } => "payload_too_large",
            TimError::UnsupportedMediaType => "unsupported_media_type",
            TimError::Unprocessable(_) => "unprocessable_entity",
            TimError::BadGateway(_) => "bad_gateway",
            TimError::UpstreamTimeout(_) => "upstream_timeout",
            TimError::Database(_) | TimError::Crypto(_) | TimError::Config(_) | TimError::Io(_) => {
                "internal_error"
            }
        }
    }
}

impl IntoResponse for TimError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        if status.is_server_error() {
            tracing::error!(error = %self, "server error");
            let body = Json(json!({ "error": code }));
            (status, body).into_response()
        } else {
            let detail = self.to_string();
            let body = match &self {
                TimError::PayloadTooLarge { max } => Json(json!({ "error": code, "max": max })),
                _ => Json(json!({ "error": code, "detail": detail })),
            };
            (status, body).into_response()
        }
    }
}

pub type Result<T> = std::result::Result<T, TimError>;
