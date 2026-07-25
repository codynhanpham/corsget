//! Application error type and HTTP response mapping.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

/// Errors produced while handling a proxy request.
#[derive(Debug, Error)]
pub enum AppError {
    /// The target URL was missing, malformed, or not absolute.
    #[error("invalid target url: {0}")]
    BadUrl(String),

    /// The target host or requesting origin was denied by policy.
    #[error("access denied: {0}")]
    Denied(String),

    /// The proxied response body exceeded the per-result size cap.
    #[error("response too large: {0}")]
    TooLarge(String),

    /// The upstream request failed (network error, timeout, too many
    /// redirects, etc.).
    #[error("upstream error: {0}")]
    Upstream(String),

    /// The rate-limit storage backend failed.
    #[error("rate limit storage failure: {0}")]
    LimitBackend(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::BadUrl(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Denied(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::TooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg.clone()),
            AppError::Upstream(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            AppError::LimitBackend(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg.clone()),
        };

        // Log the full error (with context) at the appropriate level.
        match status.as_u16() {
            500..=599 => tracing::error!(error = %self, "proxy error"),
            _ => tracing::info!(error = %self, "proxy rejected"),
        }

        let body = Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            AppError::Upstream(format!("upstream timeout: {err}"))
        } else if err.is_redirect() {
            AppError::Upstream(format!("too many redirects: {err}"))
        } else {
            AppError::Upstream(err.to_string())
        }
    }
}
