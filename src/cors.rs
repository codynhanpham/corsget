//! CORS handling.
//!
//! Adds permissive CORS headers to every response so that browsers can
//! consume proxied resources cross-origin. The `Access-Control-Allow-Origin`
//! header echoes the request's `Origin` when one is present (so credentials
//! can flow), otherwise falls back to `*`.
//!
//! An `OPTIONS` preflight handler short-circuits preflight requests with a
//! `204 No Content` plus the CORS headers, which is required for non-simple
//! GETs (e.g. those carrying an `Authorization` header) to work from a
//! browser.

use std::sync::Arc;

use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{extract::Request, middleware::Next};

use crate::error::AppError;
use crate::extractors::Origin;
use crate::proxy::{parse_target_url, validate_target_policy};
use crate::state::AppState;

/// Header names that are hop-by-hop or proxy-injected and must NOT be
/// forwarded to the target nor copied back from the target response.
///
/// Based on RFC 7230 §6.1 (hop-by-hop) plus common proxy-injected headers.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    // Proxy-injected (do not leak these to the target):
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
];

/// Returns `true` if `name` is a hop-by-hop / proxy-injected header.
pub fn is_hop_by_hop(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("x-forwarded-") || HOP_BY_HOP_HEADERS.contains(&name.as_str())
}

/// Return header names nominated by the `Connection` header.
pub fn connection_headers(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|value| value.to_str().ok().into_iter())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Build the CORS header map for a given request's `Origin`.
///
/// - `Access-Control-Allow-Origin`: echoes the request `Origin` if present,
///   else `*`.
/// - `Access-Control-Allow-Credentials: true` (only meaningful when echoing
///   a specific origin; included unconditionally for simplicity since
///   browsers ignore it with `*`).
/// - `Access-Control-Allow-Headers`: echos back the preflight request's
///   `Access-Control-Request-Headers`, so any client header is allowed.
///   (An explicit list is needed because `*` does not cover credentialed
///   requests per the Fetch spec §3.2.1.)
/// - `Access-Control-Allow-Methods: GET, OPTIONS`
/// - `Access-Control-Max-Age: 86400`
pub fn cors_headers(headers: &HeaderMap) -> HeaderMap {
    let mut map = HeaderMap::new();
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let allow_origin: HeaderValue = match &origin {
        Some(o) => o.parse().unwrap_or_else(|_| HeaderValue::from_static("*")),
        None => HeaderValue::from_static("*"),
    };
    map.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
    map.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );

    // Reflect whatever headers the client asks for in preflight.
    // The `Access-Control-Request-Headers` header is sent by the browser
    // during preflight to indicate which headers the actual request will
    // carry. Echoing it back allows any header through.
    let allow_headers = headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .filter(|v| !v.as_bytes().is_empty())
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("Authorization"));
    map.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, allow_headers);
    map.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, OPTIONS"),
    );
    map.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
    map
}

/// Middleware that injects CORS headers into every response.
pub async fn cors_layer(mut req: Request, next: Next) -> Response {
    // Capture the origin before the handler consumes the request.
    let cors = cors_headers(req.headers());
    // Stash for handlers that may want to inspect it.
    req.extensions_mut().insert(cors.clone());
    let mut response = next.run(req).await;
    response.headers_mut().extend(cors);
    response
}

/// `OPTIONS /*target` preflight handler.
///
/// Returns `204 No Content` with CORS headers. The target URL is not
/// validated here — preflight only needs to satisfy the browser's CORS
/// check before the actual GET is issued.
pub async fn preflight_handler(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    req: Request,
) -> Result<Response, AppError> {
    let cors = cors_headers(req.headers());
    let target_url = parse_target_url(&uri)?;
    if !matches!(target_url.scheme(), "http" | "https") {
        return Err(AppError::BadUrl(format!(
            "unsupported scheme `{}`; only http/https are allowed",
            target_url.scheme()
        )));
    }
    validate_target_policy(&state, &target_url, &Origin::from_headers(req.headers()))?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().extend(cors);
    Ok(response)
}

#[allow(dead_code)]
fn _ensure_header_name_parse() {
    // Compile-time sanity that the header names we use are valid.
    let _: HeaderName = header::ACCESS_CONTROL_ALLOW_ORIGIN;
}
