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

/// Returns `true` for CORS response headers generated from the consumer's
/// request. Upstream values must not be allowed to compete with these values.
pub fn is_cors_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("access-control-allow-origin")
        || name.eq_ignore_ascii_case("access-control-allow-credentials")
        || name.eq_ignore_ascii_case("access-control-allow-headers")
        || name.eq_ignore_ascii_case("access-control-allow-methods")
        || name.eq_ignore_ascii_case("access-control-max-age")
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

/// Append `field` to the response's `Vary` header set unless it is already
/// nominated (case-insensitively, across comma-separated lists and repeated
/// `Vary` headers).
///
/// corsget echoes the request's `Origin` in `Access-Control-Allow-Origin`,
/// so every such response is origin-dependent. Without `Vary: Origin`, any
/// shared HTTP cache between corsget and the browser — including the
/// browser's own HTTP cache, which is partitioned per *top-level site* and
/// therefore shared between subdomains of the same site — can store a
/// response generated for one origin and replay it to another, poisoning
/// the `Access-Control-Allow-Origin` value.
pub fn add_vary_field(headers: &mut HeaderMap, field: &str) {
    let already_nominated = headers.get_all(header::VARY).iter().any(|value| {
        value
            .to_str()
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(field))
            })
            .unwrap_or(false)
    });
    if already_nominated {
        return;
    }
    // `field` is always a compile-time constant ASCII header name, so the
    // parse cannot fail; fall back to ignoring rather than panicking.
    if let Ok(value) = HeaderValue::from_str(field) {
        headers.append(header::VARY, value);
    }
}

/// Middleware that injects CORS headers into every response.
pub async fn cors_layer(mut req: Request, next: Next) -> Response {
    // Capture the origin before the handler consumes the request.
    let cors = cors_headers(req.headers());
    // The response is origin-dependent only when an `Origin` was echoed; a
    // request without `Origin` gets `Access-Control-Allow-Origin: *`, which
    // every origin may reuse.
    let origin_echoed = req.headers().contains_key(header::ORIGIN);
    // Stash for handlers that may want to inspect it.
    req.extensions_mut().insert(cors.clone());
    let mut response = next.run(req).await;
    // Insert rather than append: a target or handler must not leave a second
    // value that could make the browser select the wrong origin.
    for (name, value) in &cors {
        response.headers_mut().insert(name, value.clone());
    }
    if origin_echoed {
        add_vary_field(response.headers_mut(), "origin");
    }
    response
}

/// `OPTIONS /*target` preflight handler.
///
/// Returns `204 No Content` with CORS headers after validating the target and
/// requesting-origin policies, including blacklist/whitelist precedence.
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
    // The preflight response echoes `Access-Control-Request-Headers` and
    // reflects the request `Origin`, so shared caches must key on both.
    add_vary_field(response.headers_mut(), "origin");
    add_vary_field(response.headers_mut(), "access-control-request-headers");
    response.headers_mut().extend(cors);
    Ok(response)
}

#[allow(dead_code)]
fn _ensure_header_name_parse() {
    // Compile-time sanity that the header names we use are valid.
    let _: HeaderName = header::ACCESS_CONTROL_ALLOW_ORIGIN;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vary_fields(headers: &HeaderMap) -> Vec<String> {
        headers
            .get_all(header::VARY)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|field| !field.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    }

    #[test]
    fn vary_field_is_added_when_absent() {
        let mut headers = HeaderMap::new();
        add_vary_field(&mut headers, "origin");
        assert_eq!(vary_fields(&headers), vec!["origin"]);
    }

    #[test]
    fn vary_field_is_not_duplicated_across_repeated_headers() {
        let mut headers = HeaderMap::new();
        headers.append(header::VARY, HeaderValue::from_static("Accept"));
        headers.append(header::VARY, HeaderValue::from_static("Origin"));
        add_vary_field(&mut headers, "origin");
        assert_eq!(vary_fields(&headers), vec!["accept", "origin"]);
    }

    #[test]
    fn vary_field_is_not_duplicated_within_a_single_header() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::VARY,
            HeaderValue::from_static("Accept-Encoding, ORIGIN"),
        );
        add_vary_field(&mut headers, "origin");
        assert_eq!(vary_fields(&headers), vec!["accept-encoding", "origin"]);
        // No extra header was appended.
        assert_eq!(headers.get_all(header::VARY).iter().count(), 1);
    }

    #[test]
    fn distinct_vary_fields_are_appended_independently() {
        let mut headers = HeaderMap::new();
        headers.append(header::VARY, HeaderValue::from_static("accept"));
        add_vary_field(&mut headers, "origin");
        add_vary_field(&mut headers, "access-control-request-headers");
        assert_eq!(
            vary_fields(&headers),
            vec!["accept", "origin", "access-control-request-headers"]
        );
    }
}
