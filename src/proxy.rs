//! The proxy handler: `GET /{ *target}`.
//!
//! Flow:
//! 1. Extract the target URL from the request path (strip leading `/`,
//!    prepend `https://` if no scheme).
//! 2. Validate the URL and evaluate target + origin policies. Blacklists are
//!    evaluated first, but matching whitelist entries override them.
//! 3. Enforce request-count rate limits (all configured tiers) via
//!    [`axum_limit`]'s [`LimitState`].
//! 4. Build an upstream GET request, forwarding client headers minus
//!    hop-by-hop / proxy-injected ones.
//! 5. Send the request with manual redirect-following (to preserve the
//!    `Authorization` header across cross-host redirects, which reqwest's
//!    built-in redirect strips for security).
//! 6. On response: check `Content-Length` against the per-result cap, copy
//!    status + headers (minus hop-by-hop and, when needed, `Content-Length`),
//!    then stream the body through the bandwidth + result-size meter.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{OriginalUri, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_limit::{LimitState, Quota};
use futures::StreamExt;
use url::Url;

use crate::error::AppError;
use crate::extractors::RateLimitKey;
use crate::limit::{ResultSizeGuard, metered_stream};
use crate::state::AppState;

fn cached_response(
    state: &AppState,
    cache: &crate::cache::Cache,
    entry: &crate::cache::CacheEntry,
    bucket: String,
    result_max: u64,
    cache_status: &'static str,
) -> Result<Response, AppError> {
    let status = StatusCode::from_u16(entry.status)
        .map_err(|error| AppError::Upstream(format!("invalid cached status: {error}")))?;
    let mut headers = crate::cache::headers_from_entry(entry);
    if result_max != 0 {
        headers.remove(header::CONTENT_LENGTH);
    }
    crate::cache::add_cache_header(&mut headers, cache_status);
    let result_guard = ResultSizeGuard::new(result_max);
    if result_guard.would_exceed(entry.body_len) {
        return Err(AppError::TooLarge(format!(
            "cached response body ({}) exceeds per-result cap ({result_max})",
            entry.body_len
        )));
    }
    let body_stream = crate::cache::file_stream(cache.entry_body_path(entry).to_path_buf());
    let metered = metered_stream(
        body_stream,
        state.bandwidth.clone(),
        bucket.clone(),
        result_guard,
    );
    let log_bucket = bucket;
    let mapped = metered.map(move |item| match item {
        Ok(bytes) => Ok::<bytes::Bytes, std::io::Error>(bytes),
        Err(error) => {
            tracing::warn!(bucket = %log_bucket, error = %error, "cached response stream ended with error");
            Err(std::io::Error::other(error.to_string()))
        }
    });
    let mut response = Response::builder().status(status);
    *response.headers_mut().unwrap() = headers;
    response.body(Body::from_stream(mapped)).map_err(|error| {
        AppError::Upstream(format!("failed to build cached response body: {error}"))
    })
}

/// Parse the target URL from the incoming request's URI.
///
/// When the request URI is absolute (e.g. `https://github.com/a/b?q=1`),
/// it is used directly. Otherwise the path portion (everything after the
/// leading `/`) is treated as the target; if it lacks a scheme, `https://`
/// is prepended. The query string is preserved.
pub(crate) fn parse_target_url(original_uri: &axum::http::Uri) -> Result<Url, AppError> {
    // If the URI itself carries a scheme (absolute form), use it whole.
    if let Some(scheme) = original_uri.scheme_str() {
        // Reject non-http(s) schemes early.
        if scheme != "http" && scheme != "https" {
            return Err(AppError::BadUrl(format!(
                "unsupported scheme `{scheme}`; only http/https are allowed"
            )));
        }
        return Url::parse(&original_uri.to_string()).map_err(|e| AppError::BadUrl(e.to_string()));
    }

    // `OriginalUri` gives us the raw, undecoded path + query.
    let path_and_query = original_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");

    // Strip exactly one leading slash.
    let raw = path_and_query.strip_prefix('/').unwrap_or(path_and_query);

    if raw.is_empty() {
        return Err(AppError::BadUrl("no target url provided".to_string()));
    }

    // Prepend a scheme if absent. We accept `http://`, `https://`, and
    // scheme-relative `//host/...`.
    let with_scheme = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.to_string()
    } else if let Some(rest) = raw.strip_prefix("//") {
        format!("https://{rest}")
    } else {
        format!("https://{raw}")
    };

    Url::parse(&with_scheme).map_err(|e| AppError::BadUrl(e.to_string()))
}

/// Forward client headers to the target, stripping hop-by-hop and
/// proxy-injected headers. The `Host` header is set to the target's host.
fn forward_headers(source: &HeaderMap, target_url: &Url) -> HeaderMap {
    let mut out = HeaderMap::new();
    let connection_headers: Vec<_> = crate::cors::connection_headers(source)
        .map(str::to_ascii_lowercase)
        .collect();
    for (name, value) in source.iter() {
        let name_str = name.as_str();
        if crate::cors::is_hop_by_hop(name_str)
            || connection_headers.iter().any(|header| header == name_str)
        {
            continue;
        }
        // Skip Host — we set it explicitly below.
        if name == header::HOST {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    // Set Host to the target's host (with port if non-default).
    let host = if let Some(port) = target_url.port() {
        match target_url.host_str() {
            Some(h) => format!("{h}:{port}"),
            None => return out,
        }
    } else {
        target_url
            .host_str()
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    if let Ok(val) = HeaderValue::from_str(&host) {
        out.insert(header::HOST, val);
    }
    out
}

/// Copy response headers from the upstream response, stripping hop-by-hop
/// headers. `Content-Length` is also removed when the body can be truncated
/// by the per-result limit.
fn copy_response_headers(source: &HeaderMap, body_may_be_truncated: bool) -> HeaderMap {
    let mut out = HeaderMap::new();
    let connection_headers: Vec<_> = crate::cors::connection_headers(source)
        .map(str::to_ascii_lowercase)
        .collect();
    for (name, value) in source.iter() {
        if crate::cors::is_hop_by_hop(name.as_str())
            || crate::cors::is_cors_response_header(name.as_str())
            || connection_headers
                .iter()
                .any(|header| header == name.as_str())
            || (body_may_be_truncated && name == header::CONTENT_LENGTH)
        {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

pub(crate) fn validate_target_policy(
    state: &AppState,
    target_url: &Url,
    origin: &crate::extractors::Origin,
) -> Result<(), AppError> {
    if !matches!(target_url.scheme(), "http" | "https") {
        return Err(AppError::BadUrl(format!(
            "unsupported scheme `{}`; only http/https are allowed",
            target_url.scheme()
        )));
    }
    let target_host = target_url
        .host_str()
        .ok_or_else(|| AppError::BadUrl("target url has no host".to_string()))?;

    if !state.match_policy.target.is_allowed(target_host) {
        tracing::info!(%target_host, "target denied by policy");
        return Err(AppError::Denied(format!(
            "target `{target_host}` is not allowed"
        )));
    }
    match &origin.0 {
        Some(origin_host) if !state.match_policy.origin.is_allowed(origin_host) => {
            tracing::info!(%origin_host, "origin denied by policy");
            return Err(AppError::Denied(format!(
                "origin `{origin_host}` is not allowed"
            )));
        }
        None if state.match_policy.origin.has_whitelist() => {
            tracing::info!("request denied because no valid origin was provided");
            return Err(AppError::Denied(
                "a valid Origin or Referer header is required".to_string(),
            ));
        }
        _ => {}
    }
    Ok(())
}

/// The main proxy handler, mounted at `GET /*target`.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    OriginalUri(original_uri): OriginalUri,
    RateLimitKey { origin, client_ip }: RateLimitKey,
    req: Request,
) -> Result<Response, AppError> {
    // --- 1. Parse + validate target URL ---
    let target_url = parse_target_url(&original_uri)?;

    // Only http/https schemes are proxyable.
    if !matches!(target_url.scheme(), "http" | "https") {
        return Err(AppError::BadUrl(format!(
            "unsupported scheme `{}`; only http/https are allowed",
            target_url.scheme()
        )));
    }

    // --- 2. Evaluate allow/deny lists ---
    validate_target_policy(&state, &target_url, &origin)?;
    let target_host = target_url.host_str().unwrap_or("unknown");

    // --- 3. Request-count rate limit (all tiers) ---
    // We check each configured tier directly via LimitState; the first to
    // fail short-circuits with a 429 (axum_limit's snapshot carries the
    // Retry-After info).
    let limit_state: &LimitState<RateLimitKey> = &state.limit_state;
    let key = RateLimitKey {
        origin: origin.clone(),
        client_ip: client_ip.clone(),
    };
    let bucket = key.bucket();
    for tier in &state.config.connection.rate_limit {
        // axum-limit stores request counts as usize and periods as milliseconds.
        // Clamp configured u64 values rather than allowing truncation or
        // multiplication overflow on unusual configurations/platforms.
        let max = tier.max.min(usize::MAX as u64) as usize;
        let period_ms = tier.window.saturating_mul(1000);
        let quota = Quota::new(max, period_ms);
        let snapshot = limit_state
            .check(key.clone(), quota)
            .await
            .map_err(|e| AppError::LimitBackend(e.to_string()))?;
        if !snapshot.allowed {
            tracing::info!(
                bucket = %bucket,
                window = tier.window,
                max = tier.max,
                "rate limit exceeded"
            );
            let mut response =
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded.").into_response();
            let now_ms = axum_limit_snapshot_now_ms();
            response.headers_mut().extend(snapshot.to_headers(now_ms));
            return Ok(response);
        }
    }

    // --- 4. Check the persistent response cache ---
    let cache_plan = state
        .cache
        .as_ref()
        .and_then(|cache| cache.plan(&target_url, req.headers()));
    let cached_entry = if let (Some(cache), Some(plan)) = (&state.cache, &cache_plan) {
        cache.lookup(plan, crate::cache::now()).await
    } else {
        None
    };
    let force_revalidation = crate::cache::request_requires_revalidation(req.headers());
    if let (Some(cache), Some(entry)) = (&state.cache, cached_entry.as_ref())
        && !force_revalidation
        && crate::cache::Cache::is_fresh(entry, crate::cache::now())
    {
        return cached_response(
            &state,
            cache,
            entry,
            bucket,
            state.config.connection.bandwidth_limit.result.max,
            "HIT",
        );
    }

    // --- 5. Build upstream request ---
    let mut forwarded = forward_headers(req.headers(), &target_url);
    if let Some(entry) = cached_entry.as_ref() {
        crate::cache::Cache::add_validators(&mut forwarded, entry);
    }
    tracing::info!(
        %target_url,
        has_auth = forwarded.contains_key(header::AUTHORIZATION),
        "proxying GET"
    );
    let mut upstream_req = state
        .http_client
        .get(target_url.as_str())
        .headers(forwarded);

    // --- 6. Send with manual redirect-following ---
    // reqwest's built-in redirect strips the Authorization header on
    // cross-host redirects (e.g. api.github.com → release-assets.githubusercontent.com).
    // We follow redirects manually so all client headers survive.
    let max_redirects = state.config.proxy.max_redirects;
    let mut redirects_left = max_redirects;
    let mut redirect_base = target_url.clone();
    let upstream_response = loop {
        let resp = upstream_req.send().await.map_err(AppError::from)?;
        if resp.status() == StatusCode::NOT_MODIFIED
            && let (Some(cache), Some(plan), Some(mut entry)) =
                (&state.cache, &cache_plan, cached_entry.clone())
        {
            cache
                .refresh(&mut entry, resp.headers(), plan.ttl())
                .await
                .map_err(|error| {
                    AppError::Upstream(format!("failed to refresh cache metadata: {error}"))
                })?;
            return cached_response(
                &state,
                cache,
                &entry,
                bucket,
                state.config.connection.bandwidth_limit.result.max,
                "REVALIDATED",
            );
        }
        // `StatusCode::is_redirection()` also includes statuses such as
        // `304 Not Modified`, which are not redirect instructions and do not
        // have to contain a Location header. Only follow statuses that
        // explicitly define redirect semantics here.
        if !is_followable_redirect(resp.status()) {
            break resp;
        }
        if max_redirects == 0 || redirects_left == 0 {
            return Err(AppError::Upstream("redirect limit reached".into()));
        }
        redirects_left -= 1;
        let target_url = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Upstream("redirect without Location header".into()))?;
        tracing::info!(%target_url, "following redirect");
        // Reuse the same headers (including Authorization) for the next hop.
        let next_url = Url::parse(target_url)
            .or_else(|_| redirect_base.join(target_url))
            .map_err(|e| AppError::BadUrl(e.to_string()))?;
        validate_target_policy(&state, &next_url, &origin)?;
        redirect_base = next_url.clone();
        let mut forwarded = forward_headers(req.headers(), &next_url);
        if let Some(entry) = cached_entry.as_ref() {
            crate::cache::Cache::add_validators(&mut forwarded, entry);
        }
        upstream_req = state.http_client.get(next_url).headers(forwarded);
    };

    // --- 7. Build the proxied response ---
    // Per-result size cap: reject early if Content-Length exceeds it.
    let result_max = state.config.connection.bandwidth_limit.result.max;
    let result_guard = ResultSizeGuard::new(result_max);
    if let Some(content_length) = upstream_response.content_length()
        && result_guard.would_exceed(content_length)
    {
        tracing::info!(
            %target_host,
            content_length,
            max = result_max,
            "result size cap exceeded (Content-Length)"
        );
        return Err(AppError::TooLarge(format!(
            "response Content-Length ({content_length}) exceeds per-result cap ({result_max})"
        )));
    }

    let status = upstream_response.status();
    // An upstream Content-Length is only a declaration. If the strict
    // per-result cap is enabled, the body may still exceed it despite a
    // smaller (or missing) declaration, so omit the header before streaming.
    // With no result cap, the proxy never truncates for bandwidth reasons and
    // can safely preserve the upstream Content-Length.
    let headers = copy_response_headers(upstream_response.headers(), result_max != 0);
    let mut headers = headers;
    if cache_plan.is_some() {
        crate::cache::add_cache_header(
            &mut headers,
            if cached_entry.is_some() && force_revalidation {
                "REVALIDATED"
            } else {
                "MISS"
            },
        );
    }

    // Begin an atomic cache write for eligible responses. Cache storage is
    // best-effort: a write failure must not interrupt the client response.
    let cache_writer = if let (Some(cache), Some(plan)) = (&state.cache, cache_plan) {
        cache
            .begin_write(
                plan,
                status.as_u16(),
                upstream_response.headers(),
                req.headers(),
            )
            .await
    } else {
        None
    };

    // Wrap the upstream body stream with bandwidth + result-size accounting.
    let body_stream = upstream_response.bytes_stream();
    let metered = metered_stream(
        body_stream,
        state.bandwidth.clone(),
        bucket.clone(),
        result_guard,
    );

    // Convert MeteredError items into a stream that axum's Body accepts while
    // teeing successful chunks into the temporary cache body.
    let mapped = async_stream::stream! {
        let mut metered = std::pin::pin!(metered);
        let mut writer = cache_writer;
        while let Some(item) = futures::StreamExt::next(&mut metered).await {
            match item {
                Ok(bytes) => {
                    if let Some(active_writer) = writer.as_mut()
                        && let Err(error) = active_writer.write(&bytes).await
                    {
                        tracing::debug!(%error, "cache write failed; continuing without caching");
                        if let Some(active_writer) = writer.take() {
                            active_writer.discard().await;
                        }
                    }
                    yield Ok::<bytes::Bytes, std::io::Error>(bytes);
                }
                Err(error) => {
                    tracing::warn!(error = %error, "stream ended with error");
                    if let Some(active_writer) = writer.take() {
                        active_writer.discard().await;
                    }
                    yield Err(std::io::Error::other(error.to_string()));
                    break;
                }
            }
        }
        if let Some(active_writer) = writer
            && let Err(error) = active_writer.finish().await
        {
            tracing::debug!(%error, "cache commit failed");
        }
    };

    let mut response = Response::builder().status(status);
    *response.headers_mut().unwrap() = headers;
    response
        .body(Body::from_stream(mapped))
        .map_err(|e| AppError::Upstream(format!("failed to build response body: {e}")))
}

/// Returns the current time in milliseconds since the Unix epoch.
///
/// Used to populate rate-limit response headers (`Retry-After`, etc.).
fn axum_limit_snapshot_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Return whether an upstream status should be followed as a redirect.
///
/// `StatusCode::is_redirection()` is broader than the set of HTTP statuses
/// that carry a redirect destination: for example, a normal `304 Not
/// Modified` response is classified as a redirection but has no `Location`
/// header. Treating every 3xx response as a redirect causes such responses to
/// fail with "redirect without Location header".
fn is_followable_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;

    #[test]
    fn parses_https_url() {
        let uri: Uri = "https://github.com/a/b?q=1".parse().unwrap();
        let url = parse_target_url(&uri).unwrap();
        assert_eq!(url.as_str(), "https://github.com/a/b?q=1");
    }

    #[test]
    fn prepends_scheme_when_absent() {
        let uri: Uri = "/github.com/search?q=rust".parse().unwrap();
        let url = parse_target_url(&uri).unwrap();
        assert_eq!(url.as_str(), "https://github.com/search?q=rust");
    }

    #[test]
    fn handles_scheme_relative() {
        let uri: Uri = "//github.com/".parse().unwrap();
        let url = parse_target_url(&uri).unwrap();
        assert_eq!(url.as_str(), "https://github.com/");
    }

    #[test]
    fn rejects_empty() {
        let uri: Uri = "/".parse().unwrap();
        let err = parse_target_url(&uri).unwrap_err();
        assert!(matches!(err, AppError::BadUrl(_)));
    }

    #[test]
    fn rejects_non_http_scheme() {
        // `ftp://` is a valid absolute URI that we reject (only http/https).
        let uri: Uri = "ftp://example.com/file".parse().unwrap();
        let err = parse_target_url(&uri).unwrap_err();
        assert!(matches!(err, AppError::BadUrl(_)));
    }

    #[test]
    fn forward_headers_strips_hop_by_hop() {
        let mut source = HeaderMap::new();
        source.insert(header::AUTHORIZATION, "Bearer x".parse().unwrap());
        source.insert(header::CONNECTION, "keep-alive".parse().unwrap());
        source.insert(header::HOST, "proxy.local".parse().unwrap());
        source.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        let url = Url::parse("https://github.com/").unwrap();
        let out = forward_headers(&source, &url);
        assert!(out.contains_key(header::AUTHORIZATION));
        assert!(!out.contains_key(header::CONNECTION));
        assert!(!out.contains_key("x-forwarded-for"));
        // Host is set to the target's host.
        assert_eq!(out.get(header::HOST).unwrap(), "github.com");
    }

    #[test]
    fn forward_headers_preserves_cookie() {
        let mut source = HeaderMap::new();
        source.insert(header::COOKIE, "session=abc".parse().unwrap());
        let url = Url::parse("https://example.com/").unwrap();
        let out = forward_headers(&source, &url);
        assert_eq!(out.get(header::COOKIE).unwrap(), "session=abc");
    }

    #[test]
    fn forward_headers_strips_connection_nominated_headers() {
        let mut source = HeaderMap::new();
        source.insert(header::CONNECTION, "x-private".parse().unwrap());
        source.insert("x-private", "secret".parse().unwrap());
        let url = Url::parse("https://example.com/").unwrap();

        let out = forward_headers(&source, &url);

        assert!(!out.contains_key("x-private"));
    }

    #[test]
    fn response_headers_remove_content_length_when_body_can_be_truncated() {
        let mut source = HeaderMap::new();
        source.insert(header::CONTENT_LENGTH, "10".parse().unwrap());
        source.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());

        let out = copy_response_headers(&source, true);

        assert!(!out.contains_key(header::CONTENT_LENGTH));
        assert!(out.contains_key(header::CONTENT_TYPE));
    }

    #[test]
    fn response_headers_preserve_content_length_without_result_cap() {
        let mut source = HeaderMap::new();
        source.insert(header::CONTENT_LENGTH, "10".parse().unwrap());

        let out = copy_response_headers(&source, false);

        assert_eq!(out.get(header::CONTENT_LENGTH).unwrap(), "10");
    }

    #[test]
    fn response_headers_preserve_authorization_vary() {
        let mut source = HeaderMap::new();
        source.insert(
            header::VARY,
            HeaderValue::from_static("Authorization, Accept-Encoding"),
        );

        let out = copy_response_headers(&source, true);

        assert_eq!(
            out.get(header::VARY).unwrap(),
            "Authorization, Accept-Encoding"
        );
    }

    #[test]
    fn response_headers_remove_upstream_cors_headers() {
        let mut source = HeaderMap::new();
        source.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("https://proxy.example"),
        );
        source.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("false"),
        );
        source.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

        let out = copy_response_headers(&source, false);

        assert!(!out.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        assert!(!out.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
        assert!(out.contains_key(header::CONTENT_TYPE));
    }

    #[test]
    fn only_location_redirect_statuses_are_followed() {
        assert!(is_followable_redirect(StatusCode::MOVED_PERMANENTLY));
        assert!(is_followable_redirect(StatusCode::FOUND));
        assert!(is_followable_redirect(StatusCode::SEE_OTHER));
        assert!(is_followable_redirect(StatusCode::TEMPORARY_REDIRECT));
        assert!(is_followable_redirect(StatusCode::PERMANENT_REDIRECT));
        assert!(!is_followable_redirect(StatusCode::NOT_MODIFIED));
        assert!(!is_followable_redirect(StatusCode::MULTIPLE_CHOICES));
    }
}
