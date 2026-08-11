//! Request extractors: requesting origin, client IP, and the composite
//! rate-limit key used by [`axum_limit`].
//!
//! The rate-limit key is `(origin, client_ip)` so that limits apply
//! per requesting site per client address, as specified in the config.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, header};
use axum_limit::{Key, StorageKey};

use crate::state::AppState;

/// The requesting site's host, derived from the `Origin` header (preferred)
/// or the `Referer` header as a fallback. `None` when neither is present
/// or parseable (e.g. same-origin / direct requests).
#[derive(Debug, Clone)]
pub struct Origin(pub Option<String>);

impl Origin {
    /// Extract the host from request headers.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        if let Some(host) = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .and_then(Self::host_of)
        {
            return Origin(Some(host));
        }
        if let Some(host) = headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .and_then(Self::host_of)
        {
            return Origin(Some(host));
        }
        Origin(None)
    }

    /// Parse a URL-ish string and return its host (lowercased).
    fn host_of(value: &str) -> Option<String> {
        url::Url::parse(value)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
    }
}

impl Key for Origin {
    type Extractor = Origin;

    fn from_extractor(extractor: &Self::Extractor) -> Self {
        extractor.clone()
    }
}

impl StorageKey for Origin {
    fn storage_key(&self) -> String {
        match &self.0 {
            Some(h) => format!("origin:{h}"),
            None => "origin:unknown".to_string(),
        }
    }
}

/// The client's real IP address, taken from the configured
/// `real_ip_header` when present (reverse-proxy scenario), falling back to
/// the TCP peer address.
#[derive(Debug, Clone)]
pub struct ClientIp(pub String);

impl ClientIp {
    /// Extract the client IP from request parts + config.
    pub fn from_parts(parts: &Parts, config: &crate::config::Config) -> Self {
        // 1. Configured real-IP header (e.g. X-Real-IP).
        if let Ok(name) = config
            .application
            .real_ip_header
            .parse::<axum::http::HeaderName>()
            && let Some(value) = parts.headers.get(&name).and_then(|v| v.to_str().ok())
        {
            let ip = value.split(',').next().unwrap_or("").trim();
            if let Ok(ip) = ip.parse::<std::net::IpAddr>() {
                return ClientIp(ip.to_string());
            }
        }
        // 2. Fall back to the TCP peer address.
        if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            return ClientIp(addr.ip().to_string());
        }
        ClientIp("unknown".to_string())
    }
}

impl Key for ClientIp {
    type Extractor = ClientIp;

    fn from_extractor(extractor: &Self::Extractor) -> Self {
        extractor.clone()
    }
}

impl StorageKey for ClientIp {
    fn storage_key(&self) -> String {
        format!("ip:{}", self.0)
    }
}

/// Composite rate-limit / bandwidth key: `(origin, client_ip)`.
///
/// This is the subject against which both request-count and byte-bandwidth
/// limits are enforced.
#[derive(Debug, Clone)]
pub struct RateLimitKey {
    /// Requesting site host (or `None` if not determinable).
    pub origin: Origin,
    /// Client IP string.
    pub client_ip: ClientIp,
}

impl RateLimitKey {
    /// A stable string key shared by both the request-count and bandwidth
    /// limiters so they bucket the same subject.
    pub fn bucket(&self) -> String {
        format!(
            "{}|{}",
            self.origin.storage_key(),
            self.client_ip.storage_key()
        )
    }
}

impl FromRequestParts<Arc<AppState>> for RateLimitKey {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let origin = Origin::from_headers(&parts.headers);
        let client_ip = ClientIp::from_parts(parts, &state.config);
        Ok(RateLimitKey { origin, client_ip })
    }
}

impl Key for RateLimitKey {
    // We use ourselves as the extractor (we implement FromRequestParts).
    type Extractor = RateLimitKey;

    fn from_extractor(extractor: &Self::Extractor) -> Self {
        extractor.clone()
    }
}

impl StorageKey for RateLimitKey {
    fn storage_key(&self) -> String {
        self.bucket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn real_ip_header_accepts_only_ip_addresses() {
        let config = crate::config::Config {
            application: crate::config::ApplicationConfig {
                host: vec!["127.0.0.1".to_string()],
                port: 9647,
                hostname: "localhost".to_string(),
                real_ip_header: "X-Real-IP".to_string(),
            },
            connection: crate::config::ConnectionConfig {
                target: Default::default(),
                origin: Default::default(),
                rate_limit: Vec::new(),
                bandwidth_limit: Default::default(),
            },
            proxy: crate::config::ProxyConfig {
                max_redirects: 0,
                timeout: 30,
            },
            cache: crate::config::CacheConfig::default(),
        };
        let request = Request::builder()
            .header("X-Real-IP", "not-an-ip")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();

        assert_eq!(ClientIp::from_parts(&parts, &config).0, "unknown");
    }
}
