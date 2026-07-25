//! Shared application state, cloned (via [`Arc`]) into every request.

use axum_limit::LimitState;

use crate::config::Config;
use crate::extractors::RateLimitKey;
use crate::limit::BandwidthLimiter;
use crate::matcher::MatchPolicy;

/// The application state shared with all handlers.
///
/// Held behind an [`Arc`] so cheap clones are passed through request
/// extensions. The rate-limit [`LimitState`] is resolved via [`FromRef`]
/// so that `axum_limit` extractors can find it.
pub struct AppState {
    /// Parsed configuration.
    pub config: Config,
    /// Pre-compiled target + origin match policy.
    pub match_policy: MatchPolicy,
    /// Request-count rate limiter (per `(origin, ip)`).
    pub limit_state: LimitState<RateLimitKey>,
    /// Byte-bandwidth limiter (per `(origin, ip)`).
    pub bandwidth: BandwidthLimiter,
    /// Reusable upstream HTTP client.
    pub http_client: reqwest::Client,
}

impl AppState {
    /// Construct the shared state from a loaded config.
    pub fn new(config: Config) -> Result<Self, crate::error::AppError> {
        let match_policy = MatchPolicy::new(
            &config.connection.target.blacklist,
            &config.connection.target.whitelist,
            &config.connection.origin.blacklist,
            &config.connection.origin.whitelist,
        )
        .map_err(|e| crate::error::AppError::Denied(format!("invalid match policy: {e}")))?;

        let limit_state = LimitState::<RateLimitKey>::default();
        let bandwidth = BandwidthLimiter::new(&config.connection.bandwidth_limit.connection);

        let http_client = reqwest::Client::builder()
            // We handle redirects manually so the Authorization header
            // survives cross-host redirects (reqwest strips it automatically
            // for security, but we're a proxy — the client intentionally
            // sent the token).
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(config.proxy.timeout))
            // No compression features are enabled, so the client performs raw
            // passthrough: the original Content-Encoding / body bytes are
            // preserved exactly.
            .build()
            .map_err(|e| crate::error::AppError::Upstream(e.to_string()))?;

        Ok(Self {
            config,
            match_policy,
            limit_state,
            bandwidth,
            http_client,
        })
    }
}
