//! Byte-bandwidth limiting.
//!
//! Two layers of byte accounting, both keyed by `(origin, client_ip)`:
//!
//! - **Connection bandwidth** — a fixed-window counter per tier (e.g.
//!   4 GiB / 60 s). Each proxied response's bytes are charged against every
//!   configured tier. Exceeding a tier is reported to the stream meter but is
//!   soft: the current response continues to completion.
//! - **Per-result size** — a hard cap on a single response body (e.g.
//!   512 MiB). If `Content-Length` advertises more, the request is rejected
//!   before streaming begins; otherwise the running total is checked per
//!   chunk and the stream is aborted if exceeded.
//!
//! Both use [`u64`] counters (the config's 4 GiB limit overflows `u32`).
//! The fixed-window approach is chosen over a token-bucket (e.g. `governor`)
//! because (a) we want immediate accounting rather than "wait until allowed",
//! and (b) `governor`'s burst capacity is a `NonZeroU32`, which cannot
//! represent 4 GiB.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::Stream;
use futures::stream::StreamExt;
use thiserror::Error;

use crate::config::LimitTier;

/// A single fixed-window byte counter.
#[derive(Debug, Clone, Copy)]
struct Window {
    /// Window length.
    period: Duration,
    /// Maximum bytes allowed within the window.
    max: u64,
}

/// Errors from bandwidth accounting.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BandwidthError {
    /// The per-result size cap was exceeded.
    #[error("result size cap exceeded ({used} > {max} bytes)")]
    ResultExceeded { used: u64, max: u64 },
    /// A connection-bandwidth tier was exceeded.
    #[error("bandwidth limit exceeded for tier ({max} bytes / {secs}s)")]
    ConnectionExceeded { max: u64, secs: u64 },
}

/// Per-key window state.
#[derive(Debug, Clone, Copy)]
struct WindowState {
    /// Bytes consumed so far in the current window.
    used: u64,
    /// Instant at which the current window started.
    window_start: Instant,
}

impl WindowState {
    fn new() -> Self {
        Self {
            used: 0,
            window_start: Instant::now(),
        }
    }

    /// Charge `n` bytes, resetting the window if it has elapsed.
    /// Returns `Err` if the charge would exceed the cap.
    fn charge(&mut self, n: u64, window: Window) -> Result<(), BandwidthError> {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= window.period {
            // Window elapsed: start a fresh one.
            self.window_start = now;
            self.used = 0;
        }
        let new_used = self.used.saturating_add(n);
        if new_used > window.max {
            return Err(BandwidthError::ConnectionExceeded {
                max: window.max,
                secs: window.period.as_secs(),
            });
        }
        self.used = new_used;
        Ok(())
    }
}

/// Per-(origin, ip) bandwidth limiter enforcing all configured connection
/// tiers simultaneously.
#[derive(Debug, Clone)]
pub struct BandwidthLimiter {
    /// One map per tier: key → window state.
    tiers: Arc<Vec<(Window, DashMap<String, WindowState>)>>,
}

impl BandwidthLimiter {
    /// Construct from the config's connection bandwidth tiers.
    pub fn new(tiers: &[LimitTier]) -> Self {
        let compiled = tiers
            .iter()
            .map(|t| {
                let window = Window {
                    period: Duration::from_secs(t.window),
                    max: t.max,
                };
                (window, DashMap::new())
            })
            .collect();
        Self {
            tiers: Arc::new(compiled),
        }
    }

    /// Charge `n` bytes against every tier for the given bucket key.
    /// Returns the first tier error encountered (all tiers are still
    /// charged up to the failing one).
    pub fn charge(&self, bucket: &str, n: u64) -> Result<(), BandwidthError> {
        for (window, map) in self.tiers.iter() {
            let mut state = map
                .entry(bucket.to_string())
                .or_insert_with(WindowState::new);
            state.charge(n, *window)?;
        }
        Ok(())
    }
}

/// A guard that tracks total bytes for a single proxied response and
/// enforces the per-result cap.
#[derive(Debug)]
pub struct ResultSizeGuard {
    /// Bytes streamed so far.
    used: u64,
    /// Hard cap on total bytes for this result.
    max: u64,
}

impl ResultSizeGuard {
    /// Create a guard. `max == 0` means "no per-result cap".
    pub fn new(max: u64) -> Self {
        Self { used: 0, max }
    }

    /// Returns `true` if a `Content-Length` of `n` would exceed the cap.
    /// When there is no cap (`max == 0`), always returns `false`.
    pub fn would_exceed(&self, n: u64) -> bool {
        self.max != 0 && n > self.max
    }

    /// Charge `n` bytes. Returns `Err` if the running total exceeds the cap.
    pub fn charge(&mut self, n: u64) -> Result<(), BandwidthError> {
        if self.max == 0 {
            return Ok(());
        }
        self.used = self.used.saturating_add(n);
        if self.used > self.max {
            return Err(BandwidthError::ResultExceeded {
                used: self.used,
                max: self.max,
            });
        }
        Ok(())
    }
}

/// A chunk yielded by a metered proxy stream.
pub type MeteredItem = Result<bytes::Bytes, MeteredError>;

/// Errors that can occur while streaming a proxied response body.
#[derive(Debug, thiserror::Error)]
pub enum MeteredError {
    /// The upstream stream produced an error.
    #[error("upstream stream error: {0}")]
    Upstream(String),
    /// The per-result size cap was exceeded.
    #[error("result size cap exceeded ({used} > {max} bytes)")]
    ResultExceeded { used: u64, max: u64 },
    /// A connection-bandwidth tier was exceeded.
    #[error("bandwidth limit exceeded for tier ({max} bytes / {secs}s)")]
    ConnectionExceeded { max: u64, secs: u64 },
}

impl From<BandwidthError> for MeteredError {
    fn from(e: BandwidthError) -> Self {
        match e {
            BandwidthError::ResultExceeded { used, max } => {
                MeteredError::ResultExceeded { used, max }
            }
            BandwidthError::ConnectionExceeded { max, secs } => {
                MeteredError::ConnectionExceeded { max, secs }
            }
        }
    }
}

/// Wrap a byte-chunk stream with bandwidth + per-result accounting.
///
/// Each chunk is charged against the per-result guard first (cheaper), then
/// the connection tiers (via `limiter`). A per-result failure terminates the
/// stream. A connection-tier exceedance is reported by the accounting
/// operation but is soft for streaming responses: it is logged and the chunk
/// is still yielded. Upstream stream errors are converted to
/// [`MeteredError::Upstream`].
///
/// `bucket` is the `(origin, ip)` key for the connection tiers.
pub fn metered_stream<S, E>(
    inner: S,
    limiter: BandwidthLimiter,
    bucket: String,
    mut result_guard: ResultSizeGuard,
) -> impl Stream<Item = MeteredItem>
where
    S: Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    async_stream::stream! {
        let mut inner = std::pin::pin!(inner);
        while let Some(chunk) = inner.next().await {
            let chunk = match chunk {
                Ok(b) => b,
                Err(e) => {
                    yield Err(MeteredError::Upstream(e.to_string()));
                    break;
                }
            };
            let n = chunk.len() as u64;
            // Per-result cap first (cheaper, no map lookup).
            if let Err(e) = result_guard.charge(n) {
                yield Err(MeteredError::from(e));
                break;
            }
            // Connection tiers are a soft cap. Continue streaming even when
            // the current window is exceeded so the response is not truncated.
            if let Err(BandwidthError::ConnectionExceeded { max, secs }) =
                limiter.charge(&bucket, n)
            {
                tracing::debug!(%bucket, max, secs, "soft connection bandwidth limit exceeded");
            }
            yield Ok(chunk);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(window: u64, max: u64) -> LimitTier {
        LimitTier { window, max }
    }

    #[test]
    fn result_guard_no_cap_when_zero() {
        let mut g = ResultSizeGuard::new(0);
        assert!(!g.would_exceed(u64::MAX));
        assert!(g.charge(1_000_000).is_ok());
    }

    #[test]
    fn result_guard_rejects_oversize_content_length() {
        let g = ResultSizeGuard::new(100);
        assert!(g.would_exceed(101));
        assert!(!g.would_exceed(100));
    }

    #[test]
    fn result_guard_aborts_mid_stream() {
        let mut g = ResultSizeGuard::new(10);
        assert!(g.charge(5).is_ok());
        assert!(g.charge(5).is_ok());
        // 11th byte exceeds.
        let err = g.charge(1).unwrap_err();
        assert_eq!(err, BandwidthError::ResultExceeded { used: 11, max: 10 });
    }

    #[test]
    fn connection_tier_charges_and_exceeds() {
        let limiter = BandwidthLimiter::new(&[tier(60, 100)]);
        assert!(limiter.charge("k", 60).is_ok());
        assert!(limiter.charge("k", 40).is_ok());
        let err = limiter.charge("k", 1).unwrap_err();
        assert_eq!(
            err,
            BandwidthError::ConnectionExceeded { max: 100, secs: 60 }
        );
    }

    #[test]
    fn multiple_tiers_all_enforced() {
        let limiter = BandwidthLimiter::new(&[tier(1, 5), tier(60, 1000)]);
        // 5 req in 1s window ok, under 1000/60s.
        for _ in 0..5 {
            assert!(limiter.charge("k", 1).is_ok());
        }
        // 6th exceeds the 1s/5 tier.
        assert!(limiter.charge("k", 1).is_err());
    }

    #[test]
    fn keys_are_isolated() {
        let limiter = BandwidthLimiter::new(&[tier(60, 10)]);
        assert!(limiter.charge("a", 10).is_ok());
        // Different key has its own bucket.
        assert!(limiter.charge("b", 10).is_ok());
        assert!(limiter.charge("a", 1).is_err());
    }
}
