//! Configuration loading and validation.
//!
//! Config is parsed from YAML via [`noyalib`] using strict deserialization
//! (unknown keys are rejected to catch typos). The structure mirrors
//! [`config.example.yml`](../../config.example.yml).

use std::path::Path;

use noyalib::from_reader_strict;
use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// Top-level configuration root.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Application server settings.
    pub application: ApplicationConfig,
    /// Connection policy: target/origin lists, rate + bandwidth limits.
    pub connection: ConnectionConfig,
    /// Proxy behaviour: redirects, timeouts.
    pub proxy: ProxyConfig,
}

/// Application server settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationConfig {
    /// Bind addresses. Accepts either one host string or a YAML list.
    #[serde(deserialize_with = "deserialize_hosts")]
    pub host: Vec<String>,
    /// Bind port.
    pub port: u16,
    /// Public hostname (used for documentation / self-reference).
    pub hostname: String,
    /// Header name used to determine the real client IP when behind a
    /// reverse proxy (e.g. `X-Real-IP`). Falls back to the TCP peer
    /// address when absent.
    #[serde(default = "default_real_ip_header")]
    pub real_ip_header: String,
}

fn default_real_ip_header() -> String {
    "X-Real-IP".to_string()
}

/// Deserialize one or more bind hosts while keeping the single-host config
/// format backwards-compatible.
fn deserialize_hosts<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Hosts {
        One(String),
        Many(Vec<String>),
    }

    match Hosts::deserialize(deserializer)? {
        Hosts::One(host) => Ok(vec![host]),
        Hosts::Many(hosts) if hosts.is_empty() => Err(serde::de::Error::custom(
            "application.host must not be empty",
        )),
        Hosts::Many(hosts) => Ok(hosts),
    }
}

/// Connection policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    /// Target URL allow/deny lists.
    pub target: TargetListConfig,
    /// Requesting-origin allow/deny lists.
    pub origin: TargetListConfig,
    /// Per-(origin, ip) request-count rate limits (all tiers apply).
    #[serde(default)]
    pub rate_limit: Vec<LimitTier>,
    /// Per-(origin, ip) byte bandwidth limits.
    #[serde(default)]
    pub bandwidth_limit: BandwidthLimitConfig,
}

/// A blacklist + whitelist pair. If both are empty, everything is allowed.
/// If the whitelist is non-empty, only whitelisted entries are allowed
/// (and must not also be blacklisted).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetListConfig {
    /// Denied entries (exact / wildcard / regex). `null` entries (e.g. from
    /// `- #` comment-only YAML list items) are filtered out.
    #[serde(default, deserialize_with = "deserialize_non_empty_strings")]
    pub blacklist: Vec<String>,
    /// Allowed entries (exact / wildcard / regex). Takes precedence over
    /// the blacklist when non-empty.
    #[serde(default, deserialize_with = "deserialize_non_empty_strings")]
    pub whitelist: Vec<String>,
}

/// Deserialize a `Vec<String>`, dropping `null` and empty/whitespace-only
/// entries. This handles YAML patterns like `- # comment` which parse as
/// a list containing `null`.
fn deserialize_non_empty_strings<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::Deserialize;

    /// A list element that may be a string or null. Using `untagged` lets
    /// serde try `Str` first (for plain string items) then fall back to
    /// `Null` (for `- # comment` items that parse as YAML null).
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum MaybeString {
        Str(String),
        Null,
    }

    impl MaybeString {
        fn into_option(self) -> Option<String> {
            match self {
                MaybeString::Str(s) if !s.trim().is_empty() => Some(s),
                _ => None,
            }
        }
    }

    let raw: Vec<MaybeString> = Vec::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .filter_map(MaybeString::into_option)
        .collect())
}

/// Deserialize a byte count that may be either a plain integer or a string
/// expression of multiplications (e.g. `1024 * 1024 * 4096`). This lets the
/// config express large byte limits readably.
fn deserialize_byte_count<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrExpr {
        Num(u64),
        Expr(String),
    }

    match NumOrExpr::deserialize(deserializer)? {
        NumOrExpr::Num(n) => Ok(n),
        NumOrExpr::Expr(s) => eval_byte_expr(&s).map_err(serde::de::Error::custom),
    }
}

/// Like [`deserialize_byte_count`] but with a default of `0` when the key
/// is absent.
fn deserialize_byte_count_default<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_byte_count(deserializer)
}

/// Evaluate a multiplication expression like `"1024 * 1024 * 4096"`.
/// Supports `*`-separated positive integers with optional whitespace.
fn eval_byte_expr(expr: &str) -> Result<u64, String> {
    let mut result: u64 = 1;
    for part in expr.split('*') {
        let trimmed = part.trim();
        let n: u64 = trimmed.parse().map_err(|_| {
            format!("invalid byte expression `{expr}`: `{trimmed}` is not a number")
        })?;
        result = result
            .checked_mul(n)
            .ok_or_else(|| format!("byte expression `{expr}` overflows u64"))?;
    }
    Ok(result)
}

/// A single rate/bandwidth limit tier: `max` units per `window` seconds.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitTier {
    /// Window length in seconds.
    pub window: u64,
    /// Maximum units (requests or bytes) allowed within the window.
    /// Accepts either a plain integer or a string expression of
    /// multiplications, e.g. `1024 * 1024 * 4096`.
    #[serde(deserialize_with = "deserialize_byte_count")]
    pub max: u64,
}

/// Bandwidth limit configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BandwidthLimitConfig {
    /// Per-(origin, ip) connection bandwidth tiers (all tiers apply).
    #[serde(default)]
    pub connection: Vec<LimitTier>,
    /// Per-result (single proxied response) byte cap.
    #[serde(default)]
    pub result: ResultSizeConfig,
}

/// Per-result byte cap.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSizeConfig {
    /// Maximum bytes for a single proxied response body.
    /// Accepts either a plain integer or a string expression of
    /// multiplications, e.g. `1024 * 1024 * 512`.
    #[serde(default, deserialize_with = "deserialize_byte_count_default")]
    pub max: u64,
}

/// Proxy behaviour.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Maximum redirects to follow (0 disables).
    pub max_redirects: u32,
    /// Upstream request timeout in seconds.
    pub timeout: u64,
}

/// Errors that can occur while loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// YAML parse / strict-deserialize failure.
    #[error("failed to parse config: {0}")]
    Parse(#[from] noyalib::Error),
    /// File I/O failure.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    /// Semantic validation failure.
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl Config {
    /// Load and validate configuration from a YAML file.
    ///
    /// Uses strict deserialization so that unknown keys (typos) produce an
    /// error rather than being silently ignored.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file = std::fs::File::open(path.as_ref())?;
        let config: Config = from_reader_strict(file)?;
        config.validate()?;
        Ok(config)
    }

    /// Semantic validation of loaded config values.
    fn validate(&self) -> Result<(), ConfigError> {
        for tier in &self.connection.rate_limit {
            if tier.window == 0 {
                return Err(ConfigError::Invalid(
                    "rate_limit: `window` must be > 0".to_string(),
                ));
            }
            if tier.max == 0 {
                return Err(ConfigError::Invalid(
                    "rate_limit: `max` must be > 0".to_string(),
                ));
            }
        }
        for tier in &self.connection.bandwidth_limit.connection {
            if tier.window == 0 {
                return Err(ConfigError::Invalid(
                    "bandwidth_limit.connection: `window` must be > 0".to_string(),
                ));
            }
            if tier.max == 0 {
                return Err(ConfigError::Invalid(
                    "bandwidth_limit.connection: `max` must be > 0".to_string(),
                ));
            }
        }
        if self.proxy.max_redirects == 0 && self.proxy.timeout == 0 {
            // Both zero is almost certainly a misconfiguration.
            return Err(ConfigError::Invalid(
                "proxy: at least one of `max_redirects` or `timeout` should be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_example_config() {
        let cfg = Config::load("config.example.yml").expect("example config should load");
        assert_eq!(cfg.application.port, 9647);
        assert_eq!(cfg.application.real_ip_header, "X-Real-IP");
        assert!(cfg.connection.target.whitelist.is_empty());
        assert_eq!(cfg.connection.rate_limit.len(), 2);
        assert_eq!(cfg.connection.rate_limit[0].window, 1);
        assert_eq!(cfg.connection.rate_limit[0].max, 5);
        assert_eq!(cfg.connection.bandwidth_limit.connection.len(), 1);
        assert_eq!(
            cfg.connection.bandwidth_limit.connection[0].max,
            1024 * 1024 * 4096
        );
        assert_eq!(cfg.connection.bandwidth_limit.result.max, 1024 * 1024 * 512);
        assert_eq!(cfg.proxy.max_redirects, 10);
        assert_eq!(cfg.proxy.timeout, 30);
    }

    #[test]
    fn rejects_unknown_key() {
        let yaml = "
application:
    host: [0.0.0.0]
  port: 9647
  hostname: localhost
  bogus_field: true
connection:
  target: {}
  origin: {}
proxy:
  max_redirects: 10
  timeout: 30
";
        let tmp = std::env::temp_dir().join("corsget_test_unknown.yml");
        std::fs::write(&tmp, yaml).unwrap();
        let err = Config::load(&tmp).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got {err:?}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn rejects_zero_window() {
        let yaml = "
application: { host: [0.0.0.0], port: 9647, hostname: localhost }
connection:
  target: {}
  origin: {}
  rate_limit:
    - { window: 0, max: 5 }
proxy: { max_redirects: 10, timeout: 30 }
";
        let tmp = std::env::temp_dir().join("corsget_test_zero.yml");
        std::fs::write(&tmp, yaml).unwrap();
        let err = Config::load(&tmp).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
        let _ = std::fs::remove_file(&tmp);
    }
}
