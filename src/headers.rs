//! Config-driven response header overrides.
//!
//! Rules are defined statically in the config (`proxy.response_headers_overrides`)
//! so the proxy owner controls, ahead of time, which response headers are
//! removed, added, or replaced for specific proxied traffic. Consumers need no
//! special parameters — they simply request the target URL as usual.
//!
//! Every rule whose `site` pattern matches the requested target URL (or the
//! final post-redirect URL) is applied, in the order the rules appear in the
//! config. Within a rule, actions are evaluated in the order
//! `remove_headers` → `add_headers` → `set_headers`:
//!
//! - **remove**: deletes the header, if present.
//! - **add**: appends a value without removing existing same-name values.
//! - **set**: replaces all existing same-name values (or adds the header when
//!   absent).
//!
//! Overrides are applied *after* the response headers are assembled (fresh
//! upstream or cache hit), so cached entries remain override-agnostic and the
//! cache identity is unaffected.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::config::{HeaderPair, ResponseHeaderOverrideConfig};
use crate::matcher::MatchEntry;

/// Header names that must never be overridden.
///
/// - Hop-by-hop / proxy-injected headers (RFC 7230 §6.1) must not be touched.
/// - `content-length` must stay consistent with the streamed body.
/// - The generated CORS response headers are overwritten by the CORS
///   middleware after the handler, so overriding them would silently no-op.
/// - `x-cache` is a proxy diagnostic header.
const FORBIDDEN_HEADER_NAMES: &[&str] = &[
    "content-length",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-max-age",
    "x-cache",
];

/// A compiled response-header override rule.
#[derive(Debug, Clone)]
pub struct HeaderOverrideRule {
    /// Compiled `site` URL pattern.
    site: MatchEntry,
    /// Raw `site` pattern for diagnostics.
    site_pattern: String,
    /// Headers to remove.
    remove: Vec<HeaderName>,
    /// Values to append without removing existing same-name values.
    add: Vec<(HeaderName, HeaderValue)>,
    /// Values that replace all existing same-name values.
    set: Vec<(HeaderName, HeaderValue)>,
}

/// Error produced while compiling override rules.
#[derive(Debug, thiserror::Error)]
pub enum HeaderOverrideError {
    /// The `site` pattern failed to compile.
    #[error("invalid `site` pattern `{pattern}`: {source}")]
    Site {
        pattern: String,
        source: crate::matcher::MatchError,
    },
    /// A header name in a rule is invalid or forbidden.
    #[error("invalid header name `{name}` in response header override: {reason}")]
    HeaderName { name: String, reason: String },
    /// A header value in a rule is invalid.
    #[error("invalid header value for `{name}` in response header override: {reason}")]
    HeaderValue { name: String, reason: String },
}

impl HeaderOverrideRule {
    /// Compile a rule from its config form, validating header names/values
    /// and rejecting forbidden header names.
    pub fn new(rule: &ResponseHeaderOverrideConfig) -> Result<Self, HeaderOverrideError> {
        let site = MatchEntry::parse(&rule.site).map_err(|source| HeaderOverrideError::Site {
            pattern: rule.site.clone(),
            source,
        })?;

        let remove = rule
            .remove_headers
            .iter()
            .map(|name| parse_header_name(name))
            .collect::<Result<Vec<_>, _>>()?;

        let add = parse_header_pairs(&rule.add_headers)?;
        let set = parse_header_pairs(&rule.set_headers)?;

        Ok(Self {
            site,
            site_pattern: rule.site.clone(),
            remove,
            add,
            set,
        })
    }

    /// Returns `true` if this rule matches either the requested target URL or
    /// the final post-redirect URL.
    fn matches(&self, requested: &Url, final_url: &Url) -> bool {
        let requested_str = requested.as_str();
        let final_str = final_url.as_str();
        self.site.is_match(requested_str) || self.site.is_match(final_str)
    }

    /// Apply this rule's actions to `headers` in the order
    /// remove → add → set.
    fn apply(&self, headers: &mut HeaderMap) {
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, value) in &self.add {
            headers.append(name, value.clone());
        }
        for (name, value) in &self.set {
            headers.insert(name, value.clone());
        }
    }
}

/// Parse and validate a header name, rejecting forbidden names.
fn parse_header_name(name: &str) -> Result<HeaderName, HeaderOverrideError> {
    let trimmed = name.trim();
    let lower = trimmed.to_ascii_lowercase();
    if crate::cors::is_hop_by_hop(&lower) {
        return Err(HeaderOverrideError::HeaderName {
            name: trimmed.to_string(),
            reason: "hop-by-hop and proxy-injected headers must not be overridden".to_string(),
        });
    }
    if FORBIDDEN_HEADER_NAMES.contains(&lower.as_str()) {
        return Err(HeaderOverrideError::HeaderName {
            name: trimmed.to_string(),
            reason: "this header is managed by the proxy and must not be overridden".to_string(),
        });
    }
    HeaderName::from_bytes(trimmed.as_bytes()).map_err(|error| HeaderOverrideError::HeaderName {
        name: trimmed.to_string(),
        reason: error.to_string(),
    })
}

/// Parse and validate `name: value` pairs, rejecting forbidden names.
fn parse_header_pairs(
    pairs: &[HeaderPair],
) -> Result<Vec<(HeaderName, HeaderValue)>, HeaderOverrideError> {
    pairs
        .iter()
        .map(|pair| {
            let name = parse_header_name(&pair.name)?;
            let value = HeaderValue::from_str(pair.value.trim()).map_err(|error| {
                HeaderOverrideError::HeaderValue {
                    name: pair.name.clone(),
                    reason: error.to_string(),
                }
            })?;
            Ok((name, value))
        })
        .collect()
}

/// The compiled set of response-header override rules.
#[derive(Debug, Clone, Default)]
pub struct HeaderOverridePolicy {
    rules: Vec<HeaderOverrideRule>,
}

impl HeaderOverridePolicy {
    /// Compile all rules from config. Returns an error if any rule is
    /// invalid, so misconfiguration fails at startup.
    pub fn new(rules: &[ResponseHeaderOverrideConfig]) -> Result<Self, HeaderOverrideError> {
        Ok(Self {
            rules: rules
                .iter()
                .map(HeaderOverrideRule::new)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    /// Returns `true` when no rules are configured.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Apply every rule whose `site` matches the requested target URL or the
    /// final post-redirect URL, in config order. Within each rule the
    /// actions run in the order remove → add → set.
    pub fn apply(&self, headers: &mut HeaderMap, requested: &Url, final_url: &Url) {
        for rule in &self.rules {
            if rule.matches(requested, final_url) {
                tracing::debug!(site = %rule.site_pattern, "applying response header override rule");
                rule.apply(headers);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResponseHeaderOverrideConfig;

    fn rule(
        site: &str,
        remove: &[&str],
        add: &[(&str, &str)],
        set: &[(&str, &str)],
    ) -> ResponseHeaderOverrideConfig {
        ResponseHeaderOverrideConfig {
            site: site.to_string(),
            remove_headers: remove.iter().map(|s| s.to_string()).collect(),
            add_headers: add
                .iter()
                .map(|(n, v)| HeaderPair {
                    name: n.to_string(),
                    value: v.to_string(),
                })
                .collect(),
            set_headers: set
                .iter()
                .map(|(n, v)| HeaderPair {
                    name: n.to_string(),
                    value: v.to_string(),
                })
                .collect(),
        }
    }

    fn policy(rules: &[ResponseHeaderOverrideConfig]) -> HeaderOverridePolicy {
        HeaderOverridePolicy::new(rules).unwrap()
    }

    fn url(raw: &str) -> Url {
        Url::parse(raw).unwrap()
    }

    #[test]
    fn set_replaces_and_adds() {
        let p = policy(&[rule(
            "*://app.example.com/*",
            &[],
            &[],
            &[("Cross-Origin-Resource-Policy", "cross-origin")],
        )]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "cross-origin-resource-policy",
            "same-origin".parse().unwrap(),
        );
        p.apply(
            &mut headers,
            &url("https://app.example.com/xyz?p=1"),
            &url("https://app.example.com/xyz?p=1"),
        );
        assert_eq!(
            headers.get("cross-origin-resource-policy").unwrap(),
            "cross-origin"
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn add_appends_without_removing() {
        let p = policy(&[rule(
            "*://example.com/*",
            &[],
            &[("x-multi", "second")],
            &[],
        )]);
        let mut headers = HeaderMap::new();
        headers.insert("x-multi", "first".parse().unwrap());
        p.apply(
            &mut headers,
            &url("https://example.com/a"),
            &url("https://example.com/a"),
        );
        let values: Vec<_> = headers.get_all("x-multi").iter().collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "first");
        assert_eq!(values[1], "second");
    }

    #[test]
    fn remove_deletes_header() {
        let p = policy(&[rule("*://example.com/*", &["x-frame-options"], &[], &[])]);
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", "DENY".parse().unwrap());
        p.apply(
            &mut headers,
            &url("https://example.com/a"),
            &url("https://example.com/a"),
        );
        assert!(!headers.contains_key("x-frame-options"));
    }

    #[test]
    fn actions_run_in_remove_add_set_order() {
        // remove deletes the upstream value, add appends a new one, set
        // replaces everything — the final value must be the `set` value.
        let p = policy(&[rule(
            "*://example.com/*",
            &["x-test"],
            &[("x-test", "added")],
            &[("x-test", "final")],
        )]);
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "upstream".parse().unwrap());
        p.apply(
            &mut headers,
            &url("https://example.com/a"),
            &url("https://example.com/a"),
        );
        let values: Vec<_> = headers.get_all("x-test").iter().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "final");
    }

    #[test]
    fn multiple_matching_rules_apply_in_config_order() {
        // Later rules run after earlier ones, so the later `set` wins.
        let p = policy(&[
            rule("*://example.com/*", &[], &[("x-a", "first")], &[]),
            rule("*://example.com/specific*", &[], &[], &[("x-a", "second")]),
        ]);
        let mut headers = HeaderMap::new();
        p.apply(
            &mut headers,
            &url("https://example.com/specific/page"),
            &url("https://example.com/specific/page"),
        );
        let values: Vec<_> = headers.get_all("x-a").iter().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "second");
    }

    #[test]
    fn non_matching_rules_are_skipped() {
        let p = policy(&[
            rule("*://other.com/*", &[], &[("x-a", "no")], &[]),
            rule("*://example.com/*", &[], &[("x-a", "yes")], &[]),
        ]);
        let mut headers = HeaderMap::new();
        p.apply(
            &mut headers,
            &url("https://example.com/page"),
            &url("https://example.com/page"),
        );
        assert_eq!(headers.get("x-a").unwrap(), "yes");
    }

    #[test]
    fn matches_final_redirect_url() {
        // The rule targets the post-redirect host only.
        let p = policy(&[rule("*://cdn.example.com/*", &[], &[("x-a", "hit")], &[])]);
        let mut headers = HeaderMap::new();
        p.apply(
            &mut headers,
            &url("https://origin.example.com/file"),
            &url("https://cdn.example.com/file"),
        );
        assert_eq!(headers.get("x-a").unwrap(), "hit");
    }

    #[test]
    fn matches_requested_url_when_final_differs() {
        let p = policy(&[rule(
            "*://origin.example.com/*",
            &[],
            &[("x-a", "hit")],
            &[],
        )]);
        let mut headers = HeaderMap::new();
        p.apply(
            &mut headers,
            &url("https://origin.example.com/file"),
            &url("https://cdn.example.com/file"),
        );
        assert_eq!(headers.get("x-a").unwrap(), "hit");
    }

    #[test]
    fn regex_site_pattern() {
        let p = policy(&[rule(
            r"/^https://api\d+\.example\.com/",
            &[],
            &[("x-a", "hit")],
            &[],
        )]);
        let mut headers = HeaderMap::new();
        p.apply(
            &mut headers,
            &url("https://api42.example.com/v1"),
            &url("https://api42.example.com/v1"),
        );
        assert_eq!(headers.get("x-a").unwrap(), "hit");

        let mut headers = HeaderMap::new();
        p.apply(
            &mut headers,
            &url("https://api.example.com/v1"),
            &url("https://api.example.com/v1"),
        );
        assert!(headers.is_empty());
    }

    #[test]
    fn empty_policy_is_a_noop() {
        let p = HeaderOverridePolicy::default();
        assert!(p.is_empty());
        let mut headers = HeaderMap::new();
        headers.insert("x-keep", "value".parse().unwrap());
        p.apply(
            &mut headers,
            &url("https://example.com/"),
            &url("https://example.com/"),
        );
        assert_eq!(headers.get("x-keep").unwrap(), "value");
    }

    #[test]
    fn rejects_hop_by_hop_header() {
        let r = rule("*://example.com/*", &["connection"], &[], &[]);
        let err = HeaderOverrideRule::new(&r).unwrap_err();
        assert!(err.to_string().contains("hop-by-hop"), "got {err}");
    }

    #[test]
    fn rejects_forwarded_prefix_header() {
        let r = rule("*://example.com/*", &["x-forwarded-for"], &[], &[]);
        let err = HeaderOverrideRule::new(&r).unwrap_err();
        assert!(err.to_string().contains("hop-by-hop"), "got {err}");
    }

    #[test]
    fn rejects_content_length() {
        let r = rule("*://example.com/*", &[], &[], &[("content-length", "5")]);
        let err = HeaderOverrideRule::new(&r).unwrap_err();
        assert!(
            err.to_string().contains("managed by the proxy"),
            "got {err}"
        );
    }

    #[test]
    fn rejects_cors_response_headers() {
        for name in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-headers",
            "access-control-allow-methods",
            "access-control-max-age",
        ] {
            let r = rule("*://example.com/*", &[], &[], &[(name, "x")]);
            let err = HeaderOverrideRule::new(&r).unwrap_err();
            assert!(
                err.to_string().contains("managed by the proxy"),
                "got {err}"
            );
        }
    }

    #[test]
    fn rejects_cache_diagnostic_header() {
        let r = rule("*://example.com/*", &["x-cache"], &[], &[]);
        let err = HeaderOverrideRule::new(&r).unwrap_err();
        assert!(
            err.to_string().contains("managed by the proxy"),
            "got {err}"
        );
    }

    #[test]
    fn rejects_invalid_header_name() {
        let r = rule("*://example.com/*", &[], &[], &[("bad header\nname", "x")]);
        let err = HeaderOverrideRule::new(&r).unwrap_err();
        assert!(err.to_string().contains("invalid header name"), "got {err}");
    }

    #[test]
    fn rejects_invalid_header_value() {
        let r = rule("*://example.com/*", &[], &[], &[("x-a", "bad\nvalue")]);
        let err = HeaderOverrideRule::new(&r).unwrap_err();
        assert!(
            err.to_string().contains("invalid header value"),
            "got {err}"
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let p = policy(&[rule("*://example.com/*", &["X-Frame-Options"], &[], &[])]);
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", "DENY".parse().unwrap());
        p.apply(
            &mut headers,
            &url("https://example.com/a"),
            &url("https://example.com/a"),
        );
        assert!(!headers.contains_key("x-frame-options"));
    }
}
