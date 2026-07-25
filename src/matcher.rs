//! Allow/deny list matching for target hosts and requesting origins.
//!
//! Each list entry is auto-detected as one of three kinds:
//!
//! - **Regex** — delimited by `/…/` with optional trailing flags (`i`).
//!   Example: `/^api\d+\.example\.com$/i`
//! - **Wildcard** — contains `*`. `*` matches any sequence of characters
//!   (including none). Example: `*.example.com` matches `a.example.com`,
//!   `a.b.example.com`, and `.example.com`.
//! - **Exact** — anything else. Compared case-insensitively against the
//!   full host string.
//!
//! A [`TargetList`] holds a blacklist and a whitelist. The decision rule:
//!
//! - If the whitelist is non-empty, the subject must match at least one
//!   whitelist entry **and** must not match any blacklist entry.
//! - Otherwise (whitelist empty), the subject is allowed unless it matches
//!   a blacklist entry.
//! - If both lists are empty, everything is allowed.

use std::sync::Arc;

use regex::{Regex, RegexBuilder};
use thiserror::Error;

/// A single compiled match entry.
#[derive(Debug, Clone)]
pub enum MatchEntry {
    /// Exact host string (case-insensitive).
    Exact(String),
    /// Wildcard pattern compiled to a regex (`*` → `.*`).
    Wildcard(Regex),
    /// User-supplied regex.
    Regex(Regex),
}

/// Error compiling a match entry.
#[derive(Debug, Error)]
pub enum MatchError {
    /// Invalid regex pattern.
    #[error("invalid regex `{pattern}`: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

impl MatchEntry {
    /// Detect and compile an entry from its raw string form.
    pub fn parse(raw: &str) -> Result<Self, MatchError> {
        let trimmed = raw.trim();
        // Regex: /pattern/flags
        if trimmed.len() >= 2
            && trimmed.starts_with('/')
            && let Some(close) = trimmed.rfind('/')
            && close > 0
        {
            let pattern = &trimmed[1..close];
            let flags = &trimmed[close + 1..];
            let mut builder = RegexBuilder::new(pattern);
            for f in flags.chars() {
                match f {
                    'i' => {
                        builder.case_insensitive(true);
                    }
                    'm' => {
                        builder.multi_line(true);
                    }
                    's' => {
                        builder.dot_matches_new_line(true);
                    }
                    'x' => {
                        builder.ignore_whitespace(true);
                    }
                    _ => {
                        return Err(MatchError::InvalidRegex {
                            pattern: raw.to_string(),
                            source: regex::Error::Syntax(format!("unknown regex flag `{f}`")),
                        });
                    }
                }
            }
            let re = builder.build().map_err(|source| MatchError::InvalidRegex {
                pattern: raw.to_string(),
                source,
            })?;
            return Ok(MatchEntry::Regex(re));
        }
        // Wildcard: contains '*'
        if trimmed.contains('*') {
            let regex_src = wildcard_to_regex(trimmed);
            let re = RegexBuilder::new(&regex_src)
                .case_insensitive(true)
                .build()
                .map_err(|source| MatchError::InvalidRegex {
                    pattern: raw.to_string(),
                    source,
                })?;
            return Ok(MatchEntry::Wildcard(re));
        }
        // Exact
        Ok(MatchEntry::Exact(trimmed.to_lowercase()))
    }

    /// Test whether `subject` (a host string) matches this entry.
    pub fn is_match(&self, subject: &str) -> bool {
        match self {
            MatchEntry::Exact(s) => s.eq_ignore_ascii_case(subject),
            MatchEntry::Wildcard(re) | MatchEntry::Regex(re) => re.is_match(subject),
        }
    }
}

/// Convert a glob-style wildcard pattern into an anchored regex source.
///
/// `*` becomes `.*`; all other characters are escaped via [`regex::escape`]
/// so that regex metacharacters in the pattern are treated literally.
fn wildcard_to_regex(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() * 2 + 2);
    out.push('^');
    for segment in pattern.split('*') {
        if !segment.is_empty() {
            out.push_str(&regex::escape(segment));
        }
        out.push_str(".*");
    }
    // `split('*')` always yields one more segment than there are `*`s, so the
    // trailing `.*` is spurious — trim it so the pattern is anchored correctly.
    if out.ends_with(".*") {
        out.truncate(out.len() - 2);
    }
    out.push('$');
    out
}

/// A compiled blacklist + whitelist pair.
#[derive(Debug, Clone, Default)]
pub struct TargetList {
    /// Denied entries.
    blacklist: Vec<MatchEntry>,
    /// Allowed entries (takes precedence when non-empty).
    whitelist: Vec<MatchEntry>,
}

impl TargetList {
    /// Build from raw string lists, compiling each entry.
    pub fn new(blacklist: &[String], whitelist: &[String]) -> Result<Self, MatchError> {
        let blacklist = blacklist
            .iter()
            .map(|s| MatchEntry::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let whitelist = whitelist
            .iter()
            .map(|s| MatchEntry::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            blacklist,
            whitelist,
        })
    }

    /// Returns `true` if `subject` is allowed by this list.
    pub fn is_allowed(&self, subject: &str) -> bool {
        let blacklisted = self.blacklist.iter().any(|e| e.is_match(subject));
        if !self.whitelist.is_empty() {
            let whitelisted = self.whitelist.iter().any(|e| e.is_match(subject));
            whitelisted && !blacklisted
        } else {
            !blacklisted
        }
    }
}

/// Pre-compiled connection policy: target + origin lists.
///
/// Wrapped in [`Arc`] for cheap cloning into request state.
#[derive(Debug, Clone)]
pub struct MatchPolicy {
    /// Target URL host allow/deny.
    pub target: Arc<TargetList>,
    /// Requesting-origin allow/deny.
    pub origin: Arc<TargetList>,
}

impl MatchPolicy {
    /// Build from raw config strings, compiling each entry.
    ///
    /// Returns an error if any entry fails to compile.
    pub fn new(
        target_blacklist: &[String],
        target_whitelist: &[String],
        origin_blacklist: &[String],
        origin_whitelist: &[String],
    ) -> Result<Self, MatchError> {
        Ok(Self {
            target: Arc::new(TargetList::new(target_blacklist, target_whitelist)?),
            origin: Arc::new(TargetList::new(origin_blacklist, origin_whitelist)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(black: &[&str], white: &[&str]) -> TargetList {
        TargetList::new(
            &black.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &white.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn exact_match_case_insensitive() {
        let e = MatchEntry::parse("Example.COM").unwrap();
        assert!(e.is_match("example.com"));
        assert!(e.is_match("EXAMPLE.COM"));
        assert!(!e.is_match("sub.example.com"));
    }

    #[test]
    fn wildcard_matches_subdomains() {
        let e = MatchEntry::parse("*.example.com").unwrap();
        assert!(e.is_match("a.example.com"));
        assert!(e.is_match("a.b.example.com"));
        assert!(e.is_match(".example.com"));
        assert!(!e.is_match("example.com"));
        assert!(!e.is_match("evil.com"));
    }

    #[test]
    fn wildcard_escapes_metachars() {
        // `+` is a regex metachar; in a wildcard it should be literal.
        let e = MatchEntry::parse("a+b.example.com").unwrap();
        assert!(e.is_match("a+b.example.com"));
        assert!(!e.is_match("aab.example.com"));
    }

    #[test]
    fn regex_with_flags() {
        let e = MatchEntry::parse(r"/^api\d+\.example\.com$/i").unwrap();
        assert!(e.is_match("API1.example.com"));
        assert!(e.is_match("api2.example.com"));
        assert!(!e.is_match("api.example.com"));
        assert!(!e.is_match("xapi1.example.com"));
    }

    #[test]
    fn regex_without_flags() {
        let e = MatchEntry::parse(r"/evil\.com$/").unwrap();
        assert!(e.is_match("sub.evil.com"));
        assert!(e.is_match("evil.com"));
        assert!(!e.is_match("evil.community"));
    }

    #[test]
    fn both_empty_allows_all() {
        let l = list(&[], &[]);
        assert!(l.is_allowed("anything.com"));
        assert!(l.is_allowed(""));
    }

    #[test]
    fn blacklist_denies() {
        let l = list(&["evil.com"], &[]);
        assert!(!l.is_allowed("evil.com"));
        assert!(l.is_allowed("good.com"));
    }

    #[test]
    fn whitelist_only_allows_listed() {
        let l = list(&[], &["good.com"]);
        assert!(l.is_allowed("good.com"));
        assert!(!l.is_allowed("evil.com"));
    }

    #[test]
    fn whitelist_precedence_over_blacklist() {
        // whitelist non-empty: must be whitelisted AND not blacklisted
        let l = list(&["bad.good.com"], &["*.good.com"]);
        assert!(l.is_allowed("ok.good.com"));
        assert!(!l.is_allowed("bad.good.com")); // blacklisted
        assert!(!l.is_allowed("evil.com")); // not whitelisted
    }

    #[test]
    fn wildcard_blacklist_denies_pattern() {
        let l = list(&["*.evil.com"], &[]);
        assert!(!l.is_allowed("a.evil.com"));
        assert!(l.is_allowed("evil.com"));
    }

    #[test]
    fn invalid_regex_flag_rejected() {
        let err = MatchEntry::parse(r"/foo/z").unwrap_err();
        assert!(err.to_string().contains("unknown regex flag"));
    }

    #[test]
    fn invalid_regex_pattern_rejected() {
        let err = MatchEntry::parse(r"/[/").unwrap_err();
        assert!(matches!(err, MatchError::InvalidRegex { .. }));
    }
}
