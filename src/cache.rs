//! Persistent, whitelist-driven response caching.
//!
//! Cache entries are stored as a metadata JSON file and a body file. The
//! metadata is written only after the body has been atomically committed, so
//! incomplete responses are ignored on restart.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use httpdate::parse_http_date;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::config::{CacheConfig, CacheRule};

const CACHE_VERSION: u8 = 1;
const CACHE_DIAGNOSTIC_HEADER: &str = "x-cache";
const SUPPORTED_VARY_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "accept-encoding",
    "origin",
    "authorization",
];
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct Cache {
    inner: Arc<CacheInner>,
}

#[derive(Debug)]
struct CacheInner {
    root: PathBuf,
    max_size: u64,
    default_max_age: u64,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    pattern: CachePattern,
    max_age: u64,
}

#[derive(Debug, Clone)]
enum CachePattern {
    Exact { host: String, suffix: String },
    Wildcard { host: Regex, path: Regex },
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub struct CachePlan {
    key: String,
    ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub version: u8,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: u64,
    pub created_at: u64,
    pub last_access: u64,
    pub ttl: u64,
    #[serde(default)]
    pub revalidate: bool,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub vary: Vec<String>,
    pub request_variants: Vec<(String, String)>,
    #[serde(skip)]
    pub key: String,
    #[serde(skip)]
    pub body_path: PathBuf,
}

pub struct CacheWriter {
    cache: Cache,
    entry: CacheEntry,
    temp_body: PathBuf,
    body_file: File,
    body_len: u64,
}

impl Cache {
    /// Create an active cache. Directory setup failure disables caching.
    pub fn new(config: &CacheConfig, config_path: &Path) -> Option<Self> {
        if !config.enabled
            || config.max_age == 0
            || config.max_size == 0
            || config.whitelist.is_empty()
        {
            return None;
        }
        let base = config_path.parent().unwrap_or_else(|| Path::new("."));
        let root = if config.location.trim().is_empty() {
            base.join(".cache")
        } else {
            let path = PathBuf::from(config.location.trim());
            if path.is_absolute() {
                path
            } else {
                base.join(path)
            }
        };
        if let Err(error) = std::fs::create_dir_all(&root) {
            tracing::warn!(path = %root.display(), %error, "cache disabled: cannot create cache directory");
            return None;
        }
        let mut rules = Vec::new();
        for rule in &config.whitelist {
            match CompiledRule::new(rule) {
                Ok(rule) => rules.push(rule),
                Err(error) => {
                    tracing::warn!(pattern = %rule.pattern, %error, "cache rule ignored");
                }
            }
        }
        if rules.is_empty() {
            tracing::warn!("cache disabled: no valid cache whitelist rules");
            return None;
        }
        Some(Self {
            inner: Arc::new(CacheInner {
                root,
                max_size: config.max_size,
                default_max_age: config.max_age,
                rules,
            }),
        })
    }

    /// Return a cache plan for a safe request matching the last whitelist rule.
    pub fn plan(&self, url: &Url, headers: &HeaderMap) -> Option<CachePlan> {
        if headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(header::COOKIE)
            || headers.contains_key(header::RANGE)
        {
            return None;
        }
        let subject = normalized_url(url);
        let mut ttl = None;
        for rule in &self.inner.rules {
            if rule.pattern.is_match(&subject) {
                ttl = Some(rule.max_age);
            }
        }
        let ttl = ttl?.min(self.inner.default_max_age);
        if ttl == 0 {
            return None;
        }
        let key = cache_key(&subject, headers);
        Some(CachePlan { key, ttl })
    }

    pub async fn lookup(&self, plan: &CachePlan, now: u64) -> Option<CacheEntry> {
        let meta_path = self.meta_path(&plan.key);
        let body_path = self.body_path(&plan.key);
        let data = match fs::read(&meta_path).await {
            Ok(data) => data,
            Err(_) => return None,
        };
        let mut entry: CacheEntry = match serde_json::from_slice(&data) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::debug!(%error, "ignoring corrupt cache metadata");
                let _ = fs::remove_file(&meta_path).await;
                return None;
            }
        };
        let body_len = fs::metadata(&body_path)
            .await
            .ok()
            .map(|metadata| metadata.len());
        if entry.version != CACHE_VERSION || body_len != Some(entry.body_len) {
            let _ = fs::remove_file(&meta_path).await;
            return None;
        }
        entry.key = plan.key.clone();
        entry.body_path = body_path;
        entry.last_access = now;
        let refreshed = entry.clone();
        let _ = self.write_metadata(&refreshed).await;
        Some(entry)
    }

    /// Refresh an entry after a successful conditional `304 Not Modified`.
    pub async fn refresh(
        &self,
        entry: &mut CacheEntry,
        response_headers: &HeaderMap,
        configured_ttl: u64,
    ) -> std::io::Result<()> {
        entry.created_at = now_seconds();
        entry.last_access = entry.created_at;
        entry.ttl = effective_ttl(configured_ttl, response_headers);
        if let Some(value) = response_headers
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
        {
            entry.etag = Some(value.to_string());
        }
        if let Some(value) = response_headers
            .get(header::LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
        {
            entry.last_modified = Some(value.to_string());
        }
        self.write_metadata(entry).await
    }

    pub fn is_fresh(entry: &CacheEntry, now: u64) -> bool {
        !entry.revalidate && now.saturating_sub(entry.created_at) < entry.ttl
    }

    pub fn add_validators(headers: &mut HeaderMap, entry: &CacheEntry) {
        if let Some(value) = &entry.etag
            && let Ok(value) = HeaderValue::from_str(value)
        {
            headers.insert(header::IF_NONE_MATCH, value);
        }
        if let Some(value) = &entry.last_modified
            && let Ok(value) = HeaderValue::from_str(value)
        {
            headers.insert(header::IF_MODIFIED_SINCE, value);
        }
    }

    pub async fn begin_write(
        &self,
        plan: CachePlan,
        status: u16,
        headers: &HeaderMap,
        request_headers: &HeaderMap,
    ) -> Option<CacheWriter> {
        if !(200..300).contains(&status) || !cacheable_headers(headers) {
            return None;
        }
        let vary = parse_vary(headers)?;
        // Authenticated requests never participate in the cache, even if a
        // future caller invokes begin_write without going through plan().
        if request_headers.contains_key(header::AUTHORIZATION) {
            return None;
        }
        let request_variants = vary
            .iter()
            .filter_map(|name| {
                request_headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| (name.clone(), value.to_string()))
            })
            .collect::<Vec<_>>();
        let entry = CacheEntry {
            version: CACHE_VERSION,
            status,
            headers: cache_headers(headers),
            body_len: 0,
            created_at: now_seconds(),
            last_access: now_seconds(),
            ttl: effective_ttl(plan.ttl, headers),
            revalidate: cache_control_requires_revalidation(headers),
            etag: headers
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            last_modified: headers
                .get(header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            vary,
            request_variants,
            key: plan.key.clone(),
            body_path: self.body_path(&plan.key),
        };
        if entry.ttl == 0 {
            return None;
        }
        let temp_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_body = self.inner.root.join(format!(
            ".{}.body.tmp-{}-{temp_id}",
            plan.key,
            std::process::id()
        ));
        let body_file = match File::create(&temp_body).await {
            Ok(file) => file,
            Err(error) => {
                tracing::debug!(%error, "cache body file could not be created");
                return None;
            }
        };
        Some(CacheWriter {
            cache: self.clone(),
            entry,
            temp_body,
            body_file,
            body_len: 0,
        })
    }

    async fn commit(&self, mut entry: CacheEntry, temp_body: &Path) -> std::io::Result<()> {
        let body_path = self.body_path(&entry.key);
        let meta_path = self.meta_path(&entry.key);
        fs::rename(temp_body, &body_path).await?;
        entry.body_path = body_path;
        self.write_metadata(&entry).await?;
        self.evict().await;
        // A failed metadata write leaves a body that will be ignored on restart.
        let _ = meta_path;
        Ok(())
    }

    async fn write_metadata(&self, entry: &CacheEntry) -> std::io::Result<()> {
        let path = self.meta_path(&entry.key);
        let temp_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp = self.inner.root.join(format!(
            ".{}.meta.tmp-{}-{temp_id}",
            entry.key,
            std::process::id()
        ));
        let data = serde_json::to_vec(entry).map_err(std::io::Error::other)?;
        fs::write(&temp, data).await?;
        fs::rename(temp, path).await
    }

    async fn evict(&self) {
        let mut entries = Vec::new();
        let mut total = 0u64;
        let mut dir = match fs::read_dir(&self.inner.root).await {
            Ok(dir) => dir,
            Err(_) => return,
        };
        while let Ok(Some(item)) = dir.next_entry().await {
            let path = item.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let meta = match fs::metadata(&path).await {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            let key = match path.file_stem().and_then(|x| x.to_str()) {
                Some(key) => key.to_string(),
                None => continue,
            };
            let entry: CacheEntry = match serde_json::from_slice(&match fs::read(&path).await {
                Ok(data) => data,
                Err(_) => continue,
            }) {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let body = self.body_path(&key);
            let body_len = fs::metadata(&body).await.map(|m| m.len()).unwrap_or(0);
            total = total.saturating_add(meta.len()).saturating_add(body_len);
            entries.push((entry.last_access, key, meta.len().saturating_add(body_len)));
        }
        if total <= self.inner.max_size {
            return;
        }
        entries.sort_by_key(|(access, _, _)| *access);
        for (_, key, size) in entries {
            if total <= self.inner.max_size {
                break;
            }
            let _ = fs::remove_file(self.meta_path(&key)).await;
            let _ = fs::remove_file(self.body_path(&key)).await;
            total = total.saturating_sub(size);
        }
    }

    pub fn body_path(&self, key: &str) -> PathBuf {
        self.inner.root.join(format!("{key}.body"))
    }
    pub fn entry_body_path<'a>(&self, entry: &'a CacheEntry) -> &'a Path {
        &entry.body_path
    }
    fn meta_path(&self, key: &str) -> PathBuf {
        self.inner.root.join(format!("{key}.json"))
    }
}

/// Stream a cached body from disk without buffering the complete response.
pub fn file_stream(
    path: PathBuf,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static {
    async_stream::try_stream! {
        let mut file = File::open(path).await?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            yield bytes::Bytes::copy_from_slice(&buffer[..read]);
        }
    }
}

impl CacheWriter {
    pub async fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.body_file.write_all(bytes).await?;
        self.body_len = self.body_len.saturating_add(bytes.len() as u64);
        Ok(())
    }

    pub async fn finish(mut self) -> std::io::Result<()> {
        self.body_file.flush().await?;
        self.entry.body_len = self.body_len;
        self.cache.commit(self.entry, &self.temp_body).await
    }

    pub async fn discard(self) {
        let _ = fs::remove_file(self.temp_body).await;
    }
}

impl CompiledRule {
    fn new(rule: &CacheRule) -> Result<Self, String> {
        let raw = rule.pattern.trim();
        if raw.is_empty() {
            return Err("empty cache rule".into());
        }
        if raw.starts_with('/')
            && raw.len() > 1
            && let Some(close) = raw.rfind('/')
            && close > 0
        {
            let mut builder = RegexBuilder::new(&raw[1..close]);
            for flag in raw[close + 1..].chars() {
                match flag {
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
                    _ => return Err(format!("unknown regex flag `{flag}`")),
                }
            }
            return builder
                .build()
                .map(|pattern| Self {
                    pattern: CachePattern::Regex(pattern),
                    max_age: rule.max_age,
                })
                .map_err(|e| e.to_string());
        }
        let raw = strip_scheme(raw);
        if raw == "*" {
            return Ok(Self {
                pattern: CachePattern::Wildcard {
                    host: Regex::new(r"^.*$").expect("static cache wildcard host regex"),
                    path: Regex::new(r"^/.*$").expect("static cache wildcard path regex"),
                },
                max_age: rule.max_age,
            });
        }
        let (host, suffix) = raw
            .split_once('/')
            .map_or((raw, "/".to_string()), |(host, suffix)| {
                (host, format!("/{suffix}"))
            });
        let host = host.to_ascii_lowercase();
        if raw.contains('*') {
            let host_pattern = host
                .split('*')
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join(".*");
            let path_pattern = suffix
                .split('*')
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join(".*");
            let host = Regex::new(&format!("^{host_pattern}$")).map_err(|e| e.to_string())?;
            let path = Regex::new(&format!("^{path_pattern}$")).map_err(|e| e.to_string())?;
            return Ok(Self {
                pattern: CachePattern::Wildcard { host, path },
                max_age: rule.max_age,
            });
        }
        Ok(Self {
            pattern: CachePattern::Exact { host, suffix },
            max_age: rule.max_age,
        })
    }
}

impl CachePattern {
    fn is_match(&self, subject: &str) -> bool {
        match self {
            CachePattern::Regex(regex) => regex.is_match(subject),
            CachePattern::Exact { host, suffix } => subject
                .strip_prefix(host)
                .is_some_and(|rest| rest == suffix),
            CachePattern::Wildcard { host, path } => {
                subject
                    .split_once('/')
                    .is_some_and(|(actual_host, actual_path)| {
                        host.is_match(actual_host) && path.is_match(&format!("/{actual_path}"))
                    })
            }
        }
    }
}

impl CachePlan {
    pub fn ttl(&self) -> u64 {
        self.ttl
    }
}

fn strip_scheme(value: &str) -> &str {
    value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .unwrap_or(value)
}

pub fn normalized_url(url: &Url) -> String {
    let mut value = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if let Some(port) = url.port() {
        value.push(':');
        value.push_str(&port.to_string());
    }
    value.push_str(if url.path().is_empty() {
        "/"
    } else {
        url.path()
    });
    if let Some(query) = url.query() {
        value.push('?');
        value.push_str(query);
    }
    value
}

fn cache_key(subject: &str, headers: &HeaderMap) -> String {
    let mut hasher = Sha256::new();
    hasher.update(subject.as_bytes());
    for name in SUPPORTED_VARY_HEADERS {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        if let Some(value) = headers.get(*name) {
            hasher.update(value.as_bytes());
        }
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cacheable_headers(headers: &HeaderMap) -> bool {
    let Some(cache_control) = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    else {
        return !headers.contains_key(header::SET_COOKIE);
    };
    let directives = cache_control
        .split(',')
        .map(|x| x.trim().to_ascii_lowercase())
        .collect::<HashSet<_>>();
    !directives.contains("no-store")
        && !directives.contains("private")
        && !headers.contains_key(header::SET_COOKIE)
}

fn parse_vary(headers: &HeaderMap) -> Option<Vec<String>> {
    let mut vary = Vec::new();
    for value in headers.get_all(header::VARY).iter() {
        let value = value.to_str().ok()?;
        for name in value
            .split(',')
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .filter(|x| !x.is_empty())
        {
            if name == "*" || !SUPPORTED_VARY_HEADERS.contains(&name.as_str()) {
                return None;
            }
            if !vary.contains(&name) {
                vary.push(name);
            }
        }
    }
    Some(vary)
}

fn effective_ttl(configured: u64, headers: &HeaderMap) -> u64 {
    let mut ttl = configured;
    let Some(value) = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    else {
        return expires_ttl(ttl, headers);
    };
    if let Some(upstream) = value.split(',').map(str::trim).find_map(|directive| {
        let (name, value) = directive.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("max-age") {
            return None;
        }
        value.trim().trim_matches('"').parse::<u64>().ok()
    }) {
        ttl = ttl.min(upstream);
    }
    expires_ttl(ttl, headers)
}

fn expires_ttl(configured: u64, headers: &HeaderMap) -> u64 {
    let Some(expires) = headers
        .get(header::EXPIRES)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_http_date(value).ok())
    else {
        return configured;
    };
    let now = SystemTime::now();
    let upstream = expires
        .duration_since(now)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    configured.min(upstream)
}

fn cache_control_requires_revalidation(headers: &HeaderMap) -> bool {
    headers
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|directive| directive.eq_ignore_ascii_case("no-cache"))
        })
}

fn cache_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            if name.as_str() == CACHE_DIAGNOSTIC_HEADER
                || crate::cors::is_hop_by_hop(name.as_str())
                || name == header::CONNECTION
            {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

pub fn headers_from_entry(entry: &CacheEntry) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in &entry.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

pub fn add_cache_header(headers: &mut HeaderMap, value: &'static str) {
    headers.insert(CACHE_DIAGNOSTIC_HEADER, HeaderValue::from_static(value));
}

/// Return whether a consumer requested cache revalidation.
pub fn request_requires_revalidation(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|directive| !directive.is_empty())
        .any(|directive| {
            let name = directive
                .split_once('=')
                .map_or(directive, |(name, _)| name.trim());
            name.eq_ignore_ascii_case("no-cache")
        })
}

pub fn now() -> u64 {
    now_seconds()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CacheConfig, CacheRule};
    use std::time::Duration;

    fn config(rules: Vec<CacheRule>) -> CacheConfig {
        CacheConfig {
            enabled: true,
            max_age: 900,
            max_size: 1024 * 1024,
            location: ".cache-test".to_string(),
            whitelist: rules,
        }
    }

    #[test]
    fn normalizes_url_without_fragment() {
        let url = Url::parse("https://EXAMPLE.com/path?q=1#fragment").unwrap();
        assert_eq!(normalized_url(&url), "example.com/path?q=1");
    }

    #[tokio::test]
    async fn last_matching_rule_wins() {
        let root = std::env::temp_dir().join(format!("corsget-cache-{}", std::process::id()));
        let mut cfg = config(vec![
            CacheRule {
                pattern: "example.com/*".to_string(),
                max_age: 10,
            },
            CacheRule {
                pattern: "example.com/private/*".to_string(),
                max_age: 0,
            },
        ]);
        cfg.location = root.to_string_lossy().to_string();
        let cache = Cache::new(&cfg, Path::new("config.yml")).unwrap();
        let headers = HeaderMap::new();
        let public = Url::parse("https://example.com/public").unwrap();
        let private = Url::parse("https://example.com/private/value").unwrap();
        assert!(cache.plan(&public, &headers).is_some());
        assert!(cache.plan(&private, &headers).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn sensitive_request_headers_bypass_cache() {
        let root =
            std::env::temp_dir().join(format!("corsget-cache-sensitive-{}", std::process::id()));
        let mut cfg = config(vec![CacheRule {
            pattern: "example.com/*".to_string(),
            max_age: 10,
        }]);
        cfg.location = root.to_string_lossy().to_string();
        let cache = Cache::new(&cfg, Path::new("config.yml")).unwrap();
        let url = Url::parse("https://example.com/").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test"),
        );
        assert!(cache.plan(&url, &headers).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cache_control_exclusions_are_respected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=60"),
        );
        assert!(!cacheable_headers(&headers));
        headers.remove(header::CACHE_CONTROL);
        headers.insert(header::SET_COOKIE, HeaderValue::from_static("session=test"));
        assert!(!cacheable_headers(&headers));
    }

    #[test]
    fn unsupported_vary_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("User-Agent"));
        assert!(parse_vary(&headers).is_none());
        headers.insert(header::VARY, HeaderValue::from_static("Accept, Origin"));
        assert_eq!(parse_vary(&headers).unwrap().len(), 2);
    }

    #[test]
    fn authorization_vary_is_supported_for_public_responses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::VARY,
            HeaderValue::from_static("Authorization, accept-encoding, AUTHORIZATION"),
        );

        assert_eq!(
            parse_vary(&headers).unwrap(),
            vec!["authorization", "accept-encoding"]
        );
    }

    #[test]
    fn vary_values_from_multiple_headers_are_combined() {
        let mut headers = HeaderMap::new();
        headers.append(header::VARY, HeaderValue::from_static("Accept"));
        headers.append(
            header::VARY,
            HeaderValue::from_static("Authorization, Origin"),
        );

        assert_eq!(
            parse_vary(&headers).unwrap(),
            vec!["accept", "authorization", "origin"]
        );
    }

    #[test]
    fn unsupported_or_star_vary_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::VARY,
            HeaderValue::from_static("Authorization, User-Agent"),
        );
        assert!(parse_vary(&headers).is_none());

        headers.insert(header::VARY, HeaderValue::from_static("*"));
        assert!(parse_vary(&headers).is_none());
    }

    #[tokio::test]
    async fn public_authorization_variant_can_be_cached() {
        let root = std::env::temp_dir().join(format!(
            "corsget-cache-public-authorization-{}",
            std::process::id()
        ));
        let mut cfg = config(vec![CacheRule {
            pattern: "example.com/*".to_string(),
            max_age: 10,
        }]);
        cfg.location = root.to_string_lossy().to_string();
        let cache = Cache::new(&cfg, Path::new("config.yml")).unwrap();
        let url = Url::parse("https://example.com/public").unwrap();
        let request_headers = HeaderMap::new();
        let plan = cache.plan(&url, &request_headers).unwrap();
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            header::VARY,
            HeaderValue::from_static("Authorization, Accept-Encoding"),
        );

        let mut writer = cache
            .begin_write(plan.clone(), 200, &response_headers, &request_headers)
            .await
            .unwrap();
        writer.write(b"public data").await.unwrap();
        writer.finish().await.unwrap();

        let entry = cache.lookup(&plan, now()).await.unwrap();
        assert_eq!(entry.body_len, 11);
        assert_eq!(entry.vary, vec!["authorization", "accept-encoding"]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn authenticated_authorization_variant_is_not_cached() {
        let root = std::env::temp_dir().join(format!(
            "corsget-cache-authenticated-{}",
            std::process::id()
        ));
        let mut cfg = config(vec![CacheRule {
            pattern: "example.com/*".to_string(),
            max_age: 10,
        }]);
        cfg.location = root.to_string_lossy().to_string();
        let cache = Cache::new(&cfg, Path::new("config.yml")).unwrap();
        let url = Url::parse("https://example.com/private").unwrap();
        let request_headers = HeaderMap::new();
        let plan = cache.plan(&url, &request_headers).unwrap();
        let mut authenticated_headers = HeaderMap::new();
        authenticated_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test"),
        );
        let mut response_headers = HeaderMap::new();
        response_headers.insert(header::VARY, HeaderValue::from_static("Authorization"));

        assert!(
            cache
                .begin_write(plan, 200, &response_headers, &authenticated_headers)
                .await
                .is_none()
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn expires_can_reduce_ttl() {
        let mut headers = HeaderMap::new();
        let expires = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(5));
        headers.insert(header::EXPIRES, HeaderValue::from_str(&expires).unwrap());
        assert!(effective_ttl(900, &headers) <= 5);
    }

    #[test]
    fn cache_control_max_age_is_case_insensitive_and_allows_spacing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, Max-Age = 5"),
        );
        assert_eq!(effective_ttl(900, &headers), 5);
    }

    #[test]
    fn request_no_cache_requires_revalidation() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        assert!(request_requires_revalidation(&headers));
    }

    #[test]
    fn request_no_cache_is_case_insensitive_and_supports_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=0, NO-CACHE=\"etag\""),
        );
        assert!(request_requires_revalidation(&headers));
    }

    #[test]
    fn request_no_cache_reads_multiple_header_values() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        headers.append(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        assert!(request_requires_revalidation(&headers));
    }

    #[test]
    fn request_without_no_cache_does_not_require_revalidation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=0, must-revalidate"),
        );
        assert!(!request_requires_revalidation(&headers));
    }
}
