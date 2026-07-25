# CORS GET

`GET` requests to any URL. CORS restrictions no more.

A backend proxy server that fetches any URL on your behalf, bypassing
client-side CORS restrictions. Point your browser requests at
`<proxy-host>/<target-url>` and the server fetches the target and returns
the exact response — status, headers, and body — with permissive CORS
headers attached.

## AI Usage Disclaimer

The project was first bootstrapped with a mix of AI models given a specification sheet written by me. Immediately, the code was reviewed manually, refactored for readability, and tested. After the initial bootstrap, AI is mostly only used for documentation and unit tests.

## Quick start

```sh
# 1. Run. On the first launch without a config argument, an annotated
#    config.yaml is created beside the executable from the embedded template.
./corsget

# 2. Edit config.yaml as needed and restart.

# 3. Proxy a request.
curl -i "http://localhost:9647/https://httpbin.org/get"
```

The server listens on `host:port` from `config.yaml` (default
`0.0.0.0:9647`). The default file is created beside the executable, not in
the current working directory. The template is also available at
[`config.example.yml`](config.example.yml).

## Routes

| Method | Path         | Behaviour                                              |
|--------|--------------|--------------------------------------------------------|
| `GET`  | `/`          | `404 Not Found`                                        |
| `GET`  | `/{target}`  | Proxy the target URL. See [Target URL format](#target-url-format). |
| `OPTIONS` | `/{target}` | CORS preflight → `204 No Content` + CORS headers.     |

### Target URL format

Append the target URL after the proxy host. The full path and query string
are preserved.

| Request                                         | Proxied to                              |
|-------------------------------------------------|-----------------------------------------|
| `GET /github.com/search?q=rust`                 | `https://github.com/search?q=rust`       |
| `GET /https://github.com/search?q=rust`         | `https://github.com/search?q=rust`       |
| `GET //github.com/path`                         | `https://github.com/path`                |

If no scheme is given, `https://` is prepended. Only `http` and `https`
schemes are allowed; others return `400 Bad Request`.

## Configuration

Config is loaded from `config.yaml` beside the executable (override with a
CLI arg or the `CORSGET_CONFIG` env var). If the implicit default file does
not exist, **`corsget`** creates it from the embedded template. Existing invalid config files
are never overwritten. Unknown keys are rejected (strict parsing) to catch
typos. See [`config.example.yml`](config.example.yml) for a full annotated
example.

### `application`

| Field           | Type   | Default   | Description                                            |
|-----------------|--------|-----------|--------------------------------------------------------|
| `host`          | string | —         | Bind address (e.g. `0.0.0.0`).                         |
| `port`          | u16    | —         | Bind port.                                             |
| `hostname`      | string | —         | Public hostname (for logging / self-reference).       |
| `real_ip_header`| string | `X-Real-IP` | Header to read the real client IP from (reverse proxy). |

`real_ip_header` must only be enabled when a trusted reverse proxy overwrites
and validates that header. Values that are not valid IPv4 or IPv6 addresses are
ignored and the TCP peer address is used instead.

### `connection.target` / `connection.origin`

Each is a blacklist + whitelist pair. If both are empty, everything is
allowed. If the whitelist is non-empty, only whitelisted entries are
allowed (and must not also be blacklisted).

| Field        | Type         | Description                                           |
|--------------|--------------|-------------------------------------------------------|
| `blacklist`  | list[string] | Denied entries.                                       |
| `whitelist`  | list[string] | Allowed entries (takes precedence when non-empty).    |

**Entry formats** (auto-detected):

| Format                  | Example                     | Matches                                   |
|-------------------------|-----------------------------|-------------------------------------------|
| Exact                   | `example.com`               | `example.com` only (case-insensitive).    |
| Wildcard (`*`)          | `*.example.com`             | Any subdomain of `example.com`.            |
| Regex (`/pattern/flags`)| `/^api\d+\.example\.com$/i`| Regex match (flags: `i`, `m`, `s`, `x`).  |

### `connection.rate_limit`

Per-(requesting-origin, client-IP) request-count limits. All tiers apply
simultaneously; the first to fail returns `429 Too Many Requests` with
`Retry-After` and `X-RateLimit-*` headers.

```yaml
rate_limit:
  - window: 1 # seconds
    max: 5 # requests
  - window: 60
    max: 500
```

### `connection.bandwidth_limit`

Per-(requesting-origin, client-IP) byte-bandwidth limits. Byte counts use
`u64`; large values can be written as multiplication expressions
(e.g. `1024 * 1024 * 4096`).

```yaml
bandwidth_limit:
  connection: # per-(origin, ip) windowed byte cap
    - window: 60 # seconds
      max: 1024 * 1024 * 4096 # 4 GiB
  result: # hard cap on a single response body
    max: 1024 * 1024 * 512 # 512 MiB
```

If a response's `Content-Length` exceeds `result.max`, it is rejected with
`413 Payload Too Large` before streaming begins. Otherwise, bytes are counted
as they stream; if `result.max` is exceeded mid-stream, the response is
truncated (the already-sent status + headers remain).

The connection bandwidth limit is a soft cap. Exceeding a connection window
does not interrupt the current response; it continues to completion. Therefore
the connection limit never causes a response to be truncated. When
`result.max` is enabled, the proxy removes `Content-Length` before streaming,
because the upstream declaration may be missing or inaccurate and the actual
body can still exceed the cap. When `result.max` is disabled, the proxy
preserves the upstream `Content-Length`.

### `proxy`

| Field          | Type | Description                                          |
|----------------|------|------------------------------------------------------|
| `max_redirects`| u32  | Max redirects to follow (`0` disables).             |
| `timeout`      | u64  | Upstream request timeout in seconds.                 |

Redirects are followed manually up to `max_redirects`, including relative
`Location` values. Every redirect destination is checked against the target
policy before it is fetched.

> [!IMPORTANT]
> Client headers, including `Authorization`, are
preserved across redirects, so **configure target allowlists accordingly**.

## Header forwarding

All client request headers are forwarded to the target **except**:

- **Hop-by-hop** (RFC 7230 §6.1): `Connection`, `Keep-Alive`,
  `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`,
  `Transfer-Encoding`, `Upgrade`.
- **Proxy-injected**: `X-Forwarded-*`, `X-Real-IP`, `Forwarded`.
- **`Host`**: set to the target's host.

Headers named by the request's `Connection` header are also treated as
hop-by-hop and removed.

This lets `Authorization`, `Cookie`, and other authentication headers
through so authenticated GETs work.

## CORS

Every response carries:

- `Access-Control-Allow-Origin`: echoes the request `Origin` (or `*`).
- `Access-Control-Allow-Credentials: true`
- `Access-Control-Allow-Headers`: echoes `Access-Control-Request-Headers` from
  the preflight request (or `Authorization` when none is supplied).
- `Access-Control-Allow-Methods: GET, OPTIONS`
- `Access-Control-Max-Age: 86400`

`OPTIONS` preflight requests return `204 No Content` with these headers,
which is required for non-simple GETs (e.g. those with `Authorization`) to
work from a browser. Preflight targets and requesting origins are checked
against the same policies as the corresponding `GET`.

## Error responses

| Status | Cause                                              |
|--------|----------------------------------------------------|
| `400`  | Invalid or missing target URL.                     |
| `403`  | Target host or requesting origin denied by policy. |
| `413`  | Response body exceeds per-result size cap.         |
| `429`  | Request-count rate limit exceeded.                 |
| `502`  | Upstream request failed (network, timeout).        |
| `503`  | Rate-limit storage backend failure.                |

Error bodies are JSON: `{ "error": "<message>" }`.

## Architecture

```
src/
  main.rs        — load config, build router, serve + graceful shutdown
  config.rs      — #[derive(Deserialize)] structs; load() via noyalib strict
  matcher.rs     — MatchEntry { Exact | Wildcard | Regex } + TargetList
  extractors.rs  — Origin, ClientIp, RateLimitKey (axum_limit::Key)
  limit.rs       — BandwidthLimiter (fixed-window u64) + ResultSizeGuard
  cors.rs        — CORS headers + OPTIONS preflight + hop-by-hop list
  proxy.rs       — proxy handler: validate, eval lists, stream response
  state.rs       — AppState (config + limiters + reqwest client)
  error.rs       — AppError → IntoResponse
```

**Key crates:**

- [`axum`](https://crates.io/crates/axum) 0.8 — HTTP server.
- [`axum-limit`](https://crates.io/crates/axum-limit) 0.1 — request-count
  rate limiting (extractor-based, tiered, per-key).
- [`noyalib`](https://crates.io/crates/noyalib) 0.0 — YAML config parsing
  (strict mode for typo detection).
- [`reqwest`](https://crates.io/crates/reqwest) 0.12 — upstream HTTP client
  (raw passthrough, no transparent decompression).

## Guarantees

- Only `GET` requests are proxied.
- The exact upstream response (status, headers, body) is returned.
- Rate limits and bandwidth limits are enforced per requesting origin per
  client IP.
- Bandwidth is enforced while streaming proxied response bodies. Generated
  proxy errors are returned immediately and are not charged to the byte
  limiter.
- The server streams responses; large responses are not buffered in
  memory (subject to the per-result cap).
