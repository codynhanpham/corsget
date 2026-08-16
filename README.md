# CORS GET

`GET` requests to any URL. CORS restrictions no more.

A backend proxy server that fetches allowed URLs on your behalf, bypassing
client-side CORS restrictions. Point your browser requests at
`<proxy-host>/<target-url>` and the server fetches the target and returns
the upstream status and body with proxy-safe headers and permissive CORS
headers attached.

## Why?

There are many CORS proxies out there, but most are either paid, rate-limited, or lack CORS controls of their own. [cors-anywhere](https://github.com/Rob--W/cors-anywhere) is *almost* what I need, but still has some limitations for what I want a proxy to do.

Here are the problems I want to solve with this project:
- You own everything. I want to proxy Authenticated requests that might contain sensitive data, owning your own server is the only answer to that.
- CORS policy for consumers of this proxy. You can control which **origins** are allowed to use your proxy, and which **target** hosts are allowed to be proxied.
- Rate limiting. Both request rate limits and bandwidth limits can be configured.
- Lightweight and fast. All in a single file. A running instance consumes < 5MB of RAM and little CPU overhead. It is written in Rust and uses async I/O for high concurrency.


## AI Usage Disclaimer

The project was first bootstrapped with a mix of AI models given a specification sheet written by me. Immediately, the code was reviewed manually, refactored for readability, and tested. After the initial bootstrap, AI is mostly only used for documentation, CI pipelines, and unit tests.

## Quick start

### Manually

Download the latest release from [GitHub Releases](https://github.com/codynhanpham/corsget/releases) and run it. The first launch creates a `config.yml` beside the executable. Edit it as needed and restart. Then proxy requests through the server.
```sh
# 1. Run. On the first launch without a config argument, an annotated
# config.yml is created beside the executable from the embedded template.
./corsget

# 2. Edit config.yml as needed and restart.

# 3. Proxy a request.
curl -i "http://localhost:9647/https://httpbin.org/get"
```

You can also download the source code and build it yourself with `cargo build --release`.

The server listens on `host:port` from `config.yml` (default
`127.0.0.1:9647` and `[::1]:9647`). The default file is created beside the executable, not in
the current working directory. The template is also available at
[`config.example.yml`](config.example.yml).

### Docker

A [`Dockerfile`](./Dockerfile) and [`docker-compose.yml`](docker-compose.yml) are provided for convenience. To use them, you first must clone the project to build the image locally. A prebuilt image might be published on Docker Hub in the future.

1. Clone the repo:
	```sh
	git clone https://github.com/codynhanpham/corsget.git
	cd corsget
	```

2. Copy and update the config file:
	```sh
	cp config.example.yml config.yml
	# Edit config.yml as needed.
	```

3. Update the `docker-compose.yml` as needed to change the host port or mount a custom config file. Config file can also be specified via the `CORSGET_CONFIG_FILE` host environment variable to pass into the container.

4. Start the container:
	```sh
	# Optionally, specify a custom config file path:
  	export CORSGET_CONFIG_FILE=/path/to/config.yml

	# Build locally & Start the container
	docker compose up -d
	```

	More docker-compose documentations is also noted at the end of the [`docker-compose.yml`](docker-compose.yml) file.

### Systemd Service

You can also build the project (or download a release) and run it as a `systemd` service. A sample unit file is provided in [`corsget.service`](corsget.service).

Please see more details in the example unit file. Main points to note are:
1. Copy or symlink the unit file to `/etc/systemd/system/corsget.service` and edit it as needed.
2. Select a user to run the service as: either a dedicated user, or as your own user. If you choose a dedicated user, make sure to create it first and give it permission to read the config file and run the executable.
3. Point the `WorkingDirectory=` to the directory where the config file is located. The default is `/etc/corsget`.
4. Update the `Environment=CORSGET_CONFIG=` line to point to your config file. The default is `/etc/corsget/config.yml`.
5. Update `ExecStart=` to point to the corsget binary. The default is `/usr/local/bin/corsget`.

Then, enable and start the service:
```sh
sudo systemctl daemon-reload
sudo systemctl enable corsget
sudo systemctl start corsget
```


## Routes

| Method | Path         | Behaviour                                                          |
|--------|--------------|--------------------------------------------------------------------|
| `GET`  | `/`          | `404 Not Found`                                                    |
| `GET`  | `/{target}`  | Proxy the target URL. See [Target URL format](#target-url-format). |
| `OPTIONS` | `/{target}` | CORS preflight → `204 No Content` + CORS headers.                |

### Target URL format

Append the target URL after the proxy host. The full path and query string
are preserved.

| Request                                         | Proxied to                              |
|-------------------------------------------------|-----------------------------------------|
| `GET /example.com/search?q=CORS`                | `https://example.com/search?q=CORS`     |
| `GET /https://example.com/search?q=CORS`        | `https://example.com/search?q=CORS`     |
| `GET //example.com/path`                        | `https://example.com/path`              |

If no scheme is given, `https://` is prepended. Only `http` and `https`
schemes are allowed; others return `400 Bad Request`.

## Configuration

Config is loaded from `config.yml` beside the executable (override with a
CLI arg or the `CORSGET_CONFIG` env var). If the implicit default file does
not exist, **`corsget`** creates it from the embedded template. Existing invalid config files
are never overwritten. Unknown keys are rejected (strict parsing) to catch
typos. See [`config.example.yml`](config.example.yml) for a full annotated
example.

On startup the resolved config path is logged, followed by the cache state:
whether caching is enabled, the resolved cache directory, and, when disabled,
the reason (for example `cache.enabled is false`, a zero `max_age`/`max_size`,
an empty whitelist, or an unavailable cache directory). When caching is
enabled, any startup cleanup of persisted entries is also reported.

### `application`

| Field           | Type   | Default   | Description                                               |
|-----------------|--------|-----------|-----------------------------------------------------------|
| `host`          | string or list[string] | - | Bind address(es), e.g. `0.0.0.0` or `[127.0.0.1, "[::1]"]`. |
| `port`          | u16    | -         | Bind port.                                                |
| `hostname`      | string | -         | Public hostname shown in startup logs.                    |
| `real_ip_header`| string | `X-Real-IP` | Header to read the real client IP from (reverse proxy). |

`real_ip_header` is trusted whenever it contains a valid IPv4 or IPv6 address;
the application does not verify that the TCP peer is a trusted proxy. Enable it
only when the service is reachable through a reverse proxy that overwrites and
validates the header. Otherwise, clients can spoof their rate-limit identity.

### `connection.target` / `connection.origin`

Each is a blacklist + whitelist pair. If both are empty, everything is
allowed. The blacklist is evaluated first, but a matching whitelist entry
overrides the blacklist. When the whitelist is non-empty, entries matching
neither list are denied. For the origin policy specifically, requests without
a valid `Origin` or `Referer` are also denied when the whitelist is non-empty.

| Field        | Type         | Description                                           |
|--------------|--------------|-------------------------------------------------------|
| `blacklist`  | list[string] or null | Denied entries, evaluated before the whitelist. A null value means empty. |
| `whitelist`  | list[string] or null | Allowed entries; a match overrides the blacklist. A null value means empty. |

**Entry formats** (auto-detected):

| Format                  | Example                     | Matches                                   |
|-------------------------|-----------------------------|-------------------------------------------|
| Exact                   | `example.com`               | `example.com` only (case-insensitive).    |
| Wildcard (`*`)          | `*.example.com`             | Any subdomain of `example.com`.           |
| Regex (`/pattern/flags`)| `/^api\d+\.example\.com$/i`| Regex match (flags: `i`, `m`, `s`, `x`).   |

Origin rules match the hostname only; scheme and port are ignored. When the
origin whitelist is non-empty, a valid `Origin` or `Referer` header is required.
The default origin allowlist uses anchored regexes for the configured IPv4
ranges (`10/8`, `192.168/16`, and `100/8`). These match only numeric IPv4
addresses with octets from `0` to `255`.

### `connection.rate_limit`

Per-(requesting-origin, client-IP) request-count limits. All tiers apply
simultaneously; the first to fail returns `429 Too Many Requests` with
`Retry-After` and `X-RateLimit-*` headers.

The list may be omitted or set to null when no request-count limits are needed.
Null list items are ignored, so `rate_limit: #` and a list containing only
`-` are equivalent to `rate_limit: []`.

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

`bandwidth_limit.connection` may likewise be omitted or set to null when no
connection bandwidth tiers are needed. Null list items are ignored.

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
| `max_redirects`| u32  | Max redirects to follow (`0` disables).              |
| `timeout`      | u64  | Upstream request timeout in seconds.                 |

Redirects are followed manually up to `max_redirects`, including relative
`Location` values. Every redirect destination is checked against the target
policy before it is fetched.

> [!IMPORTANT]
> Client headers, including `Authorization`, are
> preserved across redirects, so **configure target allowlists accordingly**.

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
- `Access-Control-Allow-Headers`: echoes `Access-Control-Request-Headers` from the preflight request (or `Authorization` when none is supplied).
- `Access-Control-Allow-Methods: GET, OPTIONS`
- `Access-Control-Max-Age: 86400`

The proxy generates these CORS response headers from the incoming consumer
request. Any same-named headers returned by the upstream target are removed,
so an upstream value cannot replace the consumer's `Origin` with the proxy's
own domain. In a browser request from `https://consumer.example.com`, the response
therefore contains `Access-Control-Allow-Origin: https://consumer.example.com`.

`OPTIONS` preflight requests return `204 No Content` with these headers,
which is required for non-simple GETs (e.g. those with `Authorization`) to
work from a browser. Preflight targets and requesting origins are checked
against the same policies as the corresponding `GET`.
Preflight requests are exempt from request-rate and bandwidth accounting.

### `cache`

The optional disk cache is disabled by default and is whitelist-only. A cache
entry is created only when `enabled` is `true`, `max_age` and `max_size` are
non-zero, and the requested target matches a `whitelist` rule. Rules match
the normalized `host/path?query`; schemes are ignored and URL fragments are
not included. Exact, wildcard, and regex rules are supported. Hosts are
matched case-insensitively, while paths and queries are case-sensitive. If
multiple rules match, the last matching rule supplies the maximum age. A
matching rule with `max_age: 0` disables caching for that target.

```yaml
cache:
  enabled: true
  max_age: 60 * 15 # global upper bound; matching rules may use a lower age
  max_size: 1024 * 1024 * 1024
  location: .cache
  whitelist:
    - match: "api.example.com/*"
      max_age: 60 * 5
```

Relative `location` paths are resolved relative to the configuration file.
The directory is created at startup. If it cannot be created or written, the
proxy continues with caching disabled. The size limit includes cached body
and metadata files; entries larger than the total limit are served but are
not stored. Least-recently-used entries are removed when the limit is
exceeded.

Cache entries persist across application restarts. `created_at` and
`last_access` are stored in each entry's metadata, so a cached response's age
and its LRU position survive a restart. On startup, the cache is cleaned
before the first request is served: stale entries (whose persisted age has
reached their stored TTL), invalid or incomplete entries, orphaned body
files, and leftover temporary files are removed, and the current `max_size`
is enforced using the persisted `last_access` order. Changing the cache
`whitelist` does not delete existing entries; it only affects which targets
are cached from that point on.

Only successful `2xx` responses are cached. `Cache-Control` and `Expires` are
honored, with the configured age acting as an upper bound. Responses marked
`no-store`, `private`, or containing `Set-Cookie` are not stored. `no-cache`
responses are revalidated on every lookup. Stale entries use `ETag` and
`Last-Modified` validators; a `304 Not Modified` response refreshes the
cached metadata and serves the stored body.

Requests containing `Authorization`, `Cookie`, or `Range` bypass the cache.
Supported `Vary` headers (`Accept`, `Accept-Language`, `Accept-Encoding`,
`Origin`, and `Authorization`) are included in the cache identity. Public
requests that do not contain `Authorization` may be cached even when the
upstream response declares `Vary: Authorization`; the unauthenticated
authorization variant is kept separate in the cache identity. Requests
containing `Authorization` always bypass cache lookup and storage, and
authenticated responses are never cached. `Vary: *` and unsupported variance
bypass caching. Cache hits still consume request-rate and bandwidth limits.
Cache-eligible responses include `X-Cache: HIT`, `MISS`, or `REVALIDATED`; this
diagnostic header is not stored in the cache. Cache-disabled or cache-ineligible
requests do not receive an `X-Cache` header.

A consumer can force an existing cache entry to be revalidated by sending
`Cache-Control: no-cache`:

```sh
curl -i \
  -H "Cache-Control: no-cache" \
  "https://proxy.example/https://api.example.com/data"
```

This bypasses a fresh cache hit and forwards the request to the target. If
the cached response has an `ETag` or `Last-Modified` value, the proxy sends
the corresponding conditional request headers. A `304 Not Modified` response
serves the cached body; a new successful response replaces the cached entry.
Both cases return `X-Cache: REVALIDATED`. This directive revalidates the
entry; it does not delete it before the target responds.

## Error responses

| Status | Cause                                              |
|--------|----------------------------------------------------|
| `400`  | Invalid or missing target URL.                     |
| `403`  | Target host or requesting origin denied by policy. |
| `413`  | Declared response body exceeds the per-result cap before streaming. |
| `429`  | Request-count rate limit exceeded.                 |
| `502`  | Upstream request failed (network, timeout).        |
| `503`  | Rate-limit storage backend failure.                |

Application-generated error bodies are JSON: `{ "error": "<message>" }`.
Unsupported methods return a JSON `405 Method Not Allowed` response; a
mid-stream size-limit failure occurs after headers have been sent and therefore
cannot be converted into a new HTTP `413` response.

## Architecture

```
src/
  main.rs        - load config, build router, serve + graceful shutdown
  config.rs      - #[derive(Deserialize)] structs; load() via noyalib strict
  matcher.rs     - MatchEntry { Exact | Wildcard | Regex } + TargetList
  extractors.rs  - Origin, ClientIp, RateLimitKey (axum_limit::Key)
  limit.rs       - BandwidthLimiter (fixed-window u64) + ResultSizeGuard
  cache.rs       - whitelist-driven disk cache, revalidation, and LRU eviction
  cors.rs        - CORS headers + OPTIONS preflight + hop-by-hop list
  proxy.rs       - proxy handler: validate, cache, and stream response
  state.rs       - AppState (config + cache + limiters + reqwest client)
  error.rs       - AppError → IntoResponse
```

**Key crates:**

- [`axum`](https://crates.io/crates/axum) - HTTP server.
- [`axum-limit`](https://crates.io/crates/axum-limit) - request-count
	rate limiting (extractor-based, tiered, per-key).
- [`noyalib`](https://crates.io/crates/noyalib) - YAML config parsing
	(strict mode for typo detection).
- [`reqwest`](https://crates.io/crates/reqwest) - upstream HTTP client
	(raw passthrough, no transparent decompression).

## Guarantees

- Only `GET` requests are proxied.
- The upstream response status and body are returned with hop-by-hop and
	proxy-injected headers removed; CORS headers are added and cached hits
	additionally include the generated `X-Cache` diagnostic header.
- Rate limits and bandwidth limits are enforced per requesting origin per
	client IP.
- Bandwidth is enforced while streaming proxied response bodies. Generated
	proxy errors are returned immediately and are not charged to the byte
	limiter.
- The server streams responses; large responses are not buffered in memory
	(subject to the per-result cap). Cache misses are written to disk while
	they are streamed to the client.
