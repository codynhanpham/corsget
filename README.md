# CORS GET

`GET` requests to any URL. CORS restrictions no more.

A backend proxy server that fetches any URL on your behalf, bypassing
client-side CORS restrictions. Point your browser requests at
`<proxy-host>/<target-url>` and the server fetches the target and returns
the exact response - status, headers, and body - with permissive CORS
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

Download the latest release from [GitHub Releases](https://github.com/codynhanpham/corsget/releases) and run it. The first launch creates a `config.yaml` beside the executable. Edit it as needed and restart. Then proxy requests through the server.
```sh
# 1. Run. On the first launch without a config argument, an annotated
#    config.yaml is created beside the executable from the embedded template.
./corsget

# 2. Edit config.yaml as needed and restart.

# 3. Proxy a request.
curl -i "http://localhost:9647/https://httpbin.org/get"
```

You can also download the source code and build it yourself with `cargo build --release`.

The server listens on `host:port` from `config.yaml` (default
`127.0.0.1:9647`). The default file is created beside the executable, not in
the current working directory. The template is also available at
[`config.example.yml`](config.example.yml).

### Docker

A [`Dockerfile`](./Dockerfile) and [`docker-compose.yml`](docker-compose.yml) are provided for convenience. To use them, you first must clone the project to build the image locally. A prebuilt image might be published on Docker Hub in the future.

1. Clone the repo and build the image:
	```sh
	git clone https://github.com/codynhanpham/corsget.git
	cd corsget
	```
2. Copy and update the config file:
	```sh
	cp config.example.yml config.yaml
	# Edit config.yaml as needed.
	```
3. Update the `docker-compose.yml` as needed to change the host port or mount a custom config file. Config file can also be specified via the `CORSGET_CONFIG_FILE` host environment variable to pass into the container.
4. Start the container:
	```sh
	# Optionally, specify a custom config file path:
	export CORSGET_CONFIG_FILE=/path/to/config.yaml

	# Build locally & Start the container
	docker compose up -d
	```
	More docker-compose documentations is also noted at the end of the [`docker-compose.yml`](docker-compose.yml) file.

### Systemd Service

You can also build the project (or download a release) and run it as a `systemd` service. A sample unit file is provided in [`corsget.service`](corsget.service).

Please see more details in the example unit file. Main points to note are:
1. Copy the unit file to `/etc/systemd/system/corsget.service` and edit it as needed.
2. Select a user to run the service as: either a dedicated user, or as your own user. If you choose a dedicated user, make sure to create it first and give it permission to read the config file.
3. Point the `WorkingDirectory=` to the directory where the config file is located. The default is `/etc/corsget`.
4. Update the `Environment=CORSGET_CONFIG=` line to point to your config file. The default is `/etc/corsget/config.yaml`.
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

Config is loaded from `config.yaml` beside the executable (override with a
CLI arg or the `CORSGET_CONFIG` env var). If the implicit default file does
not exist, **`corsget`** creates it from the embedded template. Existing invalid config files
are never overwritten. Unknown keys are rejected (strict parsing) to catch
typos. See [`config.example.yml`](config.example.yml) for a full annotated
example.

### `application`

| Field           | Type   | Default   | Description                                               |
|-----------------|--------|-----------|-----------------------------------------------------------|
| `host`          | string | -         | Bind address (e.g. `0.0.0.0`).                            |
| `port`          | u16    | -         | Bind port.                                                |
| `hostname`      | string | -         | Public hostname (for logging / self-reference).           |
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
| Wildcard (`*`)          | `*.example.com`             | Any subdomain of `example.com`.           |
| Regex (`/pattern/flags`)| `/^api\d+\.example\.com$/i`| Regex match (flags: `i`, `m`, `s`, `x`).   |

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
| `max_redirects`| u32  | Max redirects to follow (`0` disables).              |
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
  main.rs        - load config, build router, serve + graceful shutdown
  config.rs      - #[derive(Deserialize)] structs; load() via noyalib strict
  matcher.rs     - MatchEntry { Exact | Wildcard | Regex } + TargetList
  extractors.rs  - Origin, ClientIp, RateLimitKey (axum_limit::Key)
  limit.rs       - BandwidthLimiter (fixed-window u64) + ResultSizeGuard
  cors.rs        - CORS headers + OPTIONS preflight + hop-by-hop list
  proxy.rs       - proxy handler: validate, eval lists, stream response
  state.rs       - AppState (config + limiters + reqwest client)
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
- The exact upstream response (status, headers, body) is returned.
- Rate limits and bandwidth limits are enforced per requesting origin per
  client IP.
- Bandwidth is enforced while streaming proxied response bodies. Generated
  proxy errors are returned immediately and are not charged to the byte
  limiter.
- The server streams responses; large responses are not buffered in
  memory (subject to the per-result cap).
