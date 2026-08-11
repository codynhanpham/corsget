//! corsget — a CORS-bypass GET proxy server.
//!
//! Proxies `GET /{target_url}` to any allowed target, bypassing client-side
//! CORS restrictions. Enforces per-(origin, ip) request-count and byte-
//! bandwidth limits, forwards client headers (minus hop-by-hop), and
//! streams the exact upstream response back.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn;
use axum::routing::{any, get};
use futures::future::try_join_all;
use local_ip_address::list_afinet_netifas;
use tower::ServiceBuilder;

mod cache;
mod config;
mod cors;
mod error;
mod extractors;
mod limit;
mod matcher;
mod proxy;
mod state;

use crate::config::Config;
use crate::cors::{cors_layer, preflight_handler};
use crate::proxy::proxy_handler;
use crate::state::AppState;

/// Name of the config file created beside the executable when no config path
/// is provided.
const DEFAULT_CONFIG_FILENAME: &str = "config.yml";

/// The annotated config shipped with the application and used for the first
/// launch. Embedding it keeps the generated config available in release
/// binaries without requiring a separate file at runtime.
const DEFAULT_CONFIG_TEMPLATE: &[u8] = include_bytes!("../config.example.yml");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load config: CLI arg > env var > config.yml beside the executable.
    // Only the implicit default path gets an automatic config file; an
    // explicitly supplied path must fail rather than being overwritten.
    let cli_config_path = std::env::args().nth(1);
    let env_config_path = std::env::var("CORSGET_CONFIG").ok();
    let using_implicit_default = cli_config_path.is_none() && env_config_path.is_none();
    let config_path = match (cli_config_path, env_config_path) {
        (Some(path), _) | (None, Some(path)) => PathBuf::from(path),
        (None, None) => std::env::current_exe()?
            .parent()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "executable has no parent directory",
                )
            })?
            .join(DEFAULT_CONFIG_FILENAME),
    };

    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(_error) if using_implicit_default && !config_path.exists() => {
            std::fs::write(&config_path, DEFAULT_CONFIG_TEMPLATE)?;
            tracing::info!(
                path = %config_path.display(),
                "created default config from the embedded config example"
            );
            Config::load(&config_path)?
        }
        Err(error) => {
            return Err(format!(
                "failed to load config from `{}`: {error}",
                config_path.display()
            )
            .into());
        }
    };

    if !config.application.real_ip_header.trim().is_empty()
        && config
            .application
            .host
            .iter()
            .any(|host| host == "0.0.0.0" || host == "[::]" || host == "::")
    {
        tracing::warn!(
            header = %config.application.real_ip_header,
            "real IP header is trusted on wildcard binds; ensure only a trusted reverse proxy can reach this service"
        );
    }

    let addrs: Vec<SocketAddr> = config
        .application
        .host
        .iter()
        .map(|host| format!("{host}:{}", config.application.port).parse())
        .collect::<Result<_, _>>()
        .map_err(|e| {
            eprintln!("Invalid bind address in application.host: {e}");
            e
        })?;

    let hostname = config.application.hostname.clone();
    let port = config.application.port;
    let state = Arc::new(AppState::new(config, &config_path)?);

    // Build the router.
    //
    // - `GET /`         → 404 (no root service).
    // - `GET /{ *target}`  → proxy handler.
    // - `OPTIONS /{ *target}` → CORS preflight (204).
    // - The CORS middleware layer wraps everything so all responses carry
    //   CORS headers.
    let app = Router::new()
        .route("/", any(root_not_found))
        .route(
            "/{*target}",
            get(proxy_handler)
                .options(preflight_handler)
                .fallback(method_not_allowed),
        )
        .layer(ServiceBuilder::new().layer(from_fn(cors_layer)))
        .with_state(state);

    let mut listeners = Vec::with_capacity(addrs.len());
    for addr in addrs {
        listeners.push(tokio::net::TcpListener::bind(addr).await?);
    }
    // For a specific bind address, report that address. For a wildcard bind,
    // also report the machine's interface addresses as useful connection
    // addresses. The wildcard socket itself remains the authoritative bind.
    let addresses = listening_addresses(&listeners)?;
    tracing::info!(%hostname, port, "corsget listening on:\n  {addresses}");

    let servers = listeners.into_iter().map(|listener| async {
        axum::serve(
            listener,
            app.clone()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
    });
    try_join_all(servers).await?;

    tracing::info!("shutdown complete");
    Ok(())
}

/// Return useful addresses for the startup message without confusing a
/// wildcard bind with a single interface.
fn listening_addresses(listeners: &[tokio::net::TcpListener]) -> Result<String, std::io::Error> {
    let interfaces = list_afinet_netifas().ok().map(|entries| {
        entries
            .into_iter()
            .map(|(_, ip)| ip)
            .collect::<Vec<IpAddr>>()
    });

    let mut addresses = Vec::new();
    for listener in listeners {
        let bound = listener.local_addr()?;
        if !bound.ip().is_unspecified() {
            addresses.push(bound.to_string());
            continue;
        }

        let matching_interfaces = interfaces.as_deref().unwrap_or(&[]).iter().filter(|ip| {
            matches!(
                (bound.ip(), ip),
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
            )
        });

        let mut expanded = false;
        for ip in matching_interfaces {
            addresses.push(SocketAddr::new(*ip, bound.port()).to_string());
            expanded = true;
        }

        // Keep the configured wildcard visible if interface enumeration is
        // unavailable or returns no address for this address family.
        if !expanded {
            addresses.push(bound.to_string());
        }
    }

    Ok(addresses.join("\n  "))
}

/// Root handler: always returns 404.
async fn root_not_found() -> impl axum::response::IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({ "error": "not found" })),
    )
}

/// Return application-shaped JSON for methods that are not supported.
async fn method_not_allowed() -> impl axum::response::IntoResponse {
    (
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        axum::Json(serde_json::json!({ "error": "method not allowed" })),
    )
}

/// Wait for Ctrl-C / SIGTERM to trigger graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
