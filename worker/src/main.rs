//! shopguard-worker: scores the domains an OPNsense resolver sees and flags fake shops.
//!
//! `shopguard-worker` runs the service; `shopguard-worker healthcheck` queries its
//! `/healthz` and exits 0 or 1 (the image has no shell or curl for a health check).

mod analysis;
mod api;
mod config;
mod domain;
mod hosting;
mod http;
mod netguard;
mod rdap;
// used by the SIRET check to come
#[allow(dead_code)]
mod siret;
mod store;
mod tls;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("SHOPGUARD_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };

    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck(cfg.listen).await;
    }

    let store = match &cfg.data {
        Some(dir) if dir.is_dir() => match store::Store::open(dir, cfg.max_domains) {
            Ok(s) => s,
            Err(e) => {
                error!("cannot use {}: {e}", dir.join(store::FILE).display());
                return ExitCode::FAILURE;
            }
        },
        Some(dir) => {
            tracing::warn!(
                "{} does not exist: verdicts are kept in memory only",
                dir.display()
            );
            store::Store::memory(cfg.max_domains)
        }
        None => store::Store::memory(cfg.max_domains),
    };
    let store = Arc::new(store);
    let (tx, rx) = tokio::sync::mpsc::channel(cfg.queue);
    tokio::spawn(analysis::run(
        rx,
        store.clone(),
        analysis::analyzers(http::client()),
    ));
    tokio::spawn(schedule(store.clone(), tx.clone()));

    let state = api::AppState {
        store,
        queue: tx,
        token: cfg.token.into(),
        threshold: cfg.threshold,
    };
    let listener = match bind(cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            error!("cannot listen on {}: {e}", cfg.listen);
            return ExitCode::FAILURE;
        }
    };
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    info!(version = env!("CARGO_PKG_VERSION"), listen = %local, "shopguard-worker started");
    let shutdown = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        info!("shutting down");
    };
    if let Err(e) = axum::serve(listener, api::router(state))
        .with_graceful_shutdown(shutdown)
        .await
    {
        error!("server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Queues the domains due for analysis: received before a restart, or with an expired
/// verdict. Runs at start, then every minute, within the free room of the queue.
async fn schedule(store: Arc<store::Store>, tx: tokio::sync::mpsc::Sender<String>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let due = store.due(store::now(), tx.capacity()).await;
        if !due.is_empty() {
            tracing::debug!(domains = due.len(), "scheduled for analysis");
        }
        for d in due {
            if let Err(e) = tx.try_send(d) {
                let d = match e {
                    tokio::sync::mpsc::error::TrySendError::Full(d)
                    | tokio::sync::mpsc::error::TrySendError::Closed(d) => d,
                };
                store.release(&d).await;
            }
        }
    }
}

/// Binds `addr`. The default `[::]` falls back to `0.0.0.0` on hosts or container
/// networks without IPv6 (Docker disables it unless the network enables it).
async fn bind(addr: std::net::SocketAddr) -> std::io::Result<TcpListener> {
    match TcpListener::bind(addr).await {
        Err(e) if addr.is_ipv6() && addr.ip().is_unspecified() => {
            let v4 = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, addr.port()));
            tracing::warn!("no IPv6 here ({e}), listening on {v4}");
            TcpListener::bind(v4).await
        }
        r => r,
    }
}

/// Minimal HTTP/1.0 GET of /healthz on the local listener.
async fn healthcheck(listen: std::net::SocketAddr) -> ExitCode {
    // an unspecified address is reached on loopback, IPv6 first like the listener
    let addrs: Vec<std::net::SocketAddr> = if listen.ip().is_unspecified() {
        let port = listen.port();
        vec![
            (std::net::Ipv6Addr::LOCALHOST, port).into(),
            (std::net::Ipv4Addr::LOCALHOST, port).into(),
        ]
    } else {
        vec![listen]
    };
    let check = async {
        let mut stream = None;
        for a in &addrs {
            if let Ok(s) = TcpStream::connect(a).await {
                stream = Some(s);
                break;
            }
        }
        let mut s = stream?;
        s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await
            .ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        // "HTTP/1.x 200 …"
        (buf.starts_with(b"HTTP/1.") && buf.get(8..13) == Some(b" 200 ".as_slice())).then_some(())
    };
    match tokio::time::timeout(Duration::from_secs(3), check).await {
        Ok(Some(())) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
