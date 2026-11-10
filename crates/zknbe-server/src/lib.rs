//! ZK-NBE key server.
//!
//! The server holds one random OPRF key per enrolled device and evaluates it on blinded
//! inputs, subject to policy (device state, heartbeat lease, network allow-list, rate limit).
//! It never sees the device secret, the OPRF input or output, the volume master key or the
//! disk passphrase – and nothing it stores is derived from them.

pub mod admin_api;
pub mod config;
pub mod device_api;
pub mod error;
pub mod state;
pub mod store;

use state::AppState;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// How often lapsed leases are swept into the `locked` state.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Serve both listeners until `shutdown` resolves.
pub async fn serve(
    st: Arc<AppState>,
    device_listener: TcpListener,
    admin_listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    });
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                break;
            }
        }
    };

    let sweeper = {
        let st = st.clone();
        let mut rx = stop_rx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        match device_api::sweep(&st) {
                            Ok(0) => {}
                            Ok(n) => tracing::warn!("locked {n} device(s) whose lease expired"),
                            Err(e) => tracing::error!("lease sweep failed: {}", e.message),
                        }
                    }
                    _ = rx.changed() => break,
                }
            }
        })
    };

    let device = axum::serve(
        device_listener,
        device_api::router(st.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stop_rx.clone()));
    let admin = axum::serve(
        admin_listener,
        admin_api::router(st.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stop_rx.clone()));

    let (a, b) = tokio::join!(async { device.await }, async { admin.await });
    sweeper.abort();
    a?;
    b?;
    Ok(())
}
