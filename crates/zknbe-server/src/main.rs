use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use zknbe_server::config::Config;
use zknbe_server::state::AppState;

/// ZK-NBE key server.
#[derive(Parser)]
#[command(name = "zknbed", version)]
struct Args {
    /// Path to the configuration file. Built-in defaults are used if it does not exist
    /// and the flag was not given explicitly.
    #[arg(short, long, env = "ZKNBED_CONFIG")]
    config: Option<PathBuf>,

    /// Override `server.data_dir`.
    #[arg(long, env = "ZKNBED_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutting down");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let default_path = PathBuf::from("/etc/zknbe/zknbed.toml");
    let mut cfg = match &args.config {
        Some(path) => Config::load(path)?,
        None if default_path.exists() => Config::load(&default_path)?,
        None => Config::default(),
    };
    if let Some(dir) = args.data_dir {
        cfg.server.data_dir = dir;
    }
    if args.check {
        println!("configuration ok");
        return Ok(());
    }

    let device_addr = cfg.server.listen;
    let admin_addr = cfg.server.admin_listen;
    if !admin_addr.ip().is_loopback() {
        tracing::warn!(
            "admin API is listening on {admin_addr}, which is not loopback: put it behind TLS \
             and network access controls"
        );
    }
    let st = Arc::new(AppState::init(cfg)?);
    let device_listener = tokio::net::TcpListener::bind(device_addr)
        .await
        .map_err(|e| anyhow::anyhow!("cannot bind device listener {device_addr}: {e}"))?;
    let admin_listener = tokio::net::TcpListener::bind(admin_addr)
        .await
        .map_err(|e| anyhow::anyhow!("cannot bind admin listener {admin_addr}: {e}"))?;
    tracing::info!(
        server_id = %st.server_id,
        "zknbed {} listening: devices on {device_addr}, admin on {admin_addr}",
        env!("CARGO_PKG_VERSION")
    );
    zknbe_server::serve(st, device_listener, admin_listener, shutdown_signal()).await
}
