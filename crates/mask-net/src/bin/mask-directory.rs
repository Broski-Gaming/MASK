//! Run the localhost MORP service directory.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use mask_net::directory::DEFAULT_DIRECTORY;
use mask_net::directory::server::{self, DirectoryState};
use tracing::{error, info};

/// MORP service directory: stores signed descriptors for cryptographic
/// .morp addresses. No names, no aliases, no listing. Localhost only.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on (must be loopback).
    #[arg(long, default_value = DEFAULT_DIRECTORY)]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let listener = match server::bind(args.listen).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("cannot listen on {}: {e}", args.listen);
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "MORP directory v{} — EXPERIMENTAL localhost prototype. Descriptors are kept in memory only.",
        env!("CARGO_PKG_VERSION")
    );
    info!(listen = %args.listen, "directory started");

    tokio::select! {
        result = server::serve(listener, Arc::new(DirectoryState::default())) => {
            if let Err(e) = result {
                error!("directory stopped: {e}");
                return ExitCode::FAILURE;
            }
        }
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }
    ExitCode::SUCCESS
}
