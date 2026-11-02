//! Run one MASK relay (entry, middle, or exit) on localhost.

use std::net::SocketAddr;
use std::process::ExitCode;

use clap::Parser;
use mask_net::identity::Role;
use mask_net::relay::{Relay, RelayConfig};
use tracing::{error, info};

/// Run a MASK relay. EXPERIMENTAL: no encryption, not anonymous, localhost only.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Relay role: entry, middle, or exit.
    #[arg(long)]
    role: Role,

    /// Address to listen on (must be 127.0.0.1 or ::1).
    /// Defaults: entry 127.0.0.1:7101, middle :7102, exit :7103.
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Human-readable relay name shown in logs. Defaults to the role.
    #[arg(long)]
    name: Option<String>,
}

fn default_listen(role: Role) -> SocketAddr {
    let port = match role {
        Role::Entry => 7101,
        Role::Middle => 7102,
        Role::Exit | Role::Client => 7103,
    };
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let listen = args.listen.unwrap_or_else(|| default_listen(args.role));
    let name = args.name.unwrap_or_else(|| args.role.to_string());

    let relay = match Relay::bind(RelayConfig::new(name, args.role, listen)).await {
        Ok(relay) => relay,
        Err(e) => {
            error!("could not start relay on {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!(
        "MASK relay v{} — EXPERIMENTAL: messages are NOT encrypted and this is NOT anonymous.",
        env!("CARGO_PKG_VERSION")
    );

    tokio::select! {
        result = relay.serve() => {
            if let Err(e) = result {
                error!("relay stopped: {e}");
                return ExitCode::FAILURE;
            }
        }
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }
    ExitCode::SUCCESS
}
