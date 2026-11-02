//! Run one MORP relay (entry, middle, or exit) on localhost.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mask_net::crypto::keys::RelayKeys;
use mask_net::descriptor::RelayDescriptor;
use mask_net::identity::Role;
use mask_net::relay::{Relay, RelayConfig};
use tracing::{error, info};

/// Run a MORP relay. EXPERIMENTAL and unreviewed: not anonymous, localhost only.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Relay role: entry, middle, exit, or rendezvous (hidden-service
    /// introduction and rendezvous point).
    #[arg(long)]
    role: Role,

    /// Address to listen on (must be loopback).
    /// Defaults: entry 127.0.0.1:7101, middle :7102, exit :7103, rendezvous :7104.
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Relay nickname, used in logs and as the descriptor file name.
    /// Defaults to the role.
    #[arg(long)]
    name: Option<String>,

    /// Where the identity key is kept. Defaults to runtime/relays/<name>.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Folder where the signed descriptor is published for clients.
    #[arg(long, default_value = "runtime/directory")]
    directory: PathBuf,
}

fn default_listen(role: Role) -> SocketAddr {
    let port = match role {
        Role::Entry => 7101,
        Role::Middle => 7102,
        Role::Exit | Role::Client => 7103,
        Role::Rendezvous => 7104,
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
    let data_dir = args
        .data_dir
        .unwrap_or_else(|| PathBuf::from("runtime/relays").join(&name));

    let keys = match RelayKeys::load_or_create(&data_dir) {
        Ok(keys) => keys,
        Err(e) => {
            error!("cannot load identity key from {}: {e}", data_dir.display());
            return ExitCode::FAILURE;
        }
    };

    let relay = match Relay::bind(RelayConfig::new(&name, args.role, listen), keys).await {
        Ok(relay) => relay,
        Err(e) => {
            error!("could not start relay on {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let descriptor = relay.descriptor();
    let descriptor_path = match descriptor.write_to_dir(&args.directory) {
        Ok(path) => path,
        Err(e) => {
            error!(
                "cannot write descriptor to {}: {e}",
                args.directory.display()
            );
            return ExitCode::FAILURE;
        }
    };

    eprintln!(
        "MORP relay v{} — EXPERIMENTAL and unreviewed. Not anonymous. Localhost only.",
        env!("CARGO_PKG_VERSION")
    );
    info!(
        identity = %descriptor.node_id,
        descriptor = %descriptor_path.display(),
        "descriptor published"
    );

    let outcome = tokio::select! {
        result = relay.serve() => result,
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
            Ok(())
        }
    };

    // Withdraw the descriptor: its onion key dies with this process.
    let _ = std::fs::remove_file(RelayDescriptor::path_in(&args.directory, &name));

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("relay stopped: {e}");
            ExitCode::FAILURE
        }
    }
}
