//! Run one MORP relay (entry, middle, exit, or rendezvous).
//!
//! Two modes:
//! - **local** (default, one machine): flags only; the signed descriptor is
//!   written to `runtime/directory/`, and the relays found there are trusted.
//! - **network** (`--config relay.toml`, v0.6 testnet): the relay uploads its
//!   descriptor to the directory authorities in `network.toml` and trusts
//!   only relays listed in their signed consensus.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use mask_net::authority::client::{AuthorityClient, spawn_refresher};
use mask_net::config::RelayFileConfig;
use mask_net::crypto::keys::RelayKeys;
use mask_net::descriptor::RelayDescriptor;
use mask_net::identity::Role;
use mask_net::relay::{Relay, RelayConfig, RelayHandle};
use mask_net::scope::NetworkScope;
use mask_net::trust::TrustedRelays;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// How often a networked relay re-uploads its descriptor.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(60);

/// Run a MORP relay. EXPERIMENTAL and unreviewed: not anonymous.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Network mode: read this relay.toml (see deploy/). The relay then
    /// joins the testnet described by its network.toml.
    #[arg(long, conflicts_with_all = ["role", "listen", "name", "directory"])]
    config: Option<PathBuf>,

    /// Print this relay's identity (for approved-relays.toml) and exit.
    #[arg(long)]
    print_identity: bool,

    /// Local mode: relay role: entry, middle, exit, or rendezvous.
    #[arg(long, required_unless_present = "config")]
    role: Option<Role>,

    /// Local mode: address to listen on (loopback).
    /// Defaults: entry 127.0.0.1:7101, middle :7102, exit :7103, rendezvous :7104.
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Local mode: nickname (a-z, 0-9, -, _). Defaults to the role.
    #[arg(long)]
    name: Option<String>,

    /// Where the identity key is kept. Defaults to `runtime/relays/<name>`
    /// (local mode) or the data_dir in relay.toml.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Local mode: folder where descriptors are published and read.
    #[arg(long)]
    directory: Option<PathBuf>,
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
    let result = match &args.config {
        Some(path) => run_network(&args, path.clone()).await,
        None => run_local(&args).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn load_keys(data_dir: &std::path::Path) -> Result<RelayKeys, String> {
    RelayKeys::load_or_create(data_dir)
        .map_err(|e| format!("cannot load identity key from {}: {e}", data_dir.display()))
}

fn print_identity(nickname: &str, role: Role, family: &str, keys: &RelayKeys) {
    println!("# Add this to the authority's approved-relays.toml:");
    println!("[[relay]]");
    println!("nickname = \"{nickname}\"");
    println!("identity = \"{}\"", keys.node_id());
    println!("role = \"{role}\"");
    println!("family = \"{family}\"");
    println!("# operator = \"who runs this machine\"   (optional; set by the authority operator)");
}

async fn run_local(args: &Args) -> Result<(), String> {
    let role = args.role.expect("clap requires --role without --config");
    let listen = args.listen.unwrap_or_else(|| default_listen(role));
    let name = args.name.clone().unwrap_or_else(|| role.to_string());
    let data_dir = args
        .data_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("runtime/relays").join(&name));
    let directory = args
        .directory
        .clone()
        .unwrap_or_else(|| PathBuf::from("runtime/directory"));
    let keys = load_keys(&data_dir)?;
    if args.print_identity {
        print_identity(&name, role, "", &keys);
        return Ok(());
    }

    let mut config = RelayConfig::new(&name, role, listen);
    config.trusted = TrustedRelays::folder(directory.clone(), NetworkScope::Loopback);
    let relay = Relay::bind(config, keys)
        .await
        .map_err(|e| format!("could not start relay on {listen}: {e}"))?;
    let descriptor = relay.descriptor();
    let descriptor_path = descriptor
        .write_to_dir(&directory)
        .map_err(|e| format!("cannot write descriptor to {}: {e}", directory.display()))?;

    eprintln!(
        "MORP relay v{} — EXPERIMENTAL and unreviewed. Not anonymous. Local mode (this machine only).",
        env!("CARGO_PKG_VERSION")
    );
    info!(
        identity = %descriptor.node_id,
        descriptor = %descriptor_path.display(),
        "descriptor published"
    );
    let outcome = serve_until_signal(relay).await;
    // Withdraw the descriptor: its onion and link keys die with this process.
    let _ = std::fs::remove_file(RelayDescriptor::path_in(&directory, &name));
    outcome
}

async fn run_network(args: &Args, path: PathBuf) -> Result<(), String> {
    let file = RelayFileConfig::load(&path).map_err(|e| e.to_string())?;
    let data_dir = args
        .data_dir
        .clone()
        .unwrap_or_else(|| file.data_dir.clone());
    let keys = load_keys(&data_dir)?;
    if args.print_identity {
        print_identity(&file.nickname, file.role, &file.family, &keys);
        return Ok(());
    }
    let scope = file.network.scope;
    let trusted = TrustedRelays::consensus(scope);
    let authorities = AuthorityClient::new(file.network.clone());

    let mut config = RelayConfig::new(&file.nickname, file.role, file.listen);
    config.scope = scope;
    config.advertise = file.advertise;
    config.family = file.family.clone();
    config.trusted = trusted.clone();
    config.timeouts.keepalive = Duration::from_secs(file.keepalive_secs);
    if let Some(n) = file.max_links {
        config.limits.max_links = n;
    }
    if let Some(n) = file.max_links_per_ip {
        config.limits.max_links_per_ip = n;
    }
    if let Some(n) = file.max_circuits {
        config.limits.total_circuits = n;
    }
    if let Some(n) = file.max_circuits_per_link {
        config.limits.circuits_per_link = n;
    }
    if let Some(rate) = file.create_rate_per_ip {
        config.limits.create_rate_per_ip = rate;
    }
    if let Some(rate) = file.intro_rate {
        config.limits.intro_rate = rate;
    }
    let relay = Relay::bind(config, keys)
        .await
        .map_err(|e| format!("could not start relay on {}: {e}", file.listen))?;
    let descriptor = relay.descriptor();

    eprintln!(
        "MORP relay v{} — EXPERIMENTAL and unreviewed. Not anonymous. \
         Network \"{}\" ({} scope; public addresses are refused).",
        env!("CARGO_PKG_VERSION"),
        file.network.name,
        scope
    );
    info!(
        nickname = %descriptor.nickname,
        role = %descriptor.role,
        advertise = %descriptor.addr,
        family = %descriptor.family,
        identity = %descriptor.node_id,
        "relay identity"
    );

    let stop = CancellationToken::new();
    // Upload the descriptor now and every minute (authorities drop relays
    // that stop uploading), and keep the consensus fresh.
    let publisher = {
        let authorities = authorities.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PUBLISH_INTERVAL);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.cancelled() => return,
                }
                for (authority, result) in authorities.publish_relay(&descriptor).await {
                    match result {
                        Ok(detail) => info!(%authority, "descriptor uploaded: {detail}"),
                        Err(e) => warn!(%authority, "descriptor upload failed: {e}"),
                    }
                }
            }
        })
    };
    let refresher = spawn_refresher(
        authorities,
        trusted,
        Duration::from_secs(file.consensus_refresh_secs),
        stop.clone(),
    );

    let outcome = serve_until_signal(relay).await;
    stop.cancel();
    let _ = tokio::join!(publisher, refresher);
    outcome
}

/// Serve until Ctrl+C or SIGTERM, then shut down gracefully: destroy every
/// circuit (telling both neighbours) and close every link.
async fn serve_until_signal(relay: Relay) -> Result<(), String> {
    let handle: RelayHandle = relay.handle();
    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut serving = tokio::spawn(relay.serve());
    tokio::select! {
        result = &mut serving => {
            return match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(format!("relay stopped: {e}")),
                Err(e) => Err(format!("relay task failed: {e}")),
            };
        }
        _ = tokio::signal::ctrl_c() => info!("Ctrl+C: shutting down"),
        _ = sigterm.recv() => info!("SIGTERM: shutting down"),
    }
    let stats = handle.stats();
    info!(
        circuits = stats.open_circuits,
        links = stats.open_links,
        "closing circuits and links"
    );
    handle.shutdown();
    match tokio::time::timeout(Duration::from_secs(10), serving).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err(format!("relay stopped: {e}")),
        Ok(Err(e)) => Err(format!("relay task failed: {e}")),
        Err(_) => Err("shutdown did not finish within 10 s".into()),
    }
}
