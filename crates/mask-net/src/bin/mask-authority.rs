//! Run a MORP directory authority for a private testnet (v0.6).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mask_net::authority::AuthorityKeys;
use mask_net::authority::client::AuthorityClient;
use mask_net::authority::server::{Authority, AuthorityConfig};
use mask_net::config::{ApprovedRelays, AuthorityFileConfig, NetworkConfig};
use mask_net::identity::to_hex;
use mask_net::scope::NetworkScope;
use mask_net::service::now_secs;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};

/// MORP directory authority: admits allowlisted relays, checks their health,
/// signs the relay consensus, and stores .morp service descriptors.
/// EXPERIMENTAL and unreviewed. Private networks only.
#[derive(Parser)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create (or show) this authority's keys and print its network.toml entry.
    Keys {
        /// Folder for authority.key and link.key (mode 0700/0600).
        #[arg(long)]
        data_dir: PathBuf,
        /// Authority name (a-z, 0-9, -, _).
        #[arg(long)]
        name: String,
        /// Address other machines will use to reach it (private network).
        #[arg(long)]
        address: SocketAddr,
    },
    /// Run the authority from authority.toml.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Show each authority's view of the relays (health, consensus).
    Status {
        #[arg(long)]
        network: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let result = match args.command {
        Command::Keys {
            data_dir,
            name,
            address,
        } => keys(&data_dir, &name, address),
        Command::Run { config } => run(config).await,
        Command::Status { network } => status(network).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn keys(data_dir: &std::path::Path, name: &str, address: SocketAddr) -> Result<(), String> {
    if !NetworkScope::Private.allows(address) {
        return Err(format!(
            "{address} is not a loopback or private address; MORP testnets never use public addresses"
        ));
    }
    let keys = AuthorityKeys::load_or_create(data_dir)
        .map_err(|e| format!("cannot load keys from {}: {e}", data_dir.display()))?;
    println!(
        "# Keys are in {} (keep them private, never commit them).",
        data_dir.display()
    );
    println!("# Copy this block into network.toml on EVERY machine:");
    println!("[[authority]]");
    println!("name = \"{name}\"");
    println!("address = \"{address}\"");
    println!("identity = \"{}\"", to_hex(&keys.identity_public()));
    println!("link_key = \"{}\"", to_hex(&keys.link_public()));
    Ok(())
}

async fn run(path: PathBuf) -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let file = AuthorityFileConfig::load(&path).map_err(|e| e.to_string())?;
    let approved = ApprovedRelays::load(&file.approved_relays_path).map_err(|e| e.to_string())?;
    let keys = AuthorityKeys::load_or_create(&file.data_dir)
        .map_err(|e| format!("cannot load keys from {}: {e}", file.data_dir.display()))?;
    let mut config = AuthorityConfig::new(&file.name, file.listen, file.network.clone(), approved);
    config.consensus_interval = Duration::from_secs(file.consensus_interval_secs);
    config.consensus_lifetime = Duration::from_secs(file.consensus_lifetime_secs);
    config.probe_interval = Duration::from_secs(file.probe_interval_secs);
    let authority = Authority::bind(config, keys)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "MORP directory authority v{} — EXPERIMENTAL and unreviewed. Network \"{}\" ({} scope).",
        env!("CARGO_PKG_VERSION"),
        file.network.name,
        file.network.scope
    );
    let handle = authority.handle();
    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut serving = tokio::spawn(authority.serve());
    tokio::select! {
        result = &mut serving => {
            return result.map_err(|e| e.to_string())?.map_err(|e| e.to_string());
        }
        _ = tokio::signal::ctrl_c() => info!("Ctrl+C: shutting down"),
        _ = sigterm.recv() => info!("SIGTERM: shutting down"),
    }
    handle.shutdown();
    match tokio::time::timeout(Duration::from_secs(10), serving).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err(e.to_string()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => {
            error!("shutdown did not finish in time");
            Err("shutdown timed out".into())
        }
    }
}

async fn status(network: PathBuf) -> Result<(), String> {
    let network = NetworkConfig::load(&network).map_err(|e| e.to_string())?;
    let client = AuthorityClient::new(network.clone());
    let mut any = false;
    for (name, result) in client.status().await {
        match result {
            Err(e) => println!("authority {name}: UNREACHABLE ({e})\n"),
            Ok(s) => {
                any = true;
                let valid = s
                    .consensus_valid_until
                    .map(|v| format!("valid for {} s", v.saturating_sub(now_secs())))
                    .unwrap_or_else(|| "none".into());
                println!(
                    "authority {} (network \"{}\"): consensus {} ({valid})",
                    s.name,
                    s.network,
                    s.consensus_sequence
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".into())
                );
                println!(
                    "  refused: {} identity change(s), {} upload(s) from unapproved relays",
                    s.identity_changes_refused, s.unapproved_uploads
                );
                println!(
                    "  {:<14} {:<10} {:<22} {:<10} {:<8} {:>8} {:>10}",
                    "relay", "role", "address", "family", "running", "failures", "probe age"
                );
                for r in &s.relays {
                    println!(
                        "  {:<14} {:<10} {:<22} {:<10} {:<8} {:>8} {:>10}",
                        r.nickname,
                        r.role.to_string(),
                        r.address.to_string(),
                        r.family,
                        if r.running { "yes" } else { "NO" },
                        r.consecutive_probe_failures,
                        r.seconds_since_probe
                            .map(|s| format!("{s} s"))
                            .unwrap_or_else(|| "-".into())
                    );
                }
                println!();
            }
        }
    }
    match client.fetch_consensus().await {
        Ok(c) => println!(
            "Verified consensus: sequence {}, {} relay(s), signed by {}.",
            c.sequence,
            c.relays.len(),
            c.signed_by.join(", ")
        ),
        Err(e) => println!("No verifiable consensus: {e}"),
    }
    if any {
        Ok(())
    } else {
        Err("no authority answered".into())
    }
}
