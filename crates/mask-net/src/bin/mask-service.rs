//! Create, host, and verify `.morp` services.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mask_net::address::MorpAddress;
use mask_net::directory::DEFAULT_DIRECTORY;
use mask_net::directory::client::DirectoryClient;
use mask_net::identity::to_hex;
use mask_net::service::descriptor::{
    DEFAULT_LIFETIME, MAX_LIFETIME, ServiceDescriptor, ServiceEndpoint, Withdrawal,
};
use mask_net::service::fetch::{self, FetchTimeouts};
use mask_net::service::host::ServiceHost;
use mask_net::service::keys::ServiceKeys;
use mask_net::service::site::Site;
use mask_net::service::{now_millis, now_secs};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::signal::unix::{SignalKind, signal};

const PID_FILE: &str = "host.pid";

/// Manage MORP services. Addresses are generated from keys; they cannot be
/// chosen. EXPERIMENTAL v0.4: hosting is a direct localhost prototype and
/// does NOT hide the service's location.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Folder holding service keys (one subfolder per address).
    #[arg(long, global = true, default_value = "runtime/services")]
    services_dir: PathBuf,

    /// MORP directory address.
    #[arg(long, global = true, default_value = DEFAULT_DIRECTORY)]
    directory: SocketAddr,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new service identity and print its .morp address.
    Create,
    /// List the addresses of local services.
    List,
    /// Show details of a local service.
    Show { address: String },
    /// Check an address's format and checksum (offline).
    Check { address: String },
    /// Host a website folder at a service's address until stopped.
    Host {
        address: String,
        /// Folder containing index.html and other files.
        #[arg(long)]
        site: PathBuf,
        /// Local address for the service (must be loopback; port 0 = any).
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        /// Descriptor lifetime in seconds (republished at a third of this).
        #[arg(long, default_value_t = DEFAULT_LIFETIME)]
        lifetime: u64,
    },
    /// Stop a running `host` for this address.
    Stop { address: String },
    /// Look the address up in the directory and make the service prove its identity.
    Verify { address: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let result = match args.command {
        Command::Create => create(&args.services_dir),
        Command::List => list(&args.services_dir),
        Command::Show { ref address } => show(&args.services_dir, address),
        Command::Check { ref address } => check(address),
        Command::Host {
            ref address,
            ref site,
            listen,
            lifetime,
        } => {
            host(
                &args.services_dir,
                args.directory,
                address,
                site,
                listen,
                lifetime,
            )
            .await
        }
        Command::Stop { ref address } => stop(&args.services_dir, address),
        Command::Verify { ref address } => verify(args.directory, address).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn parse(address: &str) -> Result<MorpAddress, String> {
    MorpAddress::parse(address).map_err(|e| format!("invalid .morp address: {e}"))
}

fn create(services_dir: &Path) -> Result<(), String> {
    let (keys, dir) = ServiceKeys::create_in(services_dir).map_err(|e| e.to_string())?;
    println!("Created a new MORP service identity.\n");
    println!("  Address:  {}", keys.address().url());
    println!(
        "  Key file: {} (mode 600, keep it private, never commit it)",
        dir.join("service.key").display()
    );
    println!("\nThe address is derived from the key and cannot be changed or reassigned.");
    println!("Losing the key means losing the address.");
    Ok(())
}

fn list(services_dir: &Path) -> Result<(), String> {
    let services = ServiceKeys::list(services_dir).map_err(|e| e.to_string())?;
    if services.is_empty() {
        println!(
            "No services in {}. Create one with: mask-service create",
            services_dir.display()
        );
    }
    for service in services {
        match service {
            Ok(address) => println!("{}", address.url()),
            Err(problem) => eprintln!("skipped: {problem}"),
        }
    }
    Ok(())
}

fn show(services_dir: &Path, address: &str) -> Result<(), String> {
    let address = parse(address)?;
    let keys = ServiceKeys::load_address(services_dir, &address).map_err(|e| e.to_string())?;
    println!("Address:    {}", keys.address().url());
    println!("Identity:   {}", keys.address().id());
    println!("Public key: {}", to_hex(keys.address().public_key()));
    println!(
        "Key file:   {}",
        ServiceKeys::key_path(services_dir, &address).display()
    );
    Ok(())
}

fn check(address: &str) -> Result<(), String> {
    let address = parse(address)?;
    println!("Valid .morp address (version 1, checksum OK).");
    println!("  Address:    {}", address.url());
    println!("  Public key: {}", to_hex(address.public_key()));
    Ok(())
}

async fn host(
    services_dir: &Path,
    directory: SocketAddr,
    address: &str,
    site: &Path,
    listen: SocketAddr,
    lifetime: u64,
) -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    if lifetime == 0 || lifetime > MAX_LIFETIME {
        return Err(format!(
            "--lifetime must be between 1 and {MAX_LIFETIME} seconds"
        ));
    }
    let address = parse(address)?;
    let keys = ServiceKeys::load_address(services_dir, &address).map_err(|e| e.to_string())?;
    let site = Site::new(site).map_err(|e| format!("site folder {}: {e}", site.display()))?;
    let site_root = site.root().to_path_buf();
    let client =
        DirectoryClient::new(directory, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    let host = ServiceHost::bind(keys, site, listen)
        .await
        .map_err(|e| e.to_string())?;
    let keys = host.keys();
    let endpoint = ServiceEndpoint::DirectLoopback(host.local_addr());
    let descriptor =
        |revision| ServiceDescriptor::sign(&keys, endpoint.clone(), now_secs(), lifetime, revision);

    let mut revision = now_millis();
    client
        .publish(&descriptor(revision))
        .await
        .map_err(|e| format!("{e}\nIs the directory running? Start it with: mask-directory"))?;

    let pid_path = services_dir.join(address.id()).join(PID_FILE);
    fs::write(&pid_path, std::process::id().to_string()).map_err(|e| e.to_string())?;

    eprintln!("MORP service — EXPERIMENTAL v0.4 direct localhost prototype.");
    eprintln!("The service's location is NOT hidden; relays are not used yet.\n");
    println!("Serving {}", address.url());
    println!("  site:     {}", site_root.display());
    println!(
        "  endpoint: {} (published in the descriptor)",
        host.local_addr()
    );
    println!("Stop with Ctrl+C or: mask-service stop {}", address.id());

    let server = tokio::spawn(host.serve());
    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut refresh = tokio::time::interval(Duration::from_secs((lifetime / 3).max(1)));
    refresh.tick().await; // the first tick fires immediately; we just published
    loop {
        tokio::select! {
            _ = refresh.tick() => {
                revision = now_millis().max(revision + 1);
                if let Err(e) = client.publish(&descriptor(revision)).await {
                    tracing::warn!("descriptor refresh failed: {e}");
                }
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
        }
    }

    println!("\nStopping: withdrawing the descriptor.");
    server.abort();
    if let Err(e) = client.withdraw(&Withdrawal::sign(&keys, revision)).await {
        eprintln!("warning: could not withdraw descriptor: {e}");
    }
    let _ = fs::remove_file(&pid_path);
    Ok(())
}

fn stop(services_dir: &Path, address: &str) -> Result<(), String> {
    let address = parse(address)?;
    let pid_path = services_dir.join(address.id()).join(PID_FILE);
    let pid: i32 = fs::read_to_string(&pid_path)
        .map_err(|_| "this service is not running (no host.pid)".to_owned())?
        .trim()
        .parse()
        .map_err(|_| "host.pid is corrupted".to_owned())?;
    // Make sure the PID still belongs to mask-service before signalling it.
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    if comm.trim() != "mask-service" {
        let _ = fs::remove_file(&pid_path);
        return Err("this service is not running (stale host.pid removed)".into());
    }
    kill(Pid::from_raw(pid), Signal::SIGTERM)
        .map_err(|e| format!("cannot stop process {pid}: {e}"))?;
    println!("Sent stop signal to the host for {}.", address.url());
    Ok(())
}

async fn verify(directory: SocketAddr, address: &str) -> Result<(), String> {
    let address = parse(address)?;
    println!("1. Address format and checksum: OK");
    let client =
        DirectoryClient::new(directory, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    let descriptor = client
        .lookup(&address)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no descriptor is published for this address".to_owned())?;
    println!(
        "2. Descriptor signature by the address's key: OK (revision {}, expires in {} s)",
        descriptor.revision,
        descriptor.expires.saturating_sub(now_secs())
    );
    fetch::connect(&client, &address, FetchTimeouts::default())
        .await
        .map_err(|e| e.to_string())?;
    println!("3. Live service proved possession of the private key: OK");
    println!("\n{} is authentic.", address.url());
    Ok(())
}
