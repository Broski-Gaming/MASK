//! Create, host, and verify `.morp` hidden services.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mask_net::address::MorpAddress;
use mask_net::authority::client::{AuthorityClient, spawn_refresher};
use mask_net::config::NetworkConfig;
use mask_net::directory::client::DirectoryClient;
use mask_net::directory::{DEFAULT_DIRECTORY, ServiceDirectory};
use mask_net::hs::app::serve_site;
use mask_net::hs::client::{ClientConfig, MorpClient};
use mask_net::hs::service::{HiddenService, HostConfig};
use mask_net::identity::to_hex;
use mask_net::service::descriptor::{DEFAULT_LIFETIME, MAX_INTRO_POINTS, MAX_LIFETIME, Withdrawal};
use mask_net::service::keys::ServiceKeys;
use mask_net::service::site::Site;
use mask_net::service::{now_millis, now_secs};
use mask_net::trust::TrustedRelays;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::signal::unix::{SignalKind, signal};

const PID_FILE: &str = "host.pid";

/// Manage MORP hidden services. Addresses are generated from keys; they
/// cannot be chosen. EXPERIMENTAL and unreviewed: traffic goes through MORP
/// relay circuits, but this is not Tor-level anonymity.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Folder holding service keys (one subfolder per address).
    #[arg(long, global = true, default_value = "runtime/services")]
    services_dir: PathBuf,

    /// MORP service directory address.
    #[arg(long, global = true, default_value = DEFAULT_DIRECTORY)]
    directory: SocketAddr,

    /// Folder of relay descriptors published by mask-relay (local mode).
    #[arg(long, global = true, default_value = "runtime/directory")]
    relay_directory: PathBuf,

    /// Network mode (v0.6 testnet): use the directory authorities and the
    /// signed relay consensus described by this network.toml instead of
    /// --directory and --relay-directory.
    #[arg(long, global = true)]
    network: Option<PathBuf>,

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
    /// Host a website at a service's address, reachable only through MORP relays.
    Host {
        address: String,
        /// Folder with index.html etc., served by a built-in app on 127.0.0.1.
        #[arg(long, conflicts_with = "app", required_unless_present = "app")]
        site: Option<PathBuf>,
        /// Instead of --site: forward to your own web app on this loopback address.
        #[arg(long)]
        app: Option<SocketAddr>,
        /// Number of introduction points (1-3).
        #[arg(long, default_value_t = 2)]
        intro_points: usize,
        /// Descriptor lifetime in seconds (republished at a third of this).
        #[arg(long, default_value_t = DEFAULT_LIFETIME)]
        lifetime: u64,
    },
    /// Stop a running `host` for this address.
    Stop { address: String },
    /// Reach the service through MORP relays and check it proves its identity.
    Verify { address: String },
    /// Fetch one page through MORP relays and print it (like curl).
    Fetch {
        address: String,
        #[arg(default_value = "/")]
        path: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    restore_default_sigpipe();
    let args = Args::parse();
    let result = match args.command {
        Command::Create => create(&args.services_dir),
        Command::List => list(&args.services_dir),
        Command::Show { ref address } => show(&args.services_dir, address),
        Command::Check { ref address } => check(address),
        Command::Host {
            ref address,
            ref site,
            app,
            intro_points,
            lifetime,
        } => host(&args, address, site.as_deref(), app, intro_points, lifetime).await,
        Command::Stop { ref address } => stop(&args.services_dir, address),
        Command::Verify { ref address } => verify(&args, address).await,
        Command::Fetch {
            ref address,
            ref path,
        } => fetch_page(&args, address, path).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The service directory and relay source for this run.
async fn open_network(args: &Args) -> Result<(ServiceDirectory, TrustedRelays), String> {
    match &args.network {
        None => {
            let directory = DirectoryClient::new(args.directory, Duration::from_secs(5))
                .map_err(|e| e.to_string())?;
            Ok((
                directory.into(),
                TrustedRelays::from(args.relay_directory.clone()),
            ))
        }
        Some(path) => {
            let network = NetworkConfig::load(path).map_err(|e| e.to_string())?;
            let relays = TrustedRelays::consensus(network.scope);
            let authorities = AuthorityClient::new(network);
            let count = authorities
                .refresh(&relays)
                .await
                .map_err(|e| format!("{e}\nIs a directory authority running and reachable?"))?
                .unwrap_or(0);
            eprintln!(
                "Network \"{}\": verified consensus with {count} relay(s).",
                authorities.network().name
            );
            Ok((authorities.into(), relays))
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
    args: &Args,
    address: &str,
    site: Option<&Path>,
    app: Option<SocketAddr>,
    intro_points: usize,
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
    if !(1..=MAX_INTRO_POINTS).contains(&intro_points) {
        return Err(format!(
            "--intro-points must be between 1 and {MAX_INTRO_POINTS}"
        ));
    }
    let address = parse(address)?;
    let identity =
        ServiceKeys::load_address(&args.services_dir, &address).map_err(|e| e.to_string())?;
    let (client, relays) = open_network(args).await?;

    // The local web application: built-in static site or the user's own app.
    let (app_addr, app_desc) = match (site, app) {
        (Some(site), _) => {
            let site =
                Site::new(site).map_err(|e| format!("site folder {}: {e}", site.display()))?;
            let root = site.root().display().to_string();
            let (addr, _task) = serve_site(site, "127.0.0.1:0".parse().unwrap())
                .await
                .map_err(|e| e.to_string())?;
            (addr, format!("built-in static site from {root}"))
        }
        (None, Some(app)) => {
            if !app.ip().is_loopback() {
                return Err("--app must be a loopback address such as 127.0.0.1:8080".into());
            }
            (app, "your application".to_owned())
        }
        (None, None) => return Err("give --site or --app".into()),
    };

    let stop_refresh = tokio_util::sync::CancellationToken::new();
    if let Some(authorities) = client.authorities() {
        spawn_refresher(
            authorities.clone(),
            relays.clone(),
            Duration::from_secs(30),
            stop_refresh.clone(),
        );
    }
    let mut config = HostConfig::new(relays, app_addr);
    config.intro_points = intro_points;
    println!("Building introduction circuits through MORP relays…");
    let service = HiddenService::start(identity, config).await.map_err(|e| {
        format!(
            "{e}\nAre the relays running? Start an entry, a middle, and at least one \
             rendezvous relay (see README)."
        )
    })?;
    let wanted = service.wanted_intro_points();

    let mut revision = now_millis();
    client
        .publish(&service.descriptor(now_secs(), lifetime, revision))
        .await
        .map_err(|e| {
            format!("{e}\nIs the directory running? Start mask-directory (local) or mask-authority (network).")
        })?;

    let pid_path = args.services_dir.join(address.id()).join(PID_FILE);
    fs::write(&pid_path, std::process::id().to_string()).map_err(|e| e.to_string())?;

    eprintln!("MORP hidden service — EXPERIMENTAL and unreviewed. Not Tor-level anonymity.\n");
    println!("Serving {}", address.url());
    println!(
        "  introduction points: {} (descriptor lists no address or port)",
        service.intro_points().len()
    );
    println!("  local app: {app_addr} ({app_desc}; loopback only, never contacted by clients)");
    println!("Stop with Ctrl+C or: mask-service stop {}", address.id());

    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut refresh = tokio::time::interval(Duration::from_secs((lifetime / 3).max(1)));
    refresh.tick().await; // fires immediately; we just published
    // Lost introduction points are replaced (at other rendezvous-role
    // relays when possible) and the descriptor is republished.
    let mut health = tokio::time::interval(Duration::from_secs(5));
    let outcome: Result<(), String> = loop {
        let republish = tokio::select! {
            _ = refresh.tick() => true,
            _ = service.intro_point_lost() => {
                tracing::warn!(
                    live = service.live_intro_points(),
                    "an introduction point was lost; re-establishing"
                );
                replace_intro_points(&service).await
            }
            _ = health.tick() => {
                if service.live_intro_points() < wanted {
                    replace_intro_points(&service).await
                } else {
                    false
                }
            }
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = sigterm.recv() => break Ok(()),
        };
        if republish {
            revision = now_millis().max(revision + 1);
            let descriptor = service.descriptor(now_secs(), lifetime, revision);
            match client.publish(&descriptor).await {
                Ok(()) => tracing::info!(
                    intro_points = descriptor.intro_points.len(),
                    "descriptor published"
                ),
                Err(e) => tracing::warn!("descriptor publish failed: {e}"),
            }
        }
    };
    stop_refresh.cancel();

    println!("\nStopping: withdrawing the descriptor and closing circuits.");
    service.shutdown();
    if let Err(e) = client
        .withdraw(&Withdrawal::sign(&service.identity(), revision))
        .await
    {
        eprintln!("warning: could not withdraw descriptor: {e}");
    }
    let _ = fs::remove_file(&pid_path);
    outcome
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

/// Try to bring the service back to its configured intro points. Returns
/// whether the descriptor should be republished.
async fn replace_intro_points(service: &HiddenService) -> bool {
    match service.replenish().await {
        Ok(0) => false,
        Ok(added) => {
            tracing::info!(
                added,
                live = service.live_intro_points(),
                "introduction points re-established"
            );
            true
        }
        Err(e) => {
            tracing::warn!(
                live = service.live_intro_points(),
                "could not re-establish introduction points yet ({e}); will retry"
            );
            // Publish the shrunken list so clients stop trying dead intro points.
            service.live_intro_points() > 0
        }
    }
}

async fn verify(args: &Args, address: &str) -> Result<(), String> {
    let address = parse(address)?;
    println!("1. Address format and checksum: OK");
    let (directory, relays) = open_network(args).await?;
    let descriptor = directory
        .lookup(&address)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no descriptor is published for this address".to_owned())?;
    println!(
        "2. Descriptor signed by the address's key: OK ({} introduction point(s), expires in {} s)",
        descriptor.intro_points.len(),
        descriptor.expires.saturating_sub(now_secs())
    );
    let client = MorpClient::new(directory, ClientConfig::new(relays));
    let (_session, route) = client.connect(&address).await.map_err(|e| e.to_string())?;
    println!(
        "3. Reached through relays (intro point: {}; your circuit: {} → {} → {}): OK",
        route.intro_point, route.entry, route.middle, route.rendezvous
    );
    println!("4. Service proved possession of the private key at the rendezvous: OK");
    println!("\n{} is authentic.", address.url());
    Ok(())
}

async fn fetch_page(args: &Args, address: &str, path: &str) -> Result<(), String> {
    let address = parse(address)?;
    let (directory, relays) = open_network(args).await?;
    let client = MorpClient::new(directory, ClientConfig::new(relays));
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let response = client
        .fetch(
            &address,
            mask_net::hs::session::HttpRequest {
                method: "GET".into(),
                path,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "HTTP {} · {} · {} bytes (via MORP relays)",
        response.status,
        response.content_type,
        response.body.len()
    );
    use std::io::Write;
    std::io::stdout()
        .write_all(&response.body)
        .map_err(|e| e.to_string())
}

/// Exit quietly when stdout is a closed pipe (e.g. `| head`) instead of
/// panicking with "Broken pipe", like standard command-line tools.
fn restore_default_sigpipe() {
    use nix::sys::signal::{SigHandler, Signal, signal};
    // SAFETY: called once at startup before other threads use signals;
    // SIG_DFL is always a valid handler for SIGPIPE.
    unsafe {
        let _ = signal(Signal::SIGPIPE, SigHandler::SigDfl);
    }
}
