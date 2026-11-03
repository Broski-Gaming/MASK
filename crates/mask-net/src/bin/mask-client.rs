//! Build MORP circuits through local relays and send test messages.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mask_net::authority::client::AuthorityClient;
use mask_net::client::ClientLink;
use mask_net::config::NetworkConfig;
use mask_net::descriptor::Directory;
use mask_net::transport::{ConnectPolicy, Timeouts};
use mask_net::trust::TrustedRelays;

/// Send test messages over MORP circuits (entry → middle → exit) and print
/// the replies. EXPERIMENTAL and unreviewed: not anonymous.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Folder containing relay descriptors (local mode).
    #[arg(long, default_value = "runtime/directory")]
    directory: PathBuf,

    /// Network mode: take relays from the signed consensus of the
    /// authorities in this network.toml.
    #[arg(long)]
    network: Option<PathBuf>,

    /// Message to send. Repeat to send several.
    #[arg(long, short, default_value = "hello from MASK")]
    message: Vec<String>,

    /// Number of circuits to build over the same entry link.
    #[arg(long, default_value_t = 1)]
    circuits: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    restore_default_sigpipe();
    let args = Args::parse();

    let (directory, policy): (Directory, ConnectPolicy) = match &args.network {
        None => match Directory::load(&args.directory) {
            Ok((directory, problems)) => {
                for problem in problems {
                    eprintln!("skipped descriptor: {problem}");
                }
                (directory, ConnectPolicy::allow_all())
            }
            Err(e) => {
                eprintln!("{e}\nStart the three relays first (see README).");
                return ExitCode::FAILURE;
            }
        },
        Some(path) => {
            let consensus = NetworkConfig::load(path).map(AuthorityClient::new);
            let fetched = match consensus {
                Ok(client) => {
                    let trusted = TrustedRelays::consensus(client.network().scope);
                    let scope = client.network().scope;
                    client
                        .refresh(&trusted)
                        .await
                        .and_then(|_| trusted.snapshot())
                        .map(|d| (d, ConnectPolicy::allow_all().with_scope(scope)))
                }
                Err(e) => Err(e),
            };
            match fetched {
                Ok(found) => found,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    };
    let path = match directory.choose_path() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("{e}\nStart an entry, a middle, and an exit relay first.");
            return ExitCode::FAILURE;
        }
    };

    println!("Path (identities verified from signed descriptors):");
    for hop in path.hops() {
        println!(
            "  {:<6} {:<10} {}  id {}",
            hop.role.to_string(),
            hop.nickname,
            hop.addr,
            hop.node_id.short()
        );
    }

    let link =
        match ClientLink::connect_with(&path.entry, Timeouts::default(), &policy, "client").await {
            Ok(link) => link,
            Err(e) => {
                eprintln!("cannot connect to entry relay: {e}");
                return ExitCode::FAILURE;
            }
        };

    let mut failed = false;
    for n in 1..=args.circuits.max(1) {
        let mut circuit = match link.build_circuit(&path).await {
            Ok(circuit) => circuit,
            Err(e) => {
                eprintln!("circuit {n}: build FAILED: {e}");
                failed = true;
                continue;
            }
        };
        println!(
            "circuit {n} (id {:08x}): built through 3 hops",
            circuit.id()
        );
        for message in &args.message {
            match circuit.send(message.as_bytes()).await {
                Ok(reply) => println!(
                    "  sent {:?} → reply {:?}",
                    message,
                    String::from_utf8_lossy(&reply)
                ),
                Err(e) => {
                    eprintln!("  sent {message:?} → FAILED: {e}");
                    failed = true;
                }
            }
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
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
