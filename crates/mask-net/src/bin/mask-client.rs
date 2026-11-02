//! Build MORP circuits through local relays and send test messages.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mask_net::client::ClientLink;
use mask_net::descriptor::Directory;
use mask_net::transport::Timeouts;

/// Send test messages over MORP circuits (entry → middle → exit) and print
/// the replies. EXPERIMENTAL and unreviewed: not anonymous.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Folder containing relay descriptors.
    #[arg(long, default_value = "runtime/directory")]
    directory: PathBuf,

    /// Message to send. Repeat to send several.
    #[arg(long, short, default_value = "hello from MASK")]
    message: Vec<String>,

    /// Number of circuits to build over the same entry link.
    #[arg(long, default_value_t = 1)]
    circuits: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let (directory, problems) = match Directory::load(&args.directory) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("{e}\nStart the three relays first (see README).");
            return ExitCode::FAILURE;
        }
    };
    for problem in problems {
        eprintln!("skipped descriptor: {problem}");
    }
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

    let link = match ClientLink::connect(&path.entry, Timeouts::default()).await {
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
