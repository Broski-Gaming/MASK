//! Send test messages through a local entry → middle → exit route.

use std::net::SocketAddr;
use std::process::ExitCode;

use clap::Parser;
use mask_net::client::{Circuit, Route};
use mask_net::transport::Timeouts;

/// Send test messages through three local MASK relays and print the replies.
/// EXPERIMENTAL: no encryption, not anonymous.
#[derive(Parser)]
#[command(version)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7101")]
    entry: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:7102")]
    middle: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:7103")]
    exit: SocketAddr,

    /// Message to send. Repeat to send several over the same circuit.
    #[arg(long, short, default_value = "hello from MASK")]
    message: Vec<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let route = Route {
        entry: args.entry,
        middle: args.middle,
        exit: args.exit,
    };

    println!(
        "Route: client → entry {} → middle {} → exit {}",
        route.entry, route.middle, route.exit
    );

    let mut circuit = match Circuit::open(route, Timeouts::default()).await {
        Ok(circuit) => circuit,
        Err(e) => {
            eprintln!("Could not connect to the entry relay: {e}");
            return ExitCode::FAILURE;
        }
    };

    for message in &args.message {
        match circuit.send(message.as_bytes()).await {
            Ok(reply) => println!(
                "sent {:?} → reply {:?}",
                message,
                String::from_utf8_lossy(&reply)
            ),
            Err(e) => {
                eprintln!("sent {message:?} → FAILED: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
