//! The MORP testnet across Linux network namespaces (`scripts/netns-testnet.sh`).
//!
//! Needs unprivileged user namespaces, `unshare`/`nsenter` (util-linux) and
//! `ip` (iproute2), so it is opt-in:
//!
//! ```text
//! cargo build --workspace
//! cargo test -p mask-net --test netns -- --ignored --nocapture
//! ```

use std::path::Path;
use std::process::Command;

#[test]
#[ignore = "needs user + network namespaces; run with --ignored"]
fn testnet_across_network_namespaces() {
    let bin_dir = Path::new(env!("CARGO_BIN_EXE_mask-relay"))
        .parent()
        .unwrap()
        .to_owned();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/netns-testnet.sh");
    let out = Command::new(&script)
        .env("MASK_BIN", &bin_dir)
        .output()
        .expect("run netns-testnet.sh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    println!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "netns testnet failed");
    assert!(stdout.contains("ALL CHECKS PASSED"));
    assert!(!stdout.contains("FAIL "));
}
