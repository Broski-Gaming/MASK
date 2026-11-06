//! Multi-process testnet: the real binaries, configured with TOML files the
//! way an operator would, each in its own process on its own loopback
//! address (standing in for separate machines).
//!
//! authority (127.0.B.10) · entry (.11) · middle (.12) · rv1 (.13) · rv2 (.14)
//! · hidden-service host · client (`mask-service fetch` / `verify`)
//!
//! Then every process gets SIGTERM and must exit cleanly. For the same test
//! across Linux network namespaces see `scripts/netns-testnet.sh` and
//! `tests/netns.rs`.

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

const SITE_TEXT: &str = "Hello from a multi-process MORP testnet";

fn bin(name: &str) -> PathBuf {
    PathBuf::from(match name {
        "mask-authority" => env!("CARGO_BIN_EXE_mask-authority"),
        "mask-relay" => env!("CARGO_BIN_EXE_mask-relay"),
        "mask-service" => env!("CARGO_BIN_EXE_mask-service"),
        other => panic!("unknown binary {other}"),
    })
}

/// A free port on `ip` (bound and released; fine for a test).
fn free_addr(ip: [u8; 4]) -> SocketAddr {
    TcpListener::bind((std::net::Ipv4Addr::from(ip), 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

fn run(cmd: &mut Command) -> Output {
    let out = cmd.output().expect("binary runs");
    assert!(
        out.status.success(),
        "{cmd:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

struct Proc {
    name: String,
    child: Child,
    log: PathBuf,
}

impl Proc {
    fn spawn(name: &str, dir: &Path, cmd: &mut Command) -> Proc {
        let log = dir.join(format!("{name}.log"));
        let file = fs::File::create(&log).unwrap();
        let child = cmd
            .env("NO_COLOR", "1")
            .env("RUST_LOG", "info")
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .expect("spawn");
        Proc {
            name: name.into(),
            child,
            log,
        }
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// SIGTERM and wait; returns whether it exited successfully in time.
    fn terminate(&mut self) -> bool {
        let pid = nix::unistd::Pid::from_raw(self.child.id() as i32);
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return status.success();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        false
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait_for(what: &str, timeout: Duration, mut check: impl FnMut() -> bool, procs: &[Proc]) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    for p in procs {
        eprintln!("===== {} =====\n{}", p.name, p.log());
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn testnet_of_separate_processes_serves_a_morp_site() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // A /24 per run so parallel test binaries do not collide.
    let block = (std::process::id() % 200 + 20) as u8;
    let ip = |host: u8| [127, block, 0, host];

    // 1. Authority keys → network.toml (the trust anchor).
    let auth_addr = free_addr(ip(10));
    let keys = run(Command::new(bin("mask-authority")).args([
        "keys",
        "--data-dir",
        d.join("auth").to_str().unwrap(),
        "--name",
        "auth1",
        "--address",
        &auth_addr.to_string(),
    ]));
    let block_text = String::from_utf8(keys.stdout).unwrap();
    assert!(block_text.contains("[[authority]]"));
    fs::write(
        d.join("network.toml"),
        format!("name = \"proc-testnet\"\nscope = \"private\"\n\n{block_text}"),
    )
    .unwrap();

    // 2. Relay configs and identities → approved-relays.toml.
    let relays = [
        ("entry1", "entry", 11, "m-a"),
        ("middle1", "middle", 12, "m-b"),
        ("rv1", "rendezvous", 13, "m-c"),
        ("rv2", "rendezvous", 14, "m-d"),
    ];
    let mut approved = String::new();
    for (nick, role, host, family) in relays {
        let listen = free_addr(ip(host));
        fs::write(
            d.join(format!("{nick}.toml")),
            format!(
                "nickname = \"{nick}\"\nrole = \"{role}\"\nlisten = \"{listen}\"\n\
                 family = \"{family}\"\nnetwork = \"network.toml\"\n\
                 data_dir = \"relays/{nick}\"\nconsensus_refresh_secs = 2\n"
            ),
        )
        .unwrap();
        let out = run(Command::new(bin("mask-relay")).args([
            "--config",
            d.join(format!("{nick}.toml")).to_str().unwrap(),
            "--print-identity",
        ]));
        approved.push_str(&String::from_utf8(out.stdout).unwrap());
        approved.push('\n');
    }
    fs::write(d.join("approved-relays.toml"), approved).unwrap();
    fs::write(
        d.join("authority.toml"),
        format!(
            "name = \"auth1\"\nlisten = \"{auth_addr}\"\nnetwork = \"network.toml\"\n\
             approved_relays = \"approved-relays.toml\"\ndata_dir = \"auth\"\n\
             consensus_interval_secs = 10\nconsensus_lifetime_secs = 60\nprobe_interval_secs = 2\n"
        ),
    )
    .unwrap();
    let network = d.join("network.toml");
    let net = network.to_str().unwrap();

    // 3. Start the authority and the relays (separate processes).
    let mut procs = vec![Proc::spawn(
        "authority",
        d,
        Command::new(bin("mask-authority")).args([
            "run",
            "--config",
            d.join("authority.toml").to_str().unwrap(),
        ]),
    )];
    for (nick, ..) in relays {
        procs.push(Proc::spawn(
            nick,
            d,
            Command::new(bin("mask-relay"))
                .args(["--config", d.join(format!("{nick}.toml")).to_str().unwrap()]),
        ));
    }
    wait_for(
        "all four relays to be running in the consensus",
        Duration::from_secs(30),
        || {
            let out = Command::new(bin("mask-authority"))
                .args(["status", "--network", net])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).contains("4 relay(s)")
        },
        &procs,
    );
    // Every relay has installed a consensus listing all four.
    wait_for(
        "relays to install the full consensus",
        Duration::from_secs(20),
        || {
            procs[1..]
                .iter()
                .all(|p| p.log().contains("installed a new consensus relays=4"))
        },
        &procs,
    );

    // 4. A hidden service, hosted through the network.
    let services = d.join("services");
    let created = run(Command::new(bin("mask-service")).args([
        "--services-dir",
        services.to_str().unwrap(),
        "create",
    ]));
    let created = String::from_utf8(created.stdout).unwrap();
    let url = created
        .split_whitespace()
        .find(|w| w.starts_with("morp://"))
        .expect("address printed")
        .to_owned();
    let site = d.join("site");
    fs::create_dir_all(&site).unwrap();
    fs::write(site.join("index.html"), format!("<h1>{SITE_TEXT}</h1>")).unwrap();
    procs.push(Proc::spawn(
        "host",
        d,
        Command::new(bin("mask-service")).args([
            "--network",
            net,
            "--services-dir",
            services.to_str().unwrap(),
            "host",
            &url,
            "--site",
            site.to_str().unwrap(),
        ]),
    ));
    wait_for(
        "the service to publish its descriptor",
        Duration::from_secs(30),
        || procs.last().unwrap().log().contains("Serving morp://"),
        &procs,
    );

    // 5. A client in another process fetches the page through MORP relays.
    let state = d.join("state");
    let state_arg = state.to_str().unwrap();
    let fetch = || {
        Command::new(bin("mask-service"))
            .args([
                "--network",
                net,
                "--state-dir",
                state_arg,
                "fetch",
                &url,
                "/",
            ])
            .output()
            .unwrap()
    };
    let mut page = fetch();
    for _ in 0..5 {
        if page.status.success() {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
        page = fetch();
    }
    assert!(
        page.status.success(),
        "fetch failed: {}",
        String::from_utf8_lossy(&page.stderr)
    );
    assert!(String::from_utf8_lossy(&page.stdout).contains(SITE_TEXT));
    assert!(String::from_utf8_lossy(&page.stderr).contains("via MORP relays"));

    let verify = run(Command::new(bin("mask-service")).args([
        "--network",
        net,
        "--state-dir",
        state_arg,
        "verify",
        &url,
    ]));
    let verify = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.contains("is authentic"), "{verify}");

    // v0.7: the client processes kept their entry guards in a private
    // file, and the second process used one of the first one's guards.
    use std::os::unix::fs::PermissionsExt;
    let guard_file = state.join("client-guards-proc-testnet.json");
    let mode = fs::metadata(&guard_file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "guard file must be private");
    let guards = fs::read_to_string(&guard_file).unwrap();
    let entry_used = verify
        .split("your circuit: ")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .expect("verify prints the circuit");
    assert!(
        guards.contains(&format!("\"nickname\": \"{entry_used}\"")),
        "verify used {entry_used}, not one of the saved guards:\n{guards}"
    );
    // The host kept its own guards next to its key, separately.
    let id = url.trim_start_matches("morp://").trim_end_matches(".morp/");
    assert!(
        d.join("services")
            .join(id)
            .join("service-guards-proc-testnet.json")
            .exists()
    );

    // The rendezvous relays joined circuits; no relay logged page content.
    let joined = procs
        .iter()
        .filter(|p| p.log().contains("circuits joined"))
        .count();
    assert!(joined >= 1, "a rendezvous relay joined circuits");
    for p in &procs[..5] {
        assert!(
            !p.log().contains(SITE_TEXT),
            "{} logged page content",
            p.name
        );
    }

    // 6. Graceful shutdown: host first (withdraws its descriptor), then
    // relays, then the authority. Every process must exit successfully.
    let mut host = procs.pop().unwrap();
    assert!(
        host.terminate(),
        "host did not stop cleanly:\n{}",
        host.log()
    );
    assert!(host.log().contains("withdrawing the descriptor"));
    let after = fetch();
    assert!(
        !after.status.success(),
        "withdrawn service must be unreachable"
    );
    while let Some(mut p) = procs.pop() {
        let ok = p.terminate();
        assert!(ok, "{} did not stop cleanly:\n{}", p.name, p.log());
    }
}
