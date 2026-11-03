//! Malicious on-path relay tests.
//!
//! Each rendezvous-role relay is reached through a hostile man-in-the-middle
//! proxy (the relay advertises the proxy's address in its signed
//! descriptor). After a working baseline, the proxies start **tampering
//! with** or **silently dropping** traffic toward the relay. Every request
//! must then fail safely: no page content, no request reaching the service,
//! and no connection off the relay route.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mask_net::crypto::keys::RelayKeys;
use mask_net::directory::client::DirectoryClient;
use mask_net::directory::server::{self, DirectoryState};
use mask_net::hs::app::serve_site;
use mask_net::hs::client::{ClientConfig, MorpClient};
use mask_net::hs::service::{HiddenService, HostConfig};
use mask_net::hs::session::HttpRequest;
use mask_net::identity::Role;
use mask_net::relay::{Relay, RelayConfig};
use mask_net::service::descriptor::DEFAULT_LIFETIME;
use mask_net::service::keys::ServiceKeys;
use mask_net::service::site::Site;
use mask_net::service::{now_millis, now_secs};
use mask_net::transport::{ConnectPolicy, Timeouts};
use mask_net::trust::TrustedRelays;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PASS: u8 = 0;
const TAMPER: u8 = 1;
const BLACKHOLE: u8 = 2;
const SECRET: &str = "malicious-relay-test-secret";

fn timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        response: Duration::from_secs(4),
        idle: Duration::from_secs(30),
        keepalive: Duration::from_secs(5),
    }
}

/// Forward traffic toward `target`, applying `mode` to the relay-bound
/// direction.
async fn run_proxy(listener: TcpListener, target: SocketAddr, mode: Arc<AtomicU8>) {
    while let Ok((inbound, _)) = listener.accept().await {
        let Ok(outbound) = TcpStream::connect(target).await else {
            continue;
        };
        let (in_r, in_w) = inbound.into_split();
        let (out_r, out_w) = outbound.into_split();
        tokio::spawn(pump(in_r, out_w, Arc::clone(&mode), true));
        tokio::spawn(pump(out_r, in_w, Arc::clone(&mode), false));
    }
}

async fn pump(
    mut from: impl AsyncReadExt + Unpin,
    mut to: impl AsyncWriteExt + Unpin,
    mode: Arc<AtomicU8>,
    toward_relay: bool,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if toward_relay {
            match mode.load(Ordering::SeqCst) {
                TAMPER => buf[n / 2] ^= 0x55,
                BLACKHOLE => continue,
                _ => {}
            }
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

struct World {
    _dir: tempfile::TempDir,
    client: MorpClient,
    service: HiddenService,
    address: mask_net::address::MorpAddress,
    modes: Vec<Arc<AtomicU8>>,
    entry: SocketAddr,
    app: SocketAddr,
    log: Arc<Mutex<Vec<(String, SocketAddr)>>>,
}

async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir: PathBuf = dir.path().join("relays");
    let log: Arc<Mutex<Vec<(String, SocketAddr)>>> = Arc::default();
    let policy = {
        let log = Arc::clone(&log);
        ConnectPolicy::new(move |origin, addr| {
            log.lock().unwrap().push((origin.to_owned(), addr));
            true
        })
    };

    let mut entry = None;
    let mut modes = Vec::new();
    for (nick, role) in [
        ("entry", Role::Entry),
        ("middle", Role::Middle),
        ("rv0", Role::Rendezvous),
        ("rv1", Role::Rendezvous),
    ] {
        let mut config = RelayConfig::new(nick, role, "127.0.0.1:0".parse().unwrap());
        config.timeouts = timeouts();
        config.policy = policy.clone();
        config.trusted = TrustedRelays::from(relay_dir.clone());
        let proxy = if role == Role::Rendezvous {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            config.advertise = Some(listener.local_addr().unwrap());
            Some(listener)
        } else {
            None
        };
        let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
        relay.descriptor().write_to_dir(&relay_dir).unwrap();
        if let Some(listener) = proxy {
            let mode = Arc::new(AtomicU8::new(PASS));
            tokio::spawn(run_proxy(listener, relay.local_addr(), Arc::clone(&mode)));
            modes.push(mode);
        }
        if role == Role::Entry {
            entry = Some(relay.local_addr());
        }
        tokio::spawn(relay.serve());
    }

    let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let directory_addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(listener, Arc::new(DirectoryState::default())));
    let directory = DirectoryClient::new(directory_addr, Duration::from_secs(2)).unwrap();

    let site = dir.path().join("site");
    fs::create_dir_all(&site).unwrap();
    fs::write(site.join("index.html"), format!("<h1>{SECRET}</h1>")).unwrap();
    let (app, _) = serve_site(Site::new(&site).unwrap(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let identity = ServiceKeys::generate();
    let address = *identity.address();
    let mut host = HostConfig::new(relay_dir.clone(), app);
    host.intro_points = 2;
    host.timeouts = timeouts();
    host.policy = policy.clone();
    let service = HiddenService::start(identity, host).await.unwrap();
    directory
        .publish(&service.descriptor(now_secs(), DEFAULT_LIFETIME, now_millis()))
        .await
        .unwrap();

    let mut config = ClientConfig::new(relay_dir);
    config.timeouts = timeouts();
    config.policy = policy;
    config.connect_timeout = Duration::from_secs(12);
    config.rendezvous_timeout = Duration::from_secs(5);
    config.request_timeout = Duration::from_secs(5);
    World {
        _dir: dir,
        client: MorpClient::new(directory, config),
        service,
        address,
        modes,
        entry: entry.unwrap(),
        app,
        log,
    }
}

fn get() -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        path: "/".into(),
    }
}

/// Baseline through the honest proxies, then switch them to `mode` and
/// require a fresh request to fail safely.
async fn attack(mode: u8) {
    let w = world().await;
    let page = w.client.fetch(&w.address, get()).await.unwrap();
    assert!(String::from_utf8_lossy(&page.body).contains(SECRET));
    let served_before = w.service.stats().requests.load(Ordering::SeqCst);
    w.client.close_all();

    for m in &w.modes {
        m.store(mode, Ordering::SeqCst);
    }
    let result = w.client.fetch(&w.address, get()).await;
    assert!(result.is_err(), "request must fail, got {result:?}");

    // Nothing new reached the service, and nothing went off-route.
    assert_eq!(
        w.service.stats().requests.load(Ordering::SeqCst),
        served_before
    );
    let log = w.log.lock().unwrap();
    for (origin, addr) in log.iter() {
        match origin.as_str() {
            "client" => assert_eq!(*addr, w.entry, "client went off-route"),
            "service" => assert!(
                *addr == w.entry || *addr == w.app,
                "service went off-route to {addr}"
            ),
            _ => {}
        }
    }
}

#[tokio::test]
async fn tampering_relay_link_makes_requests_fail_safely() {
    attack(TAMPER).await;
}

#[tokio::test]
async fn blackholing_relay_link_makes_requests_fail_safely() {
    attack(BLACKHOLE).await;
}

#[tokio::test]
async fn relay_cannot_advertise_a_public_address_in_v05() {
    let mut config = RelayConfig::new("x", Role::Middle, "127.0.0.1:0".parse().unwrap());
    config.advertise = Some("203.0.113.5:7102".parse().unwrap());
    assert!(Relay::bind(config, RelayKeys::generate()).await.is_err());
}
