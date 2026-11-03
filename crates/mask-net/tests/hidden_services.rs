//! MORP hidden-service integration tests.
//!
//! Every test runs a real network on 127.0.0.1: entry, middle, and
//! rendezvous-role relays, the service directory, a hidden service with a
//! local web app, and a client. Routing claims are checked with
//! - a **connection policy** that records every outbound TCP connection and
//!   denies anything not on the expected route (so a direct client → service
//!   connection would be refused *and* recorded),
//! - an **observer** that records every plaintext each relay can decrypt,
//! - relay and host **counters** (not log messages).

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mask_net::address::MorpAddress;
use mask_net::client::ClientLink;
use mask_net::crypto::keys::RelayKeys;
use mask_net::descriptor::{CircuitPath, RelayDescriptor};
use mask_net::directory::client::DirectoryClient;
use mask_net::directory::server::{self, DirectoryState};
use mask_net::hs::app::serve_site;
use mask_net::hs::client::{ClientConfig, FetchError, MorpClient};
use mask_net::hs::service::{HiddenService, HostConfig};
use mask_net::hs::session::HttpRequest;
use mask_net::identity::Role;
use mask_net::protocol::{LayerBody, RelayCmd, decode};
use mask_net::relay::{Observer, Relay, RelayConfig, RelayHandle};
use mask_net::service::descriptor::{DEFAULT_LIFETIME, IntroPoint, ServiceDescriptor, Withdrawal};
use mask_net::service::keys::ServiceKeys;
use mask_net::service::site::Site;
use mask_net::service::{now_millis, now_secs};
use mask_net::transport::{ConnectPolicy, Timeouts};
use mask_net::trust::TrustedRelays;

const SECRET: &str = "TOP-SECRET-PAGE-CONTENT-7f3a";

fn timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        response: Duration::from_secs(5),
        idle: Duration::from_secs(30),
        keepalive: Duration::from_secs(5),
    }
}

/// Every connection attempt: (origin, destination, allowed).
type ConnLog = Arc<Mutex<Vec<(String, SocketAddr, bool)>>>;
/// Every plaintext a relay decrypted: (relay nickname, bytes).
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct Net {
    _dir: tempfile::TempDir,
    relay_dir: PathBuf,
    directory_addr: SocketAddr,
    entry: (RelayDescriptor, RelayHandle),
    middle: (RelayDescriptor, RelayHandle),
    rendezvous: Vec<(RelayDescriptor, RelayHandle)>,
    /// Allowed (origin prefix, destination) pairs; filled in as parts start.
    allowed: Arc<Mutex<Vec<(String, SocketAddr)>>>,
    log: ConnLog,
    seen: Seen,
}

impl Net {
    async fn start(rendezvous_relays: usize) -> Net {
        let dir = tempfile::tempdir().unwrap();
        let relay_dir = dir.path().join("relays");
        let allowed: Arc<Mutex<Vec<(String, SocketAddr)>>> = Arc::default();
        let log: ConnLog = Arc::default();
        let seen: Seen = Arc::default();

        let policy = {
            let allowed = Arc::clone(&allowed);
            let log = Arc::clone(&log);
            ConnectPolicy::new(move |origin, addr| {
                let ok = allowed
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(o, a)| o == origin && *a == addr);
                log.lock().unwrap().push((origin.to_owned(), addr, ok));
                ok
            })
        };
        let observer = {
            let seen = Arc::clone(&seen);
            Observer(Arc::new(move |relay: &str, bytes: &[u8]| {
                seen.lock()
                    .unwrap()
                    .push((relay.to_owned(), bytes.to_vec()));
            }))
        };

        let start = |nick: String, role: Role| {
            let policy = policy.clone();
            let observer = observer.clone();
            let relay_dir = relay_dir.clone();
            async move {
                let mut config = RelayConfig::new(nick, role, "127.0.0.1:0".parse().unwrap());
                config.timeouts = timeouts();
                config.policy = policy;
                config.observer = Some(observer);
                config.trusted = TrustedRelays::from(relay_dir.clone());
                let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
                let descriptor = relay.descriptor();
                descriptor.write_to_dir(&relay_dir).unwrap();
                let handle = relay.handle();
                tokio::spawn(relay.serve());
                (descriptor, handle)
            }
        };
        let entry = start("entry".into(), Role::Entry).await;
        let middle = start("middle".into(), Role::Middle).await;
        let mut rendezvous = Vec::new();
        for i in 0..rendezvous_relays {
            rendezvous.push(start(format!("rendezvous{i}"), Role::Rendezvous).await);
        }

        {
            // The only connections a correct MORP network makes.
            let mut a = allowed.lock().unwrap();
            a.push(("client".into(), entry.0.addr));
            a.push(("service".into(), entry.0.addr));
            a.push(("relay:entry".into(), middle.0.addr));
            for (rv, _) in &rendezvous {
                a.push(("relay:middle".into(), rv.addr));
            }
        }

        let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let directory_addr = listener.local_addr().unwrap();
        tokio::spawn(server::serve(listener, Arc::new(DirectoryState::default())));

        Net {
            _dir: dir,
            relay_dir,
            directory_addr,
            entry,
            middle,
            rendezvous,
            allowed,
            log,
            seen,
        }
    }

    fn policy(&self) -> ConnectPolicy {
        let allowed = Arc::clone(&self.allowed);
        let log = Arc::clone(&self.log);
        ConnectPolicy::new(move |origin, addr| {
            let ok = allowed
                .lock()
                .unwrap()
                .iter()
                .any(|(o, a)| o == origin && *a == addr);
            log.lock().unwrap().push((origin.to_owned(), addr, ok));
            ok
        })
    }

    fn directory(&self) -> DirectoryClient {
        DirectoryClient::new(self.directory_addr, Duration::from_secs(2)).unwrap()
    }

    fn client(&self) -> MorpClient {
        let mut config = ClientConfig::new(self.relay_dir.clone());
        config.timeouts = timeouts();
        config.policy = self.policy();
        config.connect_timeout = Duration::from_secs(15);
        config.rendezvous_timeout = Duration::from_secs(8);
        config.request_timeout = Duration::from_secs(10);
        MorpClient::new(self.directory(), config)
    }

    /// Start a hidden service for a test site and publish its descriptor.
    async fn host(&self, intro_points: usize) -> Hosted {
        let site_dir = tempfile::tempdir().unwrap();
        let root = site_dir.path();
        fs::write(
            root.join("index.html"),
            format!("<html><head><link rel=stylesheet href=/style.css></head><body>{SECRET}</body></html>"),
        )
        .unwrap();
        fs::write(root.join("style.css"), "body { color: purple }").unwrap();
        fs::write(root.join("app.js"), "console.log('morp')").unwrap();
        fs::write(root.join("logo.png"), [0x89, b'P', b'N', b'G', 1, 2, 3, 4]).unwrap();
        for i in 0..20 {
            fs::write(
                root.join(format!("item{i}.txt")),
                format!("item number {i}"),
            )
            .unwrap();
        }
        let (app, _) = serve_site(Site::new(root).unwrap(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        self.allowed.lock().unwrap().push(("service".into(), app));

        let identity = ServiceKeys::generate();
        let mut config = HostConfig::new(self.relay_dir.clone(), app);
        config.intro_points = intro_points;
        config.timeouts = timeouts();
        config.policy = self.policy();
        let service = HiddenService::start(identity, config).await.unwrap();
        self.directory()
            .publish(&service.descriptor(now_secs(), DEFAULT_LIFETIME, now_millis()))
            .await
            .unwrap();
        Hosted {
            service,
            app,
            _site: site_dir,
        }
    }

    fn rendezvous_handle(&self, nickname: &str) -> &RelayHandle {
        &self
            .rendezvous
            .iter()
            .find(|(d, _)| d.nickname == nickname)
            .unwrap()
            .1
    }

    fn all_handles(&self) -> Vec<&RelayHandle> {
        let mut v = vec![&self.entry.1, &self.middle.1];
        v.extend(self.rendezvous.iter().map(|(_, h)| h));
        v
    }
}

struct Hosted {
    service: HiddenService,
    app: SocketAddr,
    _site: tempfile::TempDir,
}

impl Hosted {
    fn address(&self) -> MorpAddress {
        *self.service.address()
    }
}

fn get(path: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        path: path.into(),
    }
}

async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

// ============================================================== routing

#[tokio::test]
async fn page_and_resources_load_over_relay_circuits() {
    let net = Net::start(2).await;
    let hosted = net.host(1).await;
    let client = net.client();
    let address = hosted.address();

    for (path, content_type, starts) in [
        ("/", "text/html; charset=utf-8", &b"<html>"[..]),
        ("/style.css", "text/css; charset=utf-8", b"body"),
        ("/app.js", "text/javascript; charset=utf-8", b"console"),
        ("/logo.png", "image/png", b"\x89PNG"),
    ] {
        let response = client.fetch(&address, get(path)).await.unwrap();
        assert_eq!(response.status, 200, "{path}");
        assert_eq!(response.content_type, content_type, "{path}");
        assert!(response.body.starts_with(starts), "{path}");
    }
    let missing = client.fetch(&address, get("/missing")).await.unwrap();
    assert_eq!(missing.status, 404);

    let stats = hosted.service.stats();
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(
        stats.requests.load(Relaxed),
        5,
        "every request reached the service"
    );
    assert_eq!(
        stats.sessions_started.load(Relaxed),
        1,
        "one session reused for all"
    );

    // Traffic really went through the relays.
    let entry = net.entry.1.stats();
    let middle = net.middle.1.stats();
    assert!(
        entry.cells_forwarded >= 5 && entry.cells_returned >= 5,
        "{entry:?}"
    );
    assert!(
        middle.cells_forwarded >= 5 && middle.cells_returned >= 5,
        "{middle:?}"
    );
    let joins: u64 = net
        .rendezvous
        .iter()
        .map(|(_, h)| h.stats().rendezvous_joins)
        .sum();
    let streams: u64 = net
        .rendezvous
        .iter()
        .map(|(_, h)| h.stats().stream_cells)
        .sum();
    assert_eq!(joins, 1);
    assert!(
        streams >= 10,
        "requests and responses crossed the rendezvous point"
    );
}

#[tokio::test]
async fn rendezvous_joins_the_client_circuit_to_a_separate_service_circuit() {
    let net = Net::start(2).await;
    let hosted = net.host(1).await;
    let client = net.client();
    let (session, route) = client.connect(&hosted.address()).await.unwrap();
    assert_ne!(
        route.rendezvous, route.intro_point,
        "client avoids the intro point"
    );

    let rp = net.rendezvous_handle(&route.rendezvous).stats();
    assert_eq!(rp.rendezvous_joins, 1);
    assert_eq!(
        rp.joined_circuits, 2,
        "exactly the client and service circuits are joined"
    );
    assert_eq!(
        rp.circuits_created, 2,
        "client circuit + service circuit, built separately"
    );
    assert_eq!(rp.pending_rendezvous, 0, "cookie consumed");

    let ip = net.rendezvous_handle(&route.intro_point).stats();
    assert_eq!(ip.intro_points, 1);
    assert_eq!(ip.introductions, 1);
    assert_eq!(ip.rendezvous_joins, 0);

    // The joined pair carries the session.
    let response = session
        .request(get("/item3.txt"), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.body, b"item number 3");
    assert!(
        net.rendezvous_handle(&route.rendezvous)
            .stats()
            .stream_cells
            >= 2
    );
}

#[tokio::test]
async fn no_direct_client_to_service_connection_occurs() {
    let net = Net::start(2).await;
    let hosted = net.host(2).await;
    let client = net.client();
    for path in ["/", "/style.css", "/app.js", "/logo.png"] {
        client.fetch(&hosted.address(), get(path)).await.unwrap();
    }

    let log = net.log.lock().unwrap().clone();
    assert!(!log.is_empty());
    for (origin, addr, allowed) in &log {
        assert!(allowed, "off-route connection attempted: {origin} → {addr}");
    }
    let client_targets: Vec<_> = log
        .iter()
        .filter(|(o, _, _)| o == "client")
        .map(|(_, a, _)| *a)
        .collect();
    assert!(!client_targets.is_empty());
    assert!(
        client_targets.iter().all(|a| *a == net.entry.0.addr),
        "the client only ever connects to the entry relay: {client_targets:?}"
    );
    assert!(
        !log.iter()
            .any(|(o, a, _)| o == "client" && *a == hosted.app),
        "the client never touches the service's app"
    );
    let service_targets: Vec<_> = log
        .iter()
        .filter(|(o, _, _)| o == "service")
        .map(|(_, a, _)| *a)
        .collect();
    assert!(
        service_targets
            .iter()
            .all(|a| *a == net.entry.0.addr || *a == hosted.app),
        "the service only connects out to the entry relay and its own app"
    );

    // The descriptor reveals no location.
    let descriptor = net
        .directory()
        .lookup(&hosted.address())
        .await
        .unwrap()
        .unwrap();
    let json = descriptor.to_json();
    assert!(!json.contains(&hosted.app.port().to_string()));
    assert!(!json.contains("127.0.0.1"));
}

#[tokio::test]
async fn relays_cannot_read_page_content_or_requests() {
    let net = Net::start(2).await;
    let hosted = net.host(1).await;
    let client = net.client();
    let page = client.fetch(&hosted.address(), get("/")).await.unwrap();
    assert!(String::from_utf8_lossy(&page.body).contains(SECRET));
    client
        .fetch(&hosted.address(), get("/item7.txt"))
        .await
        .unwrap();

    let seen = net.seen.lock().unwrap();
    assert!(seen.len() > 20, "the observer saw relay traffic");
    let contains =
        |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    for (relay, plaintext) in seen.iter() {
        assert!(
            !contains(plaintext, SECRET.as_bytes()),
            "{relay} saw page content"
        );
        assert!(
            !contains(plaintext, b"item7.txt"),
            "{relay} saw a request path"
        );
        assert!(
            !contains(plaintext, b"item number 7"),
            "{relay} saw a response"
        );
    }
    // Sanity: the rendezvous point did handle Stream cells (as ciphertext).
    let rp_streams = seen
        .iter()
        .filter(|(r, p)| {
            r.starts_with("rendezvous")
                && matches!(
                    decode::<LayerBody>(p),
                    Ok(LayerBody::Cmd(RelayCmd::Stream { .. }))
                )
        })
        .count();
    assert!(rp_streams >= 2);
}

#[tokio::test]
async fn many_simultaneous_requests_share_one_session() {
    let net = Net::start(2).await;
    let hosted = net.host(1).await;
    let client = net.client();
    let address = hosted.address();
    let tasks: Vec<_> = (0..20)
        .map(|i| {
            let client = client.clone();
            tokio::spawn(async move {
                let r = client
                    .fetch(&address, get(&format!("/item{i}.txt")))
                    .await
                    .unwrap();
                assert_eq!(r.body, format!("item number {i}").into_bytes());
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    let stats = hosted.service.stats();
    assert_eq!(
        stats
            .sessions_started
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

// ========================================================= authentication

#[tokio::test]
async fn forged_descriptor_from_a_lying_directory_is_rejected() {
    use axum::Router;
    use axum::routing::get as route_get;

    let net = Net::start(2).await;
    let victim = ServiceKeys::generate();
    let attacker = ServiceKeys::generate();
    let intro = mask_net::hs::crypto::IntroKeys::generate();
    let forged = ServiceDescriptor::sign(
        &attacker,
        vec![IntroPoint {
            relay: net.rendezvous[0].0.node_id,
            auth_key: intro.auth_public(),
            enc_key: intro.enc_public(),
        }],
        now_secs(),
        DEFAULT_LIFETIME,
        1,
    )
    .to_json()
    .replace(&attacker.address().id(), &victim.address().id());

    // A directory that serves the forgery for any address.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/v1/services/{id}",
        route_get(move || {
            let forged = forged.clone();
            async move { forged }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });

    let mut config = ClientConfig::new(net.relay_dir.clone());
    config.timeouts = timeouts();
    config.policy = net.policy();
    let client = MorpClient::new(
        DirectoryClient::new(fake, Duration::from_secs(2)).unwrap(),
        config,
    );
    let err = client.fetch(victim.address(), get("/")).await.unwrap_err();
    assert!(matches!(err, FetchError::DescriptorInvalid(_)), "{err}");
    assert!(
        !net.log
            .lock()
            .unwrap()
            .iter()
            .any(|(o, _, _)| o == "client"),
        "no circuit is built for an unverified descriptor"
    );
}

#[tokio::test]
async fn replayed_introduction_is_rejected_by_the_service() {
    let net = Net::start(2).await;
    let hosted = net.host(1).await;
    let client = net.client();
    client.fetch(&hosted.address(), get("/")).await.unwrap();

    // Recover the Introduce1 the intro point saw (it is ciphertext to the
    // intro point, but an attacker controlling it could replay it).
    let (auth_key, payload) = net
        .seen
        .lock()
        .unwrap()
        .iter()
        .find_map(|(_, p)| match decode::<LayerBody>(p) {
            Ok(LayerBody::Cmd(RelayCmd::Introduce1 { auth_key, payload })) => {
                Some((auth_key, payload))
            }
            _ => None,
        })
        .expect("intro point saw an introduction");

    let intro_relay = net
        .rendezvous
        .iter()
        .find(|(d, _)| d.node_id == hosted.service.intro_points()[0].relay)
        .unwrap()
        .0
        .clone();
    let path = CircuitPath::new(net.entry.0.clone(), net.middle.0.clone(), intro_relay).unwrap();
    let link = ClientLink::connect_with(&path.entry, timeouts(), &net.policy(), "client")
        .await
        .unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    let reply = circuit
        .request(
            RelayCmd::Introduce1 { auth_key, payload },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(reply, RelayCmd::IntroduceAck, "the intro point forwards it");

    let stats = hosted.service.stats();
    eventually("service rejects the replay", || {
        stats
            .replays_rejected
            .load(std::sync::atomic::Ordering::Relaxed)
            == 1
    })
    .await;
    assert_eq!(
        stats
            .sessions_started
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "no second session was created"
    );
}

#[tokio::test]
async fn tampered_introduction_is_rejected_by_the_service() {
    let net = Net::start(2).await;
    let hosted = net.host(1).await;
    let ip = &hosted.service.intro_points()[0];
    let intro_relay = net
        .rendezvous
        .iter()
        .find(|(d, _)| d.node_id == ip.relay)
        .unwrap()
        .0
        .clone();
    let (_, mut payload) = mask_net::hs::crypto::ClientIntro::new(
        hosted.address(),
        &ip.auth_key,
        &ip.enc_key,
        net.rendezvous[0].0.node_id,
        [5; 32],
    )
    .unwrap();
    let last = payload.len() - 1;
    payload[last] ^= 0x40;

    let path = CircuitPath::new(net.entry.0.clone(), net.middle.0.clone(), intro_relay).unwrap();
    let link = ClientLink::connect_with(&path.entry, timeouts(), &net.policy(), "client")
        .await
        .unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    circuit
        .request(
            RelayCmd::Introduce1 {
                auth_key: ip.auth_key,
                payload,
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let stats = hosted.service.stats();
    eventually("service rejects the tampered introduction", || {
        stats
            .bad_introductions
            .load(std::sync::atomic::Ordering::Relaxed)
            == 1
    })
    .await;
    assert_eq!(
        stats
            .sessions_started
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn introduction_for_an_unregistered_key_is_refused_by_the_intro_point() {
    let net = Net::start(1).await;
    let path = CircuitPath::new(
        net.entry.0.clone(),
        net.middle.0.clone(),
        net.rendezvous[0].0.clone(),
    )
    .unwrap();
    let link = ClientLink::connect_with(&path.entry, timeouts(), &net.policy(), "client")
        .await
        .unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    let err = circuit
        .request(
            RelayCmd::Introduce1 {
                auth_key: [3; 32],
                payload: vec![0; 64],
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("UnknownService"), "{err}");
}

#[tokio::test]
async fn rendezvous_cookie_is_single_use() {
    let net = Net::start(1).await;
    let rp = net.rendezvous[0].0.clone();
    let path = CircuitPath::new(net.entry.0.clone(), net.middle.0.clone(), rp).unwrap();
    let link = ClientLink::connect_with(&path.entry, timeouts(), &net.policy(), "client")
        .await
        .unwrap();
    let mut unknown = link.build_circuit(&path).await.unwrap();
    let err = unknown
        .request(
            RelayCmd::Rendezvous1 {
                cookie: [9; 32],
                payload: vec![1, 2, 3],
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("BadCookie"), "{err}");
}

// ================================================================= failures

#[tokio::test]
async fn unpublished_service_is_not_found() {
    let net = Net::start(1).await;
    let nobody = *ServiceKeys::generate().address();
    let err = net.client().fetch(&nobody, get("/")).await.unwrap_err();
    assert!(matches!(err, FetchError::NotFound), "{err}");
}

#[tokio::test]
async fn directory_down_fails_closed() {
    let net = Net::start(1).await;
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let mut config = ClientConfig::new(net.relay_dir.clone());
    config.policy = net.policy();
    let client = MorpClient::new(
        DirectoryClient::new(dead, Duration::from_secs(1)).unwrap(),
        config,
    );
    let err = client
        .fetch(ServiceKeys::generate().address(), get("/"))
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::DirectoryUnavailable(_)), "{err}");
}

#[tokio::test]
async fn stopped_service_is_unavailable_without_fallback() {
    let net = Net::start(2).await;
    let hosted = net.host(1).await;
    let address = hosted.address();
    hosted.service.shutdown();
    // The intro point drops the registration once the intro circuit closes.
    eventually("intro point registration removed", || {
        net.rendezvous
            .iter()
            .all(|(_, h)| h.stats().intro_points == 0)
    })
    .await;
    let err = net.client().fetch(&address, get("/")).await.unwrap_err();
    assert!(matches!(err, FetchError::ServiceUnavailable(_)), "{err}");
    assert!(net.log.lock().unwrap().iter().all(|(_, _, ok)| *ok));
}

#[tokio::test]
async fn missing_middle_relay_fails_safely() {
    let net = Net::start(2).await;
    let hosted = net.host(1).await;
    net.middle.1.shutdown();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let err = net
        .client()
        .fetch(&hosted.address(), get("/"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            FetchError::CircuitFailed(_) | FetchError::ServiceUnavailable(_)
        ),
        "{err}"
    );
    assert!(
        net.log.lock().unwrap().iter().all(|(_, _, ok)| *ok),
        "no fallback connection was attempted"
    );
}

#[tokio::test]
async fn rendezvous_relay_disconnecting_ends_the_session_safely() {
    // One rendezvous-role relay: it is both intro point and rendezvous point.
    let net = Net::start(1).await;
    let hosted = net.host(1).await;
    let client = net.client();
    client.fetch(&hosted.address(), get("/")).await.unwrap();

    net.rendezvous[0].1.shutdown();
    let err = client
        .fetch(&hosted.address(), get("/style.css"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            FetchError::CircuitFailed(_) | FetchError::ServiceUnavailable(_) | FetchError::Timeout
        ),
        "{err}"
    );
    assert!(net.log.lock().unwrap().iter().all(|(_, _, ok)| *ok));
}

// ================================================================= cleanup

#[tokio::test]
async fn circuits_are_cleaned_up_when_sessions_and_services_close() {
    let net = Net::start(2).await;
    let hosted = net.host(2).await;
    let client = net.client();
    client.fetch(&hosted.address(), get("/")).await.unwrap();

    // Client closes: the joined pair and the service's rendezvous circuit go.
    client.close_all();
    eventually("rendezvous circuits torn down", || {
        net.rendezvous.iter().all(|(_, h)| {
            let s = h.stats();
            s.joined_circuits == 0 && s.pending_rendezvous == 0
        })
    })
    .await;
    let stats = hosted.service.stats();
    eventually("service session ended", || {
        stats
            .active_sessions
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
    })
    .await;
    // Only the two intro circuits remain at the rendezvous-role relays.
    eventually("only intro circuits remain", || {
        net.rendezvous
            .iter()
            .map(|(_, h)| h.stats().open_circuits)
            .sum::<usize>()
            == 2
    })
    .await;

    // Service stops: everything is gone everywhere.
    hosted.service.shutdown();
    eventually("all relay circuits closed", || {
        net.all_handles()
            .iter()
            .all(|h| h.stats().open_circuits == 0)
    })
    .await;
    assert!(
        net.rendezvous
            .iter()
            .all(|(_, h)| h.stats().intro_points == 0)
    );
}

// ======================================================= directory (v0.4+)

#[tokio::test]
async fn directory_accepts_only_genuine_fresh_descriptors() {
    let net = Net::start(1).await;
    let directory = net.directory();
    let keys = ServiceKeys::generate();
    let intro = mask_net::hs::crypto::IntroKeys::generate();
    let ip = IntroPoint {
        relay: net.rendezvous[0].0.node_id,
        auth_key: intro.auth_public(),
        enc_key: intro.enc_public(),
    };
    let sign = |revision, published| {
        ServiceDescriptor::sign(
            &keys,
            vec![ip.clone()],
            published,
            DEFAULT_LIFETIME,
            revision,
        )
    };

    directory.publish(&sign(200, now_secs())).await.unwrap();
    assert_eq!(
        directory
            .lookup(keys.address())
            .await
            .unwrap()
            .unwrap()
            .revision,
        200
    );
    assert!(
        directory.publish(&sign(100, now_secs())).await.is_err(),
        "older"
    );
    assert!(
        directory.publish(&sign(200, now_secs())).await.is_err(),
        "replay"
    );
    let expired = sign(300, now_secs() - 2 * DEFAULT_LIFETIME);
    assert!(directory.publish(&expired).await.is_err(), "expired");

    let intruder = ServiceKeys::generate();
    let mut fake = Withdrawal::sign(&intruder, 200);
    fake.address = keys.address().host();
    assert!(directory.withdraw(&fake).await.is_err());

    directory
        .withdraw(&Withdrawal::sign(&keys, 200))
        .await
        .unwrap();
    assert!(directory.lookup(keys.address()).await.unwrap().is_none());
    assert!(
        directory.publish(&sign(200, now_secs())).await.is_err(),
        "replay after withdrawal"
    );

    let http = reqwest::Client::new();
    for (id, body) in [
        ("not-an-address".to_owned(), "{}".to_owned()),
        (keys.address().id(), "{ broken".to_owned()),
        (keys.address().id(), "x".repeat(20_000)),
    ] {
        let status = http
            .put(format!("http://{}/v1/services/{id}", net.directory_addr))
            .body(body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        assert!(matches!(status, 400 | 413), "{id}: {status}");
    }
    assert!(
        DirectoryClient::new("192.0.2.1:7200".parse().unwrap(), Duration::from_secs(1)).is_err()
    );
}
