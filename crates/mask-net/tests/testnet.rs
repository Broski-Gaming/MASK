//! v0.6 network-mode tests: a whole MORP testnet in one process.
//!
//! Each relay listens on its own loopback address (127.0.0.11, .12, …) and
//! declares its own family, standing in for separate machines; the network
//! scope is `private`. A directory authority admits allowlisted relays,
//! probes them, and signs the consensus; relays, the hidden service, and
//! the client use only that consensus. Every link is Noise-authenticated.
//!
//! Claims are proven with the deny-by-default connection policy (every
//! outbound connection is checked and recorded), the relay observer (every
//! plaintext a relay decrypts), and counters, not log messages.

use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mask_net::NetError;
use mask_net::address::MorpAddress;
use mask_net::authority::AuthorityKeys;
use mask_net::authority::client::AuthorityClient;
use mask_net::authority::server::{Authority, AuthorityConfig, AuthorityHandle};
use mask_net::client::ClientLink;
use mask_net::config::{ApprovedRelay, ApprovedRelays, AuthorityInfo, NetworkConfig};
use mask_net::crypto::keys::RelayKeys;
use mask_net::descriptor::{CircuitPath, RelayDescriptor};
use mask_net::hs::app::serve_site;
use mask_net::hs::client::{ClientConfig, MorpClient};
use mask_net::hs::service::{HiddenService, HostConfig};
use mask_net::hs::session::HttpRequest;
use mask_net::identity::Role;
use mask_net::protocol::DestroyReason;
use mask_net::relay::{Observer, Relay, RelayConfig, RelayHandle};
use mask_net::scope::NetworkScope;
use mask_net::service::keys::ServiceKeys;
use mask_net::service::site::Site;
use mask_net::service::{now_millis, now_secs};
use mask_net::transport::{ConnectPolicy, Timeouts};
use mask_net::trust::TrustedRelays;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SECRET: &str = "DISTRIBUTED-SECRET-PAGE-91c2";

fn timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        response: Duration::from_secs(5),
        idle: Duration::from_secs(30),
        keepalive: Duration::from_secs(5),
    }
}

/// Different tests use different 127.0.x.0/24 blocks so they can run in
/// parallel without port clashes.
static NEXT_BLOCK: AtomicU16 = AtomicU16::new(1);

type ConnLog = Arc<Mutex<Vec<(String, SocketAddr)>>>;
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct RelaySpec {
    nick: &'static str,
    role: Role,
    family: &'static str,
}

const SPECS: [RelaySpec; 6] = [
    RelaySpec {
        nick: "entry1",
        role: Role::Entry,
        family: "machine-a",
    },
    RelaySpec {
        nick: "entry2",
        role: Role::Entry,
        family: "machine-b",
    },
    RelaySpec {
        nick: "middle1",
        role: Role::Middle,
        family: "machine-c",
    },
    RelaySpec {
        nick: "middle2",
        role: Role::Middle,
        family: "machine-d",
    },
    RelaySpec {
        nick: "rv1",
        role: Role::Rendezvous,
        family: "machine-e",
    },
    RelaySpec {
        nick: "rv2",
        role: Role::Rendezvous,
        family: "machine-f",
    },
];

struct TestRelay {
    descriptor: RelayDescriptor,
    handle: RelayHandle,
    trusted: TrustedRelays,
}

struct Testnet {
    _dir: tempfile::TempDir,
    block: u16,
    network: NetworkConfig,
    authority: AuthorityHandle,
    authority_addr: SocketAddr,
    relays: Vec<TestRelay>,
    policy: ConnectPolicy,
    log: ConnLog,
    seen: Seen,
}

impl Testnet {
    fn relay(&self, nick: &str) -> &TestRelay {
        self.relays
            .iter()
            .find(|r| r.descriptor.nickname == nick)
            .unwrap()
    }

    fn entries(&self) -> Vec<SocketAddr> {
        self.relays
            .iter()
            .filter(|r| r.descriptor.role == Role::Entry)
            .map(|r| r.descriptor.addr)
            .collect()
    }

    fn authorities(&self, origin: &str) -> AuthorityClient {
        AuthorityClient::new(self.network.clone())
            .with_policy(self.policy.clone(), origin)
            .with_timeouts(timeouts())
    }

    /// Probe all relays, sign a consensus, and install it everywhere.
    async fn converge(&self) {
        self.authority.refresh_now().await;
        let client = self.authorities("relay");
        for relay in &self.relays {
            client.refresh(&relay.trusted).await.unwrap();
        }
    }

    async fn start(specs: &[RelaySpec]) -> Testnet {
        // MASK_TEST_LOG=1 prints relay/host logs (debugging aid).
        if std::env::var_os("MASK_TEST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("mask_net=info")
                .with_test_writer()
                .try_init();
        }
        let block = NEXT_BLOCK.fetch_add(1, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let log: ConnLog = Arc::default();
        let seen: Seen = Arc::default();
        // Records everything; individual tests decide what was allowed.
        let policy = {
            let log = Arc::clone(&log);
            ConnectPolicy::new(move |origin, addr| {
                log.lock().unwrap().push((origin.to_owned(), addr));
                true
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

        // Relay identities first: the operator approves them.
        let keys: Vec<RelayKeys> = specs.iter().map(|_| RelayKeys::generate()).collect();
        let approved = ApprovedRelays {
            relays: specs
                .iter()
                .zip(&keys)
                .map(|(s, k)| ApprovedRelay {
                    nickname: s.nick.into(),
                    identity: k.node_id(),
                    role: s.role,
                })
                .collect(),
        };

        let auth_keys = AuthorityKeys::generate();
        let auth_listener_addr: SocketAddr =
            (std::net::IpAddr::from([127, 0, block as u8, 10]), 0).into();
        // Bind once to learn a free port, then pin that address.
        let probe = TcpListener::bind(auth_listener_addr).await.unwrap();
        let authority_addr = probe.local_addr().unwrap();
        drop(probe);
        let network = NetworkConfig {
            name: "testnet".into(),
            scope: NetworkScope::Private,
            authorities: vec![AuthorityInfo {
                name: "auth1".into(),
                address: authority_addr,
                identity: auth_keys.identity_public(),
                link_key: auth_keys.link_public(),
            }],
        };
        let mut config = AuthorityConfig::new("auth1", authority_addr, network.clone(), approved);
        config.timeouts = timeouts();
        config.policy = policy.clone();
        let authority = Authority::bind(config, auth_keys).await.unwrap();
        let handle = authority.handle();
        tokio::spawn(authority.serve());

        let mut relays = Vec::new();
        for (i, (spec, keys)) in specs.iter().zip(keys).enumerate() {
            let trusted = TrustedRelays::consensus(NetworkScope::Private);
            let listen = SocketAddr::from(([127, 0, block as u8, 11 + i as u8], 0));
            let mut config = RelayConfig::new(spec.nick, spec.role, listen);
            config.scope = NetworkScope::Private;
            config.family = spec.family.into();
            config.trusted = trusted.clone();
            config.timeouts = timeouts();
            config.policy = policy.clone();
            config.observer = Some(observer.clone());
            let relay = Relay::bind(config, keys).await.unwrap();
            let descriptor = relay.descriptor();
            let relay_handle = relay.handle();
            tokio::spawn(relay.serve());
            relays.push(TestRelay {
                descriptor,
                handle: relay_handle,
                trusted,
            });
        }
        let net = Testnet {
            _dir: dir,
            block,
            network,
            authority: handle,
            authority_addr,
            relays,
            policy,
            log,
            seen,
        };
        let client = net.authorities("relay");
        for relay in &net.relays {
            for (_, result) in client.publish_relay(&relay.descriptor).await {
                result.unwrap();
            }
        }
        net.converge().await;
        net
    }

    /// A hidden service using the consensus, publishing to the authority.
    async fn host(&self, intro_points: usize) -> (HiddenService, MorpAddress, SocketAddr) {
        let site = self._dir.path().join("site");
        fs::create_dir_all(&site).unwrap();
        fs::write(site.join("index.html"), format!("<h1>{SECRET}</h1>")).unwrap();
        let (app, _) = serve_site(Site::new(&site).unwrap(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let trusted = TrustedRelays::consensus(NetworkScope::Private);
        let authorities = self.authorities("service");
        authorities.refresh(&trusted).await.unwrap();
        let identity = ServiceKeys::generate();
        let address = *identity.address();
        let mut config = HostConfig::new(trusted, app);
        config.intro_points = intro_points;
        config.timeouts = timeouts();
        config.policy = self.policy.clone();
        let service = HiddenService::start(identity, config).await.unwrap();
        authorities
            .publish_service(&service.descriptor(now_secs(), 600, now_millis()))
            .await
            .unwrap();
        (service, address, app)
    }

    fn client(&self) -> MorpClient {
        let mut config = ClientConfig::new(TrustedRelays::consensus(NetworkScope::Private));
        config.timeouts = timeouts();
        config.policy = self.policy.clone();
        config.connect_timeout = Duration::from_secs(20);
        config.rendezvous_timeout = Duration::from_secs(6);
        MorpClient::new(self.authorities("client"), config)
    }
}

fn get() -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        path: "/".into(),
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

// ===================================================================== routing

#[tokio::test]
async fn morp_site_loads_across_simulated_machines_through_authenticated_circuits() {
    let net = Testnet::start(&SPECS).await;
    let (service, address, app) = net.host(2).await;
    let client = net.client();

    let (session, route) = client.connect(&address).await.unwrap();
    let page = session
        .request(get(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(page.status, 200);
    assert!(contains(&page.body, SECRET));

    // The client's rendezvous circuit used three different families.
    let family = |nick: &str| net.relay(nick).descriptor.family.clone();
    let families = [
        family(&route.entry),
        family(&route.middle),
        family(&route.rendezvous),
    ];
    assert!(families[0] != families[1] && families[1] != families[2] && families[0] != families[2]);

    // Separate circuits joined at the rendezvous point.
    let rendezvous = net.relay(&route.rendezvous);
    let stats = rendezvous.handle.stats();
    assert_eq!(stats.rendezvous_joins, 1);
    assert_eq!(stats.joined_circuits, 2);
    assert!(stats.stream_cells >= 2);
    assert_eq!(service.stats().sessions_started.load(Ordering::SeqCst), 1);

    // Connections: the client reached only entry relays and the authority;
    // the service only entries, the authority, and its own local app.
    let entries = net.entries();
    let log = net.log.lock().unwrap();
    let mut client_entries = 0;
    for (origin, addr) in log.iter() {
        match origin.as_str() {
            "client" => {
                assert!(
                    entries.contains(addr) || *addr == net.authority_addr,
                    "client connected to {addr}"
                );
                if entries.contains(addr) {
                    client_entries += 1;
                }
                assert_ne!(*addr, app, "client connected to the service's app");
            }
            "service" => assert!(
                entries.contains(addr) || *addr == net.authority_addr || *addr == app,
                "service connected to {addr}"
            ),
            "authority" => assert!(
                net.relays.iter().any(|r| r.descriptor.addr == *addr),
                "authority connected to {addr}"
            ),
            relay if relay.starts_with("relay:") => assert!(
                net.relays.iter().any(|r| r.descriptor.addr == *addr)
                    || *addr == net.authority_addr,
                "{relay} connected to {addr}"
            ),
            "relay" => assert_eq!(*addr, net.authority_addr),
            other => panic!("unexpected origin {other}"),
        }
    }
    assert!(client_entries >= 1);
    drop(log);

    // No relay ever decrypted the page or anything of the request/response.
    for (relay, bytes) in net.seen.lock().unwrap().iter() {
        assert!(!contains(bytes, SECRET), "{relay} saw the page content");
        assert!(!contains(bytes, "GET /"), "{relay} saw the request");
    }
}

#[tokio::test]
async fn client_without_a_consensus_reaches_nothing() {
    // An authority the client cannot reach: no consensus, no circuits, and
    // no attempt to contact any relay or the service directly.
    let net = Testnet::start(&SPECS).await;
    let (_service, address, _) = net.host(1).await;
    net.authority.shutdown();
    tokio::time::sleep(Duration::from_millis(300)).await;
    net.log.lock().unwrap().clear();
    let result = net.client().connect(&address).await;
    assert!(result.is_err());
    for (origin, addr) in net.log.lock().unwrap().iter() {
        if origin == "client" {
            assert_eq!(*addr, net.authority_addr, "client went to {addr}");
        }
    }
}

// =================================================================== admission

#[tokio::test]
async fn unapproved_relay_is_never_listed() {
    let net = Testnet::start(&SPECS[..1]).await;
    let mut config = RelayConfig::new(
        "intruder",
        Role::Middle,
        SocketAddr::from(([127, 0, net.block as u8, 50], 0)),
    );
    config.scope = NetworkScope::Private;
    config.trusted = TrustedRelays::consensus(NetworkScope::Private);
    let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
    let descriptor = relay.descriptor();
    tokio::spawn(relay.serve());

    let results = net.authorities("relay").publish_relay(&descriptor).await;
    assert!(matches!(results[0].1, Err(NetError::Untrusted(_))));
    net.authority.refresh_now().await;
    let consensus = net.authorities("client").fetch_consensus().await.unwrap();
    assert!(consensus.relays.iter().all(|d| d.nickname != "intruder"));
    assert_eq!(net.authority.stats().unapproved_uploads, 1);
}

#[tokio::test]
async fn relay_identity_change_is_refused() {
    let net = Testnet::start(&SPECS[..2]).await;
    // A new key claiming an approved nickname (and its role and address).
    let original = net.relay("entry1").descriptor.clone();
    let impostor = RelayDescriptor::sign_with_family(
        &RelayKeys::generate(),
        "entry1",
        Role::Entry,
        original.addr,
        "machine-a",
    );
    let results = net.authorities("relay").publish_relay(&impostor).await;
    match &results[0].1 {
        Err(NetError::Untrusted(why)) => assert!(why.contains("identity change refused"), "{why}"),
        other => panic!("expected refusal, got {other:?}"),
    }
    assert_eq!(net.authority.stats().identity_changes_refused, 1);
    net.authority.refresh_now().await;
    let consensus = net.authorities("client").fetch_consensus().await.unwrap();
    let listed: Vec<_> = consensus
        .relays
        .iter()
        .filter(|d| d.nickname == "entry1")
        .collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].node_id, original.node_id);
}

#[tokio::test]
async fn relay_with_a_wrong_role_or_out_of_scope_address_is_refused() {
    // An authority that approves one key, as an entry named "e1".
    let keys = RelayKeys::generate();
    let auth_keys = AuthorityKeys::generate();
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let reserve = TcpListener::bind(listen).await.unwrap();
    let addr = reserve.local_addr().unwrap();
    drop(reserve);
    let network = NetworkConfig {
        name: "testnet".into(),
        scope: NetworkScope::Private,
        authorities: vec![AuthorityInfo {
            name: "auth1".into(),
            address: addr,
            identity: auth_keys.identity_public(),
            link_key: auth_keys.link_public(),
        }],
    };
    let approved = ApprovedRelays {
        relays: vec![ApprovedRelay {
            nickname: "e1".into(),
            identity: keys.node_id(),
            role: Role::Entry,
        }],
    };
    let authority = Authority::bind(
        AuthorityConfig::new("auth1", addr, network.clone(), approved),
        auth_keys,
    )
    .await
    .unwrap();
    tokio::spawn(authority.serve());
    let client = AuthorityClient::new(network).with_timeouts(timeouts());

    let wrong_role =
        RelayDescriptor::sign(&keys, "e1", Role::Middle, "127.0.0.1:7102".parse().unwrap());
    let public = RelayDescriptor::sign(&keys, "e1", Role::Entry, "8.8.8.8:7101".parse().unwrap());
    let unspecified =
        RelayDescriptor::sign(&keys, "e1", Role::Entry, "0.0.0.0:7101".parse().unwrap());
    for d in [wrong_role, public, unspecified] {
        let results = client.publish_relay(&d).await;
        assert!(results[0].1.is_err(), "{d:?} must be refused");
    }
}

#[tokio::test]
async fn consensus_from_an_impostor_authority_is_rejected() {
    // Pin auth1's keys but point the address at a different authority.
    let net = Testnet::start(&SPECS[..1]).await;
    let rogue_keys = AuthorityKeys::generate();
    let rogue_addr = SocketAddr::from(([127, 0, net.block as u8, 99], 0));
    let rogue_network = NetworkConfig {
        authorities: vec![AuthorityInfo {
            name: "auth1".into(),
            address: rogue_addr,
            identity: rogue_keys.identity_public(),
            link_key: rogue_keys.link_public(),
        }],
        ..net.network.clone()
    };
    let rogue = Authority::bind(
        AuthorityConfig::new(
            "auth1",
            rogue_addr,
            rogue_network,
            ApprovedRelays::default(),
        ),
        rogue_keys,
    )
    .await
    .unwrap();
    let rogue_addr = rogue.local_addr();
    tokio::spawn(rogue.serve());

    let mut pinned = net.network.clone();
    pinned.authorities[0].address = rogue_addr;
    let client = AuthorityClient::new(pinned).with_timeouts(timeouts());
    let trusted = TrustedRelays::consensus(NetworkScope::Private);
    assert!(client.refresh(&trusted).await.is_err());
    assert!(trusted.snapshot().is_err(), "nothing must be trusted");
}

// ================================================ disconnected and malicious

#[tokio::test]
async fn stopped_relay_leaves_the_consensus_and_clients_route_around_it() {
    let net = Testnet::start(&SPECS).await;
    let (service, address, _) = net.host(2).await;
    // Stop one middle; two probes later it is gone from the consensus.
    let gone = net.relay("middle1");
    gone.handle.shutdown();
    tokio::time::sleep(Duration::from_millis(300)).await;
    net.authority.refresh_now().await;
    net.authority.refresh_now().await;
    let consensus = net.authorities("client").fetch_consensus().await.unwrap();
    assert!(consensus.relays.iter().all(|d| d.nickname != "middle1"));
    assert!(net.authority.stats().probes_failed >= 2);

    // Intro circuits through middle1 died with it. Like `mask-service host`,
    // replace them (the service's consensus still lists middle1, so this
    // also exercises circuit retries and relay health) and republish.
    if service.live_intro_points() < service.wanted_intro_points() {
        service.replenish().await.unwrap();
        net.authorities("service")
            .publish_service(&service.descriptor(now_secs(), 600, now_millis()))
            .await
            .unwrap();
    }
    assert_eq!(service.live_intro_points(), 2);

    for _ in 0..3 {
        let client = net.client();
        let (_session, route) = client.connect(&address).await.unwrap();
        assert_ne!(route.middle, "middle1");
    }
}

#[tokio::test]
async fn lost_introduction_point_is_re_established_elsewhere() {
    let net = Testnet::start(&SPECS).await;
    let (service, address, _) = net.host(1).await;
    let first = service.intro_points()[0].relay;
    let intro = net
        .relays
        .iter()
        .find(|r| r.descriptor.node_id == first)
        .unwrap();
    intro.handle.shutdown();
    tokio::time::timeout(Duration::from_secs(10), service.intro_point_lost())
        .await
        .expect("the service notices the lost intro circuit");
    assert_eq!(service.live_intro_points(), 0);

    // The relay is still in the client's consensus here, but the service
    // must pick the other rendezvous relay for its new intro point.
    assert_eq!(service.replenish().await.unwrap(), 1);
    let replacement = service.intro_points()[0].relay;
    assert_ne!(replacement, first);
    net.authorities("service")
        .publish_service(&service.descriptor(now_secs(), 600, now_millis()))
        .await
        .unwrap();

    let page = net.client().fetch(&address, get()).await.unwrap();
    assert!(contains(&page.body, SECRET));
}

/// A TCP proxy that can stop forwarding (the far machine "vanishes"
/// without closing TCP).
async fn freezable_proxy(
    target: SocketAddr,
    frozen: Arc<AtomicBool>,
    listen: SocketAddr,
) -> SocketAddr {
    let listener = TcpListener::bind(listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((inbound, _)) = listener.accept().await {
            let Ok(outbound) = TcpStream::connect(target).await else {
                continue;
            };
            let (in_r, in_w) = inbound.into_split();
            let (out_r, out_w) = outbound.into_split();
            for (mut from, mut to) in [
                (
                    Box::new(in_r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box::new(out_w) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                ),
                (Box::new(out_r), Box::new(in_w)),
            ] {
                let frozen = Arc::clone(&frozen);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        let Ok(n) = from.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        if frozen.load(Ordering::SeqCst) {
                            continue; // swallow everything, keep TCP open
                        }
                        if to.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    });
    addr
}

#[tokio::test]
async fn keepalives_detect_a_vanished_next_hop() {
    // entry → middle goes through a proxy that silently stops forwarding.
    let trusted = TrustedRelays::fixed(NetworkScope::Loopback);
    let quick = Timeouts {
        keepalive: Duration::from_millis(200),
        ..timeouts()
    };
    let start = |nick: &'static str, role: Role| {
        let trusted = trusted.clone();
        async move {
            let mut config = RelayConfig::new(nick, role, "127.0.0.1:0".parse().unwrap());
            config.trusted = trusted.clone();
            config.timeouts = quick;
            let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
            let d = relay.descriptor();
            let h = relay.handle();
            trusted.insert(d.clone());
            tokio::spawn(relay.serve());
            (d, h)
        }
    };
    let (entry, entry_handle) = start("entry", Role::Entry).await;
    let (exit, _) = start("exit", Role::Exit).await;
    // Middle published at the proxy's address.
    let frozen = Arc::new(AtomicBool::new(false));
    let mut config = RelayConfig::new("middle", Role::Middle, "127.0.0.1:0".parse().unwrap());
    config.trusted = trusted.clone();
    config.timeouts = quick;
    let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = reserve.local_addr().unwrap();
    drop(reserve);
    config.advertise = Some(proxy_addr);
    let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
    let middle = relay.descriptor();
    let middle_real = relay.local_addr();
    trusted.insert(middle.clone());
    tokio::spawn(relay.serve());
    freezable_proxy(middle_real, Arc::clone(&frozen), proxy_addr).await;

    let link = ClientLink::connect(&entry, timeouts()).await.unwrap();
    let path = CircuitPath::new(entry.clone(), middle.clone(), exit.clone()).unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    assert_eq!(circuit.send(b"before").await.unwrap(), b"before");

    frozen.store(true, Ordering::SeqCst);
    // No traffic, no FIN: only keepalives can notice. The entry destroys the
    // circuit and tells the client.
    let err = circuit
        .recv_msg(Duration::from_secs(5))
        .await
        .expect("entry reports the dead next hop");
    assert!(
        matches!(
            err,
            mask_net::protocol::LinkMsg::Destroy {
                reason: DestroyReason::NextHopFailed,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(entry_handle.stats().keepalive_failures, 1);
}

#[tokio::test]
async fn graceful_shutdown_destroys_circuits_and_tells_the_client() {
    let net = Testnet::start(&SPECS).await;
    let entry = net.relay("entry1").descriptor.clone();
    let middle = net.relay("middle1");
    let rv = net.relay("rv1").descriptor.clone();
    let link = ClientLink::connect_with(
        &entry,
        timeouts(),
        &net.policy.clone().with_scope(NetworkScope::Private),
        "client",
    )
    .await
    .unwrap();
    let path = CircuitPath::new(entry, middle.descriptor.clone(), rv).unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    assert_eq!(middle.handle.stats().open_circuits, 1);

    middle.handle.shutdown();
    let msg = circuit.recv_msg(Duration::from_secs(5)).await.unwrap();
    assert!(
        matches!(
            msg,
            mask_net::protocol::LinkMsg::Destroy {
                reason: DestroyReason::RelayShutdown,
                ..
            }
        ),
        "{msg:?}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(net.relay("entry1").handle.stats().open_circuits, 0);
    assert_eq!(net.relay("rv1").handle.stats().open_circuits, 0);
}

// ===================================================================== limits

#[tokio::test]
async fn link_limits_per_address_are_enforced() {
    let trusted = TrustedRelays::fixed(NetworkScope::Loopback);
    let mut config = RelayConfig::new("entry", Role::Entry, "127.0.0.1:0".parse().unwrap());
    config.trusted = trusted;
    config.timeouts = timeouts();
    config.limits.max_links_per_ip = 2;
    let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
    let entry = relay.descriptor();
    let handle = relay.handle();
    tokio::spawn(relay.serve());

    let first = ClientLink::connect(&entry, timeouts()).await.unwrap();
    let second = ClientLink::connect(&entry, timeouts()).await.unwrap();
    assert!(ClientLink::connect(&entry, timeouts()).await.is_err());
    assert_eq!(handle.stats().links_refused, 1);
    assert_eq!(handle.stats().open_links, 2);
    drop((first, second));
    // Closed links free their slots.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(ClientLink::connect(&entry, timeouts()).await.is_ok());
}

#[tokio::test]
async fn connections_from_outside_the_scope_are_refused() {
    // A relay in loopback scope that somehow receives a connection from a
    // non-loopback peer cannot be tested on one machine; instead check the
    // relay refuses to extend to, and the client refuses to dial, such peers.
    let lan_entry = RelayDescriptor::sign(
        &RelayKeys::generate(),
        "lan",
        Role::Entry,
        "192.168.77.1:7101".parse().unwrap(),
    );
    let err = ClientLink::connect(&lan_entry, timeouts())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, NetError::OutOfScope { .. }), "{err:?}");
    let public_entry = RelayDescriptor::sign(
        &RelayKeys::generate(),
        "pub",
        Role::Entry,
        "8.8.8.8:7101".parse().unwrap(),
    );
    let policy = ConnectPolicy::allow_all().with_scope(NetworkScope::Private);
    let err = ClientLink::connect_with(&public_entry, timeouts(), &policy, "client")
        .await
        .err()
        .unwrap();
    assert!(matches!(err, NetError::OutOfScope { .. }), "{err:?}");
}
