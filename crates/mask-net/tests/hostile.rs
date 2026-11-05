//! v0.7 hardening: scripted hostile relays and protocol abuse.
//!
//! The hostile relays here speak real MORP (Noise links, ntor handshakes,
//! per-hop AEAD layers) and then misbehave in one specific way. Each test
//! checks that the honest side fails closed: the circuit is destroyed (and
//! the right `Destroy` reason reaches the other side), nothing hangs, and
//! other circuits keep working.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use mask_net::NetError;
use mask_net::client::ClientLink;
use mask_net::crypto::keys::RelayKeys;
use mask_net::crypto::ntor::server_respond;
use mask_net::crypto::onion::{CellCipher, Direction};
use mask_net::descriptor::{CircuitPath, RelayDescriptor};
use mask_net::hs::crypto::IntroKeys;
use mask_net::identity::Role;
use mask_net::limits::Rate;
use mask_net::protocol::{DestroyReason, ErrorCode, LayerBody, LinkMsg, RelayCmd, decode, encode};
use mask_net::relay::{Limits, Relay, RelayConfig, RelayHandle};
use mask_net::scope::NetworkScope;
use mask_net::transport::{Connection, Timeouts, handshake_inbound};
use mask_net::trust::TrustedRelays;
use tokio::net::TcpListener;

fn fast() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_millis(1500),
        response: Duration::from_secs(6),
        idle: Duration::from_secs(10),
        keepalive: Duration::from_secs(5),
    }
}

static TRUSTED: LazyLock<TrustedRelays> =
    LazyLock::new(|| TrustedRelays::fixed(NetworkScope::Loopback));

async fn start_relay_limited(role: Role, limits: Limits) -> (RelayDescriptor, RelayHandle) {
    let mut config = RelayConfig::new(role.to_string(), role, "127.0.0.1:0".parse().unwrap());
    config.timeouts = fast();
    config.trusted = TRUSTED.clone();
    config.limits = limits;
    let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
    let descriptor = relay.descriptor();
    let handle = relay.handle();
    TRUSTED.insert(descriptor.clone());
    tokio::spawn(relay.serve());
    (descriptor, handle)
}

async fn start_relay(role: Role) -> (RelayDescriptor, RelayHandle) {
    start_relay_limited(role, Limits::default()).await
}

const HOSTILE_TEXT: &str = "\x1b[2J\x1b]0;owned\x07relay says hi\nINFO forged log line\u{202e}";

/// How the fake entry misbehaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    /// Right after CREATED, send a backward cell that is not encrypted.
    GarbageBackwardCell,
    /// Answer a command meant for hop 2 with DATA from hop 1.
    DataFromIntermediateHop,
    /// Answer DATA with an error whose text contains escape sequences.
    HostileErrorText,
}

struct FakeEntry {
    descriptor: RelayDescriptor,
    /// A second hop the fake also plays (it holds both hops' keys).
    hop2: RelayDescriptor,
    /// Link messages the fake received besides CREATE and cells.
    received: Arc<Mutex<Vec<LinkMsg>>>,
}

/// A hostile entry relay for one client link.
async fn fake_entry(script: Script) -> FakeEntry {
    let keys = RelayKeys::generate();
    let keys2 = RelayKeys::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let descriptor = RelayDescriptor::sign(&keys, "fake-entry", Role::Entry, addr);
    let unused: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let hop2 = RelayDescriptor::sign(&keys2, "fake-hop2", Role::Middle, unused);
    let received: Arc<Mutex<Vec<LinkMsg>>> = Arc::default();
    let log = Arc::clone(&received);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn =
            Connection::accept(stream, keys.link_secret(), fast().handshake, |_, _| Ok(()))
                .await
                .unwrap()
                .conn;
        handshake_inbound(&mut conn, Role::Entry, None, fast().handshake)
            .await
            .unwrap();
        // Relay side of hop 1: open forward cells, seal backward cells.
        let mut hop1: Option<(CellCipher, CellCipher)> = None;
        while let Ok(Some(msg)) = conn.recv(Duration::from_secs(10)).await {
            match msg {
                LinkMsg::Create { circ, request } => {
                    let (reply, k) = server_respond(&keys, &request).unwrap();
                    hop1 = Some((
                        CellCipher::new(&k.forward, Direction::Forward),
                        CellCipher::new(&k.backward, Direction::Backward),
                    ));
                    conn.send(&LinkMsg::Created { circ, reply }).await.unwrap();
                    if script == Script::GarbageBackwardCell {
                        let cell = vec![0x42; 80];
                        conn.send(&LinkMsg::Relay { circ, cell }).await.unwrap();
                    }
                }
                LinkMsg::Relay { circ, cell } => {
                    let (forward, backward) = hop1.as_mut().unwrap();
                    let body: LayerBody = decode(&forward.open(&cell).unwrap()).unwrap();
                    let answer = match body {
                        LayerBody::Cmd(RelayCmd::Extend { request, .. }) => {
                            let (reply, _) = server_respond(&keys2, &request).unwrap();
                            RelayCmd::Extended { reply }
                        }
                        LayerBody::Relay(_) if script == Script::DataFromIntermediateHop => {
                            RelayCmd::Data {
                                bytes: b"injected by hop 1".to_vec(),
                            }
                        }
                        LayerBody::Cmd(RelayCmd::Data { .. })
                            if script == Script::HostileErrorText =>
                        {
                            RelayCmd::Error {
                                code: ErrorCode::NotAllowed,
                                detail: HOSTILE_TEXT.into(),
                            }
                        }
                        _ => continue,
                    };
                    let cell = backward.seal(&encode(&LayerBody::Cmd(answer))).unwrap();
                    conn.send(&LinkMsg::Relay { circ, cell }).await.unwrap();
                }
                other => log.lock().unwrap().push(other),
            }
        }
    });
    FakeEntry {
        descriptor,
        hop2,
        received,
    }
}

/// Wait until `check` holds (polling), or panic after `limit`.
async fn eventually(limit: Duration, what: &str, check: impl Fn() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(start.elapsed() < limit, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn destroyed_with(received: &Mutex<Vec<LinkMsg>>, reason: DestroyReason) -> bool {
    received
        .lock()
        .unwrap()
        .iter()
        .any(|m| matches!(m, LinkMsg::Destroy { reason: r, .. } if *r == reason))
}

// ======================================================= client hardening

#[tokio::test]
async fn garbage_backward_cell_destroys_the_client_circuit() {
    let fake = fake_entry(Script::GarbageBackwardCell).await;
    let link = ClientLink::connect(&fake.descriptor, fast()).await.unwrap();
    let mut circuit = link.new_circuit();
    circuit.create(&fake.descriptor).await.unwrap();

    let first = circuit.send(b"hello").await.unwrap_err();
    assert!(matches!(first, NetError::Crypto(_)), "{first:?}");
    // Regression (v0.7): the circuit used to stay usable after this.
    assert!(circuit.is_dead());
    let again = circuit.send(b"hello").await.unwrap_err();
    assert!(
        matches!(
            again,
            NetError::Destroyed(DestroyReason::AuthenticationFailed)
        ),
        "{again:?}"
    );
    // The relay was told why.
    eventually(Duration::from_secs(2), "Destroy at the relay", || {
        destroyed_with(&fake.received, DestroyReason::AuthenticationFailed)
    })
    .await;
}

#[tokio::test]
async fn intermediate_hop_cannot_answer_for_the_last_hop() {
    let fake = fake_entry(Script::DataFromIntermediateHop).await;
    let link = ClientLink::connect(&fake.descriptor, fast()).await.unwrap();
    let mut circuit = link.new_circuit();
    circuit.create(&fake.descriptor).await.unwrap();
    circuit.extend(&fake.hop2).await.unwrap();

    let err = circuit
        .request(
            RelayCmd::Data {
                bytes: b"for hop 2".to_vec(),
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::Protocol(_)), "{err:?}");
    assert!(circuit.is_dead(), "a forged answer must end the circuit");
    eventually(Duration::from_secs(2), "Destroy at the relay", || {
        destroyed_with(&fake.received, DestroyReason::ProtocolViolation)
    })
    .await;
}

#[tokio::test]
async fn hostile_error_text_is_made_safe_to_print() {
    let fake = fake_entry(Script::HostileErrorText).await;
    let link = ClientLink::connect(&fake.descriptor, fast()).await.unwrap();
    let mut circuit = link.new_circuit();
    circuit.create(&fake.descriptor).await.unwrap();
    let err = circuit.send(b"x").await.unwrap_err();
    let NetError::Remote { detail, .. } = &err else {
        panic!("expected a remote error, got {err:?}");
    };
    let shown = err.to_string();
    for text in [detail.as_str(), shown.as_str()] {
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert!(!text.contains('\u{202e}'), "{text:?}");
    }
    assert!(detail.contains("relay says hi"));
    // An error report is not a protocol violation: the circuit survives.
    assert!(!circuit.is_dead());
}

// ======================================================== relay hardening

#[tokio::test]
async fn next_hop_sending_cells_before_created_is_a_protocol_violation() {
    let (entry, entry_handle) = start_relay(Role::Entry).await;

    // A trusted "middle" that answers CREATE with a cell instead of CREATED.
    let keys = RelayKeys::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let middle = RelayDescriptor::sign(
        &keys,
        "hostile-middle",
        Role::Middle,
        listener.local_addr().unwrap(),
    );
    TRUSTED.insert(middle.clone());
    let received: Arc<Mutex<Vec<LinkMsg>>> = Arc::default();
    let log = Arc::clone(&received);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn =
            Connection::accept(stream, keys.link_secret(), fast().handshake, |_, _| Ok(()))
                .await
                .unwrap()
                .conn;
        handshake_inbound(&mut conn, Role::Middle, Some(Role::Entry), fast().handshake)
            .await
            .unwrap();
        while let Ok(Some(msg)) = conn.recv(Duration::from_secs(10)).await {
            match msg {
                LinkMsg::Create { circ, .. } => {
                    let cell = vec![7; 48];
                    conn.send(&LinkMsg::Relay { circ, cell }).await.unwrap();
                }
                other => log.lock().unwrap().push(other),
            }
        }
    });

    let link = ClientLink::connect(&entry, fast()).await.unwrap();
    let mut circuit = link.new_circuit();
    circuit.create(&entry).await.unwrap();
    let started = Instant::now();
    let err = circuit.extend(&middle).await.unwrap_err();
    // Regression (v0.7): the cell used to be dropped silently and the
    // client waited for the extend timeout instead.
    assert!(
        matches!(err, NetError::Destroyed(DestroyReason::ProtocolViolation)),
        "{err:?}"
    );
    assert!(started.elapsed() < fast().handshake, "failed fast");
    assert!(entry_handle.stats().protocol_violations >= 1);
    eventually(
        Duration::from_secs(2),
        "Destroy at the hostile middle",
        || destroyed_with(&received, DestroyReason::ProtocolViolation),
    )
    .await;
}

#[tokio::test]
async fn a_flooded_circuit_cannot_stall_the_other_circuits_on_its_link() {
    let path = CircuitPath::new(
        start_relay(Role::Entry).await.0,
        start_relay(Role::Middle).await.0,
        start_relay(Role::Exit).await.0,
    )
    .unwrap();
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut flooded = link.build_circuit(&path).await.unwrap();
    let mut healthy = link.build_circuit(&path).await.unwrap();

    // 150 echo requests whose replies nobody reads: far more than one
    // circuit's receive queue holds.
    for i in 0..150u32 {
        flooded
            .send_to_last(RelayCmd::Data {
                bytes: i.to_le_bytes().to_vec(),
            })
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Regression (v0.7): the link reader used to wait forever for the
    // flooded circuit, so this request never got its reply.
    let started = Instant::now();
    assert_eq!(healthy.send(b"still here").await.unwrap(), b"still here");
    assert!(started.elapsed() < Duration::from_secs(5));

    // The flooded circuit was given up on, and says so once drained.
    let mut drained = 0;
    loop {
        match flooded.recv_from_last(Some(Duration::from_secs(3))).await {
            Ok(RelayCmd::Data { .. }) => drained += 1,
            Err(NetError::ConnectionClosed | NetError::Destroyed(_)) => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(drained < 150, "only the queued replies were delivered");
}

#[tokio::test]
async fn circuit_creation_is_rate_limited_per_client_address() {
    let limits = Limits {
        create_rate_per_ip: Rate::new(0.001, 3),
        ..Limits::default()
    };
    let (entry, handle) = start_relay_limited(Role::Entry, limits).await;
    let link = ClientLink::connect(&entry, fast()).await.unwrap();
    let mut circuits = Vec::new();
    for _ in 0..3 {
        let mut c = link.new_circuit();
        c.create(&entry).await.unwrap();
        circuits.push(c);
    }
    // The limit is per address, not per link: a new link does not reset it.
    let other_link = ClientLink::connect(&entry, fast()).await.unwrap();
    let mut fourth = other_link.new_circuit();
    let err = fourth.create(&entry).await.unwrap_err();
    assert!(
        matches!(err, NetError::Destroyed(DestroyReason::ResourceLimit)),
        "{err:?}"
    );
    assert_eq!(handle.stats().creates_rate_limited, 1);
}

#[tokio::test]
async fn relay_to_relay_creates_are_not_limited_per_address() {
    // A middle with a tiny CREATE budget still carries every client's
    // circuits: its CREATEs arrive on a relay link, not a client link.
    let limits = Limits {
        create_rate_per_ip: Rate::new(0.001, 1),
        ..Limits::default()
    };
    let path = CircuitPath::new(
        start_relay(Role::Entry).await.0,
        start_relay_limited(Role::Middle, limits).await.0,
        start_relay(Role::Exit).await.0,
    )
    .unwrap();
    for _ in 0..4 {
        let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
        let mut circuit = link.build_circuit(&path).await.unwrap();
        assert_eq!(circuit.send(b"ok").await.unwrap(), b"ok");
    }
}

#[tokio::test]
async fn introductions_are_rate_limited_per_introduction_point() {
    let limits = Limits {
        intro_rate: Rate::new(0.001, 2),
        ..Limits::default()
    };
    let (entry, _) = start_relay(Role::Entry).await;
    let (middle, _) = start_relay(Role::Middle).await;
    let (rv, rv_handle) = start_relay_limited(Role::Rendezvous, limits).await;
    let path = CircuitPath::new(entry.clone(), middle, rv.clone()).unwrap();

    // "Service": register an intro point at rv.
    let service_link = ClientLink::connect(&entry, fast()).await.unwrap();
    let mut intro_circuit = service_link.build_circuit(&path).await.unwrap();
    let keys = IntroKeys::generate();
    let reply = intro_circuit
        .request(
            RelayCmd::EstablishIntro {
                auth_key: keys.auth_public(),
                signature: keys.establish_signature(&rv.node_id),
            },
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert_eq!(reply, RelayCmd::IntroEstablished);

    // "Client": three introductions in a row.
    let client_link = ClientLink::connect(&entry, fast()).await.unwrap();
    let mut client = client_link.build_circuit(&path).await.unwrap();
    let introduce = || RelayCmd::Introduce1 {
        auth_key: keys.auth_public(),
        payload: vec![1; 64],
    };
    for _ in 0..2 {
        let ack = client
            .request(introduce(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(ack, RelayCmd::IntroduceAck);
    }
    let err = client
        .request(introduce(), Duration::from_secs(3))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            NetError::Remote {
                code: ErrorCode::ResourceLimit,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(rv_handle.stats().introductions_rate_limited, 1);
    assert_eq!(rv_handle.stats().introductions, 2);
}

#[tokio::test]
async fn authority_limits_connections_per_address() {
    use mask_net::authority::AuthorityKeys;
    use mask_net::authority::client::AuthorityClient;
    use mask_net::authority::server::{Authority, AuthorityConfig};
    use mask_net::config::{ApprovedRelays, AuthorityInfo, NetworkConfig};
    use tokio::io::AsyncReadExt;

    let keys = AuthorityKeys::generate();
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let network = NetworkConfig {
        name: "limits".into(),
        scope: NetworkScope::Loopback,
        authorities: vec![AuthorityInfo {
            name: "auth1".into(),
            address: addr,
            identity: keys.identity_public(),
            link_key: keys.link_public(),
        }],
    };
    let mut config =
        AuthorityConfig::new("auth1", addr, network.clone(), ApprovedRelays::default());
    config.max_connections_per_ip = 2;
    config.timeouts = fast();
    let authority = Authority::bind(config, keys).await.unwrap();
    tokio::spawn(authority.serve());

    // Two silent connections take this address's slots...
    let mut hogs = Vec::new();
    for _ in 0..2 {
        hogs.push(tokio::net::TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // ...so a third is closed at once, without a Noise answer.
    let mut third = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(1), third.read(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");

    // Freeing a slot lets a real request through.
    drop(hogs.pop());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = AuthorityClient::new(network).with_timeouts(fast());
    client.fetch_consensus().await.unwrap();
}
