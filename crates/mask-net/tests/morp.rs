//! MORP end-to-end tests: real relays on 127.0.0.1 with OS-assigned ports.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use mask_net::NetError;
use mask_net::client::ClientLink;
use mask_net::crypto::keys::RelayKeys;
use mask_net::crypto::ntor::{ClientHandshake, server_respond};
use mask_net::crypto::onion::{CellCipher, Direction};
use mask_net::descriptor::{CircuitPath, RelayDescriptor};
use mask_net::identity::Role;
use mask_net::protocol::{
    DestroyReason, ErrorCode, LayerBody, LinkErrorCode, LinkMsg, MAX_DATA_LEN, MAX_FRAME_LEN,
    MORP_VERSION, RelayCmd, decode, encode,
};
use mask_net::relay::{Relay, RelayConfig};
use mask_net::transport::{Connection, Timeouts, handshake_outbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn fast() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_millis(800),
        response: Duration::from_secs(3),
        idle: Duration::from_secs(10),
    }
}

async fn start_relay_with(role: Role, keys: RelayKeys) -> RelayDescriptor {
    let mut config = RelayConfig::new(role.to_string(), role, "127.0.0.1:0".parse().unwrap());
    config.timeouts = fast();
    let relay = Relay::bind(config, keys).await.expect("relay binds");
    let descriptor = relay.descriptor();
    tokio::spawn(relay.serve());
    descriptor
}

async fn start_relay(role: Role) -> RelayDescriptor {
    start_relay_with(role, RelayKeys::generate()).await
}

async fn start_network() -> CircuitPath {
    CircuitPath::new(
        start_relay(Role::Entry).await,
        start_relay(Role::Middle).await,
        start_relay(Role::Exit).await,
    )
    .unwrap()
}

/// A loopback address with nothing listening.
async fn dead_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A validly signed descriptor for `role` that points at `addr`.
fn descriptor_at(role: Role, addr: SocketAddr) -> RelayDescriptor {
    RelayDescriptor::sign(&RelayKeys::generate(), "fake", role, addr)
}

fn with_exit(path: &CircuitPath, exit: RelayDescriptor) -> CircuitPath {
    CircuitPath {
        exit,
        ..path.clone()
    }
}

fn remote(err: NetError) -> (usize, ErrorCode) {
    match err {
        NetError::Remote { hop, code, .. } => (hop, code),
        other => panic!("expected a hop error, got {other:?}"),
    }
}

// =================================================================== routing

#[tokio::test]
async fn message_round_trips_through_three_encrypted_hops() {
    let path = start_network().await;
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    assert_eq!(circuit.hops().count(), 3);
    assert_eq!(circuit.send(b"hello MORP").await.unwrap(), b"hello MORP");
}

#[tokio::test]
async fn many_messages_on_one_circuit_keep_counters_in_step() {
    let path = start_network().await;
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    for i in 0..50 {
        let msg = format!("message {i}");
        assert_eq!(circuit.send(msg.as_bytes()).await.unwrap(), msg.as_bytes());
    }
}

#[tokio::test]
async fn several_circuits_share_one_link_concurrently() {
    let path = start_network().await;
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let link = link.clone();
            let path = path.clone();
            tokio::spawn(async move {
                let mut circuit = link.build_circuit(&path).await.unwrap();
                for j in 0..5 {
                    let msg = format!("circuit {i} message {j}");
                    assert_eq!(circuit.send(msg.as_bytes()).await.unwrap(), msg.as_bytes());
                }
                circuit.id()
            })
        })
        .collect();
    let mut ids = HashSet::new();
    for task in tasks {
        ids.insert(task.await.unwrap());
    }
    assert_eq!(ids.len(), 8, "every circuit has its own ID");
}

#[tokio::test]
async fn independent_clients_share_relay_links() {
    let path = start_network().await;
    let tasks: Vec<_> = (0..6)
        .map(|i| {
            let path = path.clone();
            tokio::spawn(async move {
                let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
                let mut circuit = link.build_circuit(&path).await.unwrap();
                let msg = format!("client {i}");
                assert_eq!(circuit.send(msg.as_bytes()).await.unwrap(), msg.as_bytes());
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn largest_allowed_message_fits_and_larger_is_refused() {
    let path = start_network().await;
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    let data = vec![0x5a; MAX_DATA_LEN];
    assert_eq!(circuit.send(&data).await.unwrap(), data);
    let too_big = vec![0; MAX_DATA_LEN + 1];
    assert!(matches!(
        circuit.send(&too_big).await,
        Err(NetError::InvalidConfig(_))
    ));
}

// ================================================================= layering

/// Simulates the three hops with the library's crypto, checking what each
/// relay can and cannot see.
#[test]
fn each_hop_opens_only_its_own_layer() {
    let relays: Vec<RelayKeys> = (0..3).map(|_| RelayKeys::generate()).collect();
    let mut client_fwd = Vec::new();
    let mut client_back = Vec::new();
    let mut relay_fwd = Vec::new();
    let mut relay_back = Vec::new();
    for relay in &relays {
        let (hs, request) = ClientHandshake::start(relay.node_id(), relay.onion_public());
        let (reply, relay_keys) = server_respond(relay, &request).unwrap();
        let keys = hs.finish(&reply).unwrap();
        client_fwd.push(CellCipher::new(&keys.forward, Direction::Forward));
        client_back.push(CellCipher::new(&keys.backward, Direction::Backward));
        relay_fwd.push(CellCipher::new(&relay_keys.forward, Direction::Forward));
        relay_back.push(CellCipher::new(&relay_keys.backward, Direction::Backward));
    }

    // Client seals DATA for the exit, then wraps for middle and entry.
    let secret = b"top secret payload".to_vec();
    let mut cell = client_fwd[2]
        .seal(&encode(&LayerBody::Cmd(RelayCmd::Data {
            bytes: secret.clone(),
        })))
        .unwrap();
    for hop in (0..2).rev() {
        cell = client_fwd[hop]
            .seal(&encode(&LayerBody::Relay(cell)))
            .unwrap();
    }
    let contains_secret = |bytes: &[u8]| bytes.windows(secret.len()).any(|w| w == secret);
    assert!(!contains_secret(&cell));

    // Middle and exit keys cannot open the outermost layer.
    assert!(
        CellCipher::new(&[0; 32], Direction::Forward)
            .open(&cell)
            .is_err()
    );

    // Entry peels one layer: learns only "relay onward", not the data.
    let LayerBody::Relay(for_middle) = decode(&relay_fwd[0].open(&cell).unwrap()).unwrap() else {
        panic!("entry should see an onward cell");
    };
    assert!(!contains_secret(&for_middle));

    // Middle peels one layer.
    let LayerBody::Relay(for_exit) = decode(&relay_fwd[1].open(&for_middle).unwrap()).unwrap()
    else {
        panic!("middle should see an onward cell");
    };
    assert!(!contains_secret(&for_exit));

    // Only the exit sees the command.
    let body: LayerBody = decode(&relay_fwd[2].open(&for_exit).unwrap()).unwrap();
    assert_eq!(
        body,
        LayerBody::Cmd(RelayCmd::Data {
            bytes: secret.clone()
        })
    );

    // Reply: exit seals, middle and entry each add a layer.
    let mut back = relay_back[2]
        .seal(&encode(&LayerBody::Cmd(RelayCmd::Data {
            bytes: b"reply".to_vec(),
        })))
        .unwrap();
    for hop in (0..2).rev() {
        back = relay_back[hop]
            .seal(&encode(&LayerBody::Relay(back)))
            .unwrap();
    }
    // Client peels entry, middle, exit in order.
    for (hop, cipher) in client_back.iter_mut().enumerate() {
        match decode::<LayerBody>(&cipher.open(&back).unwrap()).unwrap() {
            LayerBody::Relay(inner) => back = inner,
            LayerBody::Cmd(RelayCmd::Data { bytes }) => {
                assert_eq!(hop, 2);
                assert_eq!(bytes, b"reply");
                return;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    panic!("reply never reached its command layer");
}

// ======================================================= connection failures

#[tokio::test]
async fn entry_down_fails_to_connect() {
    let entry = descriptor_at(Role::Entry, dead_addr().await);
    let err = ClientLink::connect(&entry, fast()).await.err().unwrap();
    assert!(matches!(err, NetError::Io(_)), "{err:?}");
}

#[tokio::test]
async fn middle_down_is_reported_by_entry() {
    let path = start_network().await;
    let path = CircuitPath {
        middle: descriptor_at(Role::Middle, dead_addr().await),
        ..path
    };
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let err = link.build_circuit(&path).await.err().unwrap();
    assert_eq!(remote(err), (0, ErrorCode::NextHopUnreachable));
}

#[tokio::test]
async fn exit_down_is_reported_by_middle() {
    let path = start_network().await;
    let path = with_exit(&path, descriptor_at(Role::Exit, dead_addr().await));
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let err = link.build_circuit(&path).await.err().unwrap();
    assert_eq!(remote(err), (1, ErrorCode::NextHopUnreachable));
}

#[tokio::test]
async fn silent_next_hop_times_out() {
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            held.push(stream);
        }
    });
    let path = start_network().await;
    let path = with_exit(&path, descriptor_at(Role::Exit, silent_addr));
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let err = link.build_circuit(&path).await.err().unwrap();
    // The middle cannot complete the link handshake with the silent peer.
    let (hop, code) = remote(err);
    assert_eq!(hop, 1);
    assert!(
        matches!(code, ErrorCode::NextHopUnreachable | ErrorCode::Timeout),
        "{code:?}"
    );
}

#[tokio::test]
async fn failed_extend_leaves_the_partial_circuit_usable() {
    let path = start_network().await;
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut circuit = link.new_circuit();
    circuit.create(&path.entry).await.unwrap();
    let dead_middle = descriptor_at(Role::Middle, dead_addr().await);
    assert!(circuit.extend(&dead_middle).await.is_err());
    circuit.extend(&path.middle).await.unwrap();
    circuit.extend(&path.exit).await.unwrap();
    assert_eq!(circuit.send(b"recovered").await.unwrap(), b"recovered");
}

// ============================================================ authentication

#[tokio::test]
async fn stale_onion_key_after_restart_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let old_keys = RelayKeys::load_or_create(dir.path()).unwrap();
    let new_keys = RelayKeys::load_or_create(dir.path()).unwrap();
    assert_eq!(old_keys.node_id(), new_keys.node_id());

    let path = start_network().await;
    let live_exit = start_relay_with(Role::Exit, new_keys).await;
    let stale = RelayDescriptor::sign(&old_keys, "exit", Role::Exit, live_exit.addr);

    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let err = link
        .build_circuit(&with_exit(&path, stale))
        .await
        .err()
        .unwrap();
    assert_eq!(remote(err), (1, ErrorCode::ExtendRejected));
}

#[tokio::test]
async fn impostor_at_entry_address_is_refused() {
    let path = start_network().await;
    // A descriptor with someone else's identity at the real entry's address.
    let impostor = RelayDescriptor::sign(
        &RelayKeys::generate(),
        "entry",
        Role::Entry,
        path.entry.addr,
    );
    let link = ClientLink::connect(&impostor, fast()).await.unwrap();
    let mut circuit = link.new_circuit();
    let err = circuit.create(&impostor).await.err().unwrap();
    assert!(
        matches!(err, NetError::Destroyed(DestroyReason::WrongRelay)),
        "{err:?}"
    );
}

#[tokio::test]
async fn client_cannot_link_directly_to_middle_or_exit() {
    let path = start_network().await;
    for relay in [&path.middle, &path.exit] {
        let err = ClientLink::connect(relay, fast()).await.err().unwrap();
        assert!(
            matches!(
                err,
                NetError::LinkRejected {
                    code: LinkErrorCode::RoleNotAllowed,
                    ..
                }
            ),
            "{err:?}"
        );
    }
}

// ======================================================= replay and tampering

/// A one-hop circuit to the entry, plus a DATA cell sealed for it.
async fn one_hop(path: &CircuitPath) -> (ClientLink, mask_net::client::Circuit) {
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut circuit = link.new_circuit();
    circuit.create(&path.entry).await.unwrap();
    (link, circuit)
}

#[tokio::test]
async fn replayed_cell_destroys_the_circuit() {
    let path = start_network().await;
    let (link, mut circuit) = one_hop(&path).await;
    let cell = circuit
        .seal_for(
            0,
            RelayCmd::Data {
                bytes: b"x".to_vec(),
            },
        )
        .unwrap();
    let msg = LinkMsg::Relay {
        circ: circuit.id(),
        cell,
    };

    link.link().send(msg.clone()).await.unwrap();
    // First copy is accepted (the entry answers NotAllowed: it is not an exit).
    assert!(matches!(
        circuit.recv_msg(Duration::from_secs(2)).await.unwrap(),
        LinkMsg::Relay { .. }
    ));

    link.link().send(msg).await.unwrap();
    assert_eq!(
        circuit.recv_msg(Duration::from_secs(2)).await.unwrap(),
        LinkMsg::Destroy {
            circ: circuit.id(),
            reason: DestroyReason::AuthenticationFailed
        }
    );
}

#[tokio::test]
async fn tampered_cell_destroys_the_circuit() {
    let path = start_network().await;
    let (link, mut circuit) = one_hop(&path).await;
    let mut cell = circuit
        .seal_for(
            0,
            RelayCmd::Data {
                bytes: b"x".to_vec(),
            },
        )
        .unwrap();
    cell[3] ^= 0x01;
    link.link()
        .send(LinkMsg::Relay {
            circ: circuit.id(),
            cell,
        })
        .await
        .unwrap();
    assert_eq!(
        circuit.recv_msg(Duration::from_secs(2)).await.unwrap(),
        LinkMsg::Destroy {
            circ: circuit.id(),
            reason: DestroyReason::AuthenticationFailed
        }
    );
}

#[tokio::test]
async fn cell_for_unknown_circuit_is_refused() {
    let path = start_network().await;
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut never_created = link.new_circuit();
    link.link()
        .send(LinkMsg::Relay {
            circ: never_created.id(),
            cell: vec![0; 40],
        })
        .await
        .unwrap();
    assert!(matches!(
        never_created
            .recv_msg(Duration::from_secs(2))
            .await
            .unwrap(),
        LinkMsg::Destroy {
            reason: DestroyReason::ProtocolViolation,
            ..
        }
    ));
}

// ==================================================== hop rules and limits

#[tokio::test]
async fn data_is_refused_before_the_exit() {
    let path = start_network().await;
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut circuit = link.new_circuit();
    circuit.create(&path.entry).await.unwrap();
    circuit.extend(&path.middle).await.unwrap();
    let err = circuit.send(b"x").await.err().unwrap();
    assert_eq!(remote(err), (1, ErrorCode::NotAllowed));
}

#[tokio::test]
async fn exit_refuses_to_extend() {
    let path = start_network().await;
    let link = ClientLink::connect(&path.entry, fast()).await.unwrap();
    let mut circuit = link.build_circuit(&path).await.unwrap();
    let another = start_relay(Role::Exit).await;
    let err = circuit.extend(&another).await.err().unwrap();
    assert_eq!(remote(err), (2, ErrorCode::NotAllowed));
}

#[tokio::test]
async fn extend_to_non_loopback_is_refused() {
    let path = start_network().await;
    let (_link, mut circuit) = one_hop(&path).await;
    let outside = descriptor_at(Role::Middle, "192.0.2.1:7102".parse().unwrap());
    let err = circuit.extend(&outside).await.err().unwrap();
    assert_eq!(remote(err), (0, ErrorCode::ExtendRejected));
}

#[tokio::test]
async fn relay_refuses_non_loopback_listen_and_client_role() {
    let outside = RelayConfig::new("x", Role::Entry, "0.0.0.0:0".parse().unwrap());
    assert!(matches!(
        Relay::bind(outside, RelayKeys::generate()).await,
        Err(NetError::NotLoopback(_))
    ));
    let client = RelayConfig::new("x", Role::Client, "127.0.0.1:0".parse().unwrap());
    assert!(matches!(
        Relay::bind(client, RelayKeys::generate()).await,
        Err(NetError::InvalidConfig(_))
    ));
}

#[tokio::test]
async fn circuit_limit_per_link_is_enforced() {
    let mut config = RelayConfig::new("entry", Role::Entry, "127.0.0.1:0".parse().unwrap());
    config.timeouts = fast();
    config.limits.circuits_per_link = 2;
    let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
    let entry = relay.descriptor();
    tokio::spawn(relay.serve());

    let link = ClientLink::connect(&entry, fast()).await.unwrap();
    let mut kept = Vec::new();
    for _ in 0..2 {
        let mut c = link.new_circuit();
        c.create(&entry).await.unwrap();
        kept.push(c);
    }
    let mut third = link.new_circuit();
    assert!(matches!(
        third.create(&entry).await,
        Err(NetError::Destroyed(DestroyReason::ResourceLimit))
    ));
}

// ========================================================= malformed input

#[tokio::test]
async fn wrong_protocol_version_is_rejected() {
    let path = start_network().await;
    let mut conn = Connection::connect(path.entry.addr, Duration::from_secs(2))
        .await
        .unwrap();
    conn.send(&LinkMsg::Hello {
        version: MORP_VERSION + 1,
        role: Role::Client,
    })
    .await
    .unwrap();
    assert!(matches!(
        conn.recv(Duration::from_secs(2)).await.unwrap(),
        Some(LinkMsg::LinkError {
            code: LinkErrorCode::VersionMismatch,
            ..
        })
    ));
}

#[tokio::test]
async fn garbage_frame_gets_link_error_and_disconnect() {
    let path = start_network().await;
    let mut conn = Connection::connect(path.entry.addr, Duration::from_secs(2))
        .await
        .unwrap();
    handshake_outbound(&mut conn, Role::Client, Role::Entry, Duration::from_secs(2))
        .await
        .unwrap();
    drop(conn);

    let mut stream = TcpStream::connect(path.entry.addr).await.unwrap();
    stream.write_all(&4u32.to_be_bytes()).await.unwrap();
    stream.write_all(&[0xff; 4]).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
        .await
        .expect("relay should close the connection")
        .unwrap();
    let error: LinkMsg = decode(&buf[4..]).unwrap();
    assert!(matches!(
        error,
        LinkMsg::LinkError {
            code: LinkErrorCode::Malformed,
            ..
        }
    ));
}

#[tokio::test]
async fn oversized_frame_closes_the_link() {
    let path = start_network().await;
    let mut stream = TcpStream::connect(path.entry.addr).await.unwrap();
    stream
        .write_all(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("relay should close the connection");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

#[tokio::test]
async fn create_before_handshake_is_rejected() {
    let path = start_network().await;
    let mut conn = Connection::connect(path.entry.addr, Duration::from_secs(2))
        .await
        .unwrap();
    let (_, request) = ClientHandshake::start(path.entry.node_id, path.entry.onion_key);
    conn.send(&LinkMsg::Create { circ: 1, request })
        .await
        .unwrap();
    assert!(matches!(
        conn.recv(Duration::from_secs(2)).await.unwrap(),
        Some(LinkMsg::LinkError {
            code: LinkErrorCode::BadHandshake,
            ..
        })
    ));
}
