//! End-to-end tests: real relays on 127.0.0.1 with OS-assigned ports.

use std::net::SocketAddr;
use std::time::Duration;

use mask_net::NetError;
use mask_net::client::{Circuit, Route, build_onion, send_test_message};
use mask_net::identity::{NodeId, Role};
use mask_net::protocol::{ErrorCode, MAX_FRAME_LEN, Message, OnionLayer, PROTOCOL_VERSION};
use mask_net::relay::{Relay, RelayConfig};
use mask_net::transport::{Connection, Timeouts, handshake_outbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn fast_timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        response: Duration::from_millis(500),
        idle: Duration::from_secs(5),
    }
}

async fn start_relay(role: Role) -> SocketAddr {
    let mut config = RelayConfig::new(role.to_string(), role, "127.0.0.1:0".parse().unwrap());
    config.timeouts = fast_timeouts();
    let relay = Relay::bind(config).await.expect("relay binds");
    let addr = relay.local_addr();
    tokio::spawn(relay.serve());
    addr
}

async fn start_network() -> Route {
    Route {
        entry: start_relay(Role::Entry).await,
        middle: start_relay(Role::Middle).await,
        exit: start_relay(Role::Exit).await,
    }
}

/// An address on 127.0.0.1 with nothing listening.
async fn dead_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
    // listener dropped here: the port is closed.
}

fn remote_code(err: NetError) -> ErrorCode {
    match err {
        NetError::Remote { code, .. } => code,
        other => panic!("expected a relay error, got {other:?}"),
    }
}

/// Client connection to `entry` with the handshake done.
async fn client_link(entry: SocketAddr) -> Connection {
    let mut conn = Connection::connect(entry, Duration::from_secs(2))
        .await
        .unwrap();
    handshake_outbound(
        &mut conn,
        Role::Client,
        NodeId::random(),
        Role::Entry,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    conn
}

// ---------------------------------------------------------------- routing

#[tokio::test]
async fn message_travels_through_all_three_relays() {
    let route = start_network().await;
    let reply = send_test_message(route, b"hello MASK", fast_timeouts())
        .await
        .unwrap();
    assert_eq!(reply, b"hello MASK");
}

#[tokio::test]
async fn several_messages_reuse_one_circuit() {
    let route = start_network().await;
    let mut circuit = Circuit::open(route, fast_timeouts()).await.unwrap();
    for i in 0..5 {
        let msg = format!("message {i}");
        assert_eq!(circuit.send(msg.as_bytes()).await.unwrap(), msg.as_bytes());
    }
}

#[tokio::test]
async fn concurrent_clients_are_routed_independently() {
    let route = start_network().await;
    let tasks: Vec<_> = (0..10)
        .map(|i| {
            tokio::spawn(async move {
                let msg = format!("client {i}");
                let reply = send_test_message(route, msg.as_bytes(), fast_timeouts())
                    .await
                    .unwrap();
                assert_eq!(reply, msg.as_bytes());
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn largest_allowed_message_gets_through() {
    let route = start_network().await;
    // Leave room for three layers of headers inside one frame.
    let data = vec![0x5a; MAX_FRAME_LEN - 256];
    let reply = send_test_message(route, &data, fast_timeouts())
        .await
        .unwrap();
    assert_eq!(reply, data);
}

// ------------------------------------------------------- connection failures

#[tokio::test]
async fn entry_down_fails_to_connect() {
    let mut route = start_network().await;
    route.entry = dead_addr().await;
    let err = send_test_message(route, b"x", fast_timeouts())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::Io(_)), "{err:?}");
}

#[tokio::test]
async fn middle_down_is_reported_by_entry() {
    let mut route = start_network().await;
    route.middle = dead_addr().await;
    let err = send_test_message(route, b"x", fast_timeouts())
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::NextHopUnreachable);
}

#[tokio::test]
async fn exit_down_is_reported_back_through_middle_and_entry() {
    let mut route = start_network().await;
    route.exit = dead_addr().await;
    let err = send_test_message(route, b"x", fast_timeouts())
        .await
        .unwrap_err();
    let NetError::Remote { code, detail } = err else {
        panic!("expected relay error");
    };
    assert_eq!(code, ErrorCode::NextHopUnreachable);
    assert!(detail.starts_with("middle (middle)"), "{detail}");
}

#[tokio::test]
async fn silent_next_hop_times_out() {
    // Accepts TCP connections but never answers the handshake.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            held.push(stream);
        }
    });

    let mut route = start_network().await;
    route.exit = silent_addr;
    let err = send_test_message(route, b"x", fast_timeouts())
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::Timeout);
}

#[tokio::test]
async fn circuit_recovers_after_next_hop_failure() {
    let good = start_network().await;
    let broken = Route {
        exit: dead_addr().await,
        ..good
    };
    let mut conn = client_link(good.entry).await;

    // First message: the exit is down, so an error comes back...
    let payload = build_onion(&broken, b"first").unwrap();
    conn.send(&Message::Relay { payload }).await.unwrap();
    let reply = conn.recv(Duration::from_secs(2)).await.unwrap();
    assert!(matches!(reply, Some(Message::Error { .. })), "{reply:?}");

    // ...but the same client connection still works with a good route.
    let payload = build_onion(&good, b"second").unwrap();
    conn.send(&Message::Relay { payload }).await.unwrap();
    let reply = conn.recv(Duration::from_secs(2)).await.unwrap();
    assert_eq!(
        reply,
        Some(Message::RelayResponse {
            payload: b"second".to_vec()
        })
    );
}

// ------------------------------------------------------- role enforcement

#[tokio::test]
async fn relays_in_wrong_order_are_rejected() {
    let route = start_network().await;
    let swapped = Route {
        entry: route.entry,
        middle: route.exit,
        exit: route.middle,
    };
    let err = send_test_message(swapped, b"x", fast_timeouts())
        .await
        .unwrap_err();
    assert_eq!(remote_code(err), ErrorCode::NextHopRejected);
}

#[tokio::test]
async fn client_cannot_connect_directly_to_middle_or_exit() {
    let route = start_network().await;
    for addr in [route.middle, route.exit] {
        let mut conn = Connection::connect(addr, Duration::from_secs(2))
            .await
            .unwrap();
        let err = handshake_outbound(
            &mut conn,
            Role::Client,
            NodeId::random(),
            Role::Entry,
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(remote_code(err), ErrorCode::RoleNotAllowed);
    }
}

#[tokio::test]
async fn entry_refuses_to_deliver() {
    let route = start_network().await;
    let mut conn = client_link(route.entry).await;
    let payload = OnionLayer::Deliver {
        data: b"x".to_vec(),
    }
    .encode()
    .unwrap();
    conn.send(&Message::Relay { payload }).await.unwrap();
    let reply = conn.recv(Duration::from_secs(2)).await.unwrap();
    assert!(
        matches!(
            reply,
            Some(Message::Error {
                code: ErrorCode::LayerNotAllowed,
                ..
            })
        ),
        "{reply:?}"
    );
}

// ------------------------------------------------------- safety limits

#[tokio::test]
async fn non_loopback_next_hop_is_refused() {
    let route = start_network().await;
    let mut conn = client_link(route.entry).await;
    let payload = OnionLayer::Forward {
        next_hop: "192.0.2.1:80".parse().unwrap(),
        inner: Vec::new(),
    }
    .encode()
    .unwrap();
    conn.send(&Message::Relay { payload }).await.unwrap();
    let reply = conn.recv(Duration::from_secs(2)).await.unwrap();
    assert!(
        matches!(
            reply,
            Some(Message::Error {
                code: ErrorCode::NextHopRejected,
                ..
            })
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn relay_refuses_to_listen_on_non_loopback() {
    let config = RelayConfig::new("x", Role::Entry, "0.0.0.0:0".parse().unwrap());
    assert!(matches!(
        Relay::bind(config).await,
        Err(NetError::NotLoopback(_))
    ));
}

#[tokio::test]
async fn relay_role_cannot_be_client() {
    let config = RelayConfig::new("x", Role::Client, "127.0.0.1:0".parse().unwrap());
    assert!(matches!(
        Relay::bind(config).await,
        Err(NetError::InvalidConfig(_))
    ));
}

// ------------------------------------------------------- malformed input

#[tokio::test]
async fn wrong_protocol_version_is_rejected() {
    let entry = start_relay(Role::Entry).await;
    let mut conn = Connection::connect(entry, Duration::from_secs(2))
        .await
        .unwrap();
    conn.send(&Message::Hello {
        version: PROTOCOL_VERSION + 1,
        role: Role::Client,
        node_id: NodeId::random(),
    })
    .await
    .unwrap();
    let reply = conn.recv(Duration::from_secs(2)).await.unwrap();
    assert!(
        matches!(
            reply,
            Some(Message::Error {
                code: ErrorCode::VersionMismatch,
                ..
            })
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn malformed_onion_layer_is_rejected() {
    let entry = start_relay(Role::Entry).await;
    let mut conn = client_link(entry).await;
    conn.send(&Message::Relay {
        payload: vec![0xff; 16],
    })
    .await
    .unwrap();
    let reply = conn.recv(Duration::from_secs(2)).await.unwrap();
    assert!(
        matches!(
            reply,
            Some(Message::Error {
                code: ErrorCode::MalformedLayer,
                ..
            })
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn garbage_frame_gets_error_and_disconnect() {
    let entry = start_relay(Role::Entry).await;
    let mut stream = TcpStream::connect(entry).await.unwrap();
    // A valid 4-byte length prefix followed by bytes that are not a Message.
    stream.write_all(&4u32.to_be_bytes()).await.unwrap();
    stream.write_all(&[0xff; 4]).await.unwrap();

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
        .await
        .expect("relay should close the connection")
        .unwrap();
    // The relay sent an error frame before closing.
    assert!(buf.len() > 4);
}

#[tokio::test]
async fn oversized_frame_closes_connection() {
    let entry = start_relay(Role::Entry).await;
    let mut stream = TcpStream::connect(entry).await.unwrap();
    let too_big = (MAX_FRAME_LEN as u32) + 1;
    stream.write_all(&too_big.to_be_bytes()).await.unwrap();

    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("relay should close the connection");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

#[tokio::test]
async fn message_before_handshake_is_rejected() {
    let entry = start_relay(Role::Entry).await;
    let mut conn = Connection::connect(entry, Duration::from_secs(2))
        .await
        .unwrap();
    conn.send(&Message::Relay {
        payload: Vec::new(),
    })
    .await
    .unwrap();
    let reply = conn.recv(Duration::from_secs(2)).await.unwrap();
    assert!(
        matches!(
            reply,
            Some(Message::Error {
                code: ErrorCode::BadHandshake,
                ..
            })
        ),
        "{reply:?}"
    );
}
