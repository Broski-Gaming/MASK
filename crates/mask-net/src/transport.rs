//! Framed TCP connections.
//!
//! Every [`Message`] is sent as one frame: a 4-byte big-endian length
//! followed by that many bytes of postcard-encoded message. Frames larger
//! than [`MAX_FRAME_LEN`] are rejected before their body is read.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::error::NetError;
use crate::identity::{NodeId, Role};
use crate::protocol::{MAX_FRAME_LEN, Message, PROTOCOL_VERSION};

/// How long a single frame write may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeouts used by relays and clients.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// Opening a TCP connection to the next hop.
    pub connect: Duration,
    /// Waiting for `Hello` / `Welcome`.
    pub handshake: Duration,
    /// Waiting for the reply to a forwarded message.
    pub response: Duration,
    /// Closing an inbound connection that sends nothing.
    pub idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            handshake: Duration::from_secs(5),
            response: Duration::from_secs(10),
            idle: Duration::from_secs(60),
        }
    }
}

pub fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec()
}

/// One framed link to a neighbouring node.
pub struct Connection {
    framed: Framed<TcpStream, LengthDelimitedCodec>,
    peer: SocketAddr,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Result<Self, NetError> {
        let peer = stream.peer_addr()?;
        stream.set_nodelay(true)?;
        Ok(Self {
            framed: Framed::new(stream, codec()),
            peer,
        })
    }

    pub async fn connect(addr: SocketAddr, limit: Duration) -> Result<Self, NetError> {
        let stream = timeout(limit, TcpStream::connect(addr))
            .await
            .map_err(|_| NetError::Timeout)??;
        Self::new(stream)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    pub async fn send(&mut self, msg: &Message) -> Result<(), NetError> {
        let bytes = Bytes::from(msg.encode()?);
        timeout(WRITE_TIMEOUT, self.framed.send(bytes))
            .await
            .map_err(|_| NetError::Timeout)??;
        Ok(())
    }

    /// Next message, or `None` if the peer closed the connection cleanly.
    pub async fn recv(&mut self, limit: Duration) -> Result<Option<Message>, NetError> {
        match timeout(limit, self.framed.next()).await {
            Err(_) => Err(NetError::Timeout),
            Ok(None) => Ok(None),
            Ok(Some(Err(e))) => Err(NetError::Io(e)),
            Ok(Some(Ok(frame))) => Ok(Some(Message::decode(&frame)?)),
        }
    }
}

/// Connecting side of the handshake: send `Hello`, expect `Welcome` from a
/// peer with the `expected` role. Returns the peer's node ID.
pub async fn handshake_outbound(
    conn: &mut Connection,
    my_role: Role,
    my_id: NodeId,
    expected: Role,
    limit: Duration,
) -> Result<NodeId, NetError> {
    conn.send(&Message::Hello {
        version: PROTOCOL_VERSION,
        role: my_role,
        node_id: my_id,
    })
    .await?;

    match conn.recv(limit).await? {
        Some(Message::Welcome {
            version,
            role,
            node_id,
        }) => {
            if version != PROTOCOL_VERSION {
                Err(NetError::Protocol(format!(
                    "peer speaks protocol v{version}, we speak v{PROTOCOL_VERSION}"
                )))
            } else if role != expected {
                Err(NetError::Protocol(format!(
                    "expected a {expected} relay at {}, found a {role} relay",
                    conn.peer_addr()
                )))
            } else {
                Ok(node_id)
            }
        }
        Some(Message::Error { code, detail }) => Err(NetError::Remote { code, detail }),
        Some(other) => Err(NetError::Protocol(format!(
            "expected Welcome, got {}",
            message_kind(&other)
        ))),
        None => Err(NetError::ConnectionClosed),
    }
}

/// Short name of a message variant, for logs and errors (never the contents).
pub fn message_kind(msg: &Message) -> &'static str {
    match msg {
        Message::Hello { .. } => "Hello",
        Message::Welcome { .. } => "Welcome",
        Message::Relay { .. } => "Relay",
        Message::RelayResponse { .. } => "RelayResponse",
        Message::Error { .. } => "Error",
    }
}
