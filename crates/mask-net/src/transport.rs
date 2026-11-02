//! Framed TCP links.
//!
//! Every [`LinkMsg`] is one frame: a 4-byte big-endian length followed by the
//! postcard-encoded message. Frames larger than [`MAX_FRAME_LEN`] are rejected
//! before their body is read.
//!
//! After the Hello/Welcome handshake a [`Connection`] is split into a
//! [`Link`] (cheap to clone; many circuits send through it) and a
//! [`LinkReader`] (owned by one task). A dedicated writer task drains a queue
//! so messages from different circuits never interleave mid-frame and each
//! circuit's cells stay in order.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::error::NetError;
use crate::identity::Role;
use crate::protocol::{LinkErrorCode, LinkMsg, MAX_FRAME_LEN, MORP_VERSION, decode, encode};

const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const LINK_QUEUE: usize = 256;

static NEXT_LINK_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// Opening a TCP connection.
    pub connect: Duration,
    /// Link handshake, and waiting for CREATED / EXTENDED.
    pub handshake: Duration,
    /// Waiting for a reply to DATA.
    pub response: Duration,
    /// Closing an inbound link that sends nothing.
    pub idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            handshake: Duration::from_secs(10),
            response: Duration::from_secs(30),
            idle: Duration::from_secs(300),
        }
    }
}

type FramedTcp = Framed<TcpStream, LengthDelimitedCodec>;

fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec()
}

/// A TCP connection before the link handshake.
pub struct Connection {
    framed: FramedTcp,
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

    pub async fn send(&mut self, msg: &LinkMsg) -> Result<(), NetError> {
        timeout(WRITE_TIMEOUT, self.framed.send(Bytes::from(encode(msg))))
            .await
            .map_err(|_| NetError::Timeout)??;
        Ok(())
    }

    pub async fn recv(&mut self, limit: Duration) -> Result<Option<LinkMsg>, NetError> {
        recv_frame(&mut self.framed, Some(limit)).await
    }

    /// Start the writer task and split into a sending handle and a reader.
    pub fn into_link(self) -> (Link, LinkReader) {
        let (sink, stream) = self.framed.split();
        let (tx, rx) = mpsc::channel(LINK_QUEUE);
        tokio::spawn(write_loop(sink, rx));
        let link = Link {
            id: NEXT_LINK_ID.fetch_add(1, Ordering::Relaxed),
            peer: self.peer,
            tx,
        };
        (link, LinkReader { stream })
    }
}

async fn write_loop(mut sink: SplitSink<FramedTcp, Bytes>, mut rx: mpsc::Receiver<LinkMsg>) {
    while let Some(msg) = rx.recv().await {
        let sent = timeout(WRITE_TIMEOUT, sink.send(Bytes::from(encode(&msg)))).await;
        if !matches!(sent, Ok(Ok(()))) {
            return;
        }
    }
    let _ = sink.close().await;
}

/// Sending side of an established link.
#[derive(Clone, Debug)]
pub struct Link {
    id: u64,
    peer: SocketAddr,
    tx: mpsc::Sender<LinkMsg>,
}

impl Link {
    /// Process-unique link number, used as a map key.
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    pub async fn send(&self, msg: LinkMsg) -> Result<(), NetError> {
        self.tx
            .send(msg)
            .await
            .map_err(|_| NetError::ConnectionClosed)
    }

    /// Best-effort send that never waits (used from `Drop`).
    pub fn try_send(&self, msg: LinkMsg) {
        let _ = self.tx.try_send(msg);
    }

    /// True once the writer has stopped (peer gone or write error).
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Receiving side of an established link.
pub struct LinkReader {
    stream: SplitStream<FramedTcp>,
}

impl LinkReader {
    /// Next message; `None` when the peer closed the link. `limit = None`
    /// waits indefinitely.
    pub async fn recv(&mut self, limit: Option<Duration>) -> Result<Option<LinkMsg>, NetError> {
        recv_frame(&mut self.stream, limit).await
    }
}

async fn recv_frame<S>(stream: &mut S, limit: Option<Duration>) -> Result<Option<LinkMsg>, NetError>
where
    S: futures_util::Stream<Item = std::io::Result<tokio_util::bytes::BytesMut>> + Unpin,
{
    let next = match limit {
        Some(limit) => timeout(limit, stream.next())
            .await
            .map_err(|_| NetError::Timeout)?,
        None => stream.next().await,
    };
    match next {
        None => Ok(None),
        Some(Err(e)) => Err(NetError::Io(e)),
        Some(Ok(frame)) => Ok(Some(decode(&frame)?)),
    }
}

/// Opening side of the link handshake.
pub async fn handshake_outbound(
    conn: &mut Connection,
    my_role: Role,
    expected: Role,
    limit: Duration,
) -> Result<(), NetError> {
    conn.send(&LinkMsg::Hello {
        version: MORP_VERSION,
        role: my_role,
    })
    .await?;
    match conn.recv(limit).await? {
        Some(LinkMsg::Welcome { version, role }) => {
            if version != MORP_VERSION {
                Err(NetError::Protocol(format!(
                    "peer speaks MORP v{version}, we speak v{MORP_VERSION}"
                )))
            } else if role != expected {
                Err(NetError::Protocol(format!(
                    "expected a {expected} relay at {}, found a {role} relay",
                    conn.peer_addr()
                )))
            } else {
                Ok(())
            }
        }
        Some(LinkMsg::LinkError { code, detail }) => Err(NetError::LinkRejected { code, detail }),
        Some(_) => Err(NetError::Protocol("expected Welcome".into())),
        None => Err(NetError::ConnectionClosed),
    }
}

/// Accepting side of the link handshake. Returns the peer's declared role.
/// On failure a `LinkError` is sent before returning.
pub async fn handshake_inbound(
    conn: &mut Connection,
    my_role: Role,
    limit: Duration,
) -> Result<Role, NetError> {
    let reject = |code, detail: String| (code, detail);
    let outcome = match conn.recv(limit).await {
        Ok(Some(LinkMsg::Hello { version, role })) => {
            if version != MORP_VERSION {
                Err(reject(
                    LinkErrorCode::VersionMismatch,
                    format!("MORP v{version} not supported, need v{MORP_VERSION}"),
                ))
            } else if Some(role) != my_role.expected_upstream() {
                Err(reject(
                    LinkErrorCode::RoleNotAllowed,
                    format!("a {my_role} relay does not accept links from a {role}"),
                ))
            } else {
                Ok(role)
            }
        }
        Ok(Some(_)) => Err(reject(LinkErrorCode::BadHandshake, "expected Hello".into())),
        Err(NetError::Decode(_)) => Err(reject(
            LinkErrorCode::Malformed,
            "could not decode Hello".into(),
        )),
        Ok(None) => return Err(NetError::ConnectionClosed),
        Err(e) => return Err(e),
    };

    match outcome {
        Ok(role) => {
            conn.send(&LinkMsg::Welcome {
                version: MORP_VERSION,
                role: my_role,
            })
            .await?;
            Ok(role)
        }
        Err((code, detail)) => {
            let _ = conn
                .send(&LinkMsg::LinkError {
                    code,
                    detail: detail.clone(),
                })
                .await;
            Err(NetError::Protocol(detail))
        }
    }
}
