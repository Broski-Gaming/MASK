//! Authenticated, encrypted MORP links (Noise over TCP).
//!
//! Every MORP connection, between any two components and on any network,
//! is a [Noise] session. There is no plaintext mode and no way to negotiate
//! one: a peer that does not speak Noise never gets past the first frame.
//!
//! **Wire format.** Each frame is a 2-byte big-endian length followed by
//! that many bytes (at most 65 535, the Noise message limit).
//!
//! 1. Initiator → responder: `kind` (1 byte, [`LinkKind`]) + Noise message 1.
//! 2. Responder → initiator: Noise message 2.
//! 3. Then each frame is one Noise transport message whose plaintext is one
//!    postcard-encoded [`LinkMsg`] of at most [`MAX_FRAME_LEN`] bytes.
//!
//! The prologue `"MORP link v3\0" || kind` is mixed into the handshake, so
//! changing the kind byte in transit makes the handshake fail.
//!
//! **Patterns** (`25519_ChaChaPoly_SHA256`, implemented by the `snow` crate):
//! - `NK` for clients, hidden-service hosts, health probes, and directory
//!   requests: the initiator knows the responder's static **link key** (from
//!   a signed relay descriptor, or pinned in `network.toml` for authorities)
//!   and stays anonymous at the link layer.
//! - `IK` for relay → relay links: both sides are authenticated by their link
//!   keys. The responder learns the initiator's key in message 1 and refuses
//!   (closes without answering) unless it belongs to a trusted relay allowed
//!   to open that link.
//!
//! A link key is bound to a relay's Ed25519 identity by the relay's signed
//! descriptor, so completing a handshake proves the peer is that relay.
//!
//! After the Noise handshake, the MORP `Hello`/`Welcome` exchange checks the
//! protocol version and roles inside the encrypted channel.
//!
//! An established [`Connection`] is split into a [`Link`] (cheap to clone;
//! many circuits send through it) and a [`LinkReader`] (owned by one task). A
//! dedicated writer task encrypts and sends queued messages in order.
//!
//! [Noise]: https://noiseprotocol.org/noise.html

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::crypto::CryptoError;
use crate::error::NetError;
use crate::identity::Role;
use crate::protocol::{LinkErrorCode, LinkMsg, MAX_FRAME_LEN, MORP_VERSION, decode, encode};
use crate::scope::NetworkScope;

const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const LINK_QUEUE: usize = 256;
const NOISE_MAX: usize = 65_535;
const NOISE_TAG: usize = 16;
const PROLOGUE: &[u8] = b"MORP link v3\0";
const NOISE_NK: &str = "Noise_NK_25519_ChaChaPoly_SHA256";
const NOISE_IK: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

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
    /// How often an outbound link that has been quiet sends a `Ping`. A link
    /// that stays silent for two intervals after a `Ping` is declared dead,
    /// which detects machines that vanished without closing TCP.
    pub keepalive: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            handshake: Duration::from_secs(10),
            response: Duration::from_secs(30),
            idle: Duration::from_secs(300),
            keepalive: Duration::from_secs(30),
        }
    }
}

/// What the initiator wants from a link. Sent in clear as the first byte and
/// authenticated through the Noise prologue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkKind {
    /// Client or hidden-service host → entry relay (NK).
    Client = 1,
    /// Relay → next relay (IK, both sides authenticated).
    Relay = 2,
    /// Health check: prove possession of the link key, answer `Welcome`,
    /// close (NK).
    Probe = 3,
    /// Request to a directory authority (NK).
    Directory = 4,
}

impl LinkKind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Client),
            2 => Some(Self::Relay),
            3 => Some(Self::Probe),
            4 => Some(Self::Directory),
            _ => None,
        }
    }

    fn pattern(self) -> &'static str {
        match self {
            Self::Relay => NOISE_IK,
            Self::Client | Self::Probe | Self::Directory => NOISE_NK,
        }
    }

    fn prologue(self) -> Vec<u8> {
        let mut prologue = PROLOGUE.to_vec();
        prologue.push(self as u8);
        prologue
    }
}

type FramedTcp = Framed<TcpStream, LengthDelimitedCodec>;

fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u16>()
        .max_frame_length(NOISE_MAX)
        .new_codec()
}

fn noise_err(e: snow::Error) -> NetError {
    match e {
        snow::Error::Decrypt => NetError::Crypto(CryptoError::AuthenticationFailed),
        other => NetError::Protocol(format!("link handshake failed: {other:?}")),
    }
}

fn closed_during_handshake() -> NetError {
    NetError::LinkRejected {
        code: LinkErrorCode::Unauthenticated,
        detail: "peer closed the connection during the link handshake (wrong link key, \
                 or this node is not trusted by the peer)"
            .into(),
    }
}

/// Shared Noise transport state: the writer task encrypts, the reader
/// decrypts. Each direction has its own counter inside `snow`.
type Noise = Arc<Mutex<snow::TransportState>>;

/// An authenticated, encrypted connection before it is split.
pub struct Connection {
    framed: FramedTcp,
    noise: Noise,
    peer: SocketAddr,
    remote_static: Option<[u8; 32]>,
}

/// Result of accepting a connection.
pub struct Accepted {
    pub conn: Connection,
    pub kind: LinkKind,
}

impl Connection {
    /// Open a link to a responder whose link key is `remote_link_key`.
    /// `local` is required for [`LinkKind::Relay`] (IK) and ignored otherwise.
    pub async fn connect(
        addr: SocketAddr,
        kind: LinkKind,
        remote_link_key: &[u8; 32],
        local: Option<&StaticSecret>,
        timeouts: &Timeouts,
    ) -> Result<Self, NetError> {
        let stream = timeout(timeouts.connect, TcpStream::connect(addr))
            .await
            .map_err(|_| NetError::Timeout)??;
        timeout(
            timeouts.handshake,
            Self::initiate(stream, kind, remote_link_key, local),
        )
        .await
        .map_err(|_| NetError::Timeout)?
    }

    /// Check `policy` (which includes the network scope), then [`connect`].
    ///
    /// [`connect`]: Connection::connect
    pub async fn connect_checked(
        addr: SocketAddr,
        kind: LinkKind,
        remote_link_key: &[u8; 32],
        local: Option<&StaticSecret>,
        timeouts: &Timeouts,
        policy: &ConnectPolicy,
        origin: &str,
    ) -> Result<Self, NetError> {
        policy.check(origin, addr)?;
        Self::connect(addr, kind, remote_link_key, local, timeouts).await
    }

    async fn initiate(
        stream: TcpStream,
        kind: LinkKind,
        remote_link_key: &[u8; 32],
        local: Option<&StaticSecret>,
    ) -> Result<Self, NetError> {
        let peer = stream.peer_addr()?;
        stream.set_nodelay(true)?;
        let mut framed = Framed::new(stream, codec());
        let prologue = kind.prologue();
        let local_bytes = local.map(|k| Zeroizing::new(k.to_bytes()));
        let mut builder = snow::Builder::new(kind.pattern().parse().expect("valid pattern"))
            .prologue(&prologue)
            .map_err(noise_err)?
            .remote_public_key(remote_link_key)
            .map_err(noise_err)?;
        if kind == LinkKind::Relay {
            let key = local_bytes.as_ref().ok_or_else(|| {
                NetError::InvalidConfig("relay links need the local link key".into())
            })?;
            builder = builder.local_private_key(key.as_ref()).map_err(noise_err)?;
        }
        let mut hs = builder.build_initiator().map_err(noise_err)?;

        let mut msg1 = vec![0u8; NOISE_MAX];
        msg1[0] = kind as u8;
        let len = hs.write_message(&[], &mut msg1[1..]).map_err(noise_err)?;
        msg1.truncate(1 + len);
        framed.send(Bytes::from(msg1)).await?;

        let reply = match framed.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(e)) => return Err(NetError::Io(e)),
            None => return Err(closed_during_handshake()),
        };
        let mut scratch = vec![0u8; NOISE_MAX];
        hs.read_message(&reply, &mut scratch).map_err(|e| match e {
            // A wrong responder key shows up as a failed decryption.
            snow::Error::Decrypt => NetError::Untrusted(format!(
                "{peer} could not prove it holds the expected link key"
            )),
            other => noise_err(other),
        })?;
        let transport = hs.into_transport_mode().map_err(noise_err)?;
        Ok(Self {
            framed,
            noise: Arc::new(Mutex::new(transport)),
            peer,
            remote_static: None,
        })
    }

    /// Run the responder side of the Noise handshake on `stream`.
    ///
    /// `authorize(kind, initiator_key)` decides whether to continue; it sees
    /// the initiator's static key for [`LinkKind::Relay`] links. Refused
    /// peers get no answer at all: the connection is just closed.
    pub async fn accept(
        stream: TcpStream,
        local: &StaticSecret,
        limit: Duration,
        authorize: impl FnOnce(LinkKind, Option<&[u8; 32]>) -> Result<(), String>,
    ) -> Result<Accepted, NetError> {
        timeout(limit, Self::respond(stream, local, authorize))
            .await
            .map_err(|_| NetError::Timeout)?
    }

    async fn respond(
        stream: TcpStream,
        local: &StaticSecret,
        authorize: impl FnOnce(LinkKind, Option<&[u8; 32]>) -> Result<(), String>,
    ) -> Result<Accepted, NetError> {
        let peer = stream.peer_addr()?;
        stream.set_nodelay(true)?;
        let mut framed = Framed::new(stream, codec());
        let first = match framed.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(e)) => return Err(NetError::Io(e)),
            None => return Err(NetError::ConnectionClosed),
        };
        let kind = first
            .first()
            .copied()
            .and_then(LinkKind::from_byte)
            .ok_or_else(|| {
                NetError::Protocol(
                    "not a MORP v3 link (unknown link kind; plaintext links are not supported)"
                        .into(),
                )
            })?;
        let prologue = kind.prologue();
        let local_bytes = Zeroizing::new(local.to_bytes());
        let mut hs = snow::Builder::new(kind.pattern().parse().expect("valid pattern"))
            .prologue(&prologue)
            .map_err(noise_err)?
            .local_private_key(local_bytes.as_ref())
            .map_err(noise_err)?
            .build_responder()
            .map_err(noise_err)?;
        let mut scratch = vec![0u8; NOISE_MAX];
        hs.read_message(&first[1..], &mut scratch)
            .map_err(|e| match e {
                snow::Error::Decrypt => NetError::Untrusted(
                    "link handshake not addressed to this node's current link key".into(),
                ),
                other => noise_err(other),
            })?;
        let remote_static: Option<[u8; 32]> = hs
            .get_remote_static()
            .and_then(|k| <[u8; 32]>::try_from(k).ok());
        if kind == LinkKind::Relay && remote_static.is_none() {
            return Err(NetError::Protocol("relay link without a static key".into()));
        }
        authorize(kind, remote_static.as_ref()).map_err(NetError::Untrusted)?;

        let mut msg2 = vec![0u8; NOISE_MAX];
        let len = hs.write_message(&[], &mut msg2).map_err(noise_err)?;
        msg2.truncate(len);
        framed.send(Bytes::from(msg2)).await?;
        let transport = hs.into_transport_mode().map_err(noise_err)?;
        Ok(Accepted {
            conn: Self {
                framed,
                noise: Arc::new(Mutex::new(transport)),
                peer,
                remote_static,
            },
            kind,
        })
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The initiator's authenticated link key (IK links, responder side).
    pub fn remote_static(&self) -> Option<&[u8; 32]> {
        self.remote_static.as_ref()
    }

    pub async fn send(&mut self, msg: &LinkMsg) -> Result<(), NetError> {
        self.send_bytes(&encode_checked(msg)?).await
    }

    pub async fn recv(&mut self, limit: Duration) -> Result<Option<LinkMsg>, NetError> {
        match self.recv_bytes(limit).await? {
            Some(plain) => Ok(Some(decode(&plain)?)),
            None => Ok(None),
        }
    }

    /// Send one encrypted message of at most [`MAX_FRAME_LEN`] bytes (used
    /// by the directory protocol, which is not made of `LinkMsg`s).
    pub async fn send_bytes(&mut self, plain: &[u8]) -> Result<(), NetError> {
        if plain.len() > MAX_FRAME_LEN {
            return Err(NetError::Protocol(format!(
                "message of {} bytes exceeds the {MAX_FRAME_LEN}-byte frame limit",
                plain.len()
            )));
        }
        let frame = seal(&self.noise, plain)?;
        timeout(WRITE_TIMEOUT, self.framed.send(frame))
            .await
            .map_err(|_| NetError::Timeout)??;
        Ok(())
    }

    /// Receive and decrypt one message; `None` when the peer closed.
    pub async fn recv_bytes(&mut self, limit: Duration) -> Result<Option<Vec<u8>>, NetError> {
        recv_plain(&mut self.framed, &self.noise, Some(limit)).await
    }

    /// Start the writer task and split into a sending handle and a reader.
    pub fn into_link(self) -> (Link, LinkReader) {
        let (sink, stream) = self.framed.split();
        let (tx, rx) = mpsc::channel(LINK_QUEUE);
        let closing = CancellationToken::new();
        let writer = tokio::spawn(write_loop(
            sink,
            rx,
            Arc::clone(&self.noise),
            closing.clone(),
        ));
        let link = Link {
            id: NEXT_LINK_ID.fetch_add(1, Ordering::Relaxed),
            peer: self.peer,
            tx,
            closing,
        };
        (
            link,
            LinkReader {
                stream,
                noise: self.noise,
                writer,
            },
        )
    }
}

fn encode_checked(msg: &LinkMsg) -> Result<Vec<u8>, NetError> {
    let plain = encode(msg);
    if plain.len() > MAX_FRAME_LEN {
        return Err(NetError::Protocol(format!(
            "message of {} bytes exceeds the {MAX_FRAME_LEN}-byte frame limit",
            plain.len()
        )));
    }
    Ok(plain)
}

fn seal(noise: &Noise, plain: &[u8]) -> Result<Bytes, NetError> {
    let mut out = vec![0u8; plain.len() + NOISE_TAG];
    let len = noise
        .lock()
        .unwrap()
        .write_message(plain, &mut out)
        .map_err(noise_err)?;
    out.truncate(len);
    Ok(Bytes::from(out))
}

/// Encrypt and send queued messages in order. Stops when every [`Link`] is
/// dropped, or when the link is closed: then whatever is already queued is
/// still sent (for example `Destroy` messages during shutdown) and the
/// connection is closed even if other handles to the link remain.
async fn write_loop(
    mut sink: SplitSink<FramedTcp, Bytes>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    noise: Noise,
    closing: CancellationToken,
) {
    loop {
        let plain = tokio::select! {
            biased;
            plain = rx.recv() => plain,
            _ = closing.cancelled() => rx.try_recv().ok(),
        };
        let Some(plain) = plain else { break };
        let Ok(frame) = seal(&noise, &plain) else {
            break;
        };
        let sent = timeout(WRITE_TIMEOUT, sink.send(frame)).await;
        if !matches!(sent, Ok(Ok(()))) {
            return;
        }
    }
    rx.close();
    let _ = sink.close().await;
}

/// Sending side of an established link.
#[derive(Clone, Debug)]
pub struct Link {
    id: u64,
    peer: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    closing: CancellationToken,
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
        let plain = encode_checked(&msg)?;
        self.tx
            .send(plain)
            .await
            .map_err(|_| NetError::ConnectionClosed)
    }

    /// Best-effort send that never waits (used from `Drop`).
    pub fn try_send(&self, msg: LinkMsg) {
        if let Ok(plain) = encode_checked(&msg) {
            let _ = self.tx.try_send(plain);
        }
    }

    /// True once the writer has stopped (peer gone or write error).
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// A handle that does not keep the link open.
    pub fn downgrade(&self) -> WeakLink {
        WeakLink {
            id: self.id,
            peer: self.peer,
            tx: self.tx.downgrade(),
            closing: self.closing.clone(),
        }
    }

    /// Send what is already queued, then close the connection, even if
    /// other handles to this link still exist.
    pub fn close(&self) {
        self.closing.cancel();
    }
}

/// A [`Link`] handle that does not keep the link open: once every `Link`
/// is dropped, the writer closes the connection.
#[derive(Clone, Debug)]
pub struct WeakLink {
    id: u64,
    peer: SocketAddr,
    tx: mpsc::WeakSender<Vec<u8>>,
    closing: CancellationToken,
}

impl WeakLink {
    pub fn upgrade(&self) -> Option<Link> {
        Some(Link {
            id: self.id,
            peer: self.peer,
            tx: self.tx.upgrade()?,
            closing: self.closing.clone(),
        })
    }
}

/// Receiving side of an established link.
pub struct LinkReader {
    stream: SplitStream<FramedTcp>,
    noise: Noise,
    writer: tokio::task::JoinHandle<()>,
}

impl LinkReader {
    /// Close the link after everything already queued on it has been sent.
    /// Waits at most 2 s (for example while other clones of `link` are still
    /// being dropped), then stops the writer so the socket really closes and
    /// the peer is not left with a half-open connection.
    pub async fn finish(mut self, link: Link) {
        link.close();
        drop(link);
        if timeout(Duration::from_secs(2), &mut self.writer)
            .await
            .is_err()
        {
            self.writer.abort();
        }
    }

    /// Next message; `None` when the peer closed the link. `limit = None`
    /// waits indefinitely. A frame that fails Noise authentication is an
    /// error, after which the link must be closed.
    pub async fn recv(&mut self, limit: Option<Duration>) -> Result<Option<LinkMsg>, NetError> {
        recv_frame(&mut self.stream, &self.noise, limit).await
    }
}

async fn recv_plain<S>(
    stream: &mut S,
    noise: &Noise,
    limit: Option<Duration>,
) -> Result<Option<Vec<u8>>, NetError>
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
        Some(Ok(frame)) => {
            let mut plain = vec![0u8; frame.len()];
            let len = noise
                .lock()
                .unwrap()
                .read_message(&frame, &mut plain)
                .map_err(noise_err)?;
            plain.truncate(len);
            Ok(Some(plain))
        }
    }
}

async fn recv_frame<S>(
    stream: &mut S,
    noise: &Noise,
    limit: Option<Duration>,
) -> Result<Option<LinkMsg>, NetError>
where
    S: futures_util::Stream<Item = std::io::Result<tokio_util::bytes::BytesMut>> + Unpin,
{
    match recv_plain(stream, noise, limit).await? {
        Some(plain) => Ok(Some(decode(&plain)?)),
        None => Ok(None),
    }
}

/// Opening side of the MORP Hello/Welcome exchange (inside Noise).
/// The peer's role must be one of `allowed`; it is returned on success.
pub async fn handshake_outbound(
    conn: &mut Connection,
    my_role: Role,
    allowed: &[Role],
    limit: Duration,
) -> Result<Role, NetError> {
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
            } else if !allowed.contains(&role) {
                Err(NetError::Protocol(format!(
                    "unexpected {role} relay at {}",
                    conn.peer_addr()
                )))
            } else {
                Ok(role)
            }
        }
        Some(LinkMsg::LinkError { code, detail }) => Err(NetError::LinkRejected { code, detail }),
        Some(_) => Err(NetError::Protocol("expected Welcome".into())),
        None => Err(NetError::ConnectionClosed),
    }
}

/// Accepting side of the Hello/Welcome exchange. Returns the peer's role.
///
/// `authenticated` is the role of the relay the Noise handshake proved the
/// peer to be (relay links), or `None` for client links. The declared role
/// must equal it and must be the one allowed to open links to `my_role`.
/// On failure a `LinkError` is sent before returning.
pub async fn handshake_inbound(
    conn: &mut Connection,
    my_role: Role,
    authenticated: Option<Role>,
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
            } else if role.is_relay() && authenticated != Some(role) {
                Err(reject(
                    LinkErrorCode::Unauthenticated,
                    format!("peer claims to be a {role} relay but did not authenticate as one"),
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

/// Decides whether a component may open a TCP connection.
///
/// Every outbound connection in mask-net (client links, relay links,
/// authority requests, the hidden-service host's connection to its local
/// app) goes through a policy check. Two rules apply:
///
/// 1. the destination must be inside the policy's [`NetworkScope`]
///    (loopback by default; public addresses are never allowed);
/// 2. an optional custom rule. Tests install one that records each attempt
///    and denies anything not on the expected route, which proves that, for
///    example, a browser never connects directly to a service.
#[derive(Clone, Default)]
pub struct ConnectPolicy {
    rule: Option<std::sync::Arc<PolicyFn>>,
    scope: NetworkScope,
}

type PolicyFn = dyn Fn(&str, SocketAddr) -> bool + Send + Sync;

impl ConnectPolicy {
    /// Any destination inside the loopback scope.
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// `rule(origin, destination)` returns whether the connection is allowed
    /// (in addition to the scope check).
    pub fn new(rule: impl Fn(&str, SocketAddr) -> bool + Send + Sync + 'static) -> Self {
        Self {
            rule: Some(std::sync::Arc::new(rule)),
            scope: NetworkScope::default(),
        }
    }

    /// The same rule with a different network scope.
    pub fn with_scope(mut self, scope: NetworkScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn scope(&self) -> NetworkScope {
        self.scope
    }

    pub fn check(&self, origin: &str, addr: SocketAddr) -> Result<(), NetError> {
        self.scope.check(addr)?;
        match &self.rule {
            Some(rule) if !rule(origin, addr) => Err(NetError::PolicyDenied {
                origin: origin.to_owned(),
                addr,
            }),
            _ => Ok(()),
        }
    }
}

impl std::fmt::Debug for ConnectPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ConnectPolicy({}, scope {})",
            if self.rule.is_some() {
                "custom"
            } else {
                "allow all"
            },
            self.scope
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;
    use tokio::net::TcpListener;
    use x25519_dalek::PublicKey;

    fn key() -> (StaticSecret, [u8; 32]) {
        let secret = StaticSecret::from(random_bytes::<32>());
        let public = PublicKey::from(&secret).to_bytes();
        (secret, public)
    }

    fn fast() -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(2),
            handshake: Duration::from_secs(2),
            ..Timeouts::default()
        }
    }

    /// A responder that accepts one connection, echoes one message, and
    /// reports what it authenticated.
    async fn responder(
        secret: StaticSecret,
        trusted_initiator: Option<[u8; 32]>,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<(LinkKind, Option<[u8; 32]>), NetError>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let accepted =
                Connection::accept(stream, &secret, Duration::from_secs(2), |kind, rs| {
                    match (kind, rs) {
                        (LinkKind::Relay, Some(rs)) if Some(*rs) == trusted_initiator => Ok(()),
                        (LinkKind::Relay, _) => Err("unknown relay".into()),
                        _ => Ok(()),
                    }
                })
                .await?;
            let mut conn = accepted.conn;
            let rs = conn.remote_static().copied();
            if let Some(msg) = conn.recv(Duration::from_secs(2)).await? {
                conn.send(&msg).await?;
            }
            Ok((accepted.kind, rs))
        });
        (addr, task)
    }

    fn ping(nonce: u64) -> LinkMsg {
        LinkMsg::Ping { nonce }
    }

    #[tokio::test]
    async fn nk_link_round_trips_and_hides_the_initiator() {
        let (secret, public) = key();
        let (addr, task) = responder(secret, None).await;
        let mut conn = Connection::connect(addr, LinkKind::Client, &public, None, &fast())
            .await
            .unwrap();
        conn.send(&ping(7)).await.unwrap();
        assert_eq!(
            conn.recv(Duration::from_secs(2)).await.unwrap(),
            Some(ping(7))
        );
        let (kind, rs) = task.await.unwrap().unwrap();
        assert_eq!(kind, LinkKind::Client);
        assert_eq!(rs, None, "NK initiators are anonymous at the link layer");
    }

    #[tokio::test]
    async fn ik_link_authenticates_both_sides() {
        let (secret, public) = key();
        let (initiator, initiator_public) = key();
        let (addr, task) = responder(secret, Some(initiator_public)).await;
        let mut conn =
            Connection::connect(addr, LinkKind::Relay, &public, Some(&initiator), &fast())
                .await
                .unwrap();
        conn.send(&ping(1)).await.unwrap();
        assert_eq!(
            conn.recv(Duration::from_secs(2)).await.unwrap(),
            Some(ping(1))
        );
        let (kind, rs) = task.await.unwrap().unwrap();
        assert_eq!(kind, LinkKind::Relay);
        assert_eq!(rs, Some(initiator_public));
    }

    #[tokio::test]
    async fn untrusted_relay_initiator_is_refused_without_an_answer() {
        let (secret, public) = key();
        let (stranger, _) = key();
        let (_, trusted) = key();
        let (addr, task) = responder(secret, Some(trusted)).await;
        let result =
            Connection::connect(addr, LinkKind::Relay, &public, Some(&stranger), &fast()).await;
        assert!(
            matches!(
                result,
                Err(NetError::LinkRejected {
                    code: LinkErrorCode::Unauthenticated,
                    ..
                })
            ),
            "{:?}",
            result.err()
        );
        assert!(matches!(task.await.unwrap(), Err(NetError::Untrusted(_))));
    }

    #[tokio::test]
    async fn wrong_responder_key_is_detected() {
        // An impostor at the address does not hold the expected link key.
        let (impostor, _) = key();
        let (_, expected) = key();
        let (addr, task) = responder(impostor, None).await;
        let result = Connection::connect(addr, LinkKind::Client, &expected, None, &fast()).await;
        assert!(result.is_err());
        assert!(matches!(task.await.unwrap(), Err(NetError::Untrusted(_))));
    }

    #[tokio::test]
    async fn plaintext_v2_hello_is_refused() {
        // Downgrade attempt: a v0.5-style plaintext frame never reaches MORP.
        let (secret, _) = key();
        let (addr, task) = responder(secret, None).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        let hello = encode(&LinkMsg::Hello {
            version: 2,
            role: Role::Client,
        });
        stream
            .write_all(&(hello.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&hello).await.unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn changing_the_kind_byte_breaks_the_handshake() {
        // A man in the middle rewrites the kind (Client → Directory).
        let (secret, public) = key();
        let (addr, task) = responder(secret, None).await;
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut inbound, _) = proxy.accept().await.unwrap();
            let mut outbound = TcpStream::connect(addr).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = inbound.read(&mut buf).await.unwrap();
            buf[2] = LinkKind::Directory as u8; // after the 2-byte length
            outbound.write_all(&buf[..n]).await.unwrap();
            let (mut ir, mut iw) = inbound.into_split();
            let (mut or, mut ow) = outbound.into_split();
            tokio::join!(
                tokio::io::copy(&mut ir, &mut ow),
                tokio::io::copy(&mut or, &mut iw)
            )
        });
        let result =
            Connection::connect(proxy_addr, LinkKind::Client, &public, None, &fast()).await;
        assert!(result.is_err());
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn tampered_transport_frame_is_rejected() {
        let (secret, public) = key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn =
                Connection::accept(stream, &secret, Duration::from_secs(2), |_, _| Ok(()))
                    .await
                    .unwrap()
                    .conn;
            conn.recv(Duration::from_secs(2)).await
        });
        // Do the handshake properly, then send a corrupted transport frame.
        let mut conn = Connection::connect(addr, LinkKind::Client, &public, None, &fast())
            .await
            .unwrap();
        let mut frame = seal(&conn.noise, &encode(&ping(3))).unwrap().to_vec();
        frame[0] ^= 0x80;
        conn.framed.send(Bytes::from(frame)).await.unwrap();
        assert!(matches!(
            server.await.unwrap(),
            Err(NetError::Crypto(CryptoError::AuthenticationFailed))
        ));
    }

    #[test]
    fn largest_message_fits_one_noise_frame() {
        assert_eq!(MAX_FRAME_LEN + NOISE_TAG, NOISE_MAX);
    }

    #[test]
    fn policy_refuses_destinations_outside_its_scope() {
        let lan: SocketAddr = "192.168.1.20:7101".parse().unwrap();
        let public: SocketAddr = "1.1.1.1:7101".parse().unwrap();
        assert!(ConnectPolicy::allow_all().check("t", lan).is_err());
        let private = ConnectPolicy::allow_all().with_scope(NetworkScope::Private);
        assert!(private.check("t", lan).is_ok());
        assert!(private.check("t", public).is_err());
    }
}
