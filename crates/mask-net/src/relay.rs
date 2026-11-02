//! Entry / Middle / Exit relay server.
//!
//! For each inbound connection a relay:
//! 1. waits for `Hello` and checks the protocol version and that the peer has
//!    the role allowed to connect to it (client → entry → middle → exit);
//! 2. for each `Relay { payload }`, peels one [`OnionLayer`]:
//!    - Entry/Middle must get `Forward`: send `inner` to `next_hop`, wait for
//!      the reply, pass it back upstream;
//!    - Exit must get `Deliver`: hand the data to the test echo service;
//! 3. returns `Error` upstream if anything fails, so the client learns why.
//!
//! The downstream connection is opened on first use and reused for later
//! messages on the same inbound connection (a crude one-circuit-per-link
//! model; multiplexed circuits come later).
//!
//! v0.2 refuses to listen on, or forward to, anything but loopback addresses
//! so a relay cannot be used as an open proxy.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, info, info_span, warn};

use crate::error::NetError;
use crate::identity::{RelayIdentity, Role};
use crate::protocol::{ErrorCode, Message, OnionLayer, PROTOCOL_VERSION};
use crate::transport::{Connection, Timeouts, handshake_outbound, message_kind};

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub nickname: String,
    pub role: Role,
    pub listen: SocketAddr,
    pub timeouts: Timeouts,
}

impl RelayConfig {
    pub fn new(nickname: impl Into<String>, role: Role, listen: SocketAddr) -> Self {
        Self {
            nickname: nickname.into(),
            role,
            listen,
            timeouts: Timeouts::default(),
        }
    }
}

/// A bound relay, ready to [`serve`](Relay::serve).
pub struct Relay {
    inner: Arc<Inner>,
    listener: TcpListener,
}

struct Inner {
    identity: RelayIdentity,
    local_addr: SocketAddr,
    timeouts: Timeouts,
}

/// An error to send back upstream.
struct Failure {
    code: ErrorCode,
    detail: String,
}

impl Failure {
    fn into_message(self) -> Message {
        Message::Error {
            code: self.code,
            detail: self.detail,
        }
    }
}

struct Downstream {
    addr: SocketAddr,
    conn: Connection,
}

impl Relay {
    pub async fn bind(config: RelayConfig) -> Result<Self, NetError> {
        if !config.role.is_relay() {
            return Err(NetError::InvalidConfig(
                "a relay's role must be entry, middle, or exit".into(),
            ));
        }
        if !config.listen.ip().is_loopback() {
            return Err(NetError::NotLoopback(config.listen));
        }
        let listener = TcpListener::bind(config.listen).await?;
        let local_addr = listener.local_addr()?;
        let identity = RelayIdentity::generate(config.nickname, config.role);
        Ok(Self {
            inner: Arc::new(Inner {
                identity,
                local_addr,
                timeouts: config.timeouts,
            }),
            listener,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    pub fn identity(&self) -> &RelayIdentity {
        &self.inner.identity
    }

    /// Accept connections until the task is cancelled.
    pub async fn serve(self) -> Result<(), NetError> {
        let span = {
            let id = &self.inner.identity;
            info_span!(
                "relay",
                name = %id.nickname,
                role = %id.role,
                id = %id.node_id.short(),
            )
        };
        async move {
            info!(
                listen = %self.inner.local_addr,
                node_id = %self.inner.identity.node_id,
                "relay started"
            );
            loop {
                let (stream, peer) = match self.listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        // e.g. out of file descriptors: back off instead of spinning.
                        warn!(error = %e, "accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let inner = Arc::clone(&self.inner);
                tokio::spawn(
                    async move { inner.handle_inbound(stream, peer).await }
                        .instrument(tracing::Span::current()),
                );
            }
        }
        .instrument(span)
        .await
    }
}

impl Inner {
    async fn handle_inbound(&self, stream: TcpStream, peer: SocketAddr) {
        info!(%peer, "connection opened");
        match self.serve_connection(stream).await {
            Ok(()) => info!(%peer, "connection closed"),
            Err(e) => warn!(%peer, error = %e, "connection closed with error"),
        }
    }

    async fn serve_connection(&self, stream: TcpStream) -> Result<(), NetError> {
        let mut conn = Connection::new(stream)?;
        self.accept_handshake(&mut conn).await?;

        let mut downstream: Option<Downstream> = None;
        loop {
            let msg = match conn.recv(self.timeouts.idle).await {
                Ok(Some(msg)) => msg,
                Ok(None) => return Ok(()),
                Err(e @ NetError::Decode(_)) => {
                    let _ = conn
                        .send(&self.error(ErrorCode::MalformedMessage, "could not decode message"))
                        .await;
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            let Message::Relay { payload } = msg else {
                let kind = message_kind(&msg);
                let _ = conn
                    .send(&self.error(
                        ErrorCode::MalformedMessage,
                        &format!("expected Relay, got {kind}"),
                    ))
                    .await;
                return Err(NetError::Protocol(format!("unexpected {kind}")));
            };

            let reply = match self.process(payload, &mut downstream).await {
                Ok(payload) => Message::RelayResponse { payload },
                Err(failure) => {
                    warn!(code = %failure.code, detail = %failure.detail, "request failed");
                    failure.into_message()
                }
            };
            conn.send(&reply).await?;
        }
    }

    async fn accept_handshake(&self, conn: &mut Connection) -> Result<(), NetError> {
        let msg = match conn.recv(self.timeouts.handshake).await {
            Ok(Some(msg)) => msg,
            Ok(None) => return Err(NetError::ConnectionClosed),
            Err(e @ NetError::Decode(_)) => {
                let _ = conn
                    .send(&self.error(ErrorCode::BadHandshake, "could not decode Hello"))
                    .await;
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        let Message::Hello {
            version,
            role,
            node_id,
        } = msg
        else {
            let _ = conn
                .send(&self.error(ErrorCode::BadHandshake, "expected Hello"))
                .await;
            return Err(NetError::Protocol(
                "handshake did not start with Hello".into(),
            ));
        };

        if version != PROTOCOL_VERSION {
            let detail = format!("protocol v{version} not supported, need v{PROTOCOL_VERSION}");
            let _ = conn
                .send(&self.error(ErrorCode::VersionMismatch, &detail))
                .await;
            return Err(NetError::Protocol(detail));
        }

        let me = self.identity.role;
        if Some(role) != me.expected_upstream() {
            let detail = format!("a {me} relay does not accept connections from a {role}");
            let _ = conn
                .send(&self.error(ErrorCode::RoleNotAllowed, &detail))
                .await;
            return Err(NetError::Protocol(detail));
        }

        conn.send(&Message::Welcome {
            version: PROTOCOL_VERSION,
            role: me,
            node_id: self.identity.node_id,
        })
        .await?;
        info!(peer_role = %role, peer_id = %node_id.short(), "handshake complete");
        Ok(())
    }

    /// Peel one onion layer and act on it.
    async fn process(
        &self,
        payload: Vec<u8>,
        downstream: &mut Option<Downstream>,
    ) -> Result<Vec<u8>, Failure> {
        let layer = OnionLayer::decode(&payload)
            .map_err(|_| self.failure(ErrorCode::MalformedLayer, "could not decode onion layer"))?;

        match (self.identity.role, layer) {
            (Role::Exit, OnionLayer::Deliver { data }) => {
                info!(bytes = data.len(), "delivering to test echo service");
                Ok(echo_service(data))
            }
            (Role::Entry | Role::Middle, OnionLayer::Forward { next_hop, inner }) => {
                self.forward(next_hop, inner, downstream).await
            }
            (role, OnionLayer::Deliver { .. }) => Err(self.failure(
                ErrorCode::LayerNotAllowed,
                &format!("a {role} relay cannot deliver data; only exits can"),
            )),
            (role, OnionLayer::Forward { .. }) => Err(self.failure(
                ErrorCode::LayerNotAllowed,
                &format!("a {role} relay cannot forward"),
            )),
        }
    }

    async fn forward(
        &self,
        next_hop: SocketAddr,
        inner: Vec<u8>,
        downstream: &mut Option<Downstream>,
    ) -> Result<Vec<u8>, Failure> {
        if !next_hop.ip().is_loopback() {
            return Err(self.failure(
                ErrorCode::NextHopRejected,
                &format!("next hop {next_hop} is not a loopback address"),
            ));
        }
        if next_hop == self.local_addr {
            return Err(self.failure(ErrorCode::NextHopRejected, "next hop is this relay itself"));
        }

        if downstream.as_ref().is_some_and(|d| d.addr != next_hop) {
            *downstream = None;
        }
        if downstream.is_none() {
            *downstream = Some(self.open_downstream(next_hop).await?);
        }
        let link = downstream.as_mut().expect("downstream was just opened");

        info!(%next_hop, bytes = inner.len(), "forwarding");
        if let Err(e) = link.conn.send(&Message::Relay { payload: inner }).await {
            *downstream = None;
            return Err(self.failure(
                ErrorCode::NextHopUnreachable,
                &format!("sending to {next_hop} failed: {e}"),
            ));
        }

        let reply = link.conn.recv(self.timeouts.response).await;
        match reply {
            Ok(Some(Message::RelayResponse { payload })) => {
                info!(bytes = payload.len(), "response returned upstream");
                Ok(payload)
            }
            // Pass errors from further along the route back unchanged.
            Ok(Some(Message::Error { code, detail })) => Err(Failure { code, detail }),
            Ok(Some(other)) => {
                *downstream = None;
                Err(self.failure(
                    ErrorCode::NextHopRejected,
                    &format!("next hop sent unexpected {}", message_kind(&other)),
                ))
            }
            Ok(None) => {
                *downstream = None;
                Err(self.failure(
                    ErrorCode::NextHopUnreachable,
                    &format!("{next_hop} closed the connection"),
                ))
            }
            Err(NetError::Timeout) => {
                *downstream = None;
                Err(self.failure(
                    ErrorCode::Timeout,
                    &format!("{next_hop} did not respond in time"),
                ))
            }
            Err(e) => {
                *downstream = None;
                Err(self.failure(
                    ErrorCode::NextHopUnreachable,
                    &format!("reading from {next_hop} failed: {e}"),
                ))
            }
        }
    }

    async fn open_downstream(&self, next_hop: SocketAddr) -> Result<Downstream, Failure> {
        let expected = self
            .identity
            .role
            .expected_downstream()
            .expect("only entry and middle relays forward");

        let mut conn = Connection::connect(next_hop, self.timeouts.connect)
            .await
            .map_err(|e| {
                self.failure(
                    ErrorCode::NextHopUnreachable,
                    &format!("cannot connect to {next_hop}: {e}"),
                )
            })?;

        let peer_id = handshake_outbound(
            &mut conn,
            self.identity.role,
            self.identity.node_id,
            expected,
            self.timeouts.handshake,
        )
        .await
        .map_err(|e| {
            let code = match e {
                NetError::Remote { .. } | NetError::Protocol(_) => ErrorCode::NextHopRejected,
                NetError::Timeout => ErrorCode::Timeout,
                _ => ErrorCode::NextHopUnreachable,
            };
            self.failure(code, &format!("handshake with {next_hop} failed: {e}"))
        })?;

        info!(%next_hop, peer_id = %peer_id.short(), "connected to next hop");
        Ok(Downstream {
            addr: next_hop,
            conn,
        })
    }

    fn failure(&self, code: ErrorCode, detail: &str) -> Failure {
        Failure {
            code,
            detail: format!(
                "{} ({}): {detail}",
                self.identity.nickname, self.identity.role
            ),
        }
    }

    fn error(&self, code: ErrorCode, detail: &str) -> Message {
        self.failure(code, detail).into_message()
    }
}

/// Test service run by exit relays: returns the data unchanged.
/// Real exit traffic (TCP streams to websites) is a later milestone.
fn echo_service(data: Vec<u8>) -> Vec<u8> {
    data
}
