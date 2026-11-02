//! MORP relay (entry, middle, or exit).
//!
//! A relay keeps a table of circuits. Each circuit has:
//! - an inbound side: the link toward the client and its circuit ID there;
//! - the hop's forward/backward [`CellCipher`]s from the ntor handshake;
//! - optionally an outbound side: a link to the next relay and the circuit
//!   ID used on that link.
//!
//! Forward cells (from the inbound link) are opened with this hop's key. The
//! plaintext is either another sealed cell to pass to the next hop, or a
//! command for this hop (EXTEND, or DATA at an exit). Backward cells (from
//! the outbound link) and this hop's own replies are sealed with the
//! backward key and sent toward the client, adding one layer.
//!
//! Links to the next relay are shared by every circuit going there, and
//! circuit IDs keep them apart.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, info_span, warn};

use crate::crypto::CryptoError;
use crate::crypto::keys::RelayKeys;
use crate::crypto::ntor::{self, CreateRequest};
use crate::crypto::onion::{CellCipher, Direction};
use crate::descriptor::RelayDescriptor;
use crate::error::NetError;
use crate::identity::{NodeId, Role};
use crate::protocol::{
    CircId, DestroyReason, ErrorCode, LayerBody, LinkErrorCode, LinkMsg, RelayCmd, decode, encode,
};
use crate::transport::{
    Connection, Link, LinkReader, Timeouts, handshake_inbound, handshake_outbound,
};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub circuits_per_link: usize,
    pub total_circuits: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            circuits_per_link: 128,
            total_circuits: 4096,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub nickname: String,
    pub role: Role,
    pub listen: SocketAddr,
    pub timeouts: Timeouts,
    pub limits: Limits,
}

impl RelayConfig {
    pub fn new(nickname: impl Into<String>, role: Role, listen: SocketAddr) -> Self {
        Self {
            nickname: nickname.into(),
            role,
            listen,
            timeouts: Timeouts::default(),
            limits: Limits::default(),
        }
    }
}

/// A bound relay, ready to [`serve`](Relay::serve).
pub struct Relay {
    inner: Arc<Inner>,
    listener: TcpListener,
}

struct Inner {
    keys: RelayKeys,
    nickname: String,
    role: Role,
    local_addr: SocketAddr,
    descriptor: RelayDescriptor,
    timeouts: Timeouts,
    limits: Limits,
    table: Mutex<Table>,
    out_links: tokio::sync::Mutex<HashMap<SocketAddr, Link>>,
}

#[derive(Default)]
struct Table {
    /// (inbound link id, inbound circuit id) → circuit
    by_in: HashMap<(u64, CircId), Arc<Circuit>>,
    /// (outbound link id, outbound circuit id) → circuit
    by_out: HashMap<(u64, CircId), Arc<Circuit>>,
}

struct Circuit {
    inbound: Link,
    in_circ: CircId,
    forward: Mutex<CellCipher>,
    /// Async lock: sealing and queueing a backward cell must happen together
    /// so cells leave in counter order.
    backward: tokio::sync::Mutex<CellCipher>,
    next: Mutex<Next>,
    closed: AtomicBool,
}

#[derive(Clone)]
enum Next {
    None,
    /// EXTEND accepted; connecting to the next relay.
    Connecting,
    /// CREATE sent on `link` as `circ`; waiting for CREATED.
    Extending {
        link: Link,
        circ: CircId,
    },
    Open {
        link: Link,
        circ: CircId,
    },
}

impl Next {
    fn out(&self) -> Option<(&Link, CircId)> {
        match self {
            Next::Extending { link, circ } | Next::Open { link, circ } => Some((link, *circ)),
            Next::None | Next::Connecting => None,
        }
    }
}

impl Relay {
    pub async fn bind(config: RelayConfig, keys: RelayKeys) -> Result<Self, NetError> {
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
        let descriptor = RelayDescriptor::sign(&keys, &config.nickname, config.role, local_addr);
        Ok(Self {
            inner: Arc::new(Inner {
                keys,
                nickname: config.nickname,
                role: config.role,
                local_addr,
                descriptor,
                timeouts: config.timeouts,
                limits: config.limits,
                table: Mutex::new(Table::default()),
                out_links: tokio::sync::Mutex::new(HashMap::new()),
            }),
            listener,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    pub fn node_id(&self) -> NodeId {
        self.inner.keys.node_id()
    }

    /// Signed descriptor for this relay's current address and onion key.
    pub fn descriptor(&self) -> RelayDescriptor {
        self.inner.descriptor.clone()
    }

    /// Accept links until the task is cancelled.
    pub async fn serve(self) -> Result<(), NetError> {
        let span = info_span!(
            "relay",
            name = %self.inner.nickname,
            role = %self.inner.role,
            id = %self.inner.keys.node_id().short(),
        );
        async move {
            info!(
                listen = %self.inner.local_addr,
                identity = %self.inner.keys.node_id(),
                "relay started"
            );
            loop {
                let (stream, peer) = match self.listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let inner = Arc::clone(&self.inner);
                tokio::spawn(
                    inner
                        .handle_inbound(stream, peer)
                        .instrument(tracing::Span::current()),
                );
            }
        }
        .instrument(span)
        .await
    }
}

impl Inner {
    fn fail_detail(&self, detail: &str) -> String {
        format!("{} ({}): {detail}", self.nickname, self.role)
    }

    // ------------------------------------------------------------ inbound

    async fn handle_inbound(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) {
        info!(%peer, "inbound link opened");
        match self.serve_inbound(stream).await {
            Ok(()) => info!(%peer, "inbound link closed"),
            Err(e) => warn!(%peer, error = %e, "inbound link closed with error"),
        }
    }

    async fn serve_inbound(self: &Arc<Self>, stream: TcpStream) -> Result<(), NetError> {
        let mut conn = Connection::new(stream)?;
        let peer_role = handshake_inbound(&mut conn, self.role, self.timeouts.handshake).await?;
        info!(%peer_role, "link handshake complete");
        let (link, mut reader) = conn.into_link();

        let result = loop {
            let msg = match reader.recv(Some(self.timeouts.idle)).await {
                Ok(Some(msg)) => msg,
                Ok(None) => break Ok(()),
                Err(e @ NetError::Decode(_)) => {
                    let _ = link
                        .send(LinkMsg::LinkError {
                            code: LinkErrorCode::Malformed,
                            detail: "could not decode message".into(),
                        })
                        .await;
                    break Err(e);
                }
                Err(e) => break Err(e),
            };
            match msg {
                LinkMsg::Create { circ, request } => self.on_create(&link, circ, request).await,
                LinkMsg::Relay { circ, cell } => self.on_forward_cell(&link, circ, cell).await,
                LinkMsg::Destroy { circ, reason } => {
                    if let Some(circuit) = self.lookup_in(link.id(), circ) {
                        self.teardown(&circuit, reason, false, true).await;
                    }
                }
                other => {
                    let detail = format!("unexpected {other:?} on inbound link");
                    let _ = link
                        .send(LinkMsg::LinkError {
                            code: LinkErrorCode::Malformed,
                            detail: detail.clone(),
                        })
                        .await;
                    break Err(NetError::Protocol(detail));
                }
            }
        };

        let orphans: Vec<_> = {
            let table = self.table.lock().unwrap();
            table
                .by_in
                .iter()
                .filter(|((link_id, _), _)| *link_id == link.id())
                .map(|(_, c)| Arc::clone(c))
                .collect()
        };
        for circuit in orphans {
            self.teardown(&circuit, DestroyReason::LinkClosed, false, true)
                .await;
        }
        result
    }

    async fn on_create(&self, link: &Link, circ: CircId, request: CreateRequest) {
        let refuse = |reason| LinkMsg::Destroy { circ, reason };
        let admission = {
            let table = self.table.lock().unwrap();
            let on_link = table.by_in.keys().filter(|(l, _)| *l == link.id()).count();
            if circ == 0 || table.by_in.contains_key(&(link.id(), circ)) {
                Err(DestroyReason::ProtocolViolation)
            } else if on_link >= self.limits.circuits_per_link
                || table.by_in.len() >= self.limits.total_circuits
            {
                Err(DestroyReason::ResourceLimit)
            } else {
                Ok(())
            }
        };
        if let Err(reason) = admission {
            warn!(circ, ?reason, "refused CREATE");
            let _ = link.send(refuse(reason)).await;
            return;
        }

        let (reply, keys) = match ntor::server_respond(&self.keys, &request) {
            Ok(ok) => ok,
            Err(e) => {
                let reason = match e {
                    CryptoError::WrongRelay => DestroyReason::WrongRelay,
                    _ => DestroyReason::ProtocolViolation,
                };
                warn!(circ, error = %e, "handshake failed");
                let _ = link.send(refuse(reason)).await;
                return;
            }
        };

        let circuit = Arc::new(Circuit {
            inbound: link.clone(),
            in_circ: circ,
            forward: Mutex::new(CellCipher::new(&keys.forward, Direction::Forward)),
            backward: tokio::sync::Mutex::new(CellCipher::new(&keys.backward, Direction::Backward)),
            next: Mutex::new(Next::None),
            closed: AtomicBool::new(false),
        });
        drop(keys);
        self.table
            .lock()
            .unwrap()
            .by_in
            .insert((link.id(), circ), circuit);
        if link.send(LinkMsg::Created { circ, reply }).await.is_ok() {
            info!(circ, "circuit created");
        }
    }

    async fn on_forward_cell(self: &Arc<Self>, link: &Link, circ: CircId, cell: Vec<u8>) {
        let Some(circuit) = self.lookup_in(link.id(), circ) else {
            debug!(circ, "cell for unknown circuit");
            let _ = link
                .send(LinkMsg::Destroy {
                    circ,
                    reason: DestroyReason::ProtocolViolation,
                })
                .await;
            return;
        };

        let opened = circuit.forward.lock().unwrap().open(&cell);
        let plaintext = match opened {
            Ok(p) => p,
            Err(e) => {
                warn!(circ, error = %e, "forward cell rejected; destroying circuit");
                self.teardown(&circuit, DestroyReason::AuthenticationFailed, true, true)
                    .await;
                return;
            }
        };
        let Ok(body) = decode::<LayerBody>(&plaintext) else {
            warn!(circ, "undecodable layer; destroying circuit");
            self.teardown(&circuit, DestroyReason::ProtocolViolation, true, true)
                .await;
            return;
        };

        match body {
            LayerBody::Relay(inner) => {
                let next = circuit.next.lock().unwrap().clone();
                match next {
                    Next::Open {
                        link: out,
                        circ: out_circ,
                    } => {
                        debug!(circ, out_circ, bytes = inner.len(), "forwarding cell");
                        let sent = out
                            .send(LinkMsg::Relay {
                                circ: out_circ,
                                cell: inner,
                            })
                            .await;
                        if sent.is_err() {
                            self.teardown(&circuit, DestroyReason::NextHopFailed, true, false)
                                .await;
                        }
                    }
                    _ => {
                        warn!(circ, "cell to relay onward but circuit is not extended");
                        self.teardown(&circuit, DestroyReason::ProtocolViolation, true, true)
                            .await;
                    }
                }
            }
            LayerBody::Cmd(cmd) => self.on_command(&circuit, cmd).await,
        }
    }

    async fn on_command(self: &Arc<Self>, circuit: &Arc<Circuit>, cmd: RelayCmd) {
        let circ = circuit.in_circ;
        match cmd {
            RelayCmd::Extend { next_hop, request } => {
                let refusal = if self.role.expected_downstream().is_none() {
                    Some((
                        ErrorCode::NotAllowed,
                        "exit relays do not extend".to_owned(),
                    ))
                } else if !matches!(*circuit.next.lock().unwrap(), Next::None) {
                    Some((
                        ErrorCode::NotAllowed,
                        "circuit is already extended".to_owned(),
                    ))
                } else if !next_hop.ip().is_loopback() {
                    Some((
                        ErrorCode::ExtendRejected,
                        format!("{next_hop} is not a loopback address"),
                    ))
                } else if next_hop == self.local_addr {
                    Some((
                        ErrorCode::ExtendRejected,
                        "cannot extend to itself".to_owned(),
                    ))
                } else {
                    None
                };
                if let Some((code, detail)) = refusal {
                    warn!(circ, ?code, "refused EXTEND");
                    self.reply_error(circuit, code, &detail).await;
                    return;
                }
                *circuit.next.lock().unwrap() = Next::Connecting;
                let this = Arc::clone(self);
                let circuit = Arc::clone(circuit);
                tokio::spawn(
                    async move { this.extend(circuit, next_hop, request).await }
                        .instrument(tracing::Span::current()),
                );
            }
            RelayCmd::Data { bytes } => {
                let is_last = matches!(*circuit.next.lock().unwrap(), Next::None);
                if self.role == Role::Exit && is_last {
                    info!(
                        circ,
                        bytes = bytes.len(),
                        "DATA delivered to test echo service"
                    );
                    let reply = LayerBody::Cmd(RelayCmd::Data {
                        bytes: echo_service(bytes),
                    });
                    self.send_backward(circuit, reply).await;
                } else {
                    self.reply_error(
                        circuit,
                        ErrorCode::NotAllowed,
                        "only an exit at the end of a circuit accepts DATA",
                    )
                    .await;
                }
            }
            RelayCmd::Extended { .. } | RelayCmd::Error { .. } => {
                warn!(circ, "client sent a relay-only command");
                self.teardown(circuit, DestroyReason::ProtocolViolation, true, true)
                    .await;
            }
        }
    }

    async fn extend(
        self: Arc<Self>,
        circuit: Arc<Circuit>,
        next_hop: SocketAddr,
        request: CreateRequest,
    ) {
        let circ = circuit.in_circ;
        let link = match self.outbound_link(next_hop).await {
            Ok(link) => link,
            Err(e) => {
                warn!(circ, %next_hop, error = %e, "cannot reach next hop");
                *circuit.next.lock().unwrap() = Next::None;
                self.reply_error(
                    &circuit,
                    ErrorCode::NextHopUnreachable,
                    &format!("cannot reach {next_hop}: {e}"),
                )
                .await;
                return;
            }
        };

        let out_circ = {
            let mut table = self.table.lock().unwrap();
            if circuit.closed.load(Ordering::SeqCst) {
                return;
            }
            let out_circ = loop {
                let id = u32::from_le_bytes(crate::crypto::random_bytes::<4>());
                if id != 0 && !table.by_out.contains_key(&(link.id(), id)) {
                    break id;
                }
            };
            table
                .by_out
                .insert((link.id(), out_circ), Arc::clone(&circuit));
            *circuit.next.lock().unwrap() = Next::Extending {
                link: link.clone(),
                circ: out_circ,
            };
            out_circ
        };

        info!(circ, out_circ, %next_hop, "extending circuit");
        if link
            .send(LinkMsg::Create {
                circ: out_circ,
                request,
            })
            .await
            .is_err()
        {
            self.abandon_extend(
                &circuit,
                &link,
                out_circ,
                ErrorCode::NextHopUnreachable,
                "link to next hop closed",
            )
            .await;
            return;
        }

        // Watchdog: give up if CREATED does not arrive in time.
        tokio::time::sleep(self.timeouts.handshake).await;
        let still_waiting = matches!(
            &*circuit.next.lock().unwrap(),
            Next::Extending { link: l, circ: c } if l.id() == link.id() && *c == out_circ
        );
        if still_waiting {
            warn!(circ, out_circ, "next hop did not answer CREATE in time");
            let _ = link
                .send(LinkMsg::Destroy {
                    circ: out_circ,
                    reason: DestroyReason::Timeout,
                })
                .await;
            self.abandon_extend(
                &circuit,
                &link,
                out_circ,
                ErrorCode::Timeout,
                "next hop did not answer in time",
            )
            .await;
        }
    }

    /// Forget a pending extension and tell the client why.
    async fn abandon_extend(
        &self,
        circuit: &Arc<Circuit>,
        link: &Link,
        out_circ: CircId,
        code: ErrorCode,
        detail: &str,
    ) {
        self.table
            .lock()
            .unwrap()
            .by_out
            .remove(&(link.id(), out_circ));
        *circuit.next.lock().unwrap() = Next::None;
        self.reply_error(circuit, code, detail).await;
    }

    // ----------------------------------------------------------- outbound

    async fn outbound_link(self: &Arc<Self>, addr: SocketAddr) -> Result<Link, NetError> {
        let expected = self
            .role
            .expected_downstream()
            .expect("only entry and middle relays extend");
        let mut links = self.out_links.lock().await;
        if let Some(link) = links.get(&addr)
            && !link.is_closed()
        {
            return Ok(link.clone());
        }
        let mut conn = Connection::connect(addr, self.timeouts.connect).await?;
        handshake_outbound(&mut conn, self.role, expected, self.timeouts.handshake).await?;
        let (link, reader) = conn.into_link();
        links.insert(addr, link.clone());
        info!(next_hop = %addr, "outbound link opened");
        tokio::spawn(
            Arc::clone(self)
                .serve_outbound(link.clone(), reader)
                .instrument(tracing::Span::current()),
        );
        Ok(link)
    }

    async fn serve_outbound(self: Arc<Self>, link: Link, mut reader: LinkReader) {
        let result: Result<(), NetError> = loop {
            let msg = match reader.recv(None).await {
                Ok(Some(msg)) => msg,
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            };
            match msg {
                LinkMsg::Created { circ, reply } => {
                    let Some(circuit) = self.lookup_out(link.id(), circ) else {
                        continue;
                    };
                    let became_open = {
                        let mut next = circuit.next.lock().unwrap();
                        if matches!(&*next, Next::Extending { circ: c, .. } if *c == circ) {
                            *next = Next::Open {
                                link: link.clone(),
                                circ,
                            };
                            true
                        } else {
                            false
                        }
                    };
                    if became_open {
                        info!(circ = circuit.in_circ, out_circ = circ, "circuit extended");
                        self.send_backward(&circuit, LayerBody::Cmd(RelayCmd::Extended { reply }))
                            .await;
                    }
                }
                LinkMsg::Relay { circ, cell } => {
                    let Some(circuit) = self.lookup_out(link.id(), circ) else {
                        continue;
                    };
                    let open = matches!(&*circuit.next.lock().unwrap(), Next::Open { .. });
                    if open {
                        debug!(circ = circuit.in_circ, bytes = cell.len(), "returning cell");
                        self.send_backward(&circuit, LayerBody::Relay(cell)).await;
                    }
                }
                LinkMsg::Destroy { circ, reason } => {
                    let Some(circuit) = self.lookup_out(link.id(), circ) else {
                        continue;
                    };
                    let extending =
                        matches!(&*circuit.next.lock().unwrap(), Next::Extending { .. });
                    if extending {
                        // The next relay refused CREATE: keep the circuit up to
                        // here and tell the client.
                        self.abandon_extend(
                            &circuit,
                            &link,
                            circ,
                            ErrorCode::ExtendRejected,
                            &format!("next hop refused the circuit ({reason:?})"),
                        )
                        .await;
                    } else {
                        self.teardown(&circuit, reason, true, false).await;
                    }
                }
                other => {
                    break Err(NetError::Protocol(format!(
                        "unexpected {other:?} on outbound link"
                    )));
                }
            }
        };
        if let Err(e) = &result {
            warn!(next_hop = %link.peer_addr(), error = %e, "outbound link failed");
        } else {
            info!(next_hop = %link.peer_addr(), "outbound link closed");
        }

        {
            let mut links = self.out_links.lock().await;
            if links
                .get(&link.peer_addr())
                .is_some_and(|l| l.id() == link.id())
            {
                links.remove(&link.peer_addr());
            }
        }
        let orphans: Vec<_> = {
            let table = self.table.lock().unwrap();
            table
                .by_out
                .iter()
                .filter(|((link_id, _), _)| *link_id == link.id())
                .map(|(_, c)| Arc::clone(c))
                .collect()
        };
        for circuit in orphans {
            self.teardown(&circuit, DestroyReason::NextHopFailed, true, false)
                .await;
        }
    }

    // ------------------------------------------------------------ helpers

    fn lookup_in(&self, link: u64, circ: CircId) -> Option<Arc<Circuit>> {
        self.table.lock().unwrap().by_in.get(&(link, circ)).cloned()
    }

    fn lookup_out(&self, link: u64, circ: CircId) -> Option<Arc<Circuit>> {
        self.table
            .lock()
            .unwrap()
            .by_out
            .get(&(link, circ))
            .cloned()
    }

    /// Seal `body` with this hop's backward key and send it toward the client.
    async fn send_backward(&self, circuit: &Arc<Circuit>, body: LayerBody) {
        let plaintext = encode(&body);
        let mut cipher = circuit.backward.lock().await;
        let cell = match cipher.seal(&plaintext) {
            Ok(cell) => cell,
            Err(e) => {
                drop(cipher);
                warn!(circ = circuit.in_circ, error = %e, "cannot seal backward cell");
                self.teardown(circuit, DestroyReason::ResourceLimit, true, true)
                    .await;
                return;
            }
        };
        let _ = circuit
            .inbound
            .send(LinkMsg::Relay {
                circ: circuit.in_circ,
                cell,
            })
            .await;
    }

    async fn reply_error(&self, circuit: &Arc<Circuit>, code: ErrorCode, detail: &str) {
        if circuit.closed.load(Ordering::SeqCst) {
            return;
        }
        let body = LayerBody::Cmd(RelayCmd::Error {
            code,
            detail: self.fail_detail(detail),
        });
        self.send_backward(circuit, body).await;
    }

    /// Remove a circuit and optionally tell the neighbours.
    async fn teardown(
        &self,
        circuit: &Arc<Circuit>,
        reason: DestroyReason,
        notify_inbound: bool,
        notify_outbound: bool,
    ) {
        if circuit.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let next = {
            let mut table = self.table.lock().unwrap();
            table.by_in.remove(&(circuit.inbound.id(), circuit.in_circ));
            let next = std::mem::replace(&mut *circuit.next.lock().unwrap(), Next::None);
            if let Some((link, out_circ)) = next.out() {
                table.by_out.remove(&(link.id(), out_circ));
            }
            next
        };
        info!(circ = circuit.in_circ, ?reason, "circuit destroyed");
        if notify_inbound {
            let _ = circuit
                .inbound
                .send(LinkMsg::Destroy {
                    circ: circuit.in_circ,
                    reason,
                })
                .await;
        }
        if notify_outbound && let Some((link, out_circ)) = next.out() {
            let _ = link
                .send(LinkMsg::Destroy {
                    circ: out_circ,
                    reason,
                })
                .await;
        }
    }
}

/// Test service run by exit relays: returns the data unchanged.
/// Real exit traffic (TCP streams to websites) is a later milestone.
fn echo_service(data: Vec<u8>) -> Vec<u8> {
    data
}
