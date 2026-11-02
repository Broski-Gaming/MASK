//! MORP relay (entry, middle, exit, or rendezvous).
//!
//! A relay keeps a table of circuits. Each circuit has:
//! - an inbound side: the link toward the circuit's creator and its ID there;
//! - the hop's forward/backward [`CellCipher`]s from the ntor handshake;
//! - optionally an outbound side: a link to the next relay and the circuit
//!   ID used on that link.
//!
//! Forward cells (from the inbound link) are opened with this hop's key. The
//! plaintext is either another sealed cell to pass to the next hop, or a
//! command for this hop. Backward cells (from the outbound link) and this
//! hop's own replies are sealed with the backward key and sent toward the
//! circuit's creator, adding one layer.
//!
//! **Rendezvous-role relays** (always the last hop) additionally act as
//! hidden-service introduction points and rendezvous points:
//! - `EstablishIntro` registers a service's per-intro auth key on its circuit;
//!   `Introduce1` from a client is passed to that circuit as `Introduce2`.
//! - `EstablishRendezvous` parks a client circuit under a single-use cookie;
//!   `Rendezvous1` from a service with the same cookie *joins* the two
//!   circuits. After that, `Stream` cells from one side are re-sealed for the
//!   other. Their contents are end-to-end encrypted between client and
//!   service, so this relay cannot read them.
//!
//! Links to the next relay are shared by every circuit going there, and
//! circuit IDs keep them apart.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
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
    ConnectPolicy, Connection, Link, LinkReader, Timeouts, handshake_inbound, handshake_outbound,
};

/// Largest introduction payload accepted.
const MAX_INTRO_PAYLOAD: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub circuits_per_link: usize,
    pub total_circuits: usize,
    /// Introduction points registered at once (rendezvous role).
    pub intro_points: usize,
    /// Client circuits waiting at the rendezvous point at once.
    pub pending_rendezvous: usize,
    /// How long a rendezvous cookie stays valid.
    pub rendezvous_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            circuits_per_link: 128,
            total_circuits: 4096,
            intro_points: 256,
            pending_rendezvous: 1024,
            rendezvous_timeout: Duration::from_secs(60),
        }
    }
}

/// Test hook: called with every plaintext this relay can decrypt (the
/// contents of its own onion layer). Used to prove what a relay can and
/// cannot see. `None` in normal operation.
#[derive(Clone)]
pub struct Observer(pub Arc<ObserveFn>);

/// `(relay nickname, decrypted layer plaintext)`.
pub type ObserveFn = dyn Fn(&str, &[u8]) + Send + Sync;

impl std::fmt::Debug for Observer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Observer")
    }
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub nickname: String,
    pub role: Role,
    pub listen: SocketAddr,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub policy: ConnectPolicy,
    pub observer: Option<Observer>,
}

impl RelayConfig {
    pub fn new(nickname: impl Into<String>, role: Role, listen: SocketAddr) -> Self {
        Self {
            nickname: nickname.into(),
            role,
            listen,
            timeouts: Timeouts::default(),
            limits: Limits::default(),
            policy: ConnectPolicy::allow_all(),
            observer: None,
        }
    }
}

/// A bound relay, ready to [`serve`](Relay::serve).
pub struct Relay {
    inner: Arc<Inner>,
    listener: TcpListener,
}

/// Inspect or stop a running relay.
#[derive(Clone)]
pub struct RelayHandle {
    inner: Arc<Inner>,
}

/// A snapshot of relay activity, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub open_circuits: usize,
    pub intro_points: usize,
    pub pending_rendezvous: usize,
    /// Circuits currently joined to another circuit (counts both sides).
    pub joined_circuits: usize,
    pub circuits_created: u64,
    /// Cells passed to the next hop.
    pub cells_forwarded: u64,
    /// Cells passed back toward a circuit's creator.
    pub cells_returned: u64,
    pub introductions: u64,
    pub rendezvous_joins: u64,
    /// Stream cells re-sealed from one joined circuit to the other.
    pub stream_cells: u64,
}

#[derive(Default)]
struct Counters {
    circuits_created: AtomicU64,
    cells_forwarded: AtomicU64,
    cells_returned: AtomicU64,
    introductions: AtomicU64,
    rendezvous_joins: AtomicU64,
    stream_cells: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

struct Inner {
    keys: RelayKeys,
    nickname: String,
    role: Role,
    local_addr: SocketAddr,
    descriptor: RelayDescriptor,
    timeouts: Timeouts,
    limits: Limits,
    policy: ConnectPolicy,
    observer: Option<Observer>,
    table: Mutex<Table>,
    hs: Mutex<HsTable>,
    out_links: tokio::sync::Mutex<HashMap<SocketAddr, Link>>,
    counters: Counters,
    shutdown: CancellationToken,
}

#[derive(Default)]
struct Table {
    /// (inbound link id, inbound circuit id) → circuit
    by_in: HashMap<(u64, CircId), Arc<Circuit>>,
    /// (outbound link id, outbound circuit id) → circuit
    by_out: HashMap<(u64, CircId), Arc<Circuit>>,
}

/// Hidden-service state of a rendezvous-role relay.
#[derive(Default)]
struct HsTable {
    /// Intro auth key → the service's intro circuit.
    intros: HashMap<[u8; 32], Arc<Circuit>>,
    /// Rendezvous cookie → waiting client circuit and when it registered.
    cookies: HashMap<[u8; 32], (Arc<Circuit>, Instant)>,
}

struct Circuit {
    inbound: Link,
    in_circ: CircId,
    forward: Mutex<CellCipher>,
    /// Async lock: sealing and queueing a backward cell must happen together
    /// so cells leave in counter order.
    backward: tokio::sync::Mutex<CellCipher>,
    next: Mutex<Next>,
    hs: Mutex<CircHs>,
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

/// What a circuit is doing at a rendezvous-role relay.
enum CircHs {
    None,
    /// A service's introduction circuit.
    Intro([u8; 32]),
    /// A client circuit waiting under a cookie.
    Waiting([u8; 32]),
    /// Joined to another circuit at this rendezvous point.
    Joined(Weak<Circuit>),
}

impl Relay {
    pub async fn bind(config: RelayConfig, keys: RelayKeys) -> Result<Self, NetError> {
        if !config.role.is_relay() {
            return Err(NetError::InvalidConfig(
                "a relay's role must be entry, middle, exit, or rendezvous".into(),
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
                policy: config.policy,
                observer: config.observer,
                table: Mutex::new(Table::default()),
                hs: Mutex::new(HsTable::default()),
                out_links: tokio::sync::Mutex::new(HashMap::new()),
                counters: Counters::default(),
                shutdown: CancellationToken::new(),
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

    pub fn handle(&self) -> RelayHandle {
        RelayHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Accept links until [`RelayHandle::shutdown`] is called.
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
                let accepted = tokio::select! {
                    accepted = self.listener.accept() => accepted,
                    _ = self.inner.shutdown.cancelled() => break,
                };
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
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
            info!("relay stopped");
            Ok(())
        }
        .instrument(span)
        .await
    }
}

impl RelayHandle {
    pub fn stats(&self) -> RelayStats {
        let (open_circuits, joined_circuits) = {
            let table = self.inner.table.lock().unwrap();
            let joined = table
                .by_in
                .values()
                .filter(|c| matches!(*c.hs.lock().unwrap(), CircHs::Joined(_)))
                .count();
            (table.by_in.len(), joined)
        };
        let (intro_points, pending_rendezvous) = {
            let hs = self.inner.hs.lock().unwrap();
            (hs.intros.len(), hs.cookies.len())
        };
        let c = &self.inner.counters;
        RelayStats {
            open_circuits,
            intro_points,
            pending_rendezvous,
            joined_circuits,
            circuits_created: c.circuits_created.load(Ordering::Relaxed),
            cells_forwarded: c.cells_forwarded.load(Ordering::Relaxed),
            cells_returned: c.cells_returned.load(Ordering::Relaxed),
            introductions: c.introductions.load(Ordering::Relaxed),
            rendezvous_joins: c.rendezvous_joins.load(Ordering::Relaxed),
            stream_cells: c.stream_cells.load(Ordering::Relaxed),
        }
    }

    /// Stop accepting, close every link, and destroy every circuit.
    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    pub fn descriptor(&self) -> RelayDescriptor {
        self.inner.descriptor.clone()
    }
}

impl Inner {
    fn fail_detail(&self, detail: &str) -> String {
        format!("{} ({}): {detail}", self.nickname, self.role)
    }

    fn observe(&self, plaintext: &[u8]) {
        if let Some(observer) = &self.observer {
            (observer.0)(&self.nickname, plaintext);
        }
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
            let received = tokio::select! {
                received = reader.recv(Some(self.timeouts.idle)) => received,
                _ = self.shutdown.cancelled() => break Ok(()),
            };
            let msg = match received {
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
                // Idle links are closed only if they carry no circuits: a
                // hidden service's introduction circuits are legitimately quiet.
                Err(NetError::Timeout) if self.link_has_circuits(link.id()) => continue,
                Err(NetError::Timeout) => {
                    info!("closing idle link with no circuits");
                    break Ok(());
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
            hs: Mutex::new(CircHs::None),
            closed: AtomicBool::new(false),
        });
        drop(keys);
        self.table
            .lock()
            .unwrap()
            .by_in
            .insert((link.id(), circ), circuit);
        if link.send(LinkMsg::Created { circ, reply }).await.is_ok() {
            bump(&self.counters.circuits_created);
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
        self.observe(&plaintext);
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
                        } else {
                            bump(&self.counters.cells_forwarded);
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

    fn is_last_hop(&self, circuit: &Circuit) -> bool {
        matches!(*circuit.next.lock().unwrap(), Next::None)
    }

    async fn on_command(self: &Arc<Self>, circuit: &Arc<Circuit>, cmd: RelayCmd) {
        let circ = circuit.in_circ;
        match cmd {
            RelayCmd::Extend { next_hop, request } => {
                let refusal = if !self.role.extends() {
                    Some((
                        ErrorCode::NotAllowed,
                        format!("{} relays do not extend", self.role),
                    ))
                } else if !self.is_last_hop(circuit) {
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
                if self.role == Role::Exit && self.is_last_hop(circuit) {
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
            cmd @ (RelayCmd::EstablishIntro { .. }
            | RelayCmd::Introduce1 { .. }
            | RelayCmd::EstablishRendezvous { .. }
            | RelayCmd::Rendezvous1 { .. }
            | RelayCmd::Stream { .. }) => {
                if self.role != Role::Rendezvous || !self.is_last_hop(circuit) {
                    self.reply_error(
                        circuit,
                        ErrorCode::NotAllowed,
                        "hidden-service commands go to the last hop, a rendezvous relay",
                    )
                    .await;
                    return;
                }
                self.on_hidden_service(circuit, cmd).await;
            }
            RelayCmd::Extended { .. }
            | RelayCmd::Error { .. }
            | RelayCmd::IntroEstablished
            | RelayCmd::IntroduceAck
            | RelayCmd::Introduce2 { .. }
            | RelayCmd::RendezvousEstablished
            | RelayCmd::Rendezvous2 { .. } => {
                warn!(circ, "creator sent a relay-only command");
                self.teardown(circuit, DestroyReason::ProtocolViolation, true, true)
                    .await;
            }
        }
    }

    // ------------------------------------------------- hidden services

    async fn on_hidden_service(&self, circuit: &Arc<Circuit>, cmd: RelayCmd) {
        let circ = circuit.in_circ;
        let unused = matches!(*circuit.hs.lock().unwrap(), CircHs::None);
        match cmd {
            RelayCmd::EstablishIntro {
                auth_key,
                signature,
            } => {
                if !unused {
                    return self
                        .reply_error(circuit, ErrorCode::NotAllowed, "circuit already in use")
                        .await;
                }
                if crate::hs::crypto::verify_establish_intro(
                    &auth_key,
                    &self.keys.node_id(),
                    &signature,
                )
                .is_err()
                {
                    warn!(circ, "EstablishIntro with a bad signature");
                    return self
                        .reply_error(circuit, ErrorCode::Rejected, "bad intro signature")
                        .await;
                }
                let refusal = {
                    let mut hs = self.hs.lock().unwrap();
                    if hs.intros.len() >= self.limits.intro_points {
                        Some((ErrorCode::ResourceLimit, "too many intro points"))
                    } else if hs
                        .intros
                        .get(&auth_key)
                        .is_some_and(|c| !c.closed.load(Ordering::SeqCst))
                    {
                        Some((ErrorCode::Rejected, "auth key already registered"))
                    } else {
                        hs.intros.insert(auth_key, Arc::clone(circuit));
                        *circuit.hs.lock().unwrap() = CircHs::Intro(auth_key);
                        None
                    }
                };
                match refusal {
                    Some((code, detail)) => self.reply_error(circuit, code, detail).await,
                    None => {
                        info!(circ, "introduction point established");
                        self.send_backward(circuit, LayerBody::Cmd(RelayCmd::IntroEstablished))
                            .await;
                    }
                }
            }

            RelayCmd::Introduce1 { auth_key, payload } => {
                if !unused || payload.len() > MAX_INTRO_PAYLOAD {
                    return self
                        .reply_error(circuit, ErrorCode::Rejected, "invalid introduction")
                        .await;
                }
                let service = self
                    .hs
                    .lock()
                    .unwrap()
                    .intros
                    .get(&auth_key)
                    .filter(|c| !c.closed.load(Ordering::SeqCst))
                    .cloned();
                let Some(service) = service else {
                    return self
                        .reply_error(
                            circuit,
                            ErrorCode::UnknownService,
                            "no service registered for this intro key",
                        )
                        .await;
                };
                bump(&self.counters.introductions);
                info!(circ, "forwarding introduction to service");
                self.send_backward(&service, LayerBody::Cmd(RelayCmd::Introduce2 { payload }))
                    .await;
                self.send_backward(circuit, LayerBody::Cmd(RelayCmd::IntroduceAck))
                    .await;
            }

            RelayCmd::EstablishRendezvous { cookie } => {
                if !unused {
                    return self
                        .reply_error(circuit, ErrorCode::NotAllowed, "circuit already in use")
                        .await;
                }
                let refusal = {
                    let mut hs = self.hs.lock().unwrap();
                    let ttl = self.limits.rendezvous_timeout;
                    hs.cookies.retain(|_, (c, at)| {
                        at.elapsed() < ttl && !c.closed.load(Ordering::SeqCst)
                    });
                    if hs.cookies.len() >= self.limits.pending_rendezvous {
                        Some((ErrorCode::ResourceLimit, "too many pending rendezvous"))
                    } else {
                        match hs.cookies.entry(cookie) {
                            Entry::Occupied(_) => {
                                Some((ErrorCode::BadCookie, "cookie already in use"))
                            }
                            Entry::Vacant(slot) => {
                                slot.insert((Arc::clone(circuit), Instant::now()));
                                *circuit.hs.lock().unwrap() = CircHs::Waiting(cookie);
                                None
                            }
                        }
                    }
                };
                match refusal {
                    Some((code, detail)) => self.reply_error(circuit, code, detail).await,
                    None => {
                        info!(circ, "rendezvous point established");
                        self.send_backward(
                            circuit,
                            LayerBody::Cmd(RelayCmd::RendezvousEstablished),
                        )
                        .await;
                    }
                }
            }

            RelayCmd::Rendezvous1 { cookie, payload } => {
                if !unused || payload.len() > MAX_INTRO_PAYLOAD {
                    return self
                        .reply_error(circuit, ErrorCode::Rejected, "invalid rendezvous")
                        .await;
                }
                // Single use: the cookie is removed whether or not it matches.
                let waiting = self.hs.lock().unwrap().cookies.remove(&cookie);
                let client = match waiting {
                    Some((client, at))
                        if at.elapsed() < self.limits.rendezvous_timeout
                            && !client.closed.load(Ordering::SeqCst) =>
                    {
                        client
                    }
                    _ => {
                        warn!(circ, "Rendezvous1 with unknown or expired cookie");
                        return self
                            .reply_error(
                                circuit,
                                ErrorCode::BadCookie,
                                "unknown, expired, or used cookie",
                            )
                            .await;
                    }
                };
                *client.hs.lock().unwrap() = CircHs::Joined(Arc::downgrade(circuit));
                *circuit.hs.lock().unwrap() = CircHs::Joined(Arc::downgrade(&client));
                bump(&self.counters.rendezvous_joins);
                info!(
                    client_circ = client.in_circ,
                    service_circ = circ,
                    "circuits joined"
                );
                self.send_backward(&client, LayerBody::Cmd(RelayCmd::Rendezvous2 { payload }))
                    .await;
            }

            RelayCmd::Stream { bytes } => {
                let peer = match &*circuit.hs.lock().unwrap() {
                    CircHs::Joined(peer) => peer.upgrade(),
                    _ => None,
                };
                match peer {
                    Some(peer) if !peer.closed.load(Ordering::SeqCst) => {
                        bump(&self.counters.stream_cells);
                        self.send_backward(&peer, LayerBody::Cmd(RelayCmd::Stream { bytes }))
                            .await;
                    }
                    _ if matches!(*circuit.hs.lock().unwrap(), CircHs::Joined(_)) => {
                        // The other side is gone.
                        self.teardown(circuit, DestroyReason::NextHopFailed, true, false)
                            .await;
                    }
                    _ => {
                        self.reply_error(
                            circuit,
                            ErrorCode::NotAllowed,
                            "circuit is not joined at this rendezvous point",
                        )
                        .await;
                    }
                }
            }

            _ => unreachable!("only hidden-service commands are routed here"),
        }
    }

    // ------------------------------------------------------- extending

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

    /// Forget a pending extension and tell the creator why.
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
        let allowed: Vec<Role> = [Role::Middle, Role::Exit, Role::Rendezvous]
            .into_iter()
            .filter(|r| self.role.can_extend_to(*r))
            .collect();
        let mut links = self.out_links.lock().await;
        if let Some(link) = links.get(&addr)
            && !link.is_closed()
        {
            return Ok(link.clone());
        }
        let origin = format!("relay:{}", self.nickname);
        let mut conn =
            Connection::connect_checked(addr, self.timeouts.connect, &self.policy, &origin).await?;
        handshake_outbound(&mut conn, self.role, &allowed, self.timeouts.handshake).await?;
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
            let received = tokio::select! {
                received = reader.recv(None) => received,
                _ = self.shutdown.cancelled() => break Ok(()),
            };
            let msg = match received {
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
                        bump(&self.counters.cells_returned);
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
                        // here and tell the creator.
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

    fn link_has_circuits(&self, link: u64) -> bool {
        self.table
            .lock()
            .unwrap()
            .by_in
            .keys()
            .any(|(l, _)| *l == link)
    }

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

    /// Seal `body` with this hop's backward key and send it toward the creator.
    async fn send_backward(&self, circuit: &Arc<Circuit>, body: LayerBody) {
        if circuit.closed.load(Ordering::SeqCst) {
            return;
        }
        let plaintext = encode(&body);
        let mut cipher = circuit.backward.lock().await;
        let cell = match cipher.seal(&plaintext) {
            Ok(cell) => cell,
            Err(e) => {
                drop(cipher);
                warn!(circ = circuit.in_circ, error = %e, "cannot seal backward cell");
                Box::pin(self.teardown(circuit, DestroyReason::ResourceLimit, true, true)).await;
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
        let body = LayerBody::Cmd(RelayCmd::Error {
            code,
            detail: self.fail_detail(detail),
        });
        self.send_backward(circuit, body).await;
    }

    /// Remove a circuit and optionally tell the neighbours. A circuit joined
    /// at this rendezvous point takes its partner down with it.
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
        let hs_state = std::mem::replace(&mut *circuit.hs.lock().unwrap(), CircHs::None);
        let partner = {
            let mut hs = self.hs.lock().unwrap();
            match hs_state {
                CircHs::Intro(key) => {
                    if hs.intros.get(&key).is_some_and(|c| Arc::ptr_eq(c, circuit)) {
                        hs.intros.remove(&key);
                    }
                    None
                }
                CircHs::Waiting(cookie) => {
                    if hs
                        .cookies
                        .get(&cookie)
                        .is_some_and(|(c, _)| Arc::ptr_eq(c, circuit))
                    {
                        hs.cookies.remove(&cookie);
                    }
                    None
                }
                CircHs::Joined(peer) => peer.upgrade(),
                CircHs::None => None,
            }
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
        if let Some(partner) = partner {
            Box::pin(self.teardown(&partner, DestroyReason::NextHopFailed, true, false)).await;
        }
    }
}

/// Test service run by exit relays: returns the data unchanged.
fn echo_service(data: Vec<u8>) -> Vec<u8> {
    data
}
