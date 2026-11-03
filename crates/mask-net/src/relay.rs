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
//!
//! **Links (v0.6).** Every link is a Noise session (see [`crate::transport`]).
//! Clients reach only entry relays (NK). Relay → relay links use IK, and the
//! accepting relay refuses any initiator whose link key is not a relay in
//! its [`TrustedRelays`] with the role allowed to open that link. A relay
//! extends only to relays it trusts, found by the identity in the client's
//! handshake, at the address in their signed descriptor, and inside the
//! network scope; arbitrary addresses are refused. Outbound links send
//! keepalive pings so a vanished machine is noticed even if TCP is not.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
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
use crate::scope::NetworkScope;
use crate::transport::{
    ConnectPolicy, Connection, Link, LinkKind, LinkReader, Timeouts, handshake_inbound,
    handshake_outbound,
};
use crate::trust::TrustedRelays;

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
    /// Inbound links (connections) open at once, including handshakes.
    pub max_links: usize,
    /// Inbound links open at once from one IP address.
    pub max_links_per_ip: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            circuits_per_link: 128,
            total_circuits: 4096,
            intro_points: 256,
            pending_rendezvous: 1024,
            rendezvous_timeout: Duration::from_secs(60),
            max_links: 2048,
            max_links_per_ip: 256,
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
    /// Address published in the descriptor, if different from the bound
    /// address (for example behind port forwarding). Must be inside the
    /// scope. `None` publishes the bound address.
    pub advertise: Option<SocketAddr>,
    /// Which addresses this relay may bind, publish, accept, and extend to.
    pub scope: NetworkScope,
    /// Operator-assigned machine label published in the descriptor.
    pub family: String,
    /// Relays this relay accepts links from and extends to.
    pub trusted: TrustedRelays,
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
            advertise: None,
            scope: NetworkScope::Loopback,
            family: String::new(),
            trusted: TrustedRelays::fixed(NetworkScope::Loopback),
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
    /// Inbound links currently open.
    pub open_links: usize,
    /// Connections refused: outside the scope, over a limit, or failing
    /// Noise authentication.
    pub links_refused: u64,
    /// Outbound links declared dead after unanswered keepalives.
    pub keepalive_failures: u64,
}

#[derive(Default)]
struct Counters {
    circuits_created: AtomicU64,
    cells_forwarded: AtomicU64,
    cells_returned: AtomicU64,
    introductions: AtomicU64,
    rendezvous_joins: AtomicU64,
    stream_cells: AtomicU64,
    links_refused: AtomicU64,
    keepalive_failures: AtomicU64,
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
    /// Outbound links by the next relay's identity.
    out_links: tokio::sync::Mutex<HashMap<NodeId, Link>>,
    counters: Counters,
    shutdown: CancellationToken,
    scope: NetworkScope,
    trusted: TrustedRelays,
    links: Arc<Semaphore>,
    links_per_ip: Mutex<HashMap<std::net::IpAddr, usize>>,
    tasks: TaskTracker,
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
        config.scope.check(config.listen)?;
        if !crate::descriptor::valid_label(&config.nickname, crate::descriptor::MAX_NICKNAME_LEN)
            || config.nickname.is_empty()
        {
            return Err(NetError::InvalidConfig(format!(
                "nickname \"{}\" must be 1-32 characters of a-z, 0-9, - and _",
                config.nickname
            )));
        }
        if !crate::descriptor::valid_label(&config.family, crate::descriptor::MAX_FAMILY_LEN) {
            return Err(NetError::InvalidConfig(format!(
                "family \"{}\" must be up to 32 characters of a-z, 0-9, - and _",
                config.family
            )));
        }
        if config.trusted.scope() != config.scope {
            return Err(NetError::InvalidConfig(
                "the trusted relay set uses a different network scope".into(),
            ));
        }
        let listener = TcpListener::bind(config.listen).await?;
        let local_addr = listener.local_addr()?;
        let advertised = config.advertise.unwrap_or(local_addr);
        config.scope.check_reachable(advertised)?;
        let descriptor = RelayDescriptor::sign_with_family(
            &keys,
            &config.nickname,
            config.role,
            advertised,
            &config.family,
        );
        Ok(Self {
            inner: Arc::new(Inner {
                keys,
                nickname: config.nickname,
                role: config.role,
                local_addr,
                descriptor,
                timeouts: config.timeouts,
                limits: config.limits,
                policy: config.policy.with_scope(config.scope),
                observer: config.observer,
                scope: config.scope,
                trusted: config.trusted,
                links: Arc::new(Semaphore::new(config.limits.max_links)),
                links_per_ip: Mutex::new(HashMap::new()),
                tasks: TaskTracker::new(),
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
                let Some(slot) = self.inner.admit(peer) else {
                    continue; // dropped: outside the scope or over a limit
                };
                let inner = Arc::clone(&self.inner);
                self.inner.tasks.spawn(
                    async move {
                        inner.handle_inbound(stream, peer).await;
                        drop(slot);
                    }
                    .instrument(tracing::Span::current()),
                );
            }
            // Graceful shutdown: inbound tasks destroy their circuits
            // (telling both neighbours) and flush their links.
            info!("relay stopping: closing links and destroying circuits");
            drop(self.listener);
            self.inner.tasks.close();
            if tokio::time::timeout(Duration::from_secs(5), self.inner.tasks.wait())
                .await
                .is_err()
            {
                warn!("some links did not close within 5 s");
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
            open_links: self.inner.limits.max_links - self.inner.links.available_permits(),
            links_refused: c.links_refused.load(Ordering::Relaxed),
            keepalive_failures: c.keepalive_failures.load(Ordering::Relaxed),
        }
    }

    /// Stop accepting, destroy every circuit (telling both neighbours), and
    /// close every link. [`Relay::serve`] returns once this is done.
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

    /// Decide whether to take a new connection: the peer must be inside the
    /// scope, and the total and per-IP link limits must not be exceeded.
    fn admit(self: &Arc<Self>, peer: SocketAddr) -> Option<LinkSlot> {
        let refuse = |why: &str| {
            bump(&self.counters.links_refused);
            warn!(%peer, "refused connection: {why}");
            None
        };
        if !self.scope.allows(peer) {
            return refuse("peer is outside the network scope");
        }
        let Ok(permit) = Arc::clone(&self.links).try_acquire_owned() else {
            return refuse("too many links");
        };
        let mut per_ip = self.links_per_ip.lock().unwrap();
        let count = per_ip.entry(peer.ip()).or_insert(0);
        if *count >= self.limits.max_links_per_ip {
            drop(per_ip);
            return refuse("too many links from this address");
        }
        *count += 1;
        Some(LinkSlot {
            inner: Arc::clone(self),
            ip: peer.ip(),
            _permit: permit,
        })
    }

    async fn handle_inbound(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) {
        debug!(%peer, "inbound connection");
        match self.serve_inbound(stream).await {
            Ok(()) => info!(%peer, "inbound link closed"),
            Err(e @ (NetError::Untrusted(_) | NetError::Crypto(_))) => {
                bump(&self.counters.links_refused);
                warn!(%peer, error = %e, "refused link");
            }
            Err(e) => warn!(%peer, error = %e, "inbound link closed with error"),
        }
    }

    /// Who may open which kind of link to this relay.
    fn authorize(
        &self,
        kind: LinkKind,
        initiator: Option<&[u8; 32]>,
    ) -> Result<Option<Role>, String> {
        match kind {
            LinkKind::Probe => Ok(None),
            LinkKind::Client if self.role == Role::Entry => Ok(None),
            LinkKind::Client => Err(format!(
                "a {} relay does not accept client links",
                self.role
            )),
            LinkKind::Relay => {
                let key = initiator.ok_or("relay link without a key")?;
                let relay = self
                    .trusted
                    .find_by_link_key(key)
                    .ok_or("link key does not belong to any trusted relay")?;
                if Some(relay.role) != self.role.expected_upstream() {
                    return Err(format!(
                        "{} is a {} relay, which may not open links to a {} relay",
                        relay.nickname, relay.role, self.role
                    ));
                }
                Ok(Some(relay.role))
            }
            LinkKind::Directory => Err("this is a relay, not a directory authority".into()),
        }
    }

    async fn serve_inbound(self: &Arc<Self>, stream: TcpStream) -> Result<(), NetError> {
        let mut authenticated = None;
        let accepted = Connection::accept(
            stream,
            self.keys.link_secret(),
            self.timeouts.handshake,
            |kind, initiator| {
                authenticated = self.authorize(kind, initiator)?;
                Ok(())
            },
        )
        .await?;
        let mut conn = accepted.conn;
        if accepted.kind == LinkKind::Probe {
            // Health check: the Noise handshake proved we hold the link key;
            // say who we are and close.
            conn.send(&LinkMsg::Welcome {
                version: crate::protocol::MORP_VERSION,
                role: self.role,
            })
            .await?;
            debug!("answered health probe");
            return Ok(());
        }
        let peer_role =
            handshake_inbound(&mut conn, self.role, authenticated, self.timeouts.handshake).await?;
        info!(%peer_role, "link handshake complete (Noise authenticated)");
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
                LinkMsg::Ping { nonce } => {
                    let _ = link.send(LinkMsg::Pong { nonce }).await;
                }
                LinkMsg::Pong { .. } => {}
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
        // On shutdown the link is still up: tell the creator too.
        let (reason, notify_inbound) = if self.shutdown.is_cancelled() {
            (DestroyReason::RelayShutdown, true)
        } else {
            (DestroyReason::LinkClosed, false)
        };
        for circuit in orphans {
            self.teardown(&circuit, reason, notify_inbound, true).await;
        }
        reader.finish(link).await;
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
                } else {
                    self.check_extend_target(next_hop, &request.node_id).err()
                };
                if let Some((code, detail)) = refusal {
                    warn!(circ, ?code, %detail, "refused EXTEND");
                    self.reply_error(circuit, code, &detail).await;
                    return;
                }
                let Some(next) = self.trusted.find(&request.node_id) else {
                    return;
                };
                *circuit.next.lock().unwrap() = Next::Connecting;
                let this = Arc::clone(self);
                let circuit = Arc::clone(circuit);
                tokio::spawn(
                    async move { this.extend(circuit, next, request).await }
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

    /// May this relay extend to the relay with identity `node_id` at
    /// `next_hop`? Only trusted relays, at their published address, inside
    /// the scope, with the next role in the circuit order.
    fn check_extend_target(
        &self,
        next_hop: SocketAddr,
        node_id: &NodeId,
    ) -> Result<(), (ErrorCode, String)> {
        let reject = |detail: String| Err((ErrorCode::ExtendRejected, detail));
        if !self.scope.allows(next_hop) {
            return reject(format!(
                "{next_hop} is outside the network scope ({})",
                self.scope
            ));
        }
        if *node_id == self.keys.node_id()
            || next_hop == self.local_addr
            || next_hop == self.descriptor.addr
        {
            return reject("cannot extend to itself".to_owned());
        }
        let Some(next) = self.trusted.find(node_id) else {
            return reject(format!("relay {} is not trusted", node_id.short()));
        };
        if next.addr != next_hop {
            return reject(format!(
                "{} is published at {}, not {next_hop}",
                next.nickname, next.addr
            ));
        }
        if !self.role.can_extend_to(next.role) {
            return reject(format!(
                "a {} relay does not extend to a {} relay",
                self.role, next.role
            ));
        }
        Ok(())
    }

    async fn extend(
        self: Arc<Self>,
        circuit: Arc<Circuit>,
        next: RelayDescriptor,
        request: CreateRequest,
    ) {
        let circ = circuit.in_circ;
        let next_hop = next.addr;
        let link = match self.outbound_link(&next).await {
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

    async fn outbound_link(self: &Arc<Self>, next: &RelayDescriptor) -> Result<Link, NetError> {
        let mut links = self.out_links.lock().await;
        if let Some(link) = links.get(&next.node_id)
            && !link.is_closed()
        {
            return Ok(link.clone());
        }
        let origin = format!("relay:{}", self.nickname);
        let mut conn = Connection::connect_checked(
            next.addr,
            LinkKind::Relay,
            &next.link_key,
            Some(self.keys.link_secret()),
            &self.timeouts,
            &self.policy,
            &origin,
        )
        .await?;
        handshake_outbound(&mut conn, self.role, &[next.role], self.timeouts.handshake).await?;
        let (link, reader) = conn.into_link();
        links.insert(next.node_id, link.clone());
        info!(next_hop = %next.addr, relay = %next.nickname, "outbound link opened (Noise IK)");
        let key = next.node_id;
        self.tasks.spawn(
            Arc::clone(self)
                .serve_outbound(link.clone(), reader, key)
                .instrument(tracing::Span::current()),
        );
        Ok(link)
    }

    async fn serve_outbound(self: Arc<Self>, link: Link, mut reader: LinkReader, key: NodeId) {
        let mut unanswered: u32 = 0;
        let result: Result<(), NetError> = loop {
            let received = tokio::select! {
                received = reader.recv(Some(self.timeouts.keepalive)) => received,
                _ = self.shutdown.cancelled() => break Ok(()),
            };
            let msg = match received {
                Ok(Some(msg)) => {
                    unanswered = 0;
                    msg
                }
                Ok(None) => break Ok(()),
                Err(NetError::Timeout) => {
                    // Quiet link: is the next relay still there?
                    if unanswered >= 2 {
                        bump(&self.counters.keepalive_failures);
                        break Err(NetError::Protocol(
                            "next relay stopped answering keepalives".into(),
                        ));
                    }
                    unanswered += 1;
                    let nonce = u64::from_le_bytes(crate::crypto::random_bytes::<8>());
                    if link.send(LinkMsg::Ping { nonce }).await.is_err() {
                        break Err(NetError::ConnectionClosed);
                    }
                    continue;
                }
                Err(e) => break Err(e),
            };
            match msg {
                LinkMsg::Ping { nonce } => {
                    let _ = link.send(LinkMsg::Pong { nonce }).await;
                }
                LinkMsg::Pong { .. } => {}
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
            if links.get(&key).is_some_and(|l| l.id() == link.id()) {
                links.remove(&key);
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
        let reason = if self.shutdown.is_cancelled() {
            DestroyReason::RelayShutdown
        } else {
            DestroyReason::NextHopFailed
        };
        for circuit in orphans {
            self.teardown(&circuit, reason, true, true).await;
        }
        reader.finish(link).await;
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

/// One admitted inbound connection; frees its limits when dropped.
struct LinkSlot {
    inner: Arc<Inner>,
    ip: std::net::IpAddr,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for LinkSlot {
    fn drop(&mut self) {
        let mut per_ip = self.inner.links_per_ip.lock().unwrap();
        if let Entry::Occupied(mut count) = per_ip.entry(self.ip) {
            *count.get_mut() -= 1;
            if *count.get() == 0 {
                count.remove();
            }
        }
    }
}

/// Test service run by exit relays: returns the data unchanged.
fn echo_service(data: Vec<u8>) -> Vec<u8> {
    data
}
