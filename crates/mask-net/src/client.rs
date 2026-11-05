//! MORP client: opens a link to an entry relay and builds circuits over it.
//!
//! Circuits are built one hop at a time ("telescoping"):
//! 1. CREATE to the entry → ntor handshake → keys for hop 1.
//! 2. EXTEND (sealed for the entry) → entry sends CREATE to the middle →
//!    EXTENDED comes back sealed by the entry → keys for hop 2.
//! 3. EXTEND (sealed for the middle, then the entry) → keys for hop 3.
//!
//! Each relay's handshake is authenticated against the identity and onion
//! key in its signed descriptor, so a relay that forwards an EXTEND to an
//! impostor cannot fool the client.
//!
//! Several circuits can share one [`ClientLink`]; circuit IDs keep them apart.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::timeout;

use crate::crypto::ntor::ClientHandshake;
use crate::crypto::onion::{CellCipher, Direction};
use crate::descriptor::{CircuitPath, Directory, RelayDescriptor};
use crate::error::NetError;
use crate::identity::{NodeId, Role};
use crate::protocol::{
    CircId, DestroyReason, ErrorCode, LayerBody, LinkMsg, MAX_DATA_LEN, RelayCmd, decode, encode,
    sanitize_remote_text,
};
use crate::transport::{
    ConnectPolicy, Connection, Link, LinkKind, LinkReader, Timeouts, WeakLink, handshake_outbound,
};
use crate::trust::{DEFAULT_PENALTY, TrustedRelays};

/// Circuit ID → the circuit's receive queue. `None` keeps the ID reserved
/// after the link gave up on the circuit (its queue stayed full) until the
/// [`Circuit`] itself is dropped, so the ID cannot be reused under it.
type Routes = Arc<Mutex<HashMap<CircId, Option<mpsc::Sender<LinkMsg>>>>>;

/// Messages queued per circuit before the link reader waits for its owner.
const CIRCUIT_QUEUE: usize = 64;
/// How long the link reader waits for a circuit whose queue is full before
/// destroying that circuit. Bounds how long one stuck or flooded circuit can
/// hold up every other circuit on the same link.
const QUEUE_STALL: Duration = Duration::from_secs(2);

/// [`NetError::Remote`] with the remote's text made safe to show.
fn remote_error(hop: usize, code: ErrorCode, detail: &str) -> NetError {
    NetError::Remote {
        hop,
        code,
        detail: sanitize_remote_text(detail),
    }
}

/// An open link from this client to one entry relay.
#[derive(Clone)]
pub struct ClientLink {
    link: Link,
    entry: RelayDescriptor,
    routes: Routes,
    timeouts: Timeouts,
}

impl ClientLink {
    pub async fn connect(entry: &RelayDescriptor, timeouts: Timeouts) -> Result<Self, NetError> {
        Self::connect_with(entry, timeouts, &ConnectPolicy::allow_all(), "client").await
    }

    /// Connect after checking `policy` (`origin` names this component).
    pub async fn connect_with(
        entry: &RelayDescriptor,
        timeouts: Timeouts,
        policy: &ConnectPolicy,
        origin: &str,
    ) -> Result<Self, NetError> {
        if entry.role != Role::Entry {
            return Err(NetError::InvalidConfig(format!(
                "{} is a {} relay; clients connect only to entry relays",
                entry.nickname, entry.role
            )));
        }
        let mut conn = Connection::connect_checked(
            entry.addr,
            LinkKind::Client,
            &entry.link_key,
            None,
            &timeouts,
            policy,
            origin,
        )
        .await?;
        handshake_outbound(&mut conn, Role::Client, &[Role::Entry], timeouts.handshake).await?;
        let (link, reader) = conn.into_link();
        let routes: Routes = Arc::default();
        tokio::spawn(dispatch(
            reader,
            link.downgrade(),
            Arc::clone(&routes),
            timeouts.keepalive,
        ));
        Ok(Self {
            link,
            entry: entry.clone(),
            routes,
            timeouts,
        })
    }

    /// Build a three-hop circuit. `path.entry` must be this link's relay.
    pub async fn build_circuit(&self, path: &CircuitPath) -> Result<Circuit, NetError> {
        if path.entry.node_id != self.entry.node_id {
            return Err(NetError::InvalidConfig(
                "path does not start at this link's entry relay".into(),
            ));
        }
        let mut circuit = self.new_circuit();
        circuit.create(&path.entry).await?;
        circuit.extend(&path.middle).await?;
        circuit.extend(&path.last).await?;
        Ok(circuit)
    }

    /// An empty circuit (no hops yet). Exposed for tests of partial circuits.
    pub fn new_circuit(&self) -> Circuit {
        let (tx, rx) = mpsc::channel(CIRCUIT_QUEUE);
        let circ = {
            let mut routes = self.routes.lock().unwrap();
            let id = loop {
                let id = u32::from_le_bytes(crate::crypto::random_bytes::<4>());
                if id != 0 && !routes.contains_key(&id) {
                    break id;
                }
            };
            routes.insert(id, Some(tx));
            id
        };
        Circuit {
            link: self.link.clone(),
            circ,
            hops: Vec::new(),
            rx,
            routes: Arc::clone(&self.routes),
            timeouts: self.timeouts,
            destroyed: false,
            dead: None,
        }
    }

    /// Raw access to the link, for protocol tests.
    pub fn link(&self) -> &Link {
        &self.link
    }
}

/// Route each incoming message to its circuit by circuit ID, answer
/// keepalives, and ping the entry when the link is quiet. A link whose entry
/// stops answering is closed, which fails every circuit on it.
async fn dispatch(mut reader: LinkReader, link: WeakLink, routes: Routes, keepalive: Duration) {
    let mut unanswered = 0u32;
    loop {
        let msg = match reader.recv(Some(keepalive)).await {
            Ok(Some(msg)) => {
                unanswered = 0;
                msg
            }
            Err(NetError::Timeout) => {
                // Nobody uses the link any more: let it close.
                let Some(link) = link.upgrade() else { break };
                if unanswered >= 2 {
                    tracing::warn!(entry = %link.peer_addr(), "entry relay stopped answering keepalives");
                    break;
                }
                unanswered += 1;
                let nonce = u64::from_le_bytes(crate::crypto::random_bytes::<8>());
                if link.send(LinkMsg::Ping { nonce }).await.is_err() {
                    break;
                }
                continue;
            }
            Ok(None) | Err(_) => break,
        };
        let circ = match &msg {
            LinkMsg::Created { circ, .. }
            | LinkMsg::Relay { circ, .. }
            | LinkMsg::Destroy { circ, .. } => *circ,
            LinkMsg::Ping { nonce } => {
                if let Some(link) = link.upgrade() {
                    let _ = link.send(LinkMsg::Pong { nonce: *nonce }).await;
                }
                continue;
            }
            LinkMsg::Pong { .. } => continue,
            _ => break,
        };
        let tx = routes.lock().unwrap().get(&circ).cloned().flatten();
        let Some(tx) = tx else { continue };
        let stuck = match tx.try_send(msg) {
            Ok(()) | Err(TrySendError::Closed(_)) => false,
            // Wait a little for the circuit's owner, but never indefinitely:
            // every other circuit on this link waits meanwhile.
            Err(TrySendError::Full(msg)) => timeout(QUEUE_STALL, tx.send(msg)).await.is_err(),
        };
        if stuck {
            tracing::warn!(
                circ,
                "circuit receive queue stayed full; destroying the circuit"
            );
            if let Some(slot) = routes.lock().unwrap().get_mut(&circ) {
                *slot = None; // the owner sees "closed" once it drains its queue
            }
            if let Some(link) = link.upgrade() {
                link.try_send(LinkMsg::Destroy {
                    circ,
                    reason: DestroyReason::ResourceLimit,
                });
            }
        }
    }
    // Link gone: dropping the senders wakes every circuit with "closed".
    routes.lock().unwrap().clear();
}

struct ClientHop {
    descriptor: RelayDescriptor,
    forward: CellCipher,
    backward: CellCipher,
}

/// A circuit through one or more relays.
///
/// **Failure is final (v0.7).** Any cell that fails to decrypt or decode,
/// any message that does not belong at this point of the protocol, and any
/// command from the wrong hop destroys the circuit: a `Destroy` goes to the
/// entry and every later call fails with [`NetError::Destroyed`]. Only
/// timeouts and `Error` commands (a hop reporting a failed command, which
/// is authenticated by that hop's layer) leave the circuit usable.
pub struct Circuit {
    link: Link,
    circ: CircId,
    hops: Vec<ClientHop>,
    rx: mpsc::Receiver<LinkMsg>,
    routes: Routes,
    timeouts: Timeouts,
    /// The entry already knows the circuit is gone (it sent or we sent
    /// `Destroy`), so dropping the circuit sends nothing.
    destroyed: bool,
    /// Why the circuit can no longer be used.
    dead: Option<DestroyReason>,
}

impl Circuit {
    pub fn id(&self) -> CircId {
        self.circ
    }

    pub fn hops(&self) -> impl Iterator<Item = &RelayDescriptor> {
        self.hops.iter().map(|h| &h.descriptor)
    }

    /// True once the circuit has been destroyed (by either side).
    pub fn is_dead(&self) -> bool {
        self.dead.is_some()
    }

    /// Destroy the circuit because of `error` and return the error.
    fn kill(&mut self, reason: DestroyReason, error: NetError) -> NetError {
        if self.dead.is_none() {
            self.dead = Some(reason);
            if !self.destroyed {
                self.destroyed = true;
                self.link.try_send(LinkMsg::Destroy {
                    circ: self.circ,
                    reason,
                });
            }
            tracing::debug!(circ = self.circ, ?reason, error = %error, "circuit destroyed by the client");
        }
        error
    }

    fn check_alive(&self) -> Result<(), NetError> {
        match self.dead {
            Some(reason) => Err(NetError::Destroyed(reason)),
            None => Ok(()),
        }
    }

    /// The peer broke the protocol: destroy the circuit.
    fn violation(&mut self, what: impl Into<String>) -> NetError {
        self.kill(
            DestroyReason::ProtocolViolation,
            NetError::Protocol(what.into()),
        )
    }

    /// First hop: CREATE directly on the link.
    pub async fn create(&mut self, relay: &RelayDescriptor) -> Result<(), NetError> {
        self.check_alive()?;
        if !self.hops.is_empty() {
            return Err(NetError::InvalidConfig("circuit already created".into()));
        }
        let (handshake, request) = ClientHandshake::start(relay.node_id, relay.onion_key);
        self.link
            .send(LinkMsg::Create {
                circ: self.circ,
                request,
            })
            .await?;
        match self.recv_msg(self.timeouts.handshake).await? {
            LinkMsg::Created { reply, .. } => match handshake.finish(&reply) {
                Ok(keys) => {
                    self.push_hop(relay, &keys.forward, &keys.backward);
                    Ok(())
                }
                // Not the relay we asked for (impostor or stale key).
                Err(e) => Err(self.kill(DestroyReason::WrongRelay, e.into())),
            },
            LinkMsg::Destroy { reason, .. } => {
                self.destroyed = true;
                self.dead = Some(reason);
                Err(NetError::Destroyed(reason))
            }
            other => Err(self.violation(format!("expected CREATED, got {}", other.kind()))),
        }
    }

    /// Add one more hop through the current last hop.
    pub async fn extend(&mut self, relay: &RelayDescriptor) -> Result<(), NetError> {
        let Some(last) = self.hops.len().checked_sub(1) else {
            return Err(NetError::InvalidConfig("create the circuit first".into()));
        };
        let (handshake, request) = ClientHandshake::start(relay.node_id, relay.onion_key);
        self.send_cmd(
            last,
            RelayCmd::Extend {
                next_hop: relay.addr,
                request,
            },
        )
        .await?;
        match self.recv_cmd(self.timeouts.handshake * 2).await? {
            (hop, RelayCmd::Extended { reply }) if hop == last => match handshake.finish(&reply) {
                Ok(keys) => {
                    self.push_hop(relay, &keys.forward, &keys.backward);
                    Ok(())
                }
                Err(e) => Err(self.kill(DestroyReason::WrongRelay, e.into())),
            },
            (hop, RelayCmd::Error { code, detail }) => Err(remote_error(hop, code, &detail)),
            (hop, cmd) => Err(self.violation(format!(
                "expected EXTENDED, got {} from hop {}",
                cmd.kind(),
                hop + 1
            ))),
        }
    }

    /// Send `data` to the last hop and wait for its reply.
    pub async fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, NetError> {
        if data.len() > MAX_DATA_LEN {
            return Err(NetError::InvalidConfig(format!(
                "message is {} bytes; the limit is {MAX_DATA_LEN}",
                data.len()
            )));
        }
        let Some(last) = self.hops.len().checked_sub(1) else {
            return Err(NetError::InvalidConfig("circuit has no hops".into()));
        };
        self.send_cmd(
            last,
            RelayCmd::Data {
                bytes: data.to_vec(),
            },
        )
        .await?;
        match self.recv_cmd(self.timeouts.response).await? {
            (hop, RelayCmd::Data { bytes }) if hop == last => Ok(bytes),
            (hop, RelayCmd::Error { code, detail }) => Err(remote_error(hop, code, &detail)),
            (hop, cmd) => Err(self.violation(format!(
                "expected DATA, got {} from hop {}",
                cmd.kind(),
                hop + 1
            ))),
        }
    }

    fn last_hop(&self) -> Result<usize, NetError> {
        self.hops
            .len()
            .checked_sub(1)
            .ok_or_else(|| NetError::InvalidConfig("circuit has no hops".into()))
    }

    /// Send `cmd` to the last hop and wait for the last hop's reply. An
    /// `Error` from any hop becomes [`NetError::Remote`].
    pub async fn request(
        &mut self,
        cmd: RelayCmd,
        limit: std::time::Duration,
    ) -> Result<RelayCmd, NetError> {
        self.send_to_last(cmd).await?;
        self.recv_from_last(Some(limit)).await
    }

    /// Send `cmd` to the last hop without waiting for a reply.
    pub async fn send_to_last(&mut self, cmd: RelayCmd) -> Result<(), NetError> {
        let last = self.last_hop()?;
        self.send_cmd(last, cmd).await
    }

    /// Next command from the last hop. `None` waits indefinitely.
    pub async fn recv_from_last(
        &mut self,
        limit: Option<std::time::Duration>,
    ) -> Result<RelayCmd, NetError> {
        let last = self.last_hop()?;
        let (hop, cmd) = self.recv_cmd_opt(limit).await?;
        match cmd {
            RelayCmd::Error { code, detail } => Err(remote_error(hop, code, &detail)),
            cmd if hop == last => Ok(cmd),
            // A middle relay must never originate data or hidden-service
            // replies: only its own errors.
            cmd => Err(self.violation(format!(
                "unexpected {} from intermediate hop {}",
                cmd.kind(),
                hop + 1
            ))),
        }
    }

    /// Turn the circuit into a two-way pipe of `Stream` payloads exchanged
    /// with the last hop (used after a rendezvous join). The circuit is
    /// destroyed when either side of the pipe is dropped.
    pub fn into_stream_pipe(mut self) -> StreamPipe {
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(32);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(32);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    outgoing = out_rx.recv() => match outgoing {
                        Some(bytes) => {
                            if self.send_to_last(RelayCmd::Stream { bytes }).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                    incoming = self.recv_from_last(None) => match incoming {
                        Ok(RelayCmd::Stream { bytes }) => {
                            if in_tx.send(bytes).await.is_err() {
                                break;
                            }
                        }
                        Ok(_) => break,
                        Err(_) => break,
                    },
                }
            }
            // Dropping `self` sends Destroy unless the circuit is already gone.
        });
        StreamPipe {
            tx: out_tx,
            rx: in_rx,
        }
    }

    /// Seal `cmd` for hop `target`, then wrap it once for every hop before it.
    pub fn seal_for(&mut self, target: usize, cmd: RelayCmd) -> Result<Vec<u8>, NetError> {
        let mut cell = self.hops[target]
            .forward
            .seal(&encode(&LayerBody::Cmd(cmd)))?;
        for hop in self.hops[..target].iter_mut().rev() {
            cell = hop.forward.seal(&encode(&LayerBody::Relay(cell)))?;
        }
        Ok(cell)
    }

    async fn send_cmd(&mut self, target: usize, cmd: RelayCmd) -> Result<(), NetError> {
        self.check_alive()?;
        let cell = match self.seal_for(target, cmd) {
            Ok(cell) => cell,
            // Some layers may already have advanced their counters: the
            // circuit is out of step and must not be used again.
            Err(e) => return Err(self.kill(DestroyReason::ResourceLimit, e)),
        };
        self.link
            .send(LinkMsg::Relay {
                circ: self.circ,
                cell,
            })
            .await
    }

    /// Next message for this circuit from the link.
    pub async fn recv_msg(&mut self, limit: std::time::Duration) -> Result<LinkMsg, NetError> {
        self.recv_msg_opt(Some(limit)).await
    }

    async fn recv_msg_opt(
        &mut self,
        limit: Option<std::time::Duration>,
    ) -> Result<LinkMsg, NetError> {
        self.check_alive()?;
        let received = match limit {
            Some(limit) => timeout(limit, self.rx.recv())
                .await
                .map_err(|_| NetError::Timeout)?,
            None => self.rx.recv().await,
        };
        received.ok_or(NetError::ConnectionClosed)
    }

    /// Next backward command, with the index of the hop that sent it.
    async fn recv_cmd(
        &mut self,
        limit: std::time::Duration,
    ) -> Result<(usize, RelayCmd), NetError> {
        self.recv_cmd_opt(Some(limit)).await
    }

    async fn recv_cmd_opt(
        &mut self,
        limit: Option<std::time::Duration>,
    ) -> Result<(usize, RelayCmd), NetError> {
        match self.recv_msg_opt(limit).await? {
            LinkMsg::Relay { cell, .. } => match self.peel(cell) {
                Ok(found) => Ok(found),
                Err(e @ NetError::Crypto(_)) => {
                    Err(self.kill(DestroyReason::AuthenticationFailed, e))
                }
                Err(e) => Err(self.kill(DestroyReason::ProtocolViolation, e)),
            },
            LinkMsg::Destroy { reason, .. } => {
                self.destroyed = true;
                self.dead = Some(reason);
                Err(NetError::Destroyed(reason))
            }
            other => Err(self.violation(format!("unexpected {} on circuit", other.kind()))),
        }
    }

    /// Remove backward layers hop by hop until one holds a command.
    fn peel(&mut self, mut cell: Vec<u8>) -> Result<(usize, RelayCmd), NetError> {
        for (index, hop) in self.hops.iter_mut().enumerate() {
            let plaintext = hop.backward.open(&cell)?;
            match decode::<LayerBody>(&plaintext)? {
                LayerBody::Cmd(cmd) => return Ok((index, cmd)),
                LayerBody::Relay(inner) => cell = inner,
            }
        }
        Err(NetError::Protocol(
            "backward cell has more layers than the circuit has hops".into(),
        ))
    }

    fn push_hop(&mut self, relay: &RelayDescriptor, forward: &[u8; 32], backward: &[u8; 32]) {
        self.hops.push(ClientHop {
            descriptor: relay.clone(),
            forward: CellCipher::new(forward, Direction::Forward),
            backward: CellCipher::new(backward, Direction::Backward),
        });
    }
}

impl Drop for Circuit {
    fn drop(&mut self) {
        self.routes.lock().unwrap().remove(&self.circ);
        if !self.destroyed {
            self.link.try_send(LinkMsg::Destroy {
                circ: self.circ,
                reason: DestroyReason::Requested,
            });
        }
    }
}

/// Two-way channel of end-to-end `Stream` payloads over a joined circuit.
pub struct StreamPipe {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
}

/// Which relay, if any, a circuit-building error points at.
fn blame(path: &CircuitPath, error: &NetError, connected: bool) -> Option<NodeId> {
    if !connected {
        return Some(path.entry.node_id);
    }
    match error {
        // Hop `hop` could not reach (or was refused by) the next one.
        NetError::Remote {
            hop,
            code: ErrorCode::NextHopUnreachable | ErrorCode::ExtendRejected | ErrorCode::Timeout,
            ..
        } => path.hops().get(hop + 1).map(|d| d.node_id),
        NetError::Crypto(_) | NetError::Remote { .. } => None,
        // The entry stopped answering.
        NetError::Timeout | NetError::ConnectionClosed => Some(path.entry.node_id),
        _ => None,
    }
}

/// Build a three-hop circuit ending at a relay picked by `choose_last`,
/// retrying up to `attempts` times with fresh paths. Relays that fail are
/// marked in the trusted set's [`Health`](crate::trust::Health) so later
/// paths (here and elsewhere in the process) avoid them for a while.
///
/// `choose_last(directory, unhealthy)` picks the last hop.
pub async fn build_circuit_to(
    trusted: &TrustedRelays,
    choose_last: impl Fn(&Directory, &[NodeId]) -> Option<RelayDescriptor>,
    timeouts: Timeouts,
    policy: &ConnectPolicy,
    origin: &str,
    attempts: usize,
) -> Result<(ClientLink, Circuit, CircuitPath), NetError> {
    let health = trusted.health();
    let mut last_error = None;
    for attempt in 1..=attempts.max(1) {
        let directory = trusted.snapshot()?;
        let unhealthy = health.unhealthy();
        let Some(last) = choose_last(&directory, &unhealthy) else {
            return Err(last_error.unwrap_or_else(|| {
                NetError::InvalidConfig("no suitable last-hop relay is available".into())
            }));
        };
        let path = directory.path_avoiding(&last, &unhealthy)?;
        let outcome = match ClientLink::connect_with(&path.entry, timeouts, policy, origin).await {
            Ok(link) => match link.build_circuit(&path).await {
                Ok(circuit) => Ok((link, circuit)),
                Err(e) => Err((e, true)),
            },
            Err(e) => Err((e, false)),
        };
        match outcome {
            Ok((link, circuit)) => {
                for hop in path.hops() {
                    health.mark_ok(&hop.node_id);
                }
                return Ok((link, circuit, path));
            }
            Err((e, connected)) => {
                if let Some(bad) = blame(&path, &e, connected) {
                    let nickname = path
                        .hops()
                        .into_iter()
                        .find(|d| d.node_id == bad)
                        .map(|d| d.nickname.clone())
                        .unwrap_or_default();
                    tracing::warn!(attempt, relay = %nickname, error = %e, "circuit failed; avoiding relay for a while");
                    health.mark_failed(bad, DEFAULT_PENALTY);
                } else {
                    tracing::warn!(attempt, error = %e, "circuit failed");
                }
                last_error = Some(e);
            }
        }
    }
    Err(last_error.expect("at least one attempt"))
}
