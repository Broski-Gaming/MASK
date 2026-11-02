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

use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::crypto::ntor::ClientHandshake;
use crate::crypto::onion::{CellCipher, Direction};
use crate::descriptor::{CircuitPath, RelayDescriptor};
use crate::error::NetError;
use crate::identity::Role;
use crate::protocol::{
    CircId, DestroyReason, LayerBody, LinkMsg, MAX_DATA_LEN, RelayCmd, decode, encode,
};
use crate::transport::{Connection, Link, LinkReader, Timeouts, handshake_outbound};

type Routes = Arc<Mutex<HashMap<CircId, mpsc::Sender<LinkMsg>>>>;

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
        if !entry.addr.ip().is_loopback() {
            return Err(NetError::NotLoopback(entry.addr));
        }
        let mut conn = Connection::connect(entry.addr, timeouts.connect).await?;
        handshake_outbound(&mut conn, Role::Client, Role::Entry, timeouts.handshake).await?;
        let (link, reader) = conn.into_link();
        let routes: Routes = Arc::default();
        tokio::spawn(dispatch(reader, Arc::clone(&routes)));
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
        circuit.extend(&path.exit).await?;
        Ok(circuit)
    }

    /// An empty circuit (no hops yet). Exposed for tests of partial circuits.
    pub fn new_circuit(&self) -> Circuit {
        let (tx, rx) = mpsc::channel(64);
        let circ = {
            let mut routes = self.routes.lock().unwrap();
            let id = loop {
                let id = u32::from_le_bytes(crate::crypto::random_bytes::<4>());
                if id != 0 && !routes.contains_key(&id) {
                    break id;
                }
            };
            routes.insert(id, tx);
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
        }
    }

    /// Raw access to the link, for protocol tests.
    pub fn link(&self) -> &Link {
        &self.link
    }
}

/// Route each incoming message to its circuit by circuit ID.
async fn dispatch(mut reader: LinkReader, routes: Routes) {
    while let Ok(Some(msg)) = reader.recv(None).await {
        let circ = match &msg {
            LinkMsg::Created { circ, .. }
            | LinkMsg::Relay { circ, .. }
            | LinkMsg::Destroy { circ, .. } => *circ,
            _ => break,
        };
        let tx = routes.lock().unwrap().get(&circ).cloned();
        if let Some(tx) = tx {
            let _ = tx.send(msg).await;
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
pub struct Circuit {
    link: Link,
    circ: CircId,
    hops: Vec<ClientHop>,
    rx: mpsc::Receiver<LinkMsg>,
    routes: Routes,
    timeouts: Timeouts,
    destroyed: bool,
}

impl Circuit {
    pub fn id(&self) -> CircId {
        self.circ
    }

    pub fn hops(&self) -> impl Iterator<Item = &RelayDescriptor> {
        self.hops.iter().map(|h| &h.descriptor)
    }

    /// First hop: CREATE directly on the link.
    pub async fn create(&mut self, relay: &RelayDescriptor) -> Result<(), NetError> {
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
            LinkMsg::Created { reply, .. } => {
                let keys = handshake.finish(&reply)?;
                self.push_hop(relay, &keys.forward, &keys.backward);
                Ok(())
            }
            LinkMsg::Destroy { reason, .. } => {
                self.destroyed = true;
                Err(NetError::Destroyed(reason))
            }
            _ => Err(NetError::Protocol("expected CREATED".into())),
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
            (hop, RelayCmd::Extended { reply }) if hop == last => {
                let keys = handshake.finish(&reply)?;
                self.push_hop(relay, &keys.forward, &keys.backward);
                Ok(())
            }
            (hop, RelayCmd::Error { code, detail }) => Err(NetError::Remote { hop, code, detail }),
            _ => Err(NetError::Protocol("expected EXTENDED".into())),
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
            (hop, RelayCmd::Error { code, detail }) => Err(NetError::Remote { hop, code, detail }),
            _ => Err(NetError::Protocol("expected DATA".into())),
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
        let cell = self.seal_for(target, cmd)?;
        self.link
            .send(LinkMsg::Relay {
                circ: self.circ,
                cell,
            })
            .await
    }

    /// Next message for this circuit from the link.
    pub async fn recv_msg(&mut self, limit: std::time::Duration) -> Result<LinkMsg, NetError> {
        match timeout(limit, self.rx.recv()).await {
            Err(_) => Err(NetError::Timeout),
            Ok(None) => Err(NetError::ConnectionClosed),
            Ok(Some(msg)) => Ok(msg),
        }
    }

    /// Next backward command, with the index of the hop that sent it.
    async fn recv_cmd(
        &mut self,
        limit: std::time::Duration,
    ) -> Result<(usize, RelayCmd), NetError> {
        match self.recv_msg(limit).await? {
            LinkMsg::Relay { cell, .. } => self.peel(cell),
            LinkMsg::Destroy { reason, .. } => {
                self.destroyed = true;
                Err(NetError::Destroyed(reason))
            }
            _ => Err(NetError::Protocol("unexpected message on circuit".into())),
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
