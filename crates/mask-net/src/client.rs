//! Test client: builds an onion-layered payload and sends it along a route.

use std::net::SocketAddr;

use crate::error::NetError;
use crate::identity::{NodeId, Role};
use crate::protocol::{Message, OnionLayer};
use crate::transport::{Connection, Timeouts, handshake_outbound, message_kind};

/// The three relays a message passes through, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub entry: SocketAddr,
    pub middle: SocketAddr,
    pub exit: SocketAddr,
}

/// Build the nested layers for `route`, innermost (exit) first.
///
/// The entry's layer says "forward to middle", the middle's says "forward to
/// exit", the exit's says "deliver `data`". Next milestone: encrypt each layer
/// to its relay's key at this point.
pub fn build_onion(route: &Route, data: &[u8]) -> Result<Vec<u8>, NetError> {
    let exit_layer = OnionLayer::Deliver {
        data: data.to_vec(),
    }
    .encode()?;
    let middle_layer = OnionLayer::Forward {
        next_hop: route.exit,
        inner: exit_layer,
    }
    .encode()?;
    let entry_layer = OnionLayer::Forward {
        next_hop: route.middle,
        inner: middle_layer,
    }
    .encode()?;
    Ok(entry_layer)
}

/// An open connection to an entry relay. Several messages can be sent over
/// the same route.
pub struct Circuit {
    conn: Connection,
    route: Route,
    timeouts: Timeouts,
}

impl Circuit {
    pub async fn open(route: Route, timeouts: Timeouts) -> Result<Self, NetError> {
        for addr in [route.entry, route.middle, route.exit] {
            if !addr.ip().is_loopback() {
                return Err(NetError::NotLoopback(addr));
            }
        }
        let mut conn = Connection::connect(route.entry, timeouts.connect).await?;
        handshake_outbound(
            &mut conn,
            Role::Client,
            NodeId::random(),
            Role::Entry,
            timeouts.handshake,
        )
        .await?;
        Ok(Self {
            conn,
            route,
            timeouts,
        })
    }

    /// Send `data` through entry → middle → exit and return the exit's reply.
    pub async fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, NetError> {
        let payload = build_onion(&self.route, data)?;
        self.conn.send(&Message::Relay { payload }).await?;

        // Each relay waits up to `response`; leave room for both to report.
        let limit = self.timeouts.response * 3;
        match self.conn.recv(limit).await? {
            Some(Message::RelayResponse { payload }) => Ok(payload),
            Some(Message::Error { code, detail }) => Err(NetError::Remote { code, detail }),
            Some(other) => Err(NetError::Protocol(format!(
                "expected RelayResponse, got {}",
                message_kind(&other)
            ))),
            None => Err(NetError::ConnectionClosed),
        }
    }
}

/// Open a circuit, send one message, and return the reply.
pub async fn send_test_message(
    route: Route,
    data: &[u8],
    timeouts: Timeouts,
) -> Result<Vec<u8>, NetError> {
    Circuit::open(route, timeouts).await?.send(data).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> Route {
        Route {
            entry: "127.0.0.1:7101".parse().unwrap(),
            middle: "127.0.0.1:7102".parse().unwrap(),
            exit: "127.0.0.1:7103".parse().unwrap(),
        }
    }

    #[test]
    fn onion_peels_in_route_order() {
        let r = route();
        let onion = build_onion(&r, b"hello").unwrap();

        // Entry peels: forward to middle.
        let OnionLayer::Forward { next_hop, inner } = OnionLayer::decode(&onion).unwrap() else {
            panic!("entry layer should forward");
        };
        assert_eq!(next_hop, r.middle);

        // Middle peels: forward to exit.
        let OnionLayer::Forward { next_hop, inner } = OnionLayer::decode(&inner).unwrap() else {
            panic!("middle layer should forward");
        };
        assert_eq!(next_hop, r.exit);

        // Exit peels: deliver.
        assert_eq!(
            OnionLayer::decode(&inner).unwrap(),
            OnionLayer::Deliver {
                data: b"hello".to_vec()
            }
        );
    }

    #[tokio::test]
    async fn refuses_non_loopback_route() {
        let mut r = route();
        r.middle = "192.0.2.1:7102".parse().unwrap();
        let err = Circuit::open(r, Timeouts::default())
            .await
            .err()
            .expect("non-loopback route must be refused");
        assert!(matches!(err, NetError::NotLoopback(_)));
    }
}
