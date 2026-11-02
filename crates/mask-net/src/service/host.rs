//! Service host: accepts channel connections for one `.morp` identity and
//! serves a static site.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, info_span, warn};

use super::channel::SecureChannel;
use super::descriptor::{ServiceDescriptor, ServiceEndpoint};
use super::keys::ServiceKeys;
use super::site::Site;
use crate::NetError;
use crate::address::MorpAddress;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct ServiceHost {
    keys: Arc<ServiceKeys>,
    site: Arc<Site>,
    listener: TcpListener,
}

impl ServiceHost {
    /// Bind on a loopback address (port 0 picks a free port).
    pub async fn bind(keys: ServiceKeys, site: Site, listen: SocketAddr) -> Result<Self, NetError> {
        if !listen.ip().is_loopback() {
            return Err(NetError::NotLoopback(listen));
        }
        let listener = TcpListener::bind(listen).await?;
        Ok(Self {
            keys: Arc::new(keys),
            site: Arc::new(site),
            listener,
        })
    }

    pub fn address(&self) -> &MorpAddress {
        self.keys.address()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("bound listener has an address")
    }

    pub fn keys(&self) -> Arc<ServiceKeys> {
        Arc::clone(&self.keys)
    }

    /// A descriptor pointing clients at this host.
    pub fn descriptor(&self, now: u64, lifetime: u64, revision: u64) -> ServiceDescriptor {
        ServiceDescriptor::sign(
            &self.keys,
            ServiceEndpoint::DirectLoopback(self.local_addr()),
            now,
            lifetime,
            revision,
        )
    }

    /// Serve until the task is cancelled.
    pub async fn serve(self) {
        let span = info_span!("service", address = %self.keys.address().id()[..16]);
        async move {
            info!(listen = %self.local_addr(), site = %self.site.root().display(), "service started");
            loop {
                let (stream, peer) = match self.listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let keys = Arc::clone(&self.keys);
                let site = Arc::clone(&self.site);
                tokio::spawn(
                    async move {
                        if let Err(e) = serve_connection(stream, &keys, &site).await {
                            debug!(%peer, error = %e, "connection ended with error");
                        }
                    }
                    .instrument(tracing::Span::current()),
                );
            }
        }
        .instrument(span)
        .await
    }
}

async fn serve_connection(
    stream: TcpStream,
    keys: &ServiceKeys,
    site: &Site,
) -> Result<(), NetError> {
    let mut channel = SecureChannel::accept(stream, keys, HANDSHAKE_TIMEOUT).await?;
    while let Some(request) = channel.next_request(IDLE_TIMEOUT).await? {
        let response = site.handle(&request).await;
        // Log the status and size only; paths may be sensitive.
        info!(
            status = response.status,
            bytes = response.body.len(),
            "request served"
        );
        channel.respond(&response).await?;
    }
    Ok(())
}
