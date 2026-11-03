//! MORP service directory (localhost prototype).
//!
//! Stores signed service descriptors keyed by `.morp` identity. There is no
//! way to register a name, alias, or anything other than a cryptographic
//! address, and there is no endpoint that lists services.
//!
//! HTTP API (JSON bodies, 127.0.0.1 only):
//! - `GET    /v1/services/{id}`: the current descriptor, re-verified first.
//! - `PUT    /v1/services/{id}`: publish a descriptor signed by `{id}`'s key.
//! - `DELETE /v1/services/{id}`: remove it with a signed [`Withdrawal`].
//! - `GET    /v1/health`
//!
//! [`Withdrawal`]: crate::service::descriptor::Withdrawal

pub mod client;
pub mod server;

pub const DEFAULT_DIRECTORY: &str = "127.0.0.1:7200";

use crate::NetError;
use crate::address::MorpAddress;
use crate::authority::client::AuthorityClient;
use crate::service::descriptor::{ServiceDescriptor, Withdrawal};
use client::{DirectoryClient, LookupError};

/// Where `.morp` service descriptors are published and looked up.
///
/// - [`Local`](ServiceDirectory::Local): the v0.4/v0.5 HTTP directory on
///   127.0.0.1 (single machine).
/// - [`Network`](ServiceDirectory::Network): the directory authorities of a
///   v0.6 testnet, over Noise-encrypted links.
///
/// Either way, descriptors are verified by the client; the directory is
/// never trusted to vouch for a service.
#[derive(Clone, Debug)]
pub enum ServiceDirectory {
    Local(DirectoryClient),
    Network(AuthorityClient),
}

impl From<DirectoryClient> for ServiceDirectory {
    fn from(client: DirectoryClient) -> Self {
        Self::Local(client)
    }
}

impl From<AuthorityClient> for ServiceDirectory {
    fn from(client: AuthorityClient) -> Self {
        Self::Network(client)
    }
}

impl ServiceDirectory {
    pub async fn lookup(
        &self,
        address: &MorpAddress,
    ) -> Result<Option<ServiceDescriptor>, LookupError> {
        match self {
            Self::Local(c) => c.lookup(address).await,
            Self::Network(c) => c.lookup_service(address).await,
        }
    }

    pub async fn publish(&self, descriptor: &ServiceDescriptor) -> Result<(), NetError> {
        match self {
            Self::Local(c) => c.publish(descriptor).await,
            Self::Network(c) => c.publish_service(descriptor).await,
        }
    }

    pub async fn withdraw(&self, withdrawal: &Withdrawal) -> Result<(), NetError> {
        match self {
            Self::Local(c) => c.withdraw(withdrawal).await,
            Self::Network(c) => c.withdraw_service(withdrawal).await,
        }
    }

    /// The authority client, in network mode.
    pub fn authorities(&self) -> Option<&AuthorityClient> {
        match self {
            Self::Local(_) => None,
            Self::Network(c) => Some(c),
        }
    }
}
