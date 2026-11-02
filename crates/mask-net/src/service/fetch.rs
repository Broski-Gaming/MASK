//! Fetch a page from a `.morp` service: directory lookup → verified
//! descriptor → authenticated channel → GET. Used by the browser and CLI.
//!
//! Every step fails closed: there is no fallback to DNS or the internet.

use std::fmt;
use std::time::Duration;

use super::channel::{Response, SecureChannel};
use super::descriptor::ServiceEndpoint;
use crate::NetError;
use crate::address::MorpAddress;
use crate::directory::client::{DirectoryClient, LookupError};

#[derive(Clone, Copy, Debug)]
pub struct FetchTimeouts {
    pub connect: Duration,
    pub handshake: Duration,
    pub response: Duration,
}

impl Default for FetchTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            handshake: Duration::from_secs(5),
            response: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub enum FetchError {
    DirectoryUnavailable(String),
    /// The directory has no (valid, unexpired) descriptor for the address.
    NotFound,
    DescriptorInvalid(String),
    /// The descriptor is valid but nothing answers at its endpoint.
    ServiceUnavailable(String),
    /// Something answered but could not prove it holds the address's key.
    IdentityMismatch(String),
    Protocol(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectoryUnavailable(why) => write!(f, "MORP directory unavailable: {why}"),
            Self::NotFound => write!(f, "no service is currently published at this address"),
            Self::DescriptorInvalid(why) => write!(f, "invalid service descriptor: {why}"),
            Self::ServiceUnavailable(why) => write!(f, "service is not reachable: {why}"),
            Self::IdentityMismatch(why) => write!(
                f,
                "the server could not prove it owns this .morp address: {why}"
            ),
            Self::Protocol(why) => write!(f, "service protocol error: {why}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Resolve and connect, proving the service's identity. Returns the open
/// channel (useful for `verify`) without sending a request.
pub async fn connect(
    directory: &DirectoryClient,
    address: &MorpAddress,
    timeouts: FetchTimeouts,
) -> Result<SecureChannel, FetchError> {
    let descriptor = match directory.lookup(address).await {
        Ok(Some(d)) => d,
        Ok(None) => return Err(FetchError::NotFound),
        Err(LookupError::Unavailable(why)) => return Err(FetchError::DirectoryUnavailable(why)),
        Err(LookupError::Invalid(why)) => return Err(FetchError::DescriptorInvalid(why)),
    };
    let ServiceEndpoint::DirectLoopback(endpoint) = descriptor.endpoint;
    SecureChannel::connect(endpoint, address, timeouts.connect, timeouts.handshake)
        .await
        .map_err(|e| match e {
            NetError::Io(_) | NetError::Timeout | NetError::ConnectionClosed => {
                FetchError::ServiceUnavailable(e.to_string())
            }
            NetError::Crypto(_) | NetError::Protocol(_) | NetError::Decode(_) => {
                FetchError::IdentityMismatch(e.to_string())
            }
            other => FetchError::Protocol(other.to_string()),
        })
}

/// Fetch `path` (with query) from the service at `address`.
pub async fn fetch(
    directory: &DirectoryClient,
    address: &MorpAddress,
    path: &str,
    timeouts: FetchTimeouts,
) -> Result<Response, FetchError> {
    let mut channel = connect(directory, address, timeouts).await?;
    channel
        .get(path, timeouts.response)
        .await
        .map_err(|e| match e {
            NetError::Io(_) | NetError::Timeout | NetError::ConnectionClosed => {
                FetchError::ServiceUnavailable(e.to_string())
            }
            other => FetchError::Protocol(other.to_string()),
        })
}
