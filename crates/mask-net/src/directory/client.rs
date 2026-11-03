//! Directory client used by service hosts, the CLI, and the browser.
//!
//! The HTTP client is built without TLS and without system proxy support,
//! and only accepts a loopback directory, so lookups for `.morp` addresses
//! cannot leave the machine.

use std::net::SocketAddr;
use std::time::Duration;

use crate::NetError;
use crate::address::MorpAddress;
use crate::service::descriptor::{ServiceDescriptor, Withdrawal};
use crate::service::now_secs;

#[derive(Clone, Debug)]
pub struct DirectoryClient {
    base: String,
    http: reqwest::Client,
}

#[derive(Debug)]
pub enum LookupError {
    /// The directory could not be reached or answered strangely.
    Unavailable(String),
    /// The directory returned a descriptor that failed verification.
    Invalid(String),
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(why) => write!(f, "directory unavailable: {why}"),
            Self::Invalid(why) => write!(f, "directory returned an invalid descriptor: {why}"),
        }
    }
}

impl DirectoryClient {
    pub fn new(directory: SocketAddr, timeout: Duration) -> Result<Self, NetError> {
        crate::scope::NetworkScope::Loopback.check(directory)?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| NetError::InvalidConfig(format!("HTTP client: {e}")))?;
        Ok(Self {
            base: format!("http://{directory}/v1/services/"),
            http,
        })
    }

    fn url(&self, address: &MorpAddress) -> String {
        format!("{}{}", self.base, address.id())
    }

    /// Find and verify the descriptor for `address`. `Ok(None)` if the
    /// directory has none.
    pub async fn lookup(
        &self,
        address: &MorpAddress,
    ) -> Result<Option<ServiceDescriptor>, LookupError> {
        let response = self
            .http
            .get(self.url(address))
            .send()
            .await
            .map_err(|e| LookupError::Unavailable(e.to_string()))?;
        match response.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            other => return Err(LookupError::Unavailable(format!("HTTP {other}"))),
        }
        let body = response
            .text()
            .await
            .map_err(|e| LookupError::Unavailable(e.to_string()))?;
        // Never trust the directory: verify everything ourselves.
        let descriptor =
            ServiceDescriptor::from_json(&body).map_err(|e| LookupError::Invalid(e.to_string()))?;
        if descriptor.address != *address {
            return Err(LookupError::Invalid(
                "descriptor is for a different address".into(),
            ));
        }
        descriptor
            .verify(now_secs())
            .map_err(|e| LookupError::Invalid(e.to_string()))?;
        Ok(Some(descriptor))
    }

    pub async fn publish(&self, descriptor: &ServiceDescriptor) -> Result<(), NetError> {
        let response = self
            .http
            .put(self.url(&descriptor.address))
            .body(descriptor.to_json())
            .send()
            .await
            .map_err(|e| NetError::Protocol(format!("directory unreachable: {e}")))?;
        check(response).await
    }

    pub async fn withdraw(&self, withdrawal: &Withdrawal) -> Result<(), NetError> {
        let address = MorpAddress::parse_host(&withdrawal.address)
            .map_err(|e| NetError::InvalidConfig(e.to_string()))?;
        let response = self
            .http
            .delete(self.url(&address))
            .body(serde_json::to_string(withdrawal).expect("withdrawal serializes"))
            .send()
            .await
            .map_err(|e| NetError::Protocol(format!("directory unreachable: {e}")))?;
        check(response).await
    }
}

async fn check(response: reqwest::Response) -> Result<(), NetError> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    Err(NetError::Protocol(format!(
        "directory refused (HTTP {}): {body}",
        status.as_u16()
    )))
}
