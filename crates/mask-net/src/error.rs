use std::fmt;
use std::io;
use std::net::SocketAddr;

use crate::crypto::CryptoError;
use crate::protocol::{DestroyReason, ErrorCode, LinkErrorCode};
use crate::scope::NetworkScope;

#[derive(Debug)]
pub enum NetError {
    Io(io::Error),
    Decode(postcard::Error),
    Timeout,
    ConnectionClosed,
    /// The peer broke the protocol rules.
    Protocol(String),
    Crypto(CryptoError),
    /// The neighbour refused the link handshake.
    LinkRejected {
        code: LinkErrorCode,
        detail: String,
    },
    /// The circuit was torn down.
    Destroyed(DestroyReason),
    /// Hop number `hop` (0 = entry) reported that a command failed.
    Remote {
        hop: usize,
        code: ErrorCode,
        detail: String,
    },
    Descriptor(String),
    /// The address is outside the configured network scope (public
    /// addresses are always outside it).
    OutOfScope {
        addr: SocketAddr,
        scope: NetworkScope,
    },
    /// A peer, relay, or document is not trusted (unknown key, identity
    /// change, bad authority signature, ...).
    Untrusted(String),
    InvalidConfig(String),
    /// The connection policy refused this connection.
    PolicyDenied {
        origin: String,
        addr: SocketAddr,
    },
    /// The component was shut down.
    Shutdown,
    /// No entry guard can be used (all down, or all related to the last
    /// hop). Fails closed: no unrelated entry relay is tried instead.
    NoGuard(String),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Decode(e) => write!(f, "malformed message: {e}"),
            Self::Timeout => write!(f, "timed out"),
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Crypto(e) => write!(f, "cryptographic check failed: {e}"),
            Self::LinkRejected { code, detail } => {
                write!(f, "link rejected ({code:?}): {detail}")
            }
            Self::Destroyed(reason) => write!(f, "circuit destroyed ({reason:?})"),
            Self::Remote { hop, code, detail } => {
                write!(f, "hop {} reported {code:?}: {detail}", hop + 1)
            }
            Self::Descriptor(msg) => write!(f, "relay descriptor: {msg}"),
            Self::OutOfScope { addr, scope } => write!(
                f,
                "{addr} is outside the allowed network scope ({}); MORP never uses public addresses",
                scope.describe()
            ),
            Self::Untrusted(why) => write!(f, "untrusted: {why}"),
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
            Self::PolicyDenied { origin, addr } => {
                write!(f, "connection from {origin} to {addr} denied by policy")
            }
            Self::Shutdown => write!(f, "shut down"),
            Self::NoGuard(why) => write!(f, "no usable entry guard: {why}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for NetError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<postcard::Error> for NetError {
    fn from(e: postcard::Error) -> Self {
        Self::Decode(e)
    }
}

impl From<CryptoError> for NetError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}
