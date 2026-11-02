use std::fmt;
use std::io;
use std::net::SocketAddr;

use crate::crypto::CryptoError;
use crate::protocol::{DestroyReason, ErrorCode, LinkErrorCode};

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
    /// MORP currently only runs on loopback addresses.
    NotLoopback(SocketAddr),
    InvalidConfig(String),
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
            Self::NotLoopback(addr) => write!(
                f,
                "{addr} is not a loopback address; MORP currently only runs on 127.0.0.1"
            ),
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
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
