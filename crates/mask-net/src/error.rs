use std::fmt;
use std::io;
use std::net::SocketAddr;

use crate::protocol::ErrorCode;

#[derive(Debug)]
pub enum NetError {
    Io(io::Error),
    Decode(postcard::Error),
    Timeout,
    ConnectionClosed,
    /// The peer broke the handshake or protocol rules.
    Protocol(String),
    /// A relay on the route reported an error.
    Remote {
        code: ErrorCode,
        detail: String,
    },
    /// v0.2 only runs on loopback addresses.
    NotLoopback(SocketAddr),
    InvalidConfig(String),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Decode(e) => write!(f, "malformed message: {e}"),
            Self::Timeout => write!(f, "timed out"),
            Self::ConnectionClosed => write!(f, "connection closed by peer"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Remote { code, detail } => write!(f, "relay error {code}: {detail}"),
            Self::NotLoopback(addr) => write!(
                f,
                "{addr} is not a loopback address; MASK v0.2 only runs on 127.0.0.1"
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
