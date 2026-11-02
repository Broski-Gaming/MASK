//! MASK relay network (v0.2 prototype).
//!
//! **Not anonymous. Not encrypted. Not secure.** Every relay can read every
//! message and the full route. This milestone only proves that structured,
//! framed messages can be routed through Entry → Middle → Exit relays on
//! localhost. Layered (onion) encryption is the next milestone.
//!
//! Modules:
//! - [`identity`]: relay identities and roles.
//! - [`protocol`]: wire messages and onion layers (encoding/decoding only).
//! - [`transport`]: length-prefixed framed TCP connections and the handshake.
//! - [`relay`]: the Entry / Middle / Exit relay server.
//! - [`client`]: builds onion-layered payloads and sends test messages.
//!
//! This crate has no GUI dependencies, so relays can run on machines without
//! a desktop. The browser (`mask` crate) will use it through [`client`].

pub mod client;
pub mod error;
pub mod identity;
pub mod protocol;
pub mod relay;
pub mod transport;

pub use error::NetError;
