//! MASK network: **MORP**, the MASK Onion Routing Protocol (experimental).
//!
//! **Not reviewed. Do not rely on it for anonymity or security.** MORP is a
//! learning prototype that runs only on localhost. See `docs/MORP.md` for
//! the protocol, threat model, and known limitations.
//!
//! Modules:
//! - [`crypto`]: keys, ntor-style handshake, per-hop authenticated encryption.
//! - [`descriptor`]: signed relay descriptors, local directory, path choice.
//! - [`protocol`]: wire messages and onion-layer plaintexts.
//! - [`transport`]: framed TCP links shared by many circuits.
//! - [`relay`]: the entry / middle / exit relay server.
//! - [`client`]: builds circuits and sends data through them.
//!
//! This crate has no GUI dependencies, so relays can run headless.

pub mod client;
pub mod crypto;
pub mod descriptor;
pub mod error;
pub mod identity;
pub mod protocol;
pub mod relay;
pub mod transport;

pub use error::NetError;
