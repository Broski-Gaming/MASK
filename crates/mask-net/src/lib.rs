//! MASK network: **MORP**, the MASK Onion Routing Protocol (experimental),
//! and cryptographic `.morp` service addresses.
//!
//! **Not reviewed. Do not rely on it for anonymity or security.** MORP is a
//! learning prototype that runs only on localhost. See `docs/MORP.md` and
//! `docs/MORP_ADDRESSES.md` for the protocols, threat models, and known
//! limitations.
//!
//! Modules:
//! - [`address`]: `.morp` addresses derived from Ed25519 public keys.
//! - [`service`]: service keys, signed descriptors, the authenticated
//!   service channel, static site hosting, and fetching.
//! - [`directory`]: the localhost service directory (server and client).
//! - [`crypto`]: keys, ntor-style handshake, per-hop authenticated encryption.
//! - [`descriptor`]: signed relay descriptors, local directory, path choice.
//! - [`protocol`]: relay wire messages and onion-layer plaintexts.
//! - [`transport`]: framed TCP links shared by many circuits.
//! - [`relay`]: the entry / middle / exit relay server.
//! - [`client`]: builds circuits and sends data through them.
//!
//! This crate has no GUI dependencies, so relays and services run headless.

pub mod address;
pub mod client;
pub mod crypto;
pub mod descriptor;
pub mod directory;
pub mod error;
pub mod hs;
pub mod identity;
pub mod protocol;
pub mod relay;
pub mod service;
pub mod transport;

pub use error::NetError;
