//! MASK — Multi-hop Anonymous Service Kit: the browser.
//!
//! **Not anonymous.** Normal websites are loaded over the direct internet
//! connection. `.morp` services are resolved through the local MORP
//! directory and reached over an authenticated, encrypted localhost
//! connection (v0.4 prototype: not through relays, location not hidden).
//!
//! Module layout:
//! - [`address`]: parses and validates what the user types in the address bar.
//! - [`morp`]: the `morp://` protocol handler (no DNS, no clearnet fallback).
//! - [`browser`]: the GTK window, toolbar, and embedded WebKit view.
//!
//! Networking lives in the separate `mask-net` crate.

pub mod address;
pub mod browser;
pub mod morp;
pub mod privacy;
