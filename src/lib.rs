//! MASK — Multi-hop Anonymous Service Kit: the browser.
//!
//! **Not anonymous.** Normal websites are loaded over the direct internet
//! connection. `.morp` services are resolved through the MORP directory
//! (never public DNS) and reached only through MORP relay circuits joined
//! at a rendezvous point. Experimental and unreviewed: not Tor-level
//! anonymity. See `docs/SECURITY_MODEL.md` and `docs/THREAT_MODEL.md`.
//!
//! Module layout:
//! - [`address`]: parses and validates what the user types in the address bar.
//! - [`morp`]: the `morp://` protocol handler (no DNS, no clearnet fallback).
//! - [`privacy`]: leak-prevention and anti-fingerprinting policy (v0.7).
//! - [`browser`]: the GTK window, toolbar, and embedded WebKit view.
//!
//! Networking lives in the separate `mask-net` crate.

pub mod address;
pub mod browser;
pub mod morp;
pub mod privacy;
