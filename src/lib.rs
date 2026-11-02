//! MASK — Multi-hop Anonymous Service Kit.
//!
//! Version 0.1 contains only the browser shell. Pages are loaded over the
//! normal, direct internet connection: there is no onion routing yet and
//! MASK does not provide anonymity.
//!
//! Module layout:
//! - [`address`]: parses and validates what the user types in the address bar.
//! - [`browser`]: the GTK window, toolbar, and embedded WebKit view.
//!
//! Future networking code (relays, circuits, SOCKS5, `.mask` services) will
//! live in its own modules and plug into the browser through the address and
//! connection layers rather than the UI code.

pub mod address;
pub mod browser;
