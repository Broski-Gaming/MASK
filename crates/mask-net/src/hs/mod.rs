//! MORP hidden services (v0.5): `.morp` connections routed entirely
//! through MORP relays, using introduction points and rendezvous points.
//!
//! ```text
//! client:  entry → middle → RENDEZVOUS ←── joined ──→ RENDEZVOUS ← middle ← entry :service
//!                                                                   (separate circuit)
//! client:  entry → middle → INTRO ← middle ← entry :service  (introduction only)
//! ```
//!
//! - [`crypto`]: intro keys, encrypted introductions, service authentication,
//!   end-to-end session keys.
//! - [`session`]: end-to-end encrypted, multiplexed request/response.
//! - [`service`]: the hidden-service host.
//! - [`client`]: fetching from a `.morp` service.
//! - [`app`]: the service's local web application and request forwarder.
//!
//! **Experimental and unreviewed.** See `docs/MORP_HIDDEN_SERVICES.md` for
//! the threat model; this does not provide Tor-level anonymity.

pub mod app;
pub mod client;
pub mod crypto;
pub mod service;
pub mod session;
