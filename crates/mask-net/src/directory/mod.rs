//! MORP service directory (localhost prototype).
//!
//! Stores signed service descriptors keyed by `.morp` identity. There is no
//! way to register a name, alias, or anything other than a cryptographic
//! address, and there is no endpoint that lists services.
//!
//! HTTP API (JSON bodies, 127.0.0.1 only):
//! - `GET    /v1/services/{id}`: the current descriptor, re-verified first.
//! - `PUT    /v1/services/{id}`: publish a descriptor signed by `{id}`'s key.
//! - `DELETE /v1/services/{id}`: remove it with a signed [`Withdrawal`].
//! - `GET    /v1/health`
//!
//! [`Withdrawal`]: crate::service::descriptor::Withdrawal

pub mod client;
pub mod server;

pub const DEFAULT_DIRECTORY: &str = "127.0.0.1:7200";
