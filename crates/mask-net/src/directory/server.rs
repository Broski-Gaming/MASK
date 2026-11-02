//! Directory server (Axum).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::NetError;
use crate::address::MorpAddress;
use crate::service::descriptor::{ServiceDescriptor, Withdrawal};
use crate::service::now_secs;

/// Largest accepted request body. Descriptors are well under 1 KiB.
const MAX_BODY: usize = 8 * 1024;
/// Most descriptors held at once.
const MAX_SERVICES: usize = 10_000;

#[derive(Default)]
pub struct DirectoryState {
    store: RwLock<Store>,
}

#[derive(Default)]
struct Store {
    services: HashMap<[u8; 32], ServiceDescriptor>,
    /// Highest revision withdrawn per service, so old descriptors cannot be
    /// replayed after a withdrawal.
    withdrawn: HashMap<[u8; 32], u64>,
}

fn reply(status: StatusCode, message: &str) -> Response {
    (
        status,
        format!("{{\"error\":{}}}", serde_json::Value::from(message)),
    )
        .into_response()
}

fn parse_id(id: &str) -> Result<MorpAddress, Box<Response>> {
    MorpAddress::parse_id(id).map_err(|e| Box::new(reply(StatusCode::BAD_REQUEST, &e.to_string())))
}

pub fn router(state: Arc<DirectoryState>) -> Router {
    Router::new()
        .route("/v1/health", get(|| async { "ok" }))
        .route(
            "/v1/services/{id}",
            get(lookup).put(publish).delete(withdraw),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

async fn lookup(State(state): State<Arc<DirectoryState>>, Path(id): Path<String>) -> Response {
    let address = match parse_id(&id) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    let key = *address.public_key();
    let found = state.store.read().unwrap().services.get(&key).cloned();
    let Some(descriptor) = found else {
        return reply(StatusCode::NOT_FOUND, "no descriptor for this address");
    };
    // Verify again before returning: never hand out an expired or invalid one.
    if let Err(e) = descriptor.verify(now_secs()) {
        state.store.write().unwrap().services.remove(&key);
        return reply(StatusCode::NOT_FOUND, &format!("descriptor dropped: {e}"));
    }
    (StatusCode::OK, descriptor.to_json()).into_response()
}

async fn publish(
    State(state): State<Arc<DirectoryState>>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let address = match parse_id(&id) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    let descriptor = match ServiceDescriptor::from_json(&body) {
        Ok(d) => d,
        Err(e) => return reply(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    if descriptor.address != address {
        return reply(
            StatusCode::BAD_REQUEST,
            "descriptor is for a different address than the URL",
        );
    }
    if let Err(e) = descriptor.verify(now_secs()) {
        warn!(address = %&address.id()[..16], error = %e, "rejected descriptor");
        return reply(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
    }

    let key = *address.public_key();
    let mut store = state.store.write().unwrap();
    let newest = store
        .services
        .get(&key)
        .map(|d| d.revision)
        .into_iter()
        .chain(store.withdrawn.get(&key).copied())
        .max();
    if newest.is_some_and(|r| descriptor.revision <= r) {
        return reply(
            StatusCode::CONFLICT,
            "a descriptor with the same or newer revision exists (possible replay)",
        );
    }
    if !store.services.contains_key(&key) && store.services.len() >= MAX_SERVICES {
        return reply(StatusCode::INSUFFICIENT_STORAGE, "directory is full");
    }
    info!(address = %&address.id()[..16], revision = descriptor.revision, "descriptor stored");
    store.services.insert(key, descriptor);
    reply(StatusCode::OK, "stored")
}

async fn withdraw(
    State(state): State<Arc<DirectoryState>>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let address = match parse_id(&id) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    let withdrawal: Withdrawal = match serde_json::from_str(&body) {
        Ok(w) => w,
        Err(e) => return reply(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    match withdrawal.verify() {
        Ok(signed_for) if signed_for == address => {}
        Ok(_) => return reply(StatusCode::BAD_REQUEST, "withdrawal is for another address"),
        Err(e) => return reply(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
    }

    let key = *address.public_key();
    let mut store = state.store.write().unwrap();
    let Some(current) = store.services.get(&key).map(|d| d.revision) else {
        return reply(StatusCode::NOT_FOUND, "no descriptor for this address");
    };
    if withdrawal.revision < current {
        return reply(
            StatusCode::CONFLICT,
            "withdrawal is older than the descriptor",
        );
    }
    store.services.remove(&key);
    store.withdrawn.insert(key, withdrawal.revision);
    info!(address = %&address.id()[..16], "descriptor withdrawn");
    reply(StatusCode::OK, "withdrawn")
}

/// Bind the directory on a loopback address.
pub async fn bind(listen: SocketAddr) -> Result<TcpListener, NetError> {
    if !listen.ip().is_loopback() {
        return Err(NetError::NotLoopback(listen));
    }
    Ok(TcpListener::bind(listen).await?)
}

/// Serve until the task is cancelled.
pub async fn serve(listener: TcpListener, state: Arc<DirectoryState>) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}
