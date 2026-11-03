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

/// Why the store refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    BadRequest,
    NotFound,
    Invalid,
    Conflict,
    Full,
}

impl StoreError {
    fn status(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Full => StatusCode::INSUFFICIENT_STORAGE,
        }
    }
}

type StoreResult<T> = Result<T, (StoreError, String)>;

impl DirectoryState {
    /// The current descriptor for `address`, re-verified first.
    pub fn lookup(&self, address: &MorpAddress) -> StoreResult<ServiceDescriptor> {
        let key = *address.public_key();
        let found = self.store.read().unwrap().services.get(&key).cloned();
        let Some(descriptor) = found else {
            return Err((
                StoreError::NotFound,
                "no descriptor for this address".into(),
            ));
        };
        // Verify again before returning: never hand out an expired or invalid one.
        if let Err(e) = descriptor.verify(now_secs()) {
            self.store.write().unwrap().services.remove(&key);
            return Err((StoreError::NotFound, format!("descriptor dropped: {e}")));
        }
        Ok(descriptor)
    }

    /// Store a descriptor (JSON) for `address`.
    pub fn publish(&self, address: &MorpAddress, json: &str) -> StoreResult<()> {
        let descriptor = ServiceDescriptor::from_json(json)
            .map_err(|e| (StoreError::BadRequest, e.to_string()))?;
        if descriptor.address != *address {
            return Err((
                StoreError::BadRequest,
                "descriptor is for a different address than the URL".into(),
            ));
        }
        if let Err(e) = descriptor.verify(now_secs()) {
            warn!(address = %&address.id()[..16], error = %e, "rejected descriptor");
            return Err((StoreError::Invalid, e.to_string()));
        }

        let key = *address.public_key();
        let mut store = self.store.write().unwrap();
        let newest = store
            .services
            .get(&key)
            .map(|d| d.revision)
            .into_iter()
            .chain(store.withdrawn.get(&key).copied())
            .max();
        if newest.is_some_and(|r| descriptor.revision <= r) {
            return Err((
                StoreError::Conflict,
                "a descriptor with the same or newer revision exists (possible replay)".into(),
            ));
        }
        if !store.services.contains_key(&key) && store.services.len() >= MAX_SERVICES {
            return Err((StoreError::Full, "directory is full".into()));
        }
        info!(address = %&address.id()[..16], revision = descriptor.revision, "descriptor stored");
        store.services.insert(key, descriptor);
        Ok(())
    }

    /// Remove `address`'s descriptor with a signed withdrawal (JSON).
    pub fn withdraw(&self, address: &MorpAddress, json: &str) -> StoreResult<()> {
        let withdrawal: Withdrawal =
            serde_json::from_str(json).map_err(|e| (StoreError::BadRequest, e.to_string()))?;
        match withdrawal.verify() {
            Ok(signed_for) if signed_for == *address => {}
            Ok(_) => {
                return Err((
                    StoreError::BadRequest,
                    "withdrawal is for another address".into(),
                ));
            }
            Err(e) => return Err((StoreError::Invalid, e.to_string())),
        }

        let key = *address.public_key();
        let mut store = self.store.write().unwrap();
        let Some(current) = store.services.get(&key).map(|d| d.revision) else {
            return Err((
                StoreError::NotFound,
                "no descriptor for this address".into(),
            ));
        };
        if withdrawal.revision < current {
            return Err((
                StoreError::Conflict,
                "withdrawal is older than the descriptor".into(),
            ));
        }
        store.services.remove(&key);
        store.withdrawn.insert(key, withdrawal.revision);
        info!(address = %&address.id()[..16], "descriptor withdrawn");
        Ok(())
    }
}

fn store_reply<T>(result: StoreResult<T>, ok: impl FnOnce(T) -> Response) -> Response {
    match result {
        Ok(value) => ok(value),
        Err((kind, message)) => reply(kind.status(), &message),
    }
}

async fn lookup(State(state): State<Arc<DirectoryState>>, Path(id): Path<String>) -> Response {
    let address = match parse_id(&id) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    store_reply(state.lookup(&address), |d| {
        (StatusCode::OK, d.to_json()).into_response()
    })
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
    store_reply(state.publish(&address, &body), |()| {
        reply(StatusCode::OK, "stored")
    })
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
    store_reply(state.withdraw(&address, &body), |()| {
        reply(StatusCode::OK, "withdrawn")
    })
}

/// Bind the directory on a loopback address.
pub async fn bind(listen: SocketAddr) -> Result<TcpListener, NetError> {
    crate::scope::NetworkScope::Loopback.check(listen)?;
    Ok(TcpListener::bind(listen).await?)
}

/// Serve until the task is cancelled.
pub async fn serve(listener: TcpListener, state: Arc<DirectoryState>) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}
