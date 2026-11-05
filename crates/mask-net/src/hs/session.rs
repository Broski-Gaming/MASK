//! End-to-end encrypted HTTP-style session between a client and a `.morp`
//! service, carried as `Stream` payloads over the joined rendezvous circuits.
//!
//! Every payload is one ChaCha20-Poly1305 frame sealed with the session keys
//! from [`super::crypto`]. Nonces are 64-bit counters per direction (the
//! same [`CellCipher`] as MORP cells), so replayed, reordered, dropped, or
//! modified frames fail authentication and end the session. Relays, including
//! the rendezvous point, only ever see these ciphertexts.
//!
//! Requests carry an ID so many can be in flight at once (a page and its
//! CSS, JavaScript, and images load in parallel). Response bodies are split
//! into chunks that fit in one MORP cell.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::timeout;

use super::crypto::SessionKeys;
use crate::client::StreamPipe;
use crate::crypto::onion::{CellCipher, Direction};
use crate::protocol::{decode, encode};

/// Largest response body accepted by a client.
pub const MAX_BODY: u64 = 16 * 1024 * 1024;
/// Body bytes per frame (fits in one MORP cell with headers and tags).
pub const CHUNK: usize = 32 * 1024;
/// Requests in flight per session.
pub const MAX_IN_FLIGHT: usize = 64;
/// Response bytes a client buffers at once over all in-flight requests
/// (v0.7). Without it a hostile service could announce 64 responses of
/// [`MAX_BODY`] each and make the client hold 1 GiB.
pub const MAX_BUFFERED: u64 = 64 * 1024 * 1024;
/// Longest request path (with query) a client sends or a service accepts.
pub const MAX_PATH_LEN: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    /// Path and query, starting with `/`.
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum ClientFrame {
    Request { id: u32, request: HttpRequest },
}

#[derive(Serialize, Deserialize)]
enum ServiceFrame {
    Head {
        id: u32,
        status: u16,
        content_type: String,
        length: u64,
    },
    Body {
        id: u32,
        chunk: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The circuits closed or the session ended.
    Closed(String),
    Timeout,
    TooManyRequests,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(why) => write!(f, "MORP session closed: {why}"),
            Self::Timeout => write!(f, "the service did not answer in time"),
            Self::TooManyRequests => write!(f, "too many requests in flight"),
        }
    }
}

impl std::error::Error for SessionError {}

// ================================================================= client

struct Pending {
    request: HttpRequest,
    reply: oneshot::Sender<Result<HttpResponse, SessionError>>,
}

/// Client end of a session. Cheap to clone; all clones share the circuits.
#[derive(Clone)]
pub struct ClientSession {
    commands: mpsc::Sender<Pending>,
}

struct InFlight {
    reply: oneshot::Sender<Result<HttpResponse, SessionError>>,
    head: Option<(u16, String, u64)>,
    body: Vec<u8>,
}

impl ClientSession {
    pub fn start(pipe: StreamPipe, keys: SessionKeys) -> Self {
        let (commands, rx) = mpsc::channel(MAX_IN_FLIGHT);
        let send = CellCipher::new(&keys.client_to_service, Direction::Forward);
        let recv = CellCipher::new(&keys.service_to_client, Direction::Backward);
        tokio::spawn(client_actor(pipe, send, recv, rx));
        Self { commands }
    }

    /// False once the circuits are gone; a new session is then needed.
    pub fn is_open(&self) -> bool {
        !self.commands.is_closed()
    }

    pub async fn request(
        &self,
        request: HttpRequest,
        limit: Duration,
    ) -> Result<HttpResponse, SessionError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Pending { request, reply })
            .await
            .map_err(|_| SessionError::Closed("session ended".into()))?;
        match timeout(limit, answer).await {
            Err(_) => Err(SessionError::Timeout),
            Ok(Err(_)) => Err(SessionError::Closed("session ended".into())),
            Ok(Ok(result)) => result,
        }
    }
}

async fn client_actor(
    mut pipe: StreamPipe,
    mut send: CellCipher,
    mut recv: CellCipher,
    mut commands: mpsc::Receiver<Pending>,
) {
    let mut in_flight: HashMap<u32, InFlight> = HashMap::new();
    let mut next_id: u32 = 1;

    let reason = loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(Pending { request, reply }) = command else {
                    break "client closed the session".to_owned();
                };
                if in_flight.len() >= MAX_IN_FLIGHT {
                    let _ = reply.send(Err(SessionError::TooManyRequests));
                    continue;
                }
                if request.path.len() > MAX_PATH_LEN || request.method.len() > 16 {
                    let _ = reply.send(Err(SessionError::Closed("request too long".into())));
                    continue;
                }
                // IDs wrap after 2^32 requests; never reuse one still in flight.
                let id = loop {
                    let id = next_id;
                    next_id = next_id.wrapping_add(1).max(1);
                    if !in_flight.contains_key(&id) {
                        break id;
                    }
                };
                let frame = match send.seal(&encode(&ClientFrame::Request { id, request })) {
                    Ok(frame) => frame,
                    Err(e) => break format!("cannot seal request: {e}"),
                };
                if pipe.tx.send(frame).await.is_err() {
                    let _ = reply.send(Err(SessionError::Closed("circuit closed".into())));
                    break "circuit closed".to_owned();
                }
                in_flight.insert(id, InFlight { reply, head: None, body: Vec::new() });
            }
            frame = pipe.rx.recv() => {
                let Some(frame) = frame else {
                    break "circuit closed".to_owned();
                };
                let plaintext = match recv.open(&frame) {
                    Ok(p) => p,
                    Err(_) => break "a frame failed authentication (tampering or replay)".to_owned(),
                };
                let Ok(frame) = decode::<ServiceFrame>(&plaintext) else {
                    break "malformed frame from service".to_owned();
                };
                if let Err(why) = deliver(&mut in_flight, frame) {
                    break why;
                }
            }
        }
    };

    for (_, pending) in in_flight.drain() {
        let _ = pending
            .reply
            .send(Err(SessionError::Closed(reason.clone())));
    }
}

fn deliver(in_flight: &mut HashMap<u32, InFlight>, frame: ServiceFrame) -> Result<(), String> {
    let id = match &frame {
        ServiceFrame::Head { id, .. } | ServiceFrame::Body { id, .. } => *id,
    };
    // Bytes already announced by other in-flight responses (quota check).
    let announced_elsewhere: u64 = in_flight
        .iter()
        .filter(|(other, _)| **other != id)
        .filter_map(|(_, e)| e.head.as_ref().map(|(_, _, len)| *len))
        .sum();
    let Some(entry) = in_flight.get_mut(&id) else {
        return Err(format!("service answered unknown request {id}"));
    };
    match frame {
        ServiceFrame::Head {
            status,
            content_type,
            length,
            ..
        } => {
            if entry.head.is_some() {
                return Err("duplicate response head".into());
            }
            if length > MAX_BODY {
                return Err(format!("response of {length} bytes exceeds the limit"));
            }
            if announced_elsewhere + length > MAX_BUFFERED {
                return Err(format!(
                    "service announced more than {MAX_BUFFERED} bytes in flight"
                ));
            }
            entry.head = Some((status, content_type, length));
        }
        ServiceFrame::Body { chunk, .. } => {
            let Some((_, _, length)) = &entry.head else {
                return Err("body before head".into());
            };
            if entry.body.len() as u64 + chunk.len() as u64 > *length {
                return Err("body longer than announced".into());
            }
            entry.body.extend_from_slice(&chunk);
        }
    }
    let complete = entry
        .head
        .as_ref()
        .is_some_and(|(_, _, length)| entry.body.len() as u64 == *length);
    if complete {
        let done = in_flight.remove(&id).expect("present");
        let (status, content_type, _) = done.head.expect("complete implies head");
        let _ = done.reply.send(Ok(HttpResponse {
            status,
            content_type,
            body: done.body,
        }));
    }
    Ok(())
}

// ================================================================ service

pub type Handler =
    Arc<dyn Fn(HttpRequest) -> Pin<Box<dyn Future<Output = HttpResponse> + Send>> + Send + Sync>;

/// Serve one client session until the circuits close. Returns why it ended.
pub async fn serve(pipe: StreamPipe, keys: SessionKeys, handler: Handler) -> String {
    let StreamPipe { tx, mut rx } = pipe;
    let mut recv = CellCipher::new(&keys.client_to_service, Direction::Forward);
    let mut send = CellCipher::new(&keys.service_to_client, Direction::Backward);
    drop(keys);

    // One writer owns the sending cipher so frames leave in counter order.
    let (frames, mut frame_rx) = mpsc::channel::<ServiceFrame>(64);
    let writer = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            let Ok(sealed) = send.seal(&encode(&frame)) else {
                break;
            };
            if tx.send(sealed).await.is_err() {
                break;
            }
        }
    });

    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let reason = loop {
        let Some(frame) = rx.recv().await else {
            break "circuit closed".to_owned();
        };
        let plaintext = match recv.open(&frame) {
            Ok(p) => p,
            Err(_) => break "a frame failed authentication (tampering or replay)".to_owned(),
        };
        let Ok(ClientFrame::Request { id, request }) = decode::<ClientFrame>(&plaintext) else {
            break "malformed frame from client".to_owned();
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            break "client exceeded the in-flight request limit".to_owned();
        };
        let handler = Arc::clone(&handler);
        let frames = frames.clone();
        tokio::spawn(async move {
            let response = handler(request).await;
            let _ = frames
                .send(ServiceFrame::Head {
                    id,
                    status: response.status,
                    content_type: response.content_type,
                    length: response.body.len() as u64,
                })
                .await;
            for chunk in response.body.chunks(CHUNK) {
                if frames
                    .send(ServiceFrame::Body {
                        id,
                        chunk: chunk.to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            drop(permit);
        });
    };
    drop(frames);
    writer.abort();
    reason
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two pipes wired back to back, with an optional tap that can change
    /// frames travelling client → service.
    fn wired(tap: impl Fn(Vec<u8>) -> Vec<Vec<u8>> + Send + 'static) -> (StreamPipe, StreamPipe) {
        let (c_tx, mut c_out) = mpsc::channel::<Vec<u8>>(64);
        let (s_in_tx, s_rx) = mpsc::channel::<Vec<u8>>(64);
        let (s_tx, s_out) = mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            while let Some(frame) = c_out.recv().await {
                for f in tap(frame) {
                    if s_in_tx.send(f).await.is_err() {
                        return;
                    }
                }
            }
        });
        (
            StreamPipe {
                tx: c_tx,
                rx: s_out,
            },
            StreamPipe { tx: s_tx, rx: s_rx },
        )
    }

    fn keys() -> (SessionKeys, SessionKeys) {
        let make = || SessionKeys {
            client_to_service: [1; 32],
            service_to_client: [2; 32],
        };
        (make(), make())
    }

    fn echo_handler() -> Handler {
        Arc::new(|req: HttpRequest| {
            Box::pin(async move {
                let body = if req.path == "/big" {
                    (0..200_000u32).map(|i| (i % 253) as u8).collect()
                } else {
                    format!("{} {}", req.method, req.path).into_bytes()
                };
                HttpResponse {
                    status: 200,
                    content_type: "text/plain".into(),
                    body,
                }
            })
        })
    }

    fn get(path: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            path: path.into(),
        }
    }

    #[tokio::test]
    async fn requests_and_large_responses_round_trip() {
        let (client_pipe, service_pipe) = wired(|f| vec![f]);
        let (ck, sk) = keys();
        tokio::spawn(serve(service_pipe, sk, echo_handler()));
        let session = ClientSession::start(client_pipe, ck);

        let r = session
            .request(get("/a"), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(r.body, b"GET /a");
        let big = session
            .request(get("/big"), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(big.body.len(), 200_000);
        assert_eq!(big.body[1000], (1000 % 253) as u8);
    }

    #[tokio::test]
    async fn many_parallel_requests_are_kept_apart() {
        let (client_pipe, service_pipe) = wired(|f| vec![f]);
        let (ck, sk) = keys();
        tokio::spawn(serve(service_pipe, sk, echo_handler()));
        let session = ClientSession::start(client_pipe, ck);
        let tasks: Vec<_> = (0..40)
            .map(|i| {
                let s = session.clone();
                tokio::spawn(async move {
                    let path = format!("/item/{i}");
                    let r = s.request(get(&path), Duration::from_secs(5)).await.unwrap();
                    assert_eq!(r.body, format!("GET {path}").into_bytes());
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
    }

    #[tokio::test]
    async fn replayed_frame_ends_the_session() {
        // The tap duplicates every client frame.
        let (client_pipe, service_pipe) = wired(|f| vec![f.clone(), f]);
        let (ck, sk) = keys();
        let service = tokio::spawn(serve(service_pipe, sk, echo_handler()));
        let session = ClientSession::start(client_pipe, ck);
        let _ = session.request(get("/x"), Duration::from_secs(2)).await;
        let reason = service.await.unwrap();
        assert!(reason.contains("authentication"), "{reason}");
    }

    #[tokio::test]
    async fn tampered_frame_ends_the_session() {
        let (client_pipe, service_pipe) = wired(|mut f| {
            f[0] ^= 1;
            vec![f]
        });
        let (ck, sk) = keys();
        let service = tokio::spawn(serve(service_pipe, sk, echo_handler()));
        let session = ClientSession::start(client_pipe, ck);
        assert!(
            session
                .request(get("/x"), Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(service.await.unwrap().contains("authentication"));
    }

    #[tokio::test]
    async fn wrong_session_keys_cannot_talk() {
        let (client_pipe, service_pipe) = wired(|f| vec![f]);
        let (ck, _) = keys();
        let other = SessionKeys {
            client_to_service: [7; 32],
            service_to_client: [8; 32],
        };
        let service = tokio::spawn(serve(service_pipe, other, echo_handler()));
        let session = ClientSession::start(client_pipe, ck);
        assert!(
            session
                .request(get("/x"), Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(service.await.unwrap().contains("authentication"));
    }

    #[tokio::test]
    async fn closed_circuit_fails_pending_requests() {
        let (client_pipe, service_pipe) = wired(|f| vec![f]);
        drop(service_pipe);
        let (ck, _) = keys();
        let session = ClientSession::start(client_pipe, ck);
        let err = session
            .request(get("/x"), Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(err, SessionError::Closed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn hostile_service_cannot_make_the_client_buffer_without_limit() {
        // Regression (v0.7): a service could announce MAX_BODY for each of
        // 64 requests and make the client hold up to 1 GiB.
        let (client_pipe, service_pipe) = wired(|f| vec![f]);
        let (ck, sk) = keys();
        tokio::spawn(async move {
            // Announces a maximal body for every request, never sends it.
            let StreamPipe { tx, mut rx } = service_pipe;
            let mut recv = CellCipher::new(&sk.client_to_service, Direction::Forward);
            let mut send = CellCipher::new(&sk.service_to_client, Direction::Backward);
            while let Some(frame) = rx.recv().await {
                let Ok(ClientFrame::Request { id, .. }) = decode(&recv.open(&frame).unwrap())
                else {
                    break;
                };
                let head = ServiceFrame::Head {
                    id,
                    status: 200,
                    content_type: "application/octet-stream".into(),
                    length: MAX_BODY,
                };
                if tx.send(send.seal(&encode(&head)).unwrap()).await.is_err() {
                    break;
                }
            }
        });
        let session = ClientSession::start(client_pipe, ck);
        let tasks: Vec<_> = (0..8)
            .map(|i| {
                let s = session.clone();
                tokio::spawn(async move {
                    s.request(get(&format!("/{i}")), Duration::from_secs(3))
                        .await
                })
            })
            .collect();
        let mut quota = 0;
        for t in tasks {
            match t.await.unwrap() {
                Err(SessionError::Closed(why)) => quota += usize::from(why.contains("in flight")),
                other => panic!("expected the session to end, got {other:?}"),
            }
        }
        assert!(quota >= 1, "the quota ended the session");
        assert!(!session.is_open());
    }

    #[tokio::test]
    async fn overlong_request_paths_are_refused_locally() {
        let (client_pipe, service_pipe) = wired(|f| vec![f]);
        let (ck, sk) = keys();
        tokio::spawn(serve(service_pipe, sk, echo_handler()));
        let session = ClientSession::start(client_pipe, ck);
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert!(
            session
                .request(get(&long), Duration::from_secs(2))
                .await
                .is_err()
        );
        // The session is still usable afterwards.
        let ok = session
            .request(get("/x"), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(ok.body, b"GET /x");
    }
}
