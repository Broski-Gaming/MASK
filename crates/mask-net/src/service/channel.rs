//! Authenticated, encrypted connection between a client and a `.morp`
//! service ("MORP service channel").
//!
//! Handshake (signed ephemeral Diffie-Hellman, the same pattern as the
//! server authentication in TLS 1.3 / SIGMA):
//!
//! ```text
//! client: x random, X = x·G
//!   ClientHello { version, service_key = address public key, X } ──▶
//! service: refuse unless service_key is its own key
//!   y random, Y = y·G
//!   sig = Ed25519-Sign(service_key, DOMAIN || service_key || X || Y)
//!   ◀── ServerHello::Accept { Y, sig }
//! client: verify sig with the public key inside the .morp address
//! both:   c2s || s2c = HKDF-SHA256(salt = DOMAIN, ikm = x·Y,
//!                                  info = INFO || service_key || X || Y)
//! ```
//!
//! After that every frame is sealed with ChaCha20-Poly1305 using the same
//! counter-nonce [`CellCipher`] as MORP cells, so tampering, replay, and
//! reordering are detected. Only the holder of the address's private key can
//! complete the handshake. The client stays anonymous to the service at this
//! layer (though in v0.4 the service sees the client's loopback connection).

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::Signature;
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::keys::ServiceKeys;
use crate::NetError;
use crate::address::MorpAddress;
use crate::crypto::onion::{CellCipher, Direction};
use crate::crypto::{CryptoError, random_bytes};
use crate::protocol::{MAX_FRAME_LEN, decode, encode};

pub const CHANNEL_VERSION: u16 = 1;
/// Largest response body a client accepts.
pub const MAX_BODY: u64 = 16 * 1024 * 1024;
/// Body bytes per sealed frame.
pub const CHUNK: usize = 32 * 1024;

const DOMAIN: &[u8] = b"MORP-v1 service handshake\0";
const KEY_INFO: &[u8] = b"MORP-v1 service channel keys";
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
struct ClientHello {
    version: u16,
    service_key: [u8; 32],
    client_ephemeral: [u8; 32],
}

#[derive(Serialize, Deserialize)]
enum ServerHello {
    Accept {
        server_ephemeral: [u8; 32],
        signature: Vec<u8>,
    },
    Reject {
        reason: String,
    },
}

/// A request from client to service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    /// Path and query, starting with `/`.
    pub path: String,
}

#[derive(Serialize, Deserialize)]
enum ServerFrame {
    Head {
        status: u16,
        content_type: String,
        length: u64,
    },
    Body(Vec<u8>),
}

/// A complete response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

type FramedTcp = Framed<TcpStream, LengthDelimitedCodec>;

/// An established channel (either side).
pub struct SecureChannel {
    framed: FramedTcp,
    send: CellCipher,
    recv: CellCipher,
}

fn framed(stream: TcpStream) -> FramedTcp {
    let _ = stream.set_nodelay(true);
    Framed::new(
        stream,
        LengthDelimitedCodec::builder()
            .length_field_type::<u32>()
            .max_frame_length(MAX_FRAME_LEN)
            .new_codec(),
    )
}

async fn send_frame(framed: &mut FramedTcp, bytes: Vec<u8>) -> Result<(), NetError> {
    timeout(WRITE_TIMEOUT, framed.send(Bytes::from(bytes)))
        .await
        .map_err(|_| NetError::Timeout)??;
    Ok(())
}

async fn recv_frame(framed: &mut FramedTcp, limit: Duration) -> Result<Option<Vec<u8>>, NetError> {
    match timeout(limit, framed.next()).await {
        Err(_) => Err(NetError::Timeout),
        Ok(None) => Ok(None),
        Ok(Some(Err(e))) => Err(NetError::Io(e)),
        Ok(Some(Ok(frame))) => Ok(Some(frame.to_vec())),
    }
}

fn transcript(service_key: &[u8; 32], client: &[u8; 32], server: &[u8; 32]) -> Vec<u8> {
    let mut t = DOMAIN.to_vec();
    t.extend_from_slice(service_key);
    t.extend_from_slice(client);
    t.extend_from_slice(server);
    t
}

fn derive(
    shared: &[u8; 32],
    service_key: &[u8; 32],
    client: &[u8; 32],
    server: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut info = KEY_INFO.to_vec();
    info.extend_from_slice(service_key);
    info.extend_from_slice(client);
    info.extend_from_slice(server);
    let mut okm = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(DOMAIN), shared)
        .expand(&info, okm.as_mut())
        .expect("64 bytes is a valid HKDF output length");
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&okm[..32]);
    s2c.copy_from_slice(&okm[32..]);
    (c2s, s2c)
}

impl SecureChannel {
    /// Connect to `endpoint` and require it to prove it is `address`.
    pub async fn connect(
        endpoint: SocketAddr,
        address: &MorpAddress,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self, NetError> {
        let stream = timeout(connect_timeout, TcpStream::connect(endpoint))
            .await
            .map_err(|_| NetError::Timeout)??;
        let mut framed = framed(stream);

        let secret = StaticSecret::from(random_bytes::<32>());
        let client_ephemeral = PublicKey::from(&secret).to_bytes();
        let service_key = *address.public_key();
        send_frame(
            &mut framed,
            encode(&ClientHello {
                version: CHANNEL_VERSION,
                service_key,
                client_ephemeral,
            }),
        )
        .await?;

        let frame = recv_frame(&mut framed, handshake_timeout)
            .await?
            .ok_or(NetError::ConnectionClosed)?;
        let (server_ephemeral, signature) = match decode::<ServerHello>(&frame)? {
            ServerHello::Accept {
                server_ephemeral,
                signature,
            } => (server_ephemeral, signature),
            ServerHello::Reject { reason } => {
                return Err(NetError::Protocol(format!("service refused: {reason}")));
            }
        };

        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| NetError::Crypto(CryptoError::BadSignature))?;
        address
            .verifying_key()
            .verify_strict(
                &transcript(&service_key, &client_ephemeral, &server_ephemeral),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| NetError::Crypto(CryptoError::BadSignature))?;

        let shared = secret.diffie_hellman(&PublicKey::from(server_ephemeral));
        if !shared.was_contributory() {
            return Err(NetError::Crypto(CryptoError::WeakKey));
        }
        let (c2s, s2c) = derive(
            shared.as_bytes(),
            &service_key,
            &client_ephemeral,
            &server_ephemeral,
        );
        Ok(Self {
            framed,
            send: CellCipher::new(&c2s, Direction::Forward),
            recv: CellCipher::new(&s2c, Direction::Backward),
        })
    }

    /// Service side: prove our identity to a connecting client.
    pub async fn accept(
        stream: TcpStream,
        keys: &ServiceKeys,
        handshake_timeout: Duration,
    ) -> Result<Self, NetError> {
        let mut framed = framed(stream);
        let frame = recv_frame(&mut framed, handshake_timeout)
            .await?
            .ok_or(NetError::ConnectionClosed)?;
        let hello: ClientHello = decode(&frame)?;

        let reject = |reason: &str| {
            encode(&ServerHello::Reject {
                reason: reason.to_owned(),
            })
        };
        if hello.version != CHANNEL_VERSION {
            let _ = send_frame(&mut framed, reject("unsupported channel version")).await;
            return Err(NetError::Protocol("unsupported channel version".into()));
        }
        if hello.service_key != *keys.address().public_key() {
            let _ = send_frame(&mut framed, reject("this is a different .morp service")).await;
            return Err(NetError::Crypto(CryptoError::WrongRelay));
        }

        let secret = StaticSecret::from(random_bytes::<32>());
        let server_ephemeral = PublicKey::from(&secret).to_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(hello.client_ephemeral));
        if !shared.was_contributory() {
            let _ = send_frame(&mut framed, reject("weak key")).await;
            return Err(NetError::Crypto(CryptoError::WeakKey));
        }
        let signature = keys.sign(&transcript(
            &hello.service_key,
            &hello.client_ephemeral,
            &server_ephemeral,
        ));
        send_frame(
            &mut framed,
            encode(&ServerHello::Accept {
                server_ephemeral,
                signature: signature.to_vec(),
            }),
        )
        .await?;

        let (c2s, s2c) = derive(
            shared.as_bytes(),
            &hello.service_key,
            &hello.client_ephemeral,
            &server_ephemeral,
        );
        Ok(Self {
            framed,
            send: CellCipher::new(&s2c, Direction::Backward),
            recv: CellCipher::new(&c2s, Direction::Forward),
        })
    }

    async fn send_sealed<T: Serialize>(&mut self, value: &T) -> Result<(), NetError> {
        let sealed = self.send.seal(&encode(value))?;
        send_frame(&mut self.framed, sealed).await
    }

    async fn recv_sealed<T: DeserializeOwned>(
        &mut self,
        limit: Duration,
    ) -> Result<Option<T>, NetError> {
        match recv_frame(&mut self.framed, limit).await? {
            None => Ok(None),
            Some(frame) => Ok(Some(decode(&self.recv.open(&frame)?)?)),
        }
    }

    // ---------------------------------------------------------- client

    /// Send a GET for `path` and read the whole response.
    pub async fn get(&mut self, path: &str, limit: Duration) -> Result<Response, NetError> {
        self.send_sealed(&Request {
            method: "GET".into(),
            path: path.into(),
        })
        .await?;
        let (status, content_type, length) = match self.recv_sealed(limit).await? {
            Some(ServerFrame::Head {
                status,
                content_type,
                length,
            }) => (status, content_type, length),
            Some(ServerFrame::Body(_)) => {
                return Err(NetError::Protocol("body before head".into()));
            }
            None => return Err(NetError::ConnectionClosed),
        };
        if length > MAX_BODY {
            return Err(NetError::Protocol(format!(
                "response of {length} bytes exceeds the {MAX_BODY}-byte limit"
            )));
        }
        let mut body = Vec::with_capacity(length as usize);
        while (body.len() as u64) < length {
            match self.recv_sealed(limit).await? {
                Some(ServerFrame::Body(chunk)) => {
                    if body.len() as u64 + chunk.len() as u64 > length {
                        return Err(NetError::Protocol("body longer than announced".into()));
                    }
                    body.extend_from_slice(&chunk);
                }
                Some(ServerFrame::Head { .. }) => {
                    return Err(NetError::Protocol("unexpected second head".into()));
                }
                None => return Err(NetError::ConnectionClosed),
            }
        }
        Ok(Response {
            status,
            content_type,
            body,
        })
    }

    // --------------------------------------------------------- service

    /// Next request, or `None` when the client closed the connection.
    pub async fn next_request(&mut self, idle: Duration) -> Result<Option<Request>, NetError> {
        self.recv_sealed(idle).await
    }

    pub async fn respond(&mut self, response: &Response) -> Result<(), NetError> {
        self.send_sealed(&ServerFrame::Head {
            status: response.status,
            content_type: response.content_type.clone(),
            length: response.body.len() as u64,
        })
        .await?;
        for chunk in response.body.chunks(CHUNK) {
            self.send_sealed(&ServerFrame::Body(chunk.to_vec())).await?;
        }
        Ok(())
    }
}
