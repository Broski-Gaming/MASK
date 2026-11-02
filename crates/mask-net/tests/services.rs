//! End-to-end tests for .morp services: directory, hosting, fetching, and
//! failure handling. Everything runs on 127.0.0.1 with OS-assigned ports.

use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mask_net::address::MorpAddress;
use mask_net::directory::client::{DirectoryClient, LookupError};
use mask_net::directory::server::{self, DirectoryState};
use mask_net::service::channel::SecureChannel;
use mask_net::service::descriptor::{
    DEFAULT_LIFETIME, ServiceDescriptor, ServiceEndpoint, Withdrawal,
};
use mask_net::service::fetch::{self, FetchError, FetchTimeouts};
use mask_net::service::host::ServiceHost;
use mask_net::service::keys::ServiceKeys;
use mask_net::service::site::Site;
use mask_net::service::{now_millis, now_secs};
use tokio::net::TcpListener;

fn timeouts() -> FetchTimeouts {
    FetchTimeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        response: Duration::from_secs(5),
    }
}

async fn start_directory() -> (SocketAddr, DirectoryClient) {
    let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(listener, Arc::new(DirectoryState::default())));
    (
        addr,
        DirectoryClient::new(addr, Duration::from_secs(2)).unwrap(),
    )
}

/// A site folder with HTML, CSS, JS, and a PNG.
fn make_site() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("index.html"), "<h1>Hello from MORP</h1>").unwrap();
    fs::write(root.join("style.css"), "h1 { color: purple }").unwrap();
    fs::write(root.join("app.js"), "console.log('morp')").unwrap();
    fs::write(root.join("logo.png"), [0x89, b'P', b'N', b'G', 0, 1, 2, 3]).unwrap();
    dir
}

struct Hosted {
    keys: Arc<ServiceKeys>,
    endpoint: SocketAddr,
    _site: tempfile::TempDir,
}

impl Hosted {
    fn address(&self) -> MorpAddress {
        *self.keys.address()
    }

    fn descriptor(&self, revision: u64) -> ServiceDescriptor {
        ServiceDescriptor::sign(
            &self.keys,
            ServiceEndpoint::DirectLoopback(self.endpoint),
            now_secs(),
            DEFAULT_LIFETIME,
            revision,
        )
    }
}

async fn host_service() -> Hosted {
    let site_dir = make_site();
    let host = ServiceHost::bind(
        ServiceKeys::generate(),
        Site::new(site_dir.path()).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    let hosted = Hosted {
        keys: host.keys(),
        endpoint: host.local_addr(),
        _site: site_dir,
    };
    tokio::spawn(host.serve());
    hosted
}

async fn dead_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

// ============================================================== directory

#[tokio::test]
async fn publish_then_lookup_by_cryptographic_identity() {
    let (_, directory) = start_directory().await;
    let service = host_service().await;
    let descriptor = service.descriptor(now_millis());
    directory.publish(&descriptor).await.unwrap();

    let found = directory.lookup(&service.address()).await.unwrap().unwrap();
    assert_eq!(found, descriptor);
}

#[tokio::test]
async fn unknown_address_is_not_found() {
    let (_, directory) = start_directory().await;
    let nobody = *ServiceKeys::generate().address();
    assert!(directory.lookup(&nobody).await.unwrap().is_none());
}

#[tokio::test]
async fn forged_descriptor_is_rejected() {
    let (addr, directory) = start_directory().await;
    let victim = ServiceKeys::generate();
    let attacker = ServiceKeys::generate();
    // The attacker signs a descriptor with their own key and submits it
    // under the victim's address.
    let forged_json = ServiceDescriptor::sign(
        &attacker,
        ServiceEndpoint::DirectLoopback("127.0.0.1:9".parse().unwrap()),
        now_secs(),
        DEFAULT_LIFETIME,
        now_millis(),
    )
    .to_json()
    .replace(&attacker.address().id(), &victim.address().id());

    let status = reqwest::Client::new()
        .put(format!(
            "http://{addr}/v1/services/{}",
            victim.address().id()
        ))
        .body(forged_json)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status.as_u16(), 422);
    assert!(directory.lookup(victim.address()).await.unwrap().is_none());
}

#[tokio::test]
async fn descriptor_under_wrong_url_is_rejected() {
    let (addr, _) = start_directory().await;
    let a = ServiceKeys::generate();
    let b = ServiceKeys::generate();
    let d = ServiceDescriptor::sign(
        &a,
        ServiceEndpoint::DirectLoopback("127.0.0.1:9".parse().unwrap()),
        now_secs(),
        DEFAULT_LIFETIME,
        1,
    );
    let status = reqwest::Client::new()
        .put(format!("http://{addr}/v1/services/{}", b.address().id()))
        .body(d.to_json())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status.as_u16(), 400);
}

#[tokio::test]
async fn expired_descriptor_is_rejected() {
    let (_, directory) = start_directory().await;
    let keys = ServiceKeys::generate();
    let expired = ServiceDescriptor::sign(
        &keys,
        ServiceEndpoint::DirectLoopback("127.0.0.1:9".parse().unwrap()),
        now_secs() - 2 * DEFAULT_LIFETIME,
        DEFAULT_LIFETIME,
        1,
    );
    let err = directory.publish(&expired).await.unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
}

#[tokio::test]
async fn malformed_requests_are_rejected() {
    let (addr, _) = start_directory().await;
    let http = reqwest::Client::new();
    let valid_id = ServiceKeys::generate().address().id();
    for (id, body) in [
        ("not-an-address".to_owned(), "{}".to_owned()),
        (valid_id.clone(), "{ broken".to_owned()),
        (valid_id.clone(), "x".repeat(20_000)),
    ] {
        let status = http
            .put(format!("http://{addr}/v1/services/{id}"))
            .body(body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        assert!(matches!(status, 400 | 413), "{id}: {status}");
    }
    let status = http
        .get(format!("http://{addr}/v1/services/UPPERCASE"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status.as_u16(), 400);
}

#[tokio::test]
async fn older_revision_cannot_replace_newer() {
    let (_, directory) = start_directory().await;
    let service = host_service().await;
    let old = service.descriptor(100);
    let new = service.descriptor(200);
    directory.publish(&new).await.unwrap();
    assert!(directory.publish(&old).await.is_err());
    assert!(
        directory.publish(&new).await.is_err(),
        "same revision replay"
    );
    assert_eq!(
        directory
            .lookup(&service.address())
            .await
            .unwrap()
            .unwrap()
            .revision,
        200
    );
}

#[tokio::test]
async fn withdrawal_removes_and_blocks_replay() {
    let (_, directory) = start_directory().await;
    let service = host_service().await;
    let d = service.descriptor(100);
    directory.publish(&d).await.unwrap();

    // A withdrawal signed by someone else is refused.
    let intruder = ServiceKeys::generate();
    let mut fake = Withdrawal::sign(&intruder, 100);
    fake.address = service.address().host();
    assert!(directory.withdraw(&fake).await.is_err());

    directory
        .withdraw(&Withdrawal::sign(&service.keys, 100))
        .await
        .unwrap();
    assert!(
        directory
            .lookup(&service.address())
            .await
            .unwrap()
            .is_none()
    );

    // Replaying the old descriptor after withdrawal fails.
    assert!(directory.publish(&d).await.is_err());
    // A genuinely newer one is accepted.
    directory.publish(&service.descriptor(101)).await.unwrap();
}

// ================================================================ hosting

#[tokio::test]
async fn hosted_site_serves_html_css_js_and_images() {
    let (_, directory) = start_directory().await;
    let service = host_service().await;
    directory
        .publish(&service.descriptor(now_millis()))
        .await
        .unwrap();
    let address = service.address();

    for (path, content_type, starts) in [
        ("/", "text/html; charset=utf-8", &b"<h1>Hello"[..]),
        ("/style.css", "text/css; charset=utf-8", b"h1"),
        ("/app.js", "text/javascript; charset=utf-8", b"console"),
        ("/logo.png", "image/png", b"\x89PNG"),
    ] {
        let response = fetch::fetch(&directory, &address, path, timeouts())
            .await
            .unwrap();
        assert_eq!(response.status, 200, "{path}");
        assert_eq!(response.content_type, content_type, "{path}");
        assert!(response.body.starts_with(starts), "{path}");
    }

    let missing = fetch::fetch(&directory, &address, "/nope", timeouts())
        .await
        .unwrap();
    assert_eq!(missing.status, 404);
    let escape = fetch::fetch(&directory, &address, "/../etc/passwd", timeouts())
        .await
        .unwrap();
    assert_eq!(escape.status, 403);
}

#[tokio::test]
async fn large_file_arrives_intact_across_many_frames() {
    let (_, directory) = start_directory().await;
    let site_dir = tempfile::tempdir().unwrap();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(site_dir.path().join("big.bin"), &big).unwrap();
    let host = ServiceHost::bind(
        ServiceKeys::generate(),
        Site::new(site_dir.path()).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    let descriptor = host.descriptor(now_secs(), DEFAULT_LIFETIME, 1);
    let address = *host.address();
    tokio::spawn(host.serve());
    directory.publish(&descriptor).await.unwrap();

    let response = fetch::fetch(&directory, &address, "/big.bin", timeouts())
        .await
        .unwrap();
    assert_eq!(response.body, big);
}

// ============================================================== identity

#[tokio::test]
async fn channel_proves_identity_and_rejects_impostors() {
    let real = host_service().await;
    let other = host_service().await;

    // Connecting to the real service as its own address works.
    SecureChannel::connect(
        real.endpoint,
        &real.address(),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    // Expecting `real` but reaching `other` fails: `other` refuses, and
    // could not produce a valid signature for `real` anyway.
    let err = SecureChannel::connect(
        other.endpoint,
        &real.address(),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .err()
    .unwrap();
    assert!(err.to_string().contains("refused"), "{err}");
}

#[tokio::test]
async fn descriptor_pointing_at_another_service_fails_identity_check() {
    let (_, directory) = start_directory().await;
    let victim = host_service().await;
    let impostor = host_service().await;
    // The victim's own (validly signed) descriptor, but naming the
    // impostor's endpoint, e.g. after the impostor took over the port.
    let misdirected = ServiceDescriptor::sign(
        &victim.keys,
        ServiceEndpoint::DirectLoopback(impostor.endpoint),
        now_secs(),
        DEFAULT_LIFETIME,
        now_millis(),
    );
    directory.publish(&misdirected).await.unwrap();
    let err = fetch::fetch(&directory, &victim.address(), "/", timeouts())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::IdentityMismatch(_)), "{err}");
}

// ============================================================== failures

#[tokio::test]
async fn unpublished_service_is_not_found() {
    let (_, directory) = start_directory().await;
    let nobody = *ServiceKeys::generate().address();
    let err = fetch::fetch(&directory, &nobody, "/", timeouts())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::NotFound), "{err}");
}

#[tokio::test]
async fn published_but_stopped_service_is_unavailable() {
    let (_, directory) = start_directory().await;
    let keys = ServiceKeys::generate();
    let address = *keys.address();
    let d = ServiceDescriptor::sign(
        &keys,
        ServiceEndpoint::DirectLoopback(dead_addr().await),
        now_secs(),
        DEFAULT_LIFETIME,
        1,
    );
    directory.publish(&d).await.unwrap();
    let err = fetch::fetch(&directory, &address, "/", timeouts())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::ServiceUnavailable(_)), "{err}");
}

#[tokio::test]
async fn directory_down_fails_closed() {
    let directory = DirectoryClient::new(dead_addr().await, Duration::from_secs(1)).unwrap();
    let address = *ServiceKeys::generate().address();
    assert!(matches!(
        directory.lookup(&address).await,
        Err(LookupError::Unavailable(_))
    ));
    let err = fetch::fetch(&directory, &address, "/", timeouts())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::DirectoryUnavailable(_)), "{err}");
}

#[tokio::test]
async fn silent_service_times_out() {
    let (_, directory) = start_directory().await;
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push(s);
        }
    });
    let keys = ServiceKeys::generate();
    let address = *keys.address();
    directory
        .publish(&ServiceDescriptor::sign(
            &keys,
            ServiceEndpoint::DirectLoopback(silent_addr),
            now_secs(),
            DEFAULT_LIFETIME,
            1,
        ))
        .await
        .unwrap();
    let err = fetch::fetch(&directory, &address, "/", timeouts())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::ServiceUnavailable(_)), "{err}");
}

#[tokio::test]
async fn directory_and_service_refuse_non_loopback() {
    assert!(
        DirectoryClient::new("192.0.2.1:7200".parse().unwrap(), Duration::from_secs(1)).is_err()
    );
    assert!(server::bind("0.0.0.0:0".parse().unwrap()).await.is_err());
    let site = make_site();
    assert!(
        ServiceHost::bind(
            ServiceKeys::generate(),
            Site::new(site.path()).unwrap(),
            "0.0.0.0:0".parse().unwrap()
        )
        .await
        .is_err()
    );
}
