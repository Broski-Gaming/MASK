//! The `morp://` protocol handler.
//!
//! WebKit hands every `morp://` request to [`handle`], which:
//! 1. validates the `.morp` address (length, Base32, version, checksum, key);
//! 2. resolves it through the MORP directory (the local one, or the
//!    testnet's directory authorities over Noise links; never public DNS)
//!    and verifies the signed descriptor;
//! 3. reaches the service **only through MORP relay circuits**: a circuit to
//!    a rendezvous point, an introduction via one of the service's intro
//!    points, and the service's own circuit joined at the rendezvous point;
//! 4. checks the service's signature against the address and exchanges
//!    end-to-end encrypted requests and responses;
//! 5. returns the page, or a local error page.
//!
//! The first request to an address builds the session; the page's CSS,
//! JavaScript, images, and later pages reuse it. There is no direct
//! connection and no fallback: if any step fails the user sees an error page.
//!
//! Experimental and unreviewed: not Tor-level anonymity.

use std::path::PathBuf;
use std::time::Duration;

use http::{Response, StatusCode, header};
use mask_net::address::parse_url;
use mask_net::authority::client::AuthorityClient;
use mask_net::config::NetworkConfig;
use mask_net::directory::DEFAULT_DIRECTORY;
use mask_net::directory::client::DirectoryClient;
use mask_net::guards::{GuardConfig, Guards};
use std::sync::{Arc, Mutex};

use http::HeaderValue;
use mask_net::hs::client::{ClientConfig, FetchError, IsolationContext, MorpClient};
use mask_net::hs::session::{HttpRequest, HttpResponse};
use mask_net::trust::TrustedRelays;
use tokio::sync::Semaphore;

use crate::privacy::{ERROR_CSP, morp_headers};

/// `morp://` requests handled at once; more get a local error page (a page
/// cannot queue unbounded work).
pub const MAX_CONCURRENT_REQUESTS: usize = 64;

/// The browser's `morp://` handler: the MORP client, the current isolation
/// context (one per browser identity), and a concurrency limit.
#[derive(Clone)]
pub struct MorpHandler {
    client: MorpClient,
    context: Arc<Mutex<IsolationContext>>,
    in_flight: Arc<Semaphore>,
}

impl MorpHandler {
    pub fn new(client: MorpClient) -> Self {
        Self {
            client,
            context: Arc::new(Mutex::new(IsolationContext::fresh())),
            in_flight: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        }
    }

    /// "New identity": later requests use a fresh isolation context (new
    /// sessions, circuits, rendezvous points), and the old context's
    /// sessions are closed.
    pub fn new_identity(&self) {
        let old = std::mem::replace(
            &mut *self.context.lock().unwrap(),
            IsolationContext::fresh(),
        );
        self.client.close_context(old);
    }

    pub fn context(&self) -> IsolationContext {
        *self.context.lock().unwrap()
    }

    /// Handle one `morp://` request in the current context.
    pub async fn handle(&self, method: &str, uri: &str) -> Response<Vec<u8>> {
        let Ok(_permit) = self.in_flight.try_acquire() else {
            return error_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many requests",
                "This page made too many .morp requests at once.",
            );
        };
        handle_in(&self.client, self.context(), method, uri).await
    }
}

/// The browser's MORP client.
///
/// Network mode (v0.6 testnet):
/// - `MASK_NETWORK=/path/to/network.toml`: relays come from the consensus
///   signed by the authorities pinned there, and service descriptors are
///   looked up at those authorities over Noise links.
///
/// Local mode (one machine, the default):
/// - `MASK_DIRECTORY` (default 127.0.0.1:7200): service directory.
/// - `MASK_RELAY_DIRECTORY` (default `runtime/directory`): relay descriptors.
///
/// Both modes keep the browser's entry guards (v0.7) in `MASK_STATE_DIR`
/// (default `runtime/state`), as `browser-guards-<network>.json` (0600).
pub fn morp_client() -> Result<MorpClient, mask_net::NetError> {
    let state_dir = std::env::var_os("MASK_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("runtime/state"));
    if let Some(path) = std::env::var_os("MASK_NETWORK") {
        let network = NetworkConfig::load(std::path::Path::new(&path))?;
        tracing::info!(
            network = %network.name,
            scope = %network.scope,
            authorities = network.authorities.len(),
            "MORP network mode"
        );
        let mut config = ClientConfig::new(TrustedRelays::consensus(network.scope));
        config.guards = Guards::open_in(
            &state_dir,
            "browser",
            &network.name,
            GuardConfig::for_network(&network),
        )?;
        return Ok(MorpClient::new(AuthorityClient::new(network), config));
    }
    let directory = std::env::var("MASK_DIRECTORY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| DEFAULT_DIRECTORY.parse().expect("valid default"));
    let relays = std::env::var("MASK_RELAY_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("runtime/directory"));
    let mut config = ClientConfig::new(relays);
    config.guards = Guards::open_in(&state_dir, "browser", "local", GuardConfig::default())?;
    Ok(MorpClient::new(
        DirectoryClient::new(directory, Duration::from_secs(5))?,
        config,
    ))
}

/// Handle one `morp://` request in the default isolation context.
pub async fn handle(client: &MorpClient, method: &str, uri: &str) -> Response<Vec<u8>> {
    handle_in(client, IsolationContext::DEFAULT, method, uri).await
}

/// The page as WebKit gets it. Everything from the service is checked:
/// a status outside 200-599 or a content type that is not a valid header
/// value (a hostile service could send newlines to inject headers) is
/// replaced, never trusted. Regression (v0.7): an invalid content type used
/// to make the handler panic.
pub fn page_response(page: HttpResponse, method: &str) -> Response<Vec<u8>> {
    let status = StatusCode::from_u16(page.status)
        .ok()
        .filter(|s| (200..600).contains(&s.as_u16()))
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = HeaderValue::from_str(&page.content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type);
    for (name, value) in morp_headers() {
        response = response.header(name, value);
    }
    let body = if method == "HEAD" {
        Vec::new()
    } else {
        page.body
    };
    response.body(body).expect("only checked header values")
}

/// Handle one `morp://` request in `context`.
pub async fn handle_in(
    client: &MorpClient,
    context: IsolationContext,
    method: &str,
    uri: &str,
) -> Response<Vec<u8>> {
    if method != "GET" && method != "HEAD" {
        return error_page(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed",
            "MORP services in this version only support GET requests.",
        );
    }
    let (address, path) = match parse_url(uri) {
        Ok(parsed) => parsed,
        Err(e) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid .morp address",
                &format!("{e}. Nothing was loaded."),
            );
        }
    };

    let request = HttpRequest {
        method: method.to_owned(),
        path,
    };
    match client.fetch_in(context, &address, request).await {
        Ok(page) => page_response(page, method),
        Err(e) => {
            // The address is browsing history: never logged (v0.7).
            tracing::warn!(error = %e, "morp request failed");
            let (status, title, hint) = match &e {
                FetchError::NotFound => (
                    StatusCode::NOT_FOUND,
                    "Service not found",
                    " The service may be offline.",
                ),
                FetchError::DirectoryUnavailable(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "MORP directory unavailable",
                    " Start mask-directory (local mode) or check that a directory authority is reachable (MASK_NETWORK).",
                ),
                FetchError::RelaysUnavailable(_) | FetchError::CircuitFailed(_) => (
                    StatusCode::BAD_GATEWAY,
                    "MORP circuit failed",
                    " Are the entry, middle, and rendezvous relays running (and listed in the consensus)?",
                ),
                FetchError::ServiceUnavailable(_) => (
                    StatusCode::BAD_GATEWAY,
                    "Service unavailable",
                    " The service may be offline.",
                ),
                FetchError::IdentityMismatch(_) | FetchError::DescriptorInvalid(_) => (
                    StatusCode::BAD_GATEWAY,
                    "Service identity could not be verified",
                    "",
                ),
                FetchError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "MORP request timed out", ""),
            };
            error_page(
                status,
                title,
                &format!("{e}.{hint}\n\nAddress: {}", address.url()),
            )
        }
    }
}

fn html_escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

/// A self-contained error page (no scripts, no external resources).
pub fn error_page(status: StatusCode, title: &str, detail: &str) -> Response<Vec<u8>> {
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>
 html,body{{height:100%;margin:0}}
 body{{background:#111318;color:#c9d1d9;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center}}
 main{{max-width:620px;padding:32px}}
 h1{{color:#ffb4b4;font-size:24px;margin:0 0 12px}}
 pre{{white-space:pre-wrap;word-break:break-all;background:#1a1d24;border:1px solid #2a2f3a;border-radius:8px;padding:12px;color:#e6edf3}}
 p{{color:#8b949e}}
</style></head>
<body><main>
<h1>{title}</h1>
<pre>{detail}</pre>
<p>MASK did not contact public DNS or the internet for this address.</p>
</main></body></html>"#,
        title = html_escape(title),
        detail = html_escape(detail),
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CONTENT_SECURITY_POLICY, ERROR_CSP)
        .header(header::CACHE_CONTROL, "no-store")
        .body(body.into_bytes())
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use mask_net::crypto::keys::RelayKeys;
    use mask_net::directory::server::{self, DirectoryState};
    use mask_net::hs::app::serve_site;
    use mask_net::hs::service::{HiddenService, HostConfig};
    use mask_net::identity::Role;
    use mask_net::relay::{Relay, RelayConfig, RelayHandle};
    use mask_net::service::keys::ServiceKeys;
    use mask_net::service::site::Site;
    use mask_net::service::{now_millis, now_secs};
    use mask_net::transport::{ConnectPolicy, Timeouts};
    use mask_net::trust::TrustedRelays;

    fn timeouts() -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(2),
            handshake: Duration::from_secs(2),
            response: Duration::from_secs(5),
            idle: Duration::from_secs(30),
            keepalive: Duration::from_secs(5),
        }
    }

    struct World {
        _dir: tempfile::TempDir,
        client: MorpClient,
        url: String,
        rendezvous: Vec<RelayHandle>,
        log: Arc<Mutex<Vec<(String, SocketAddr)>>>,
        entry: SocketAddr,
        app: SocketAddr,
        _service: Option<HiddenService>,
    }

    /// Relays + directory + hidden service, all on 127.0.0.1.
    async fn world(host_service: bool) -> World {
        let dir = tempfile::tempdir().unwrap();
        let relay_dir = dir.path().join("relays");
        let log: Arc<Mutex<Vec<(String, SocketAddr)>>> = Arc::default();
        let policy = {
            let log = Arc::clone(&log);
            ConnectPolicy::new(move |origin, addr| {
                log.lock().unwrap().push((origin.to_owned(), addr));
                true
            })
        };
        let mut rendezvous = Vec::new();
        let mut entry = None;
        for (nick, role) in [
            ("entry", Role::Entry),
            ("middle", Role::Middle),
            ("rv0", Role::Rendezvous),
            ("rv1", Role::Rendezvous),
        ] {
            let mut config = RelayConfig::new(nick, role, "127.0.0.1:0".parse().unwrap());
            config.timeouts = timeouts();
            config.policy = policy.clone();
            config.trusted = TrustedRelays::from(relay_dir.clone());
            let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
            relay.descriptor().write_to_dir(&relay_dir).unwrap();
            if role == Role::Rendezvous {
                rendezvous.push(relay.handle());
            }
            if role == Role::Entry {
                entry = Some(relay.local_addr());
            }
            tokio::spawn(relay.serve());
        }
        let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let directory_addr = listener.local_addr().unwrap();
        tokio::spawn(server::serve(listener, Arc::new(DirectoryState::default())));
        let directory = DirectoryClient::new(directory_addr, Duration::from_secs(2)).unwrap();

        let site = dir.path().join("site");
        fs::create_dir_all(site.join("img")).unwrap();
        fs::write(
            site.join("index.html"),
            "<html><link rel=stylesheet href=/style.css><script src=/app.js></script>\
             <img src=/img/logo.svg><h1>MORP works</h1></html>",
        )
        .unwrap();
        fs::write(site.join("style.css"), "h1{color:purple}").unwrap();
        fs::write(site.join("app.js"), "console.log(1)").unwrap();
        fs::write(
            site.join("img/logo.svg"),
            "<svg xmlns='http://www.w3.org/2000/svg'/>",
        )
        .unwrap();
        let (app, _) = serve_site(Site::new(&site).unwrap(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let identity = ServiceKeys::generate();
        let url = identity.address().url();
        let service = if host_service {
            let mut config = HostConfig::new(relay_dir.clone(), app);
            config.intro_points = 1;
            config.timeouts = timeouts();
            config.policy = policy.clone();
            let service = HiddenService::start(identity, config).await.unwrap();
            directory
                .publish(&service.descriptor(now_secs(), 600, now_millis()))
                .await
                .unwrap();
            Some(service)
        } else {
            None
        };

        let mut config = ClientConfig::new(relay_dir);
        config.timeouts = timeouts();
        config.policy = policy;
        config.connect_timeout = Duration::from_secs(15);
        config.rendezvous_timeout = Duration::from_secs(8);
        World {
            _dir: dir,
            client: MorpClient::new(directory, config),
            url,
            rendezvous,
            log,
            entry: entry.unwrap(),
            app,
            _service: service,
        }
    }

    fn body(response: &Response<Vec<u8>>) -> String {
        String::from_utf8_lossy(response.body()).into_owned()
    }

    #[tokio::test]
    async fn page_and_all_resources_load_through_morp_circuits() {
        let w = world(true).await;
        let page = handle(&w.client, "GET", &w.url).await;
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(
            page.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert!(page.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        assert!(body(&page).contains("MORP works"));

        // The resources the page references, as WebKit would request them.
        for (path, content_type) in [
            ("style.css", "text/css; charset=utf-8"),
            ("app.js", "text/javascript; charset=utf-8"),
            ("img/logo.svg", "image/svg+xml"),
        ] {
            let r = handle(&w.client, "GET", &format!("{}{path}", w.url)).await;
            assert_eq!(r.status(), StatusCode::OK, "{path}");
            assert_eq!(r.headers()[header::CONTENT_TYPE], content_type, "{path}");
        }
        let missing = handle(&w.client, "GET", &format!("{}nope", w.url)).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        // Everything went through one rendezvous join, as stream cells.
        let joins: u64 = w
            .rendezvous
            .iter()
            .map(|h| h.stats().rendezvous_joins)
            .sum();
        let streams: u64 = w.rendezvous.iter().map(|h| h.stats().stream_cells).sum();
        assert_eq!(joins, 1);
        assert!(streams >= 10, "{streams}");

        // The browser side only ever connected to the entry relay.
        let log = w.log.lock().unwrap();
        assert!(
            log.iter()
                .filter(|(o, _)| o == "client")
                .all(|(_, a)| *a == w.entry)
        );
        assert!(!log.iter().any(|(o, a)| o == "client" && *a == w.app));
    }

    #[tokio::test]
    async fn invalid_address_fails_before_any_network_activity() {
        let w = world(false).await;
        for uri in [
            "morp://example.morp/",
            "morp://abc/",
            "morp://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.morp/",
        ] {
            let page = handle(&w.client, "GET", uri).await;
            assert_eq!(page.status(), StatusCode::BAD_REQUEST, "{uri}");
            assert!(body(&page).contains("Invalid .morp address"), "{uri}");
        }
        assert!(
            w.log.lock().unwrap().is_empty(),
            "no connection was attempted"
        );
    }

    #[tokio::test]
    async fn unpublished_service_shows_not_found() {
        let w = world(false).await;
        let page = handle(&w.client, "GET", &w.url).await;
        assert_eq!(page.status(), StatusCode::NOT_FOUND);
        assert!(body(&page).contains("Service not found"));
        assert!(body(&page).contains("did not contact public DNS"));
    }

    #[tokio::test]
    async fn relay_failure_shows_an_error_not_a_fallback() {
        let w = world(true).await;
        for h in &w.rendezvous {
            h.shutdown();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let page = handle(&w.client, "GET", &w.url).await;
        assert!(page.status().is_server_error(), "{}", page.status());
        assert!(
            !w.log
                .lock()
                .unwrap()
                .iter()
                .any(|(o, a)| o == "client" && *a == w.app)
        );
    }

    #[tokio::test]
    async fn directory_down_shows_directory_error() {
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let client = MorpClient::new(
            DirectoryClient::new(dead, Duration::from_secs(1)).unwrap(),
            ClientConfig::new(PathBuf::from("/nonexistent")),
        );
        let url = ServiceKeys::generate().address().url();
        let page = handle(&client, "GET", &url).await;
        assert_eq!(page.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(body(&page).contains("directory unavailable"));
    }

    #[tokio::test]
    async fn only_get_and_head_are_allowed() {
        let client = MorpClient::new(
            DirectoryClient::new("127.0.0.1:9".parse().unwrap(), Duration::from_secs(1)).unwrap(),
            ClientConfig::new(PathBuf::from("/nonexistent")),
        );
        let url = ServiceKeys::generate().address().url();
        let page = handle(&client, "POST", &url).await;
        assert_eq!(page.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn hostile_status_and_content_type_cannot_break_the_handler() {
        // Regression (v0.7): an invalid content type from the service made
        // the handler panic (the page then hung); 1xx codes passed through.
        let page = HttpResponse {
            status: 101,
            content_type: "text/html\r\nSet-Cookie: tracker=1".into(),
            body: b"<h1>x</h1>".to_vec(),
        };
        let r = page_response(page, "GET");
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            r.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert!(!r.headers().contains_key(header::SET_COOKIE));
    }

    #[test]
    fn morp_pages_get_the_privacy_headers_and_head_has_no_body() {
        let page = || HttpResponse {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            body: b"<h1>x</h1>".to_vec(),
        };
        let r = page_response(page(), "GET");
        for (name, value) in crate::privacy::morp_headers() {
            assert_eq!(r.headers()[name], value, "{name}");
        }
        assert_eq!(r.body(), b"<h1>x</h1>");
        assert!(page_response(page(), "HEAD").body().is_empty());
    }

    #[tokio::test]
    async fn new_identity_gets_a_new_session_and_rendezvous() {
        let w = world(true).await;
        let handler = MorpHandler::new(w.client.clone());
        let joins = || -> u64 {
            w.rendezvous
                .iter()
                .map(|h| h.stats().rendezvous_joins)
                .sum()
        };
        assert_eq!(handler.handle("GET", &w.url).await.status(), StatusCode::OK);
        assert_eq!(handler.handle("GET", &w.url).await.status(), StatusCode::OK);
        assert_eq!(joins(), 1, "same identity, same session");
        let before = handler.context();
        handler.new_identity();
        assert_ne!(handler.context(), before);
        assert_eq!(handler.handle("GET", &w.url).await.status(), StatusCode::OK);
        assert_eq!(joins(), 2, "a new identity uses new circuits");
    }

    #[test]
    fn error_pages_escape_their_text() {
        let page = error_page(StatusCode::BAD_REQUEST, "<x>", "<script>alert(1)</script>");
        let html = body(&page);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
