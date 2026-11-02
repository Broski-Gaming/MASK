//! The `morp://` protocol handler.
//!
//! WebKit hands every `morp://` request to [`handle`], which:
//! 1. validates the `.morp` address (length, Base32, version, checksum, key);
//! 2. resolves it through the local MORP directory (never public DNS) and
//!    verifies the signed descriptor;
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
use mask_net::directory::DEFAULT_DIRECTORY;
use mask_net::directory::client::DirectoryClient;
use mask_net::hs::client::{ClientConfig, FetchError, MorpClient};
use mask_net::hs::session::HttpRequest;

/// Restricts `.morp` pages to their own service: no requests to the
/// internet or to other origins, so a page cannot leak to clearnet.
const PAGE_CSP: &str = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; \
    connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'self'";

const ERROR_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'";

/// The browser's MORP client.
/// - `MASK_DIRECTORY` (default 127.0.0.1:7200): service directory.
/// - `MASK_RELAY_DIRECTORY` (default `runtime/directory`): relay descriptors.
pub fn morp_client() -> Result<MorpClient, mask_net::NetError> {
    let directory = std::env::var("MASK_DIRECTORY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| DEFAULT_DIRECTORY.parse().expect("valid default"));
    let relays = std::env::var("MASK_RELAY_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("runtime/directory"));
    Ok(MorpClient::new(
        DirectoryClient::new(directory, Duration::from_secs(5))?,
        ClientConfig::new(relays),
    ))
}

/// Handle one `morp://` request.
pub async fn handle(client: &MorpClient, method: &str, uri: &str) -> Response<Vec<u8>> {
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
    match client.fetch(&address, request).await {
        Ok(page) => {
            let status = StatusCode::from_u16(page.status).unwrap_or(StatusCode::BAD_GATEWAY);
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, page.content_type)
                .header(header::CONTENT_SECURITY_POLICY, PAGE_CSP)
                .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
                .header(header::CACHE_CONTROL, "no-store")
                .header(header::REFERRER_POLICY, "no-referrer")
                .body(page.body)
                .expect("valid response")
        }
        Err(e) => {
            tracing::warn!(address = %address, error = %e, "morp request failed");
            let (status, title, hint) = match &e {
                FetchError::NotFound => (
                    StatusCode::NOT_FOUND,
                    "Service not found",
                    " The service may be offline.",
                ),
                FetchError::DirectoryUnavailable(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "MORP directory unavailable",
                    " Start it with: cargo run -p mask-net --bin mask-directory",
                ),
                FetchError::RelaysUnavailable(_) | FetchError::CircuitFailed(_) => (
                    StatusCode::BAD_GATEWAY,
                    "MORP circuit failed",
                    " Are the entry, middle, and rendezvous relays running?",
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

    fn timeouts() -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(2),
            handshake: Duration::from_secs(2),
            response: Duration::from_secs(5),
            idle: Duration::from_secs(30),
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
    fn error_pages_escape_their_text() {
        let page = error_page(StatusCode::BAD_REQUEST, "<x>", "<script>alert(1)</script>");
        let html = body(&page);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
