//! The `morp://` protocol handler.
//!
//! WebKit hands every `morp://` request to [`handle`], which:
//! 1. validates the `.morp` address (length, Base32, version, checksum, key);
//! 2. resolves it through the local MORP directory (never public DNS);
//! 3. connects to the service and makes it prove it holds the address's key;
//! 4. returns the page, or a local error page.
//!
//! There is no fallback: if any step fails the user sees an error page and
//! nothing is sent to the internet.
//!
//! **v0.4 prototype:** the connection to the service is direct over
//! localhost (authenticated and encrypted, but not through relays). It does
//! not hide where the service runs. Hidden-service circuits are v0.5.

use std::net::SocketAddr;
use std::time::Duration;

use http::{Response, StatusCode, header};
use mask_net::address::parse_url;
use mask_net::directory::DEFAULT_DIRECTORY;
use mask_net::directory::client::DirectoryClient;
use mask_net::service::fetch::{self, FetchError, FetchTimeouts};

/// Restricts `.morp` pages to their own service: no requests to the
/// internet or to other origins, so a page cannot leak to clearnet.
const PAGE_CSP: &str = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; \
    connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'self'";

const ERROR_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'";

/// Directory used by the browser. Override with `MASK_DIRECTORY=127.0.0.1:PORT`.
pub fn directory_addr() -> SocketAddr {
    std::env::var("MASK_DIRECTORY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| DEFAULT_DIRECTORY.parse().expect("valid default"))
}

pub fn directory_client() -> Result<DirectoryClient, mask_net::NetError> {
    DirectoryClient::new(directory_addr(), Duration::from_secs(5))
}

/// Handle one `morp://` request.
pub async fn handle(
    directory: &DirectoryClient,
    method: &str,
    uri: &str,
    timeouts: FetchTimeouts,
) -> Response<Vec<u8>> {
    if method != "GET" {
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

    match fetch::fetch(directory, &address, &path, timeouts).await {
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
            let (status, title) = match &e {
                FetchError::NotFound => (StatusCode::NOT_FOUND, "Service not found"),
                FetchError::DirectoryUnavailable(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "MORP directory unavailable",
                ),
                FetchError::ServiceUnavailable(_) => {
                    (StatusCode::BAD_GATEWAY, "Service unavailable")
                }
                FetchError::IdentityMismatch(_) | FetchError::DescriptorInvalid(_) => (
                    StatusCode::BAD_GATEWAY,
                    "Service identity could not be verified",
                ),
                FetchError::Protocol(_) => (StatusCode::BAD_GATEWAY, "Service error"),
            };
            let hint = match &e {
                FetchError::DirectoryUnavailable(_) => {
                    " Start it with: cargo run -p mask-net --bin mask-directory"
                }
                FetchError::NotFound | FetchError::ServiceUnavailable(_) => {
                    " The service may be offline."
                }
                _ => "",
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
    use std::sync::Arc;

    use mask_net::directory::server::{self, DirectoryState};
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

    async fn directory() -> DirectoryClient {
        let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server::serve(listener, Arc::new(DirectoryState::default())));
        DirectoryClient::new(addr, Duration::from_secs(2)).unwrap()
    }

    async fn dead_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// Host a site and publish it; returns its morp:// URL.
    async fn hosted_site(directory: &DirectoryClient) -> (String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("index.html"), "<h1>MORP works</h1>").unwrap();
        fs::write(dir.path().join("style.css"), "h1{}").unwrap();
        let host = ServiceHost::bind(
            ServiceKeys::generate(),
            Site::new(dir.path()).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let descriptor = host.descriptor(now_secs(), 600, now_millis());
        let url = host.address().url();
        tokio::spawn(host.serve());
        directory.publish(&descriptor).await.unwrap();
        (url, dir)
    }

    fn body(response: &Response<Vec<u8>>) -> String {
        String::from_utf8_lossy(response.body()).into_owned()
    }

    #[tokio::test]
    async fn navigating_to_a_hosted_site_returns_the_page() {
        let directory = directory().await;
        let (url, _site) = hosted_site(&directory).await;

        let page = handle(&directory, "GET", &url, timeouts()).await;
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(
            page.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert!(page.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        assert_eq!(body(&page), "<h1>MORP works</h1>");

        let css = handle(&directory, "GET", &format!("{url}style.css"), timeouts()).await;
        assert_eq!(css.status(), StatusCode::OK);
        assert_eq!(
            css.headers()[header::CONTENT_TYPE],
            "text/css; charset=utf-8"
        );

        let missing = handle(&directory, "GET", &format!("{url}nope"), timeouts()).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_address_fails_without_any_lookup() {
        // A directory that does not exist: an invalid address must fail
        // before it is ever contacted.
        let directory = DirectoryClient::new(dead_addr().await, Duration::from_secs(1)).unwrap();
        for uri in [
            "morp://example.morp/",
            "morp://abc/",
            "morp://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.morp/",
        ] {
            let page = handle(&directory, "GET", uri, timeouts()).await;
            assert_eq!(page.status(), StatusCode::BAD_REQUEST, "{uri}");
            assert!(body(&page).contains("Invalid .morp address"), "{uri}");
        }
    }

    #[tokio::test]
    async fn unknown_service_shows_not_found() {
        let directory = directory().await;
        let url = ServiceKeys::generate().address().url();
        let page = handle(&directory, "GET", &url, timeouts()).await;
        assert_eq!(page.status(), StatusCode::NOT_FOUND);
        assert!(body(&page).contains("Service not found"));
        assert!(body(&page).contains("did not contact public DNS"));
    }

    #[tokio::test]
    async fn offline_service_shows_unavailable() {
        let directory = directory().await;
        let keys = ServiceKeys::generate();
        let descriptor = mask_net::service::descriptor::ServiceDescriptor::sign(
            &keys,
            mask_net::service::descriptor::ServiceEndpoint::DirectLoopback(dead_addr().await),
            now_secs(),
            600,
            1,
        );
        directory.publish(&descriptor).await.unwrap();
        let page = handle(&directory, "GET", &keys.address().url(), timeouts()).await;
        assert_eq!(page.status(), StatusCode::BAD_GATEWAY);
        assert!(body(&page).contains("Service unavailable"));
    }

    #[tokio::test]
    async fn directory_down_shows_directory_error() {
        let directory = DirectoryClient::new(dead_addr().await, Duration::from_secs(1)).unwrap();
        let url = ServiceKeys::generate().address().url();
        let page = handle(&directory, "GET", &url, timeouts()).await;
        assert_eq!(page.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(body(&page).contains("directory unavailable"));
    }

    #[tokio::test]
    async fn only_get_is_allowed() {
        let directory = directory().await;
        let url = ServiceKeys::generate().address().url();
        let page = handle(&directory, "POST", &url, timeouts()).await;
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
