//! The service's local web application and the forwarder that passes MORP
//! requests to it.
//!
//! The application listens on 127.0.0.1 only. Clients never connect to it:
//! requests arrive over the rendezvous circuit, and the service host makes
//! the local HTTP request on their behalf.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use tokio::task::JoinHandle;

use super::session::{HttpRequest, HttpResponse, MAX_BODY};
use crate::NetError;
use crate::service::site::Site;
use crate::transport::ConnectPolicy;

/// Serve `site` as a plain HTTP application on a loopback address.
pub async fn serve_site(
    site: Site,
    listen: SocketAddr,
) -> Result<(SocketAddr, JoinHandle<()>), NetError> {
    if !listen.ip().is_loopback() {
        return Err(NetError::NotLoopback(listen));
    }
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let app = Router::new()
        .fallback(site_handler)
        .with_state(Arc::new(site));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, task))
}

async fn site_handler(State(site): State<Arc<Site>>, method: Method, uri: Uri) -> Response {
    let path = uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |p| p.as_str().to_owned());
    let response = site
        .handle(&HttpRequest {
            method: method.as_str().to_owned(),
            path,
        })
        .await;
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(header::CONTENT_TYPE, response.content_type)],
        response.body,
    )
        .into_response()
}

/// Passes requests from MORP sessions to the local application.
pub struct AppForwarder {
    app: SocketAddr,
    http: reqwest::Client,
    policy: ConnectPolicy,
}

impl AppForwarder {
    pub fn new(
        app: SocketAddr,
        policy: ConnectPolicy,
        timeout: Duration,
    ) -> Result<Self, NetError> {
        if !app.ip().is_loopback() {
            return Err(NetError::NotLoopback(app));
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| NetError::InvalidConfig(format!("HTTP client: {e}")))?;
        Ok(Self { app, http, policy })
    }

    pub fn app_addr(&self) -> SocketAddr {
        self.app
    }

    pub async fn forward(&self, request: HttpRequest) -> HttpResponse {
        let method = match request.method.as_str() {
            "GET" => reqwest::Method::GET,
            "HEAD" => reqwest::Method::HEAD,
            _ => return text(405, "Only GET and HEAD are supported over MORP."),
        };
        let path = &request.path;
        if !path.starts_with('/') || path.chars().any(|c| c.is_control() || c == ' ') {
            return text(400, "Bad request path.");
        }
        if self.policy.check("service", self.app).is_err() {
            return text(502, "Local application blocked by policy.");
        }
        let url = format!("http://{}{path}", self.app);
        let response = match self.http.request(method, url).send().await {
            Ok(r) => r,
            Err(_) => return text(502, "The local web application is not responding."),
        };
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        if response.content_length().is_some_and(|n| n > MAX_BODY) {
            return text(502, "Response too large.");
        }
        match response.bytes().await {
            Ok(body) if body.len() as u64 <= MAX_BODY => HttpResponse {
                status,
                content_type,
                body: body.to_vec(),
            },
            Ok(_) => text(502, "Response too large."),
            Err(_) => text(502, "The local web application failed mid-response."),
        }
    }
}

fn text(status: u16, message: &str) -> HttpResponse {
    HttpResponse {
        status,
        content_type: "text/plain; charset=utf-8".into(),
        body: format!("{status} {message}\n").into_bytes(),
    }
}
