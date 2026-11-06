//! The network gate (v0.7): no direct connection while a `.morp` page is
//! shown.
//!
//! **Why.** The navigation policy refuses to let a `.morp` page open a
//! clearnet website, but WebKit opens a *speculative* connection to a
//! link's host as soon as the link is activated, before it asks the policy
//! (found by the live leak test, `tests/browser_leaks.rs`). That connection
//! alone tells the website the user's IP address. No WebKit setting turns
//! it off, so the fix works one layer lower:
//!
//! While the gate is **sealed**, WebKit's whole network stack (every
//! `http(s)`/`ws(s)` connection, speculative or not) goes to a proxy that
//! is a black hole owned by the browser on 127.0.0.1: it accepts and closes.
//! No connection reaches any other host, and no hostname is looked up
//! (proxied names are not resolved locally). `morp://` is unaffected: it
//! never uses WebKit's network stack.
//!
//! - MORP-only mode: sealed for the whole session.
//! - Normal mode: sealed as soon as the main frame starts loading a
//!   `.morp` page; opened again only for a clearnet navigation the user
//!   started (typed address, back/forward), just before it proceeds.

use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use webkit2gtk::{NetworkProxyMode, NetworkProxySettings, WebViewExt, WebsiteDataManagerExt};

pub struct NetworkGate {
    black_hole: SocketAddr,
    sealed: Cell<bool>,
    /// Never opened (MORP-only mode).
    permanent: bool,
    refused: Arc<AtomicU64>,
}

impl NetworkGate {
    /// Start the black hole on `runtime`.
    pub fn new(runtime: &tokio::runtime::Handle, permanent: bool) -> std::io::Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let black_hole = listener.local_addr()?;
        let refused = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&refused);
        runtime.spawn(async move {
            let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                return;
            };
            while let Ok((stream, _)) = listener.accept().await {
                // Close at once: nothing is forwarded, ever.
                drop(stream);
                let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(
                    n,
                    "refused a direct connection while the network gate was sealed"
                );
            }
        });
        Ok(Self {
            black_hole,
            sealed: Cell::new(false),
            permanent,
            refused,
        })
    }

    /// Connections the black hole has refused (diagnostics, tests).
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Route every WebKit connection into the black hole.
    pub fn seal(&self, view: &webkit2gtk::WebView) {
        if self.sealed.get() {
            return;
        }
        let Some(data) = view.website_data_manager() else {
            return;
        };
        let proxy = format!("http://{}", self.black_hole);
        // No ignore list: localhost and private addresses are proxied too.
        let mut settings = NetworkProxySettings::new(Some(&proxy), &[]);
        data.set_network_proxy_settings(NetworkProxyMode::Custom, Some(&mut settings));
        self.sealed.set(true);
        tracing::debug!("network gate sealed");
    }

    /// Back to normal networking (no-op in MORP-only mode).
    pub fn open(&self, view: &webkit2gtk::WebView) {
        if !self.sealed.get() || self.permanent {
            return;
        }
        if let Some(data) = view.website_data_manager() {
            data.set_network_proxy_settings(NetworkProxyMode::Default, None);
            self.sealed.set(false);
            tracing::debug!("network gate opened for a navigation the user started");
        }
    }
}
