//! The MASK Browser window: a native GTK toolbar above a Wry/WebKitGTK view.
//!
//! The toolbar is native GTK rather than HTML so that web content can never
//! script or restyle the browser's own controls.
//!
//! **Hardening (v0.7)**, applied before any page loads (see
//! [`crate::privacy`] and `docs/SECURITY_MODEL.md`):
//! - WebKit content rules confine `.morp` pages to `morp:` and keep
//!   clearnet pages away from `morp:` and `.morp` names. Installed first;
//!   the browser refuses to start without them.
//! - Every top-level navigation passes [`privacy::navigation`]: a `.morp`
//!   page cannot open a clearnet website (only the user can, by typing it);
//!   other schemes are refused; new windows and downloads are refused.
//! - WebKit settings: WebRTC, media capture, WebGL, WebAudio, DNS
//!   prefetching, hyperlink auditing, page cache, and more are off; a fixed
//!   user agent and language; permission requests are always denied;
//!   third-party cookies are refused.
//! - "New identity" switches the MORP isolation context (new circuits and
//!   rendezvous points for every service) and forgets all website data.
//! - The network gate (`gate.rs`) routes every WebKit connection into a black
//!   hole while a `.morp` page is shown (and always in MORP-only mode), so
//!   even WebKit's speculative connections cannot reach the internet.

mod content_filter;
mod gate;
mod start_page;
mod theme;

use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;

use gtk::glib;
use gtk::prelude::*;
use webkit2gtk::{
    CookieAcceptPolicy, CookieManagerExt, NavigationPolicyDecision, NavigationPolicyDecisionExt,
    NavigationType, PermissionRequestExt, PolicyDecisionExt, PolicyDecisionType,
    ResponsePolicyDecision, ResponsePolicyDecisionExt, SettingsExt, URIRequestExt, WebContextExt,
    WebViewExt, WebsiteDataManagerExt, WebsiteDataManagerExtManual, WebsiteDataTypes,
};
use wry::{WebViewBuilder, WebViewBuilderExtUnix, WebViewExtUnix};

use crate::address::{display_text, parse_address};
use crate::privacy::{self, BrowserMode, Initiator};

pub const WINDOW_TITLE: &str = "MASK Browser";

/// Honest descriptions of the current connection, shown in the toolbar.
const WEB_STATUS: &str = "Direct connection · not anonymous";
const WEB_TOOLTIP: &str = "Websites are loaded directly. They see your real IP address.";
const MORP_ONLY_STATUS: &str = "MORP-only mode · websites blocked";
const MORP_ONLY_TOOLTIP: &str = "MASK_MORP_ONLY is set: only morp:// addresses are loaded; \
    every website request is refused.";
const MORP_STATUS: &str = "MORP service · via relay circuits · experimental";
const MORP_TOOLTIP: &str = "Found through the MORP directory (no DNS) and reached only \
    through MORP relay circuits joined at a rendezvous point. The service proved it owns this \
    .morp address; traffic is end-to-end encrypted. Experimental and unreviewed: not Tor-level \
    anonymity.";

/// What the user just asked for, so the navigation policy can tell their
/// navigations from a page's.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Expected {
    /// A URL typed in the address bar (or given on the command line).
    Url(String),
    /// Back, forward, or reload from the toolbar.
    History,
}

fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Build the window and run the GTK main loop until it is closed.
/// `initial` is an optional address to open, validated like address bar input.
pub fn run(initial: Option<&str>) -> Result<(), Box<dyn Error>> {
    gtk::init()?;
    theme::apply()?;
    let mode = BrowserMode::from_env();

    // Background threads for morp:// requests, so the UI never blocks.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("mask-morp")
        .enable_all()
        .build()?;
    let morp_runtime = runtime.handle().clone();
    let morp = crate::morp::MorpHandler::new(crate::morp::morp_client()?);

    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title(WINDOW_TITLE);
    // A common, fixed size (window size is a fingerprinting surface; the
    // user can still resize).
    window.set_default_size(1200, 800);

    let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
    window.add(&root);

    // Toolbar: back, forward, reload, address bar, new identity, status.
    let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    toolbar.style_context().add_class("mask-toolbar");
    let back = icon_button("go-previous-symbolic", "Back");
    let forward = icon_button("go-next-symbolic", "Forward");
    let reload = icon_button("view-refresh-symbolic", "Reload");
    let identity = icon_button(
        "avatar-default-symbolic",
        "New identity: new MORP circuits for every service, and forget all cookies and site data",
    );
    let address = gtk::Entry::new();
    address.style_context().add_class("mask-address");
    address.set_hexpand(true);
    address.set_placeholder_text(Some(match mode {
        BrowserMode::Normal => "Enter https://… or a morp://<id>.morp address",
        BrowserMode::MorpOnly => "Enter a morp://<id>.morp address (MORP-only mode)",
    }));
    let (idle_status, idle_tooltip) = match mode {
        BrowserMode::Normal => (WEB_STATUS, WEB_TOOLTIP),
        BrowserMode::MorpOnly => (MORP_ONLY_STATUS, MORP_ONLY_TOOLTIP),
    };
    let status = gtk::Label::new(Some(idle_status));
    status.style_context().add_class("mask-status");
    status.set_tooltip_text(Some(idle_tooltip));
    toolbar.pack_start(&back, false, false, 0);
    toolbar.pack_start(&forward, false, false, 0);
    toolbar.pack_start(&reload, false, false, 0);
    toolbar.pack_start(&address, true, true, 4);
    toolbar.pack_start(&identity, false, false, 0);
    toolbar.pack_start(&status, false, false, 0);
    root.pack_start(&toolbar, false, false, 0);

    // Error bar for rejected addresses and blocked navigations.
    let notice = gtk::Label::new(None);
    notice.style_context().add_class("mask-notice");
    notice.set_xalign(0.0);
    notice.set_line_wrap(true);
    root.pack_start(&notice, false, false, 0);

    // Web content area. Nothing is loaded until the view is hardened.
    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    root.pack_start(&content, true, true, 0);
    let handler = morp.clone();
    let wry_view = WebViewBuilder::new()
        // Ephemeral session: cookies, cache and storage are discarded on exit.
        .with_incognito(true)
        .with_user_agent(privacy::USER_AGENT)
        // morp:// is answered only by the MORP handler: directory lookup,
        // identity proof, then the page, or a local error page. Never DNS.
        .with_asynchronous_custom_protocol("morp".into(), move |_id, request, responder| {
            let method = request.method().as_str().to_owned();
            let uri = request.uri().to_string();
            let handler = handler.clone();
            morp_runtime.spawn(async move {
                responder.respond(handler.handle(&method, &uri).await);
            });
        })
        .build_gtk(&content)?;
    let view = wry_view.webview();
    let filter_dir = harden(&view, mode)?;
    let gate = Rc::new(gate::NetworkGate::new(
        runtime.handle(),
        mode == BrowserMode::MorpOnly,
    )?);
    if mode == BrowserMode::MorpOnly {
        gate.seal(&view);
    }
    // Seal before a .morp page's content can run: the main frame (all that
    // load-changed reports) commits to the page before any of its scripts
    // run. At `Started` the view's URI is still empty, so `Committed` is the
    // first event that names the page.
    view.connect_load_changed(glib::clone!(@strong gate => move |view, event| {
        if matches!(event, webkit2gtk::LoadEvent::Started | webkit2gtk::LoadEvent::Committed)
            && view.uri().is_some_and(|u| u.starts_with("morp:"))
        {
            gate.seal(view);
        }
    }));

    let expected: Rc<RefCell<Option<Expected>>> = Rc::default();
    install_navigation_policy(&view, mode, &expected, &notice, &gate);
    view.load_html(start_page::HTML, None);

    back.set_sensitive(false);
    forward.set_sensitive(false);

    let user_history = |expected: &Rc<RefCell<Option<Expected>>>| {
        *expected.borrow_mut() = Some(Expected::History);
    };
    back.connect_clicked(glib::clone!(@weak view, @strong expected => move |_| {
        user_history(&expected);
        view.go_back();
    }));
    forward.connect_clicked(glib::clone!(@weak view, @strong expected => move |_| {
        user_history(&expected);
        view.go_forward();
    }));
    reload.connect_clicked(glib::clone!(@weak view, @strong expected => move |_| {
        user_history(&expected);
        view.reload();
    }));

    identity.connect_clicked(glib::clone!(@weak view, @weak notice, @strong expected => move |_| {
        morp.new_identity();
        if let Some(data) = view.website_data_manager() {
            data.clear(WebsiteDataTypes::ALL, glib::TimeSpan::from_seconds(0), None::<&gtk::gio::Cancellable>, |_| {});
        }
        notice.set_text("New identity: new MORP circuits for every service; cookies and site data forgotten.");
        notice.show();
        user_history(&expected);
        view.reload();
    }));

    address.connect_activate(glib::clone!(@weak view, @weak notice, @strong expected, @strong gate => move |entry| {
        match parse_address(&entry.text()) {
            Ok(url) => {
                // Check before WebKit sees the URL: loading starts with a
                // speculative connection even if the policy then refuses.
                let current = view.uri().map(|u| u.to_string()).unwrap_or_default();
                if let Err(blocked) = privacy::navigation(&current, url.as_str(), Initiator::User, mode) {
                    notice.set_text(&blocked.to_string());
                    notice.show();
                    return;
                }
                notice.hide();
                if url.scheme() == "morp" {
                    gate.seal(&view);
                } else {
                    gate.open(&view);
                }
                *expected.borrow_mut() = Some(Expected::Url(url.as_str().to_owned()));
                view.load_uri(url.as_str());
                view.grab_focus();
            }
            Err(err) => {
                notice.set_text(&err.to_string());
                notice.show();
            }
        }
    }));

    // Keep the address bar in sync with the page, including link clicks.
    view.connect_uri_notify(glib::clone!(@weak address, @weak status => move |view| {
        let uri = view.uri().unwrap_or_default();
        address.set_text(display_text(&uri));
        let (text, tooltip) = if uri.starts_with("morp://") {
            (MORP_STATUS, MORP_TOOLTIP)
        } else {
            (idle_status, idle_tooltip)
        };
        status.set_text(text);
        status.set_tooltip_text(Some(tooltip));
    }));

    view.connect_title_notify(glib::clone!(@weak window => move |view| {
        let title = view.title();
        window.set_title(&window_title(title.as_deref()));
    }));

    view.connect_load_changed(glib::clone!(@weak back, @weak forward => move |view, _| {
        back.set_sensitive(view.can_go_back());
        forward.set_sensitive(view.can_go_forward());
    }));

    window.connect_destroy(|_| gtk::main_quit());
    window.show_all();
    notice.hide();
    address.grab_focus();

    if let Some(initial) = initial {
        address.set_text(initial);
        address.emit_activate();
    }

    gtk::main();

    if gate.refused() > 0 {
        tracing::info!(
            refused = gate.refused(),
            "network gate: direct connections refused while .morp pages were shown"
        );
    }

    // The wry WebView and the runtime must live as long as the window.
    drop(wry_view);
    runtime.shutdown_background();
    let _ = std::fs::remove_dir_all(filter_dir);
    Ok(())
}

/// Apply MASK's privacy settings to `view` before it loads anything.
/// Returns the folder holding the compiled content rules (removed on exit).
fn harden(
    view: &webkit2gtk::WebView,
    mode: BrowserMode,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    // 1. Content rules, enforced by WebKit for every load. Fail closed.
    let dir = std::env::temp_dir().join(format!("mask-browser-rules-{}", std::process::id()));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
    }
    content_filter::install(
        view,
        &privacy::content_rules_json(mode == BrowserMode::MorpOnly),
        &dir,
    )
    .map_err(|e| format!("cannot install the content-blocking rules ({e}); refusing to start"))?;

    // 2. Settings: each one is set by its WebKit property name and read
    //    back, so the table in privacy.rs is exactly what is in force.
    let settings = WebViewExt::settings(view).ok_or("the web view has no settings")?;
    for (name, value) in privacy::SETTINGS {
        let Some(spec) = settings.find_property(name) else {
            // Removed in this WebKit version (the feature is gone with it).
            tracing::debug!(setting = name, "WebKit has no such setting");
            continue;
        };
        if spec.flags().contains(glib::ParamFlags::DEPRECATED) {
            // A no-op in this WebKit version (for example WebKitGTK 2.54
            // ignores enable-hyperlink-auditing and never prefetches DNS).
            // The content rules and the live leak test cover these.
            tracing::debug!(setting = name, "deprecated WebKit setting; not relied on");
            continue;
        }
        settings.set_property(name, value);
        if settings.property::<bool>(name) != *value {
            return Err(
                format!("WebKit refused to set {name} = {value}; refusing to start").into(),
            );
        }
    }
    settings.set_user_agent(Some(privacy::USER_AGENT));

    // 3. Language and cookies.
    if let Some(context) = view.context() {
        context.set_preferred_languages(privacy::LANGUAGES);
    }
    if let Some(data) = view.website_data_manager() {
        if let Some(cookies) = data.cookie_manager() {
            cookies.set_accept_policy(CookieAcceptPolicy::NoThirdParty);
        }
        data.set_itp_enabled(true);
    }

    // 4. Camera, microphone, location, notifications, ...: always no.
    view.connect_permission_request(|_, request| {
        request.deny();
        true
    });
    Ok(dir)
}

/// Check every navigation (and refuse new windows and downloads).
fn install_navigation_policy(
    view: &webkit2gtk::WebView,
    mode: BrowserMode,
    expected: &Rc<RefCell<Option<Expected>>>,
    notice: &gtk::Label,
    gate: &Rc<gate::NetworkGate>,
) {
    let expected = Rc::clone(expected);
    let gate = Rc::clone(gate);
    view.connect_decide_policy(
        glib::clone!(@weak notice => @default-return false, move |view, decision, kind| {
            let block = |message: &str| {
                decision.ignore();
                notice.set_text(message);
                notice.show();
                true
            };
            match kind {
                PolicyDecisionType::NavigationAction | PolicyDecisionType::NewWindowAction => {
                    let Some(nav) = decision.downcast_ref::<NavigationPolicyDecision>() else {
                        decision.ignore();
                        return true;
                    };
                    let Some(action) = nav.navigation_action() else {
                        decision.ignore();
                        return true;
                    };
                    let target = action
                        .request()
                        .and_then(|r| r.uri())
                        .map(|u| u.to_string())
                        .unwrap_or_default();
                    if kind == PolicyDecisionType::NewWindowAction {
                        return block("Blocked: pages cannot open new windows.");
                    }
                    let initiator = {
                        let mut pending = expected.borrow_mut();
                        let user = match &*pending {
                            Some(Expected::Url(url)) => same_url(url, &target),
                            Some(Expected::History) => matches!(
                                action.navigation_type(),
                                NavigationType::BackForward | NavigationType::Reload
                            ),
                            None => false,
                        };
                        if user {
                            *pending = None;
                            Initiator::User
                        } else {
                            Initiator::Page
                        }
                    };
                    let current = view.uri().map(|u| u.to_string()).unwrap_or_default();
                    match privacy::navigation(&current, &target, initiator, mode) {
                        Ok(()) => {
                            // Leaving a .morp page for a website the user chose:
                            // let this navigation through the gate.
                            if initiator == Initiator::User && !target.starts_with("morp:") {
                                gate.open(view);
                            }
                            decision.use_();
                            true
                        }
                        Err(blocked) => block(&blocked.to_string()),
                    }
                }
                PolicyDecisionType::Response => {
                    // Content WebKit cannot show would be downloaded: refused
                    // (files from a page could be opened by other programs).
                    match decision.downcast_ref::<ResponsePolicyDecision>() {
                        Some(r) if !r.is_mime_type_supported() => {
                            block("Blocked: downloads are disabled in MASK Browser.")
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }),
    );
}

fn icon_button(icon: &str, tooltip: &str) -> gtk::Button {
    let button = gtk::Button::from_icon_name(Some(icon), gtk::IconSize::Button);
    button.set_tooltip_text(Some(tooltip));
    button
}

/// Window title for a page: "Page title — MASK Browser".
fn window_title(page_title: Option<&str>) -> String {
    match page_title.map(str::trim) {
        Some(title) if !title.is_empty() && title != WINDOW_TITLE => {
            format!("{title} — {WINDOW_TITLE}")
        }
        _ => WINDOW_TITLE.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_title_includes_page_title() {
        assert_eq!(window_title(Some("Example")), "Example — MASK Browser");
    }

    #[test]
    fn window_title_falls_back_to_browser_name() {
        assert_eq!(window_title(None), "MASK Browser");
        assert_eq!(window_title(Some("   ")), "MASK Browser");
        assert_eq!(window_title(Some("MASK Browser")), "MASK Browser");
    }

    #[test]
    fn typed_urls_match_with_or_without_a_trailing_slash() {
        assert!(same_url("https://example.com/", "https://example.com"));
        assert!(!same_url("https://example.com/", "https://example.org/"));
    }
}
