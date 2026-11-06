//! The browser's leak-prevention and anti-fingerprinting policy (v0.7).
//!
//! Everything here is plain data and pure functions so it can be unit
//! tested; `browser/` applies it to WebKit. See `docs/SECURITY_MODEL.md`
//! (browser section) for the audit of fingerprinting surfaces and what is
//! *not* protected.
//!
//! Three layers stop `.morp` pages and `.morp` names from leaking:
//!
//! 1. **Content rules** ([`content_rules`]), enforced by WebKit itself for
//!    every load a page makes (images, scripts, frames, fetch, WebSocket,
//!    beacons, prefetches): a `.morp` page may load only from `morp:` (and
//!    inline `data:`/`blob:`), a clearnet page may not load `morp:` at all,
//!    and no page may load an `http(s)`/`ws(s)` URL whose host ends in
//!    `.morp` (that would hand the name to public DNS).
//! 2. **Navigation policy** ([`navigation`]): top-level navigations are not
//!    covered by content rules, so they are checked separately. A `.morp`
//!    page cannot send the browser to a clearnet address (by a link, a
//!    script, a redirect, or a form): clearnet pages are loaded directly
//!    and would see the user's real IP address. Only the user can do that,
//!    by typing the address.
//! 3. **Response headers** on `.morp` pages ([`morp_headers`]): a strict
//!    Content-Security-Policy, no DNS prefetching, no powerful features.
//!
//! Plus WebKit settings ([`SETTINGS`]): WebRTC, WebGL, WebAudio, media
//! capture, DNS prefetching, hyperlink auditing, and other leaky or
//! fingerprintable features off; a fixed user agent and language.

use serde::Serialize;

/// Fixed user agent: the same for every MASK Browser, whatever the
/// WebKitGTK version, distribution, or CPU (WebKit's default names them).
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 \
    (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

/// The only language advertised (`Accept-Language`, `navigator.language`).
pub const LANGUAGES: &[&str] = &["en-US"];

/// Time zone forced at startup (`TZ`), so `Date` and `Intl` do not reveal
/// the user's location. `MASK_KEEP_TIMEZONE=1` keeps the system zone.
pub const TIME_ZONE: &str = "UTC";

/// Content-Security-Policy for `.morp` pages: only the page's own service.
/// `'self'` is the page's own `morp://<id>.morp` origin, so another
/// service's resources are blocked too (one session = one first party).
pub const PAGE_CSP: &str = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; \
    connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'self'; \
    object-src 'none'; webrtc 'block'";

/// Content-Security-Policy for MASK's own error pages.
pub const ERROR_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'";

/// Features `.morp` pages may never use.
pub const PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=(), \
    display-capture=(), usb=(), serial=(), hid=(), bluetooth=(), payment=(), \
    publickey-credentials-get=(), xr-spatial-tracking=(), screen-wake-lock=()";

/// Headers added to every `.morp` response (on top of the content type).
pub fn morp_headers() -> [(&'static str, &'static str); 8] {
    [
        ("content-security-policy", PAGE_CSP),
        ("permissions-policy", PERMISSIONS_POLICY),
        // WebKit resolves link hosts ahead of time unless told not to:
        // that would send names from a .morp page to public DNS.
        ("x-dns-prefetch-control", "off"),
        ("x-content-type-options", "nosniff"),
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        // Other origins (clearnet pages) may not embed or open these.
        ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-opener-policy", "same-origin"),
    ]
}

// ------------------------------------------------------- content rules

/// One WebKit content-blocker rule (Safari's JSON format).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Rule {
    pub trigger: Trigger,
    pub action: Action,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Trigger {
    /// Regular expression on the full URL (WebKit's restricted syntax: no
    /// `|`, no `{n}`; case-insensitive by default).
    #[serde(rename = "url-filter")]
    pub url_filter: String,
    /// Apply only when the page's top-level URL matches one of these.
    #[serde(rename = "if-top-url", skip_serializing_if = "Vec::is_empty")]
    pub if_top_url: Vec<String>,
    /// Apply unless the page's top-level URL matches one of these.
    #[serde(rename = "unless-top-url", skip_serializing_if = "Vec::is_empty")]
    pub unless_top_url: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "block")]
    Block,
    /// Cancel every earlier rule that matched this load.
    #[serde(rename = "ignore-previous-rules")]
    IgnorePrevious,
}

fn rule(filter: &str, action: Action) -> Rule {
    Rule {
        trigger: Trigger {
            url_filter: filter.into(),
            ..Trigger::default()
        },
        action,
    }
}

fn on_morp_pages(mut r: Rule) -> Rule {
    r.trigger.if_top_url = vec!["^morp:".into()];
    r
}

/// The content rules, in order (later `ignore-previous-rules` cancel
/// earlier matches, so the order matters).
///
/// `morp_only`: also block every clearnet (`http(s)`, `ws(s)`) load; see
/// [`BrowserMode::MorpOnly`].
pub fn content_rules(morp_only: bool) -> Vec<Rule> {
    let mut rules = vec![
        // On .morp pages, block everything...
        on_morp_pages(rule(".*", Action::Block)),
        // ...except the morp: scheme and inline data.
        on_morp_pages(rule("^morp:", Action::IgnorePrevious)),
        on_morp_pages(rule("^data:", Action::IgnorePrevious)),
        on_morp_pages(rule("^blob:", Action::IgnorePrevious)),
        on_morp_pages(rule("^about:", Action::IgnorePrevious)),
    ];
    // These come after every ignore rule, so nothing can cancel them.
    // No page may load morp: unless it is itself a .morp page (a clearnet
    // page could otherwise make the browser contact services, or time
    // loads to learn which services the user has open).
    let mut no_morp_from_clearnet = rule("^morp:", Action::Block);
    no_morp_from_clearnet.trigger.unless_top_url = vec!["^morp:".into()];
    rules.push(no_morp_from_clearnet);
    // No http(s)/ws(s) URL with a .morp host, from any page: the name
    // would go to public DNS. (`[^/?#]*` also covers user@host forms.)
    for scheme in ["https?", "wss?"] {
        rules.push(rule(
            &format!("^{scheme}://[^/?#]*\\.morp\\.?$"),
            Action::Block,
        ));
        rules.push(rule(
            &format!("^{scheme}://[^/?#]*\\.morp\\.?[:/?#]"),
            Action::Block,
        ));
    }
    if morp_only {
        rules.push(rule("^https?:", Action::Block));
        rules.push(rule("^wss?:", Action::Block));
    }
    rules
}

/// [`content_rules`] as the JSON WebKit compiles.
pub fn content_rules_json(morp_only: bool) -> String {
    serde_json::to_string(&content_rules(morp_only)).expect("rules serialize")
}

// ---------------------------------------------------------- navigation

/// How the browser treats clearnet websites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserMode {
    /// Clearnet websites load directly (not anonymous), as in v0.1-v0.6.
    Normal,
    /// Only `morp://` is ever loaded; every clearnet load and navigation
    /// is refused (`MASK_MORP_ONLY=1`). Nothing can then bypass MORP.
    MorpOnly,
}

impl BrowserMode {
    pub fn from_env() -> Self {
        match std::env::var("MASK_MORP_ONLY").as_deref() {
            Ok("1" | "true" | "yes") => Self::MorpOnly,
            _ => Self::Normal,
        }
    }
}

/// Who started a top-level navigation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Initiator {
    /// The user: typed in the address bar, or used back/forward/reload.
    User,
    /// The page: a link, a form, a script, a redirect.
    Page,
}

/// Why a navigation was refused (shown to the user).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// http(s) with a `.morp` host: would leak the name to public DNS.
    MorpOverClearnet,
    /// A `.morp` page tried to open a clearnet address.
    LeavingMorp(String),
    /// MORP-only mode.
    ClearnetDisabled(String),
    /// file:, javascript:, mailto:, data:, ... (could open other programs
    /// or local files).
    Scheme(String),
}

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MorpOverClearnet => write!(
                f,
                "Blocked: .morp addresses are only opened with morp://, never over http(s) or public DNS."
            ),
            Self::LeavingMorp(host) => write!(
                f,
                "Blocked: a .morp page tried to open the website {host}. Websites are loaded \
                 directly (they would see your IP address). Type the address yourself to open it."
            ),
            Self::ClearnetDisabled(host) => write!(
                f,
                "Blocked {host}: MORP-only mode (MASK_MORP_ONLY) refuses all websites."
            ),
            Self::Scheme(scheme) => write!(f, "Blocked: \"{scheme}:\" links are not opened."),
        }
    }
}

/// May the main frame go from `current` to `target`?
pub fn navigation(
    current: &str,
    target: &str,
    initiator: Initiator,
    mode: BrowserMode,
) -> Result<(), Blocked> {
    let Ok(url) = url::Url::parse(target) else {
        return Err(Blocked::Scheme("invalid".into()));
    };
    match url.scheme() {
        "morp" => Ok(()), // validated by the morp: handler; MORP only
        "about" if url.path() == "blank" || url.path() == "srcdoc" => Ok(()),
        "http" | "https" => {
            if mask_net::address::is_clearnet_morp_url(target) {
                return Err(Blocked::MorpOverClearnet);
            }
            let host = url.host_str().unwrap_or("?").to_owned();
            if mode == BrowserMode::MorpOnly {
                return Err(Blocked::ClearnetDisabled(host));
            }
            let from_morp = current.starts_with("morp:");
            if from_morp && initiator == Initiator::Page {
                return Err(Blocked::LeavingMorp(host));
            }
            Ok(())
        }
        other => Err(Blocked::Scheme(other.to_owned())),
    }
}

// ------------------------------------------------------------ settings

/// WebKit settings MASK enforces, as (name, value) for display and tests;
/// `browser::harden` applies exactly these.
pub const SETTINGS: &[(&str, bool)] = &[
    // Network leaks
    ("enable-webrtc", false), // ICE would reveal local/public IPs, bypass proxies
    ("enable-media-stream", false), // camera/microphone capture
    ("enable-dns-prefetching", false),
    ("enable-hyperlink-auditing", false), // <a ping>
    ("enable-page-cache", false),         // keep nothing of past pages in memory
    ("enable-offline-web-application-cache", false),
    ("enable-html5-database", false),
    // Fingerprinting surfaces
    ("enable-webgl", false),    // GPU model, driver, rendering quirks
    ("enable-webaudio", false), // audio-stack fingerprint
    ("enable-encrypted-media", false),
    ("enable-site-specific-quirks", false),
    ("enable-developer-extras", false),
    ("enable-write-console-messages-to-stdout", false), // page text in logs
    // Abuse
    ("javascript-can-open-windows-automatically", false),
    ("javascript-can-access-clipboard", false),
    ("allow-file-access-from-file-urls", false),
    ("allow-universal-access-from-file-urls", false),
    ("allow-top-navigation-to-data-urls", false),
    ("allow-modal-dialogs", false),
];

/// The value [`SETTINGS`] requires for `name`.
pub fn setting(name: &str) -> Option<bool> {
    SETTINGS.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex_automata::meta::Regex;
    use regex_automata::util::syntax;

    /// Evaluate the rules like WebKit does: a load is blocked if the last
    /// applicable rule that matches is a block that no later
    /// `ignore-previous-rules` cancelled.
    fn blocked(rules: &[Rule], top: &str, url: &str) -> bool {
        let matches = |re: &str, text: &str| {
            Regex::builder()
                .syntax(syntax::Config::new().case_insensitive(true))
                .build(re)
                .unwrap()
                .is_match(text)
        };
        let mut block = false;
        for r in rules {
            let t = &r.trigger;
            if !matches(&t.url_filter, url) {
                continue;
            }
            if !t.if_top_url.is_empty() && !t.if_top_url.iter().any(|p| matches(p, top)) {
                continue;
            }
            if t.unless_top_url.iter().any(|p| matches(p, top)) {
                continue;
            }
            match r.action {
                Action::Block => block = true,
                Action::IgnorePrevious => block = false,
            }
        }
        block
    }

    const ID: &str = "tx5y5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn morp_pages_load_only_from_morp() {
        let rules = content_rules(false);
        let top = format!("morp://{ID}.morp/");
        for allowed in [
            format!("morp://{ID}.morp/style.css"),
            "data:image/png;base64,AAAA".into(),
            "blob:morp://x/1".into(),
            "about:blank".into(),
        ] {
            assert!(!blocked(&rules, &top, &allowed), "{allowed}");
        }
        for leak in [
            "https://tracker.example/pixel.gif",
            "http://127.0.0.1:8080/",
            "ws://10.0.0.1/socket",
            "wss://evil.example/",
            "ftp://old.example/",
            "file:///etc/passwd",
        ] {
            assert!(blocked(&rules, &top, leak), "{leak}");
        }
    }

    #[test]
    fn clearnet_pages_cannot_load_morp_or_morp_names() {
        let rules = content_rules(false);
        let top = "https://news.example/";
        assert!(!blocked(&rules, top, "https://news.example/logo.png"));
        assert!(!blocked(&rules, top, "wss://news.example/live"));
        for leak in [
            format!("morp://{ID}.morp/probe.png"),
            format!("https://{ID}.morp/"),
            format!("https://{ID}.morp"),
            format!("http://{ID}.morp:80/x"),
            format!("https://user@{ID}.morp/"),
            format!("https://{ID}.MORP/"),
            format!("https://{ID}.morp./x"),
            format!("wss://{ID}.morp/socket"),
            "https://anything.morp?x=1".into(),
        ] {
            assert!(blocked(&rules, top, &leak), "{leak}");
        }
        // Not .morp names.
        assert!(!blocked(&rules, top, "https://morp.example.com/"));
        assert!(!blocked(&rules, top, "https://example.com/a.morp/b"));
    }

    #[test]
    fn typed_morp_navigation_is_not_blocked_by_the_rules() {
        // For a main-frame load the top URL is the page being loaded.
        let rules = content_rules(true);
        let url = format!("morp://{ID}.morp/");
        assert!(!blocked(&rules, &url, &url));
    }

    #[test]
    fn morp_only_mode_blocks_all_clearnet_loads() {
        let rules = content_rules(true);
        for top in ["https://news.example/", "about:blank"] {
            assert!(blocked(&rules, top, "https://news.example/"));
            assert!(blocked(&rules, top, "ws://news.example/"));
        }
    }

    #[test]
    fn rules_use_only_webkit_regex_syntax() {
        for r in content_rules(true) {
            let all = std::iter::once(&r.trigger.url_filter)
                .chain(&r.trigger.if_top_url)
                .chain(&r.trigger.unless_top_url);
            for re in all {
                assert!(!re.contains('|') && !re.contains('{'), "{re}");
            }
            assert!(r.trigger.if_top_url.is_empty() || r.trigger.unless_top_url.is_empty());
        }
        let json: serde_json::Value = serde_json::from_str(&content_rules_json(false)).unwrap();
        assert_eq!(json[0]["action"]["type"], "block");
        assert_eq!(json[0]["trigger"]["if-top-url"][0], "^morp:");
    }

    #[test]
    fn morp_pages_cannot_navigate_to_clearnet_but_the_user_can() {
        let morp = format!("morp://{ID}.morp/");
        let site = "https://example.com/";
        assert!(matches!(
            navigation(&morp, site, Initiator::Page, BrowserMode::Normal),
            Err(Blocked::LeavingMorp(_))
        ));
        assert!(navigation(&morp, site, Initiator::User, BrowserMode::Normal).is_ok());
        assert!(navigation(site, &morp, Initiator::Page, BrowserMode::Normal).is_ok());
        assert!(
            navigation(
                site,
                "https://other.example/",
                Initiator::Page,
                BrowserMode::Normal
            )
            .is_ok()
        );
    }

    #[test]
    fn dangerous_navigations_are_refused_everywhere() {
        let site = "https://example.com/";
        for target in [
            format!("https://{ID}.morp/"),
            format!("http://{ID}.morp.:8080/"),
        ] {
            assert_eq!(
                navigation(site, &target, Initiator::User, BrowserMode::Normal),
                Err(Blocked::MorpOverClearnet)
            );
        }
        for target in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "mailto:a@example.com",
            "data:text/html,hi",
            "magnet:?xt=urn:x",
            "ftp://example.com/",
        ] {
            assert!(
                matches!(
                    navigation(site, target, Initiator::User, BrowserMode::Normal),
                    Err(Blocked::Scheme(_))
                ),
                "{target}"
            );
        }
        assert!(navigation(site, "about:blank", Initiator::Page, BrowserMode::Normal).is_ok());
    }

    #[test]
    fn morp_only_mode_refuses_even_typed_websites() {
        assert!(matches!(
            navigation(
                "about:blank",
                "https://example.com/",
                Initiator::User,
                BrowserMode::MorpOnly
            ),
            Err(Blocked::ClearnetDisabled(_))
        ));
        let morp = format!("morp://{ID}.morp/");
        assert!(navigation("about:blank", &morp, Initiator::User, BrowserMode::MorpOnly).is_ok());
    }

    #[test]
    fn leaky_and_fingerprintable_features_are_off() {
        for name in [
            "enable-webrtc",
            "enable-media-stream",
            "enable-dns-prefetching",
            "enable-webgl",
            "enable-webaudio",
            "enable-hyperlink-auditing",
            "enable-write-console-messages-to-stdout",
        ] {
            assert_eq!(setting(name), Some(false), "{name}");
        }
        assert!(USER_AGENT.starts_with("Mozilla/5.0 (X11; Linux x86_64)"));
        let headers = morp_headers();
        assert!(headers.contains(&("x-dns-prefetch-control", "off")));
        assert!(PAGE_CSP.contains("connect-src 'self'") && PAGE_CSP.contains("object-src 'none'"));
    }
}
