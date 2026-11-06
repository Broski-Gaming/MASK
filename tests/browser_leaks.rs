//! Live leak test of the real MASK Browser (v0.7). Opt-in: needs a display.
//!
//! ```text
//! cargo build --workspace
//! scripts/browser-leak-test.sh          # recommended: adds a DNS canary and
//!                                       # a packet capture in a namespace
//! cargo test --test browser_leaks -- --ignored --nocapture   # without DNS checks
//! ```
//!
//! A local MORP network serves a hostile `.morp` page that tries to leak by
//! every means a page has (images, fetch, WebSocket, beacons, pings, CSS,
//! frames, DNS prefetch, WebRTC/STUN, redirects and navigations to the
//! clearnet) and reports what JavaScript can see (fingerprinting surface).
//! A hostile *clearnet* page tries to load `morp:` resources and `.morp`
//! names over https. Canaries record what actually escapes:
//! - an HTTP server standing in for "the internet" (127.0.0.1);
//! - a UDP port standing in for a STUN server;
//! - with `MASK_LEAK_DNS_CANARY=1` (set by the script, which runs the test
//!   in a namespace whose only resolver is 127.0.0.1:53): a DNS server.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mask_net::crypto::keys::RelayKeys;
use mask_net::directory::client::DirectoryClient;
use mask_net::directory::server::{self, DirectoryState};
use mask_net::hs::service::{HiddenService, HostConfig};
use mask_net::identity::Role;
use mask_net::relay::{Relay, RelayConfig};
use mask_net::service::keys::ServiceKeys;
use mask_net::service::{now_millis, now_secs};
use mask_net::trust::TrustedRelays;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

type Log = Arc<Mutex<Vec<String>>>;
type Page = Arc<dyn Fn(&str) -> Option<(&'static str, String)> + Send + Sync>;

/// Which part of the test is running (connections are tagged with it).
static PHASE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static START: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

fn ms() -> u128 {
    START.elapsed().as_millis()
}

fn phase() -> u8 {
    PHASE.load(std::sync::atomic::Ordering::SeqCst)
}

/// A tiny HTTP/1.1 server: records each request path, answers with `page`.
/// `connections` gets one entry per TCP connection (tagged with the phase),
/// even if nothing is sent on it (WebKit pre-connects).
async fn http_server(listener: TcpListener, log: Log, connections: Log, page: Page) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        connections
            .lock()
            .unwrap()
            .push(format!("phase {}", phase()));
        eprintln!(
            "[{} ms] connection to {} (phase {})",
            ms(),
            listener.local_addr().unwrap(),
            phase()
        );
        let log = Arc::clone(&log);
        let page = Arc::clone(&page);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut len = 0;
            while len < buf.len() {
                match stream.read(&mut buf[len..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => len += n,
                }
                if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf[..len]).into_owned();
            let path = head.split_whitespace().nth(1).unwrap_or("?").to_owned();
            eprintln!("[{} ms] request {path}", ms());
            log.lock().unwrap().push(path.clone());
            let (status, ctype, body) = match page(&path) {
                Some((ctype, body)) => ("200 OK", ctype, body),
                None => ("404 Not Found", "text/plain", "not found".into()),
            };
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        });
    }
}

/// Answers every DNS query with NXDOMAIN, recording the queried names.
async fn dns_canary(socket: UdpSocket, log: Log) {
    let mut buf = [0u8; 512];
    while let Ok((n, from)) = socket.recv_from(&mut buf).await {
        let mut name = Vec::new();
        let mut i = 12;
        while i < n && buf[i] != 0 {
            let len = buf[i] as usize;
            name.push(String::from_utf8_lossy(&buf[i + 1..(i + 1 + len).min(n)]).into_owned());
            i += 1 + len;
        }
        log.lock()
            .unwrap()
            .push(format!("phase {}: {}", phase(), name.join(".")));
        if n >= 12 {
            let mut reply = buf[..n].to_vec();
            reply[2] = 0x80 | (buf[2] & 0x01); // response, keep RD
            reply[3] = 0x83; // RA, NXDOMAIN
            let _ = socket.send_to(&reply, from).await;
        }
    }
}

async fn udp_canary(socket: UdpSocket, log: Log) {
    let mut buf = [0u8; 2048];
    while let Ok((n, from)) = socket.recv_from(&mut buf).await {
        log.lock().unwrap().push(format!("{n} bytes from {from}"));
    }
}

fn morp_page(canary: SocketAddr, stun: SocketAddr, other_morp: &str) -> String {
    let c = format!("http://{canary}");
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>MORP leak test</title>
<meta http-equiv="refresh" content="7;url={c}/meta-refresh-from-morp">
<link rel="dns-prefetch" href="//dns-prefetch-from-morp.example">
<link rel="preconnect" href="https://preconnect-from-morp.example">
<link rel="prefetch" href="{c}/prefetch-from-morp">
<link rel="stylesheet" href="{c}/css-from-morp">
<style>@import url({c}/import-from-morp); body {{ background: url({c}/bg-from-morp) }}
@font-face {{ font-family: x; src: url({c}/font-from-morp) }}</style>
</head><body>
<h1>MORP leak test</h1>
<img src="{c}/img-from-morp">
<img src="https://{other_morp}.morp/img-over-https">
<iframe src="{c}/iframe-from-morp"></iframe>
<a id="link" href="{c}/link-from-morp" ping="{c}/ping-from-morp">a link</a>
<a href="https://anchor-prefetch-from-morp.example/">another</a>
<script>
const r = {{}};
r.webrtc = typeof RTCPeerConnection;
r.webgl = String(!!document.createElement('canvas').getContext('webgl'));
r.webaudio = typeof AudioContext;
r.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
r.lang = navigator.language;
r.ua = navigator.userAgent;
r.getusermedia = String(!!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia));
r.cores = String(navigator.hardwareConcurrency);
r.screen = screen.width + 'x' + screen.height;
try {{ fetch('{c}/fetch-from-morp').catch(() => {{}}); }} catch (e) {{}}
try {{ new WebSocket('ws://{canary}/ws-from-morp'); }} catch (e) {{}}
try {{ navigator.sendBeacon('{c}/beacon-from-morp', 'x'); }} catch (e) {{}}
try {{ const x = new XMLHttpRequest(); x.open('GET', '{c}/xhr-from-morp'); x.send(); }} catch (e) {{}}
try {{ new Worker('{c}/worker-from-morp'); }} catch (e) {{}}
try {{ window.open('{c}/popup-from-morp'); }} catch (e) {{}}
try {{
  if (window.RTCPeerConnection) {{
    const pc = new RTCPeerConnection({{iceServers: [{{urls: 'stun:{stun}'}}]}});
    pc.createDataChannel('x');
    pc.createOffer().then(o => pc.setLocalDescription(o));
    r.webrtc_ran = 'yes';
  }}
}} catch (e) {{ r.webrtc_error = String(e); }}
setTimeout(() => {{
  fetch('/report?' + new URLSearchParams(r)).then(() => {{
    fetch('/mark?before-click');
    setTimeout(() => {{ document.getElementById('link').click(); }}, 1000);
    setTimeout(() => {{ fetch('/mark?before-location'); }}, 2000);
    setTimeout(() => {{ location.href = '{c}/location-from-morp'; }}, 3000);
    setTimeout(() => {{ fetch('/done'); }}, 5000);
  }});
}}, 800);
</script></body></html>"#
    )
}

fn clearnet_page(id: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>clearnet leak test</title>
<link rel="dns-prefetch" href="//{id}.morp">
</head><body>
<h1>A clearnet page trying to reach .morp</h1>
<img src="morp://{id}.morp/probe-img">
<iframe src="morp://{id}.morp/probe-frame"></iframe>
<script src="morp://{id}.morp/probe-script.js"></script>
<img src="https://{id}.morp/probe-https-img">
<img src="http://{id}.morp/probe-http-img">
<a href="https://{id}.morp/">a .morp name over https</a>
<script>
const r = {{}};
try {{ fetch('morp://{id}.morp/probe-fetch').catch(() => {{}}); }} catch (e) {{}}
try {{ new WebSocket('wss://{id}.morp/probe-ws'); }} catch (e) {{}}
r.webrtc = typeof RTCPeerConnection;
setTimeout(() => {{
  fetch('/clear-report?' + new URLSearchParams(r));
  setTimeout(() => {{ location.href = 'https://{id}.morp/probe-navigation'; }}, 300);
  setTimeout(() => {{ fetch('/clear-done'); }}, 2500);
}}, 800);
</script></body></html>"#
    )
}

struct Browser(Child);

impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch(url: &str, env: &[(&str, String)]) -> Browser {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mask-browser"));
    cmd.arg(url)
        .env(
            "RUST_LOG",
            std::env::var("MASK_LEAK_BROWSER_LOG").unwrap_or_else(|_| "warn".into()),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (k, v) in env {
        cmd.env(k, v);
    }
    Browser(cmd.spawn().expect("start mask-browser"))
}

async fn wait_for(log: &Log, what: &str, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if log.lock().unwrap().iter().any(|p| p.starts_with(what)) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn report(log: &Log, prefix: &str) -> Vec<(String, String)> {
    let entry = log
        .lock()
        .unwrap()
        .iter()
        .find(|p| p.starts_with(prefix))
        .cloned()
        .unwrap_or_default();
    url::form_urlencoded::parse(entry.split_once('?').map_or("", |(_, q)| q).as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn value<'a>(report: &'a [(String, String)], key: &str) -> &'a str {
    report
        .iter()
        .find(|(k, _)| k == key)
        .map_or("<missing>", |(_, v)| v.as_str())
}

#[tokio::test]
#[ignore = "launches the real browser; needs a display (see scripts/browser-leak-test.sh)"]
async fn the_browser_does_not_leak() {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        eprintln!("skipped: no display");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = dir.path().join("relays");

    // Canaries.
    let canary_log: Log = Arc::default();
    let canary_connections: Log = Arc::default();
    let stun_log: Log = Arc::default();
    let dns_log: Log = Arc::default();
    let stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun.local_addr().unwrap();
    tokio::spawn(udp_canary(stun, Arc::clone(&stun_log)));
    let dns_checked = std::env::var_os("MASK_LEAK_DNS_CANARY").is_some();
    if dns_checked {
        let dns = UdpSocket::bind("127.0.0.1:53")
            .await
            .expect("DNS canary needs port 53 (run scripts/browser-leak-test.sh)");
        tokio::spawn(dns_canary(dns, Arc::clone(&dns_log)));
        // Positive control: a lookup made here must reach the canary,
        // otherwise "no queries seen" below would prove nothing (for
        // example if lookups still went to the host's systemd-resolved).
        let lookup = tokio::task::spawn_blocking(|| {
            use std::net::ToSocketAddrs;
            "canary-selftest.example:80"
                .to_socket_addrs()
                .map(|a| a.count())
        });
        let _ = tokio::time::timeout(Duration::from_secs(10), lookup).await;
        let seen = dns_log.lock().unwrap().clone();
        assert!(
            seen.iter().any(|q| q.contains("canary-selftest.example")),
            "the DNS canary does not see this process's lookups ({seen:?}); \
             run this test through scripts/browser-leak-test.sh"
        );
        dns_log.lock().unwrap().clear();
    }

    // A local MORP network: entry, middle, two rendezvous relays, directory.
    for (nick, role) in [
        ("entry", Role::Entry),
        ("middle", Role::Middle),
        ("rv0", Role::Rendezvous),
        ("rv1", Role::Rendezvous),
    ] {
        let mut config = RelayConfig::new(nick, role, "127.0.0.1:0".parse().unwrap());
        config.trusted = TrustedRelays::from(relay_dir.clone());
        let relay = Relay::bind(config, RelayKeys::generate()).await.unwrap();
        relay.descriptor().write_to_dir(&relay_dir).unwrap();
        tokio::spawn(relay.serve());
    }
    let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let directory_addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(listener, Arc::new(DirectoryState::default())));

    // The hostile .morp site, and the "internet" canary.
    let identity = ServiceKeys::generate();
    let url = identity.address().url();
    let id = identity.address().id().to_owned();
    let canary = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let canary_addr = canary.local_addr().unwrap();
    let other_morp = ServiceKeys::generate().address().id().to_owned();
    let app_log: Log = Arc::default();
    let page = morp_page(canary_addr, stun_addr, &other_morp);
    let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_addr = app.local_addr().unwrap();
    tokio::spawn(http_server(
        app,
        Arc::clone(&app_log),
        Arc::default(),
        Arc::new(move |path| {
            (path == "/")
                .then(|| ("text/html; charset=utf-8", page.clone()))
                .or(Some(("text/plain", "ok".into())))
        }),
    ));
    let clear = clearnet_page(&id);
    tokio::spawn(http_server(
        canary,
        Arc::clone(&canary_log),
        Arc::clone(&canary_connections),
        Arc::new(move |path| {
            (path == "/clear")
                .then(|| ("text/html; charset=utf-8", clear.clone()))
                .or(Some(("text/plain", "ok".into())))
        }),
    ));

    let mut host = HostConfig::new(relay_dir.clone(), app_addr);
    host.intro_points = 1;
    let service = HiddenService::start(identity, host).await.unwrap();
    DirectoryClient::new(directory_addr, Duration::from_secs(2))
        .unwrap()
        .publish(&service.descriptor(now_secs(), 600, now_millis()))
        .await
        .unwrap();

    let env = |extra: &[(&'static str, &str)]| -> Vec<(&'static str, String)> {
        let mut v = vec![
            ("MASK_DIRECTORY", directory_addr.to_string()),
            ("MASK_RELAY_DIRECTORY", relay_dir.display().to_string()),
            (
                "MASK_STATE_DIR",
                dir.path().join("state").display().to_string(),
            ),
        ];
        v.extend(extra.iter().map(|(k, v)| (*k, (*v).to_owned())));
        v
    };

    // ---- 1. The hostile .morp page.
    PHASE.store(1, std::sync::atomic::Ordering::SeqCst);
    eprintln!("[{} ms] ===== phase 1", ms());
    {
        let _browser = launch(&url, &env(&[]));
        assert!(
            wait_for(&app_log, "/report", Duration::from_secs(60)).await,
            "the .morp page never reported (did it load? app saw {:?})",
            app_log.lock().unwrap()
        );
        assert!(
            wait_for(&app_log, "/done", Duration::from_secs(20)).await,
            "the page was navigated away (to the clearnet?)"
        );
    }
    let r = report(&app_log, "/report");
    eprintln!("what a .morp page sees: {r:?}");
    assert_eq!(value(&r, "webrtc"), "undefined", "WebRTC must not exist");
    assert_eq!(value(&r, "webgl"), "false", "WebGL must be off");
    assert_eq!(value(&r, "webaudio"), "undefined", "WebAudio must be off");
    assert_eq!(value(&r, "getusermedia"), "false", "no media capture");
    assert_eq!(value(&r, "tz"), "UTC", "time zone must be hidden");
    assert_eq!(value(&r, "lang"), "en-US");
    assert_eq!(value(&r, "ua"), mask::privacy::USER_AGENT);

    // ---- 2. A hostile clearnet page (opened by the user).
    tokio::time::sleep(Duration::from_millis(500)).await;
    PHASE.store(2, std::sync::atomic::Ordering::SeqCst);
    eprintln!("[{} ms] ===== phase 2", ms());
    {
        let _browser = launch(&format!("http://{canary_addr}/clear"), &env(&[]));
        assert!(
            wait_for(&canary_log, "/clear-done", Duration::from_secs(40)).await,
            "the clearnet page did not finish: {:?}",
            canary_log.lock().unwrap()
        );
    }
    let r = report(&canary_log, "/clear-report");
    assert_eq!(value(&r, "webrtc"), "undefined");

    // ---- 3. MORP-only mode: even a typed website is refused.
    tokio::time::sleep(Duration::from_millis(500)).await;
    PHASE.store(3, std::sync::atomic::Ordering::SeqCst);
    eprintln!("[{} ms] ===== phase 3", ms());
    let before = canary_log.lock().unwrap().len();
    {
        let _browser = launch(
            &format!("http://{canary_addr}/morp-only"),
            &env(&[("MASK_MORP_ONLY", "1")]),
        );
        tokio::time::sleep(Duration::from_secs(8)).await;
    }

    // ---- What escaped.
    let connections = canary_connections.lock().unwrap().clone();
    for forbidden in ["phase 1", "phase 3"] {
        assert!(
            !connections.iter().any(|c| c == forbidden),
            "the internet canary got a connection during {forbidden}: {connections:?}"
        );
    }
    let canary_hits = canary_log.lock().unwrap().clone();
    let from_morp: Vec<_> = canary_hits
        .iter()
        .filter(|p| p.contains("from-morp"))
        .collect();
    assert!(
        from_morp.is_empty(),
        "the .morp page reached the internet: {from_morp:?}"
    );
    assert_eq!(
        canary_hits.len(),
        before,
        "MORP-only mode loaded a website: {canary_hits:?}"
    );
    let probes: Vec<_> = app_log
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.contains("probe"))
        .cloned()
        .collect();
    assert!(
        probes.is_empty(),
        "a clearnet page loaded .morp content: {probes:?}"
    );
    let stun_hits = stun_log.lock().unwrap().clone();
    assert!(
        stun_hits.is_empty(),
        "WebRTC reached the STUN canary: {stun_hits:?}"
    );
    if dns_checked {
        let queries = dns_log.lock().unwrap().clone();
        eprintln!("DNS queries seen: {queries:?}");
        let morp: Vec<_> = queries.iter().filter(|q| q.contains("morp")).collect();
        assert!(
            morp.is_empty(),
            "a .morp name or page leaked to DNS: {morp:?}"
        );
        // While a .morp page was open, and in MORP-only mode, nothing at
        // all may be looked up.
        let during: Vec<_> = queries
            .iter()
            .filter(|q| q.starts_with("phase 1") || q.starts_with("phase 3"))
            .collect();
        assert!(
            during.is_empty(),
            "DNS lookups while MORP was in use: {during:?}"
        );
    } else {
        eprintln!("DNS not checked (run scripts/browser-leak-test.sh for that)");
    }
    eprintln!("internet canary saw only: {canary_hits:?}");
}
