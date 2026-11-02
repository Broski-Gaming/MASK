//! The page shown when the browser opens. Static HTML, no scripts.

pub const HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>MASK Browser</title>
<style>
  html, body { height: 100%; margin: 0; }
  body {
    background: #111318;
    color: #c9d1d9;
    font-family: system-ui, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  main { max-width: 560px; padding: 32px; text-align: center; }
  h1 { color: #e6edf3; font-size: 40px; letter-spacing: 0.3em; margin: 0 0 4px; }
  .version { color: #8b6cff; margin: 0 0 28px; }
  .warning {
    text-align: left;
    background: #2a2414;
    border: 1px solid #5c4a1a;
    color: #e3c77a;
    border-radius: 10px;
    padding: 14px 18px;
    line-height: 1.5;
  }
</style>
</head>
<body>
<main>
  <h1>MASK</h1>
  <p class="version">Multi-hop Anonymous Service Kit · v0.4 development build</p>
  <p>Type a website (<code>https://…</code>) or a cryptographic <code>morp://&lt;id&gt;.morp</code> address above.</p>
  <div class="warning">
    <strong>Not anonymous.</strong> Websites are loaded directly over your normal
    internet connection. <code>.morp</code> services are found through the local MORP
    directory (never public DNS) and must prove they own their address, but this
    prototype connects to them directly on localhost: their location is not hidden
    and no relays are used. Cookies and site data are discarded when the window closes.
  </div>
</main>
</body>
</html>
"#;
