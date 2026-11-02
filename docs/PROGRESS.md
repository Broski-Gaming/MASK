# MASK Progress Notes

## v0.1 — Browser window (2026-11-01)

**Done**
- GTK3 window titled "MASK Browser" with a dark theme.
- Native GTK toolbar: back, forward, reload, address bar, connection status
  label ("Direct connection · not anonymous").
- Wry/WebKitGTK web view; ephemeral (incognito) session.
- Address bar accepts http/https only; bare domains default to https;
  `.mask` shows "not available yet".
- Static start page with a "Not anonymous" warning and a strict CSP.

**Known limitations**
- No tabs. Links that open new windows may do nothing. No search.
- On NVIDIA systems Mesa prints harmless `failed to create dri2 screen`
  warnings; pages still render.

## v0.2 — Relay network foundation (2026-11-01)

**Done**
- Converted the repo to a Cargo workspace; new crate `crates/mask-net`
  with no GUI dependencies.
- `mask-relay --role entry|middle|exit`: separate relay processes on
  127.0.0.1 (default ports 7101/7102/7103).
- `mask-client`: sends one or more test messages over a single circuit.
- Wire format: u32 length-prefixed frames (max 64 KiB) carrying
  postcard-encoded `Message`s.
- Handshake with protocol version and role-order checks
  (client → entry → middle → exit).
- Onion-shaped routing: client builds nested `OnionLayer`s; each relay
  peels one, forwards the rest, and returns the reply upstream. The exit
  runs a test echo service.
- Errors (unreachable hop, timeout, wrong role, malformed frame/layer,
  version mismatch) are returned to the client with the reporting relay's
  name.
- Structured logging with `tracing`: relay name, role, node ID, peers,
  byte counts. Message contents are never logged.
- Safety limits: loopback-only listen and next-hop addresses (prevents use
  as an open proxy), frame size cap, connect/handshake/response/idle
  timeouts.
- 29 network tests (unit + end-to-end), 9 browser tests.

**Security status: none.** Layers are plaintext, so every relay sees the
full route and the message. Node IDs are random labels regenerated on each
start and prove nothing. Peer roles in the handshake are self-declared.

**Known limitations**
- One downstream connection per inbound connection (no circuit IDs or
  multiplexing yet).
- One request in flight per circuit; replies are matched by order.
- Message sizes are visible (no fixed-size cells or padding).
- No limit on the number of simultaneous connections.

## v0.3 — MORP v1: encrypted onion routing (2026-11-01)

Full specification, threat model, and limitations: `docs/MORP.md`.

**Done**
- Replaced the v0.2 plaintext protocol with MORP v1 (v0.2 code remains in
  Git history).
- Relay identity: Ed25519 key in `runtime/relays/<name>/identity.key`
  (mode 0600; refuses to start if group/other can read it). Fresh X25519
  onion key on every start.
- Signed relay descriptors (`runtime/directory/<name>.json`), verified
  with `verify_strict`; tampered or malformed descriptors are skipped.
  Relays withdraw their descriptor on Ctrl+C.
- Telescoping circuits: CREATE to the entry, EXTEND through entry and
  middle. ntor-style handshake (adapted from Tor) with X25519,
  HKDF-SHA256, HMAC-SHA256; low-order keys rejected; constant-time MAC check.
- Layered ChaCha20-Poly1305: separate keys per hop and direction, implicit
  64-bit counter nonces, no wraparound. Replayed, reordered, dropped, or
  modified cells fail authentication and destroy the circuit.
- Encrypted replies: each hop adds one backward layer; the client peels
  them and knows which hop answered.
- Circuit IDs: random per-link u32s; many circuits and many clients share
  links; relays reuse one outbound link per next hop.
- Errors (`NextHopUnreachable`, `ExtendRejected`, `NotAllowed`,
  `Timeout`) returned to the client encrypted by the reporting hop; a
  failed EXTEND leaves the partial circuit usable.
- Limits: 64 KiB frames, 60 KiB data per cell, 128 circuits per link,
  4096 per relay, connect/handshake/response/idle timeouts.
- `mask-client` loads the directory, prints the verified path, supports
  `--circuits N`.
- Tests: 32 unit (keys, handshake, AEAD, descriptors, protocol) + 26
  end-to-end (routing, concurrency, layer isolation, relay failures,
  timeouts, stale keys, impostors, replay, tampering, malformed frames,
  limits). End-to-end suite ran 10× in a row without failures.
- Manual run with three relay processes: routing, 2 circuits over one link,
  exit shutdown, stale onion key rejection; no plaintext in relay logs.

**Security status: unreviewed.** See the threat model in `docs/MORP.md`.
Main gaps: links are plain TCP (no TLS/Noise), variable cell sizes,
trusted local directory, no guard nodes, error details name relays.

## Next

Candidates, one at a time:
- Authenticated, encrypted links (TLS 1.3 or Noise) and fixed-size cells.
- Real exit streams and a local SOCKS5 proxy.
- Connect the browser to the network (status panel, circuit info).
- Later: `.mask` hidden services.

## v0.4 — Cryptographic `.morp` addresses (2026-11-01)

Specification, threat model, and limitations: `docs/MORP_ADDRESSES.md`.

**Decision:** MASK supports only cryptographic `.morp` service addresses.
No names, aliases, DNS, or registration. Recorded in CLAUDE.md.

**Done**
- Address format: lowercase Base32 of Ed25519 public key + 2-byte SHA3-256
  checksum (domain `"MORP address checksum v1"`) + version `0x01`
  (56 characters). Validation of length, alphabet, version, checksum, and
  key (invalid and small-order points rejected). Known-answer vector
  cross-checked against an independent implementation.
- Service identities: `runtime/services/<id>/service.key` (0600, folder
  0700, never overwritten; folder must match the key's address).
- Signed service descriptors with revision, ≤ 3 h lifetime, 5 min clock
  skew, loopback endpoint; signed withdrawals.
- `mask-directory` (Axum, 127.0.0.1:7200): publish / lookup / withdraw by
  identity only; verifies before storing and before returning; rejects
  forged, expired, malformed, mismatched, and replayed descriptors; no
  listing endpoint; 8 KiB body cap.
- Service channel: signed ephemeral X25519 handshake proving key
  possession on every connection, then ChaCha20-Poly1305 with counter
  nonces; chunked responses up to 16 MiB.
- Static site hosting with traversal, dotfile, and symlink-escape
  protection; content types for HTML/CSS/JS/images/fonts.
- `mask-service`: create, list, show, check, host, stop (PID file +
  SIGTERM, checks the process name), verify.
- Browser: `morp://` via Wry `with_asynchronous_custom_protocol` on a
  background Tokio runtime; address bar accepts `morp://<id>.morp` and bare
  `<id>.morp`; refuses `http(s)://*.morp` and `.mask`; navigation handler
  blocks clearnet `.morp`; restrictive CSP on `.morp` pages; local error
  pages; toolbar status shows "MORP service · localhost prototype · not
  anonymous"; optional start address argument (`mask-browser <address>`).
- Example site: `examples/morp-site/`.
- Tests: 122 total (19 browser, 60 network unit, 26 MORP end-to-end,
  17 service end-to-end).
- Manual: created an address, hosted the example site, `verify` passed,
  opened it in MASK Browser (HTML, CSS, JS, SVG rendered); a test page's
  `<img>` and `fetch()` to an outside listener made no connection; stopped
  service showed "Service not found"; mistyped address rejected by checksum.

**Security status: unreviewed.** Service location is NOT hidden (direct
loopback endpoint in the descriptor). The directory sees all lookups and
endpoints. See the threat model.

## Next: v0.5 hidden-service circuits

Planned, not started:
- Introduction points and rendezvous circuits over MORP relays, so the
  descriptor no longer reveals the service's endpoint.
- Consider encrypting descriptors so the directory cannot read them.
