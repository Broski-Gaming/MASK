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

## Next: layered onion encryption

Planned, not started:
- Persistent relay identity keys (Ed25519) with node ID = key fingerprint.
- Per-hop key agreement (X25519) and authenticated encryption of each
  `OnionLayer` with RustCrypto crates.
- Replies encrypted once per hop on the way back.
- Consider fixed-size cells to hide message lengths.
- Tests that a relay cannot read layers meant for other hops.
