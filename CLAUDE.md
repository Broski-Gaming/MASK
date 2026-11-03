# MASK — Project Context

## Project Overview
MASK stands for Multi-hop Anonymous Service Kit.

MASK is an experimental privacy browser and independent onion-routing network inspired by Tor.

The goal is to build a working browser, encrypted multi-hop routing network, and custom hidden-service ecosystem.

## Development Environment
- Operating system: Arch Linux
- Desktop environment: KDE Plasma
- Terminal: Konsole
- Programming language: Rust
- Package manager: Cargo
- Version control: Git
- Default Git branch: main

## Technology Stack
- Rust for all core application code
- Tokio for asynchronous networking
- Wry and WebKitGTK for browser rendering
- RustCrypto libraries for cryptography
- Axum for network APIs
- Serde for configuration

## MASK Network
MASK will eventually support:
- Encrypted multi-hop routing
- Entry, middle, and exit relay nodes
- SOCKS5 proxy connections
- Independent relay identities
- Private cryptographic `.morp` addresses (see "Service Addresses" below)
- Cryptographically generated service identities
- Hidden websites hosted by MASK users
- Introduction points and rendezvous circuits

## Browser Features
- Custom dark interface
- Tabs and address bar
- Normal HTTPS website browsing
- `.morp` website browsing (cryptographic addresses only)
- Network connection status
- Relay and circuit information
- Privacy settings

## Architecture
Cargo workspace with two crates:
- `mask` (repo root, `src/`): the browser. Binary `mask-browser`. GTK3 toolbar is native GTK (not HTML) so web content cannot script browser controls; Wry embeds the WebKitGTK view.
- `mask-net` (`crates/mask-net/`): the relay network. No GUI dependencies so relays can run headless. Binaries `mask-relay`, `mask-client`, `mask-service`, `mask-directory`, `mask-authority`.

Network protocol: **MORP** (MASK Onion Routing Protocol). Full spec, threat model, and limitations in `docs/MORP.md` — keep it in sync with the code.
- Link level (MORP v3, since v0.6): every link is a **Noise** session (`snow`, RustCrypto/dalek backends only): `Noise_NK` client/host → entry, probes, and authority requests; `Noise_IK` relay → relay. Frames are u16-length Noise messages; one postcard `LinkMsg` (≤ 65 519 bytes) each. No plaintext mode, ever. Per-run relay link key signed into descriptor v3. `Hello`/`Welcome` inside Noise checks version and role order; on relay links the role must match the authenticated relay. `Ping`/`Pong` keepalives. Many circuits per link via random per-link `u32` circuit IDs.
- Relays accept relay links from, and extend only to, relays in their `TrustedRelays` (`trust.rs`: descriptor folder in local mode, signed consensus in network mode), at the published address, inside the network scope. Never let a relay connect to an arbitrary address.
- Circuits are telescoping (Tor-style): CREATE to entry, then EXTEND through each hop.
- Handshake: ntor-style (adapted from Tor) with X25519 + HKDF-SHA256 + HMAC-SHA256, authenticated against the Ed25519 identity and X25519 onion key in a signed relay descriptor.
- Layers: ChaCha20-Poly1305 per hop and direction; nonces are implicit 64-bit counters (never sent), giving replay/reorder detection. Any failure destroys the circuit.
- Relay identity keys live in `runtime/relays/<name>/identity.key` (mode 0600, git-ignored); descriptors in `runtime/directory/`. Never commit anything under `runtime/`.
- Network scope (`scope.rs`): `loopback` (default, local mode) or `private` (network mode). Public, unspecified (`0.0.0.0`), link-local, and multicast addresses are refused everywhere; never add a public scope.
- Crypto rule: use established primitives from RustCrypto/dalek only; never invent cryptographic algorithms.

## Service Addresses (decision, v0.4)
**MASK exclusively supports cryptographic `.morp` service addresses.** This is a permanent design decision:
- An address is `morp://<56-char id>.morp/`, where the id is lowercase Base32 of `Ed25519 public key (32) || SHA3-256("MORP address checksum v1" || key || version)[..2] || version 0x01`. Spec: `docs/MORP_ADDRESSES.md`.
- Never add friendly names, aliases, nicknames, DNS records, registrars, petnames, or manually chosen/registered service names. Never allow an address to be reassigned to another key.
- `.morp` names must never be resolved through public DNS or sent over `http(s)`; `morp://` is served only by the browser's custom protocol handler via the MORP directory, failing closed with a local error page.
- `.mask` and other named schemes are rejected.
- Service keys live in `runtime/services/<id>/service.key` (0600, folder 0700, folder named by the address). The directory never stores private keys.
- Since v0.5, `.morp` traffic travels **only** through MORP relay circuits (introduction points + rendezvous). Never add a direct browser-to-service connection, a clearnet/exit path for `.morp`, or any fallback. Descriptors (v2) list intro points only, never a network location.
- Even so: do not claim Tor-level anonymity or real location hiding. At most a handful of relays run by one operator on one machine or a private LAN, and nothing has been independently reviewed. Spreading traffic over several machines is not anonymity.

Components: `mask-service` (create/list/show/check/host/stop/verify/fetch; `--network` for the testnet), `mask-directory` (Axum, 127.0.0.1:7200, local mode), `mask-authority` (network mode: also stores service descriptors, over Noise), `crates/mask-net/src/hs/` (hidden services), `src/morp.rs` (browser handler). In local mode the relay directory (`runtime/directory/`, files) and the service directory (HTTP) are separate.

## Hidden Services (v0.5)
Spec and threat model: `docs/MORP_HIDDEN_SERVICES.md`.
- Relay role `rendezvous` (last hop after a middle) acts as introduction point and rendezvous point. Exits are never used for `.morp`.
- Service: per-run intro auth (Ed25519) + intro encryption (X25519) keys per intro point; the identity key never leaves the host. Introductions are encrypted to the service; replays rejected.
- Client: random rendezvous relay + single-use 32-byte cookie; service builds its own circuit to it; rendezvous joins the circuits; service signs the handshake with its identity key; end-to-end ChaCha20-Poly1305 session with counter nonces, multiplexed requests.
- Testing rules: prove routing with the `ConnectPolicy` (deny-by-default, records every outbound connection), the relay `Observer` (every plaintext a relay decrypts), and relay/host counters, not log messages.

## Milestones
- [x] v0.1 — Browser window: dark GTK UI, address bar, HTTPS browsing, ephemeral session.
- [x] v0.2 — Relay network foundation: entry/middle/exit relays on 127.0.0.1, framed structured messages, plaintext onion layers, error propagation, logging, tests.
- [x] v0.3 — MORP v1: Ed25519 relay identities, signed descriptors, ntor-style handshakes, layered ChaCha20-Poly1305 with replay protection, circuit IDs, encrypted replies, tests. Unreviewed.
- [x] v0.4 — Cryptographic `.morp` addresses: Ed25519 service identities, signed expiring descriptors, localhost directory, authenticated encrypted service channel, static site hosting, `morp://` in MASK Browser with no DNS/clearnet fallback. Direct localhost prototype (location not hidden). Unreviewed.
- [x] v0.5 — Relay-routed `.morp` hidden services: rendezvous-role relays, introduction points, rendezvous joins, encrypted introductions, service authentication, end-to-end encrypted multiplexed sessions, descriptor v2 (no location), browser loads full sites via MORP, no-bypass/auth/failure/cleanup tests. Direct v0.4 path removed. Unreviewed, localhost only.
- [x] v0.5 verified (2026-11-01): addresses, relay-only routing, separate joined circuits, no direct connections, safe failure with disconnected and malicious (tampering/black-holing) relays; 141 tests. Report in `docs/PROGRESS.md`.
- [x] v0.6 (2026-11-02) — Distributed MORP testnet: private network scope, Noise-authenticated links, `mask-authority` (allowlist, identity-change refusal, health probes, signed expiring consensus, `.morp` directory), TOML configs (`deploy/`), keepalives, link limits, graceful shutdown, family-aware paths with retries, intro-point re-establishment, browser network mode (`MASK_NETWORK`). Verified with multiple processes and Linux network namespaces (`scripts/netns-testnet.sh`); 194 tests. Docs: `docs/DISTRIBUTED_NETWORK.md`. Unreviewed.
- [ ] v0.6 LAN trial on separate physical machines (procedure in `docs/DISTRIBUTED_NETWORK.md` §4–§5), recorded in `docs/PROGRESS.md`.
- [ ] Later: multiple authorities with threshold signatures; entry guards; fixed-size cells and padding; circuit-routed descriptor lookups; encrypted/blinded service descriptors; introduction rate limits; browser circuit status panel; fuzzing; external security review before any public deployment.

## Distributed Testnet Rules (v0.6)
Architecture and operator guide: `docs/DISTRIBUTED_NETWORK.md` (keep in sync with the code).
- No public deployment: relays, authorities, directories, and services must refuse public IP addresses; only loopback and private ranges (RFC 1918, 100.64/10, fc00::/7).
- Every MORP link is authenticated and encrypted (Noise, keys bound to relay identities). Never disable encryption or authentication, not even in tests.
- Relay discovery comes from signed, expiring consensus documents verified against pinned authority keys in `network.toml` (rollback refused); never trust an unsigned relay list on the network. `network.toml` is copied by hand, never downloaded.
- The authority admits only relays in `approved-relays.toml` (nickname bound to one identity and role); identity changes are refused. Clients/relays also pin nickname → identity per process.
- Relays bind to `listen` and publish `advertise`; `family` labels the machine. Paths prefer three distinct families.
- Two modes: local (`runtime/directory/` folder + HTTP `mask-directory`, one machine) and network (`--config relay.toml`, `--network network.toml`, `MASK_NETWORK`). Both must keep working.
- Authority and relay private keys: mode 0600, git-ignored, never committed. Testnet files for real machines live outside the repo (e.g. `~/morp-testnet/`).
- Testing: `tests/testnet.rs` (in-process testnet), `tests/processes.rs` (real binaries), `scripts/netns-testnet.sh` / `tests/netns.rs --ignored` (network namespaces, no root).

## Project Documentation

- Keep CLAUDE.md accurate as the project evolves.
- Update it when major architectural decisions change.
- Record completed milestones and upcoming goals.
- Preserve important development and security rules.
- Do not overwrite existing instructions without reason.
- Keep detailed progress notes in docs/PROGRESS.md.

## Development Rules
1. Write the project in Rust, not Python.
2. Build one feature at a time.
3. Start with a working localhost prototype.
4. Prefer well-maintained libraries.
5. Write automated tests.
6. Use `cargo fmt`, `cargo check`, and `cargo test`.
7. Explain installation and terminal commands clearly.
8. Preserve existing project files and Git history.
9. Never commit passwords, tokens, or private keys.
10. Do not claim real anonymity until the implementation has been independently evaluated.

## Development Goal
Build MASK into a functional experimental network and browser with its own onion-style hidden services.

Prioritize reliability, understandable architecture, and security testing over adding features quickly.
