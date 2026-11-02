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
- Private `.mask` addresses
- Cryptographically generated service identities
- Hidden websites hosted by MASK users
- Introduction points and rendezvous circuits

## Browser Features
- Custom dark interface
- Tabs and address bar
- Normal HTTPS website browsing
- `.mask` website browsing
- Network connection status
- Relay and circuit information
- Privacy settings

## Architecture
Cargo workspace with two crates:
- `mask` (repo root, `src/`): the browser. Binary `mask-browser`. GTK3 toolbar is native GTK (not HTML) so web content cannot script browser controls; Wry embeds the WebKitGTK view.
- `mask-net` (`crates/mask-net/`): the relay network. No GUI dependencies so relays can run headless. Binaries `mask-relay` and `mask-client`.

Network protocol: **MORP** (MASK Onion Routing Protocol). Full spec, threat model, and limitations in `docs/MORP.md` — keep it in sync with the code.
- Link level: `LinkMsg` (postcard) in u32 length-prefixed frames, max 64 KiB. `Hello`/`Welcome` link handshake checks version and role order client → entry → middle → exit. Many circuits per link via random per-link `u32` circuit IDs.
- Circuits are telescoping (Tor-style): CREATE to entry, then EXTEND through each hop.
- Handshake: ntor-style (adapted from Tor) with X25519 + HKDF-SHA256 + HMAC-SHA256, authenticated against the Ed25519 identity and X25519 onion key in a signed relay descriptor.
- Layers: ChaCha20-Poly1305 per hop and direction; nonces are implicit 64-bit counters (never sent), giving replay/reorder detection. Any failure destroys the circuit.
- Relay identity keys live in `runtime/relays/<name>/identity.key` (mode 0600, git-ignored); descriptors in `runtime/directory/`. Never commit anything under `runtime/`.
- Relays only bind to and extend to loopback addresses until the network is ready to leave localhost.
- Crypto rule: use established primitives from RustCrypto/dalek only; never invent cryptographic algorithms.

## Milestones
- [x] v0.1 — Browser window: dark GTK UI, address bar, HTTPS browsing, ephemeral session.
- [x] v0.2 — Relay network foundation: entry/middle/exit relays on 127.0.0.1, framed structured messages, plaintext onion layers, error propagation, logging, tests.
- [x] v0.3 — MORP v1: Ed25519 relay identities, signed descriptors, ntor-style handshakes, layered ChaCha20-Poly1305 with replay protection, circuit IDs, encrypted replies, tests. Unreviewed.
- [ ] Next candidates: TLS/Noise-encrypted links and fixed-size cells; SOCKS5 proxy and real exit streams; connecting the browser to the network.
- [ ] Later: `.mask` hidden services (introduction points, rendezvous circuits).

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
