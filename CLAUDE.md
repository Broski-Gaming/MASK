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
- Since v0.7 the entry is always one of the component's persistent **entry guards** (`guards.rs`: 2 primary, ≤ 5 sampled, 30-60 days, 0600 files per network and component: `client-`, `browser-`, `service-guards-<net>.json`), never related (same family or operator) to the last hop; middles avoid both ends' family, operator, and /16. Failures never cause new guards to be sampled: with all usable guards failing, the one that failed longest ago is retried (circuit fails if still down); no usable guard at all → `NetError::NoGuard`; guards unlisted for 7 days are dropped.
- Handshake: ntor-style (adapted from Tor) with X25519 + HKDF-SHA256 + HMAC-SHA256, authenticated against the Ed25519 identity and X25519 onion key in a signed relay descriptor.
- Layers: ChaCha20-Poly1305 per hop and direction; nonces are implicit 64-bit counters (never sent), giving replay/reorder detection. Any failure destroys the circuit. `CellCipher` is locked to seal *or* open by first use and refuses everything after one failed open (v0.7); clients destroy circuits on any bad or out-of-place cell or a command from the wrong hop.
- Relay identity keys live in `runtime/relays/<name>/identity.key` (mode 0600, git-ignored); descriptors in `runtime/directory/`. Never commit anything under `runtime/`.
- Network scope (`scope.rs`): `loopback` (default, local mode) or `private` (network mode). Public, unspecified (`0.0.0.0`), link-local, and multicast addresses are refused everywhere; never add a public scope.
- Consensus format 2 (v0.7): entries carry the authority-assigned `operator` and `listed_since`; clients reject shared identities/nicknames/addresses/keys, lifetimes > 24 h, listings in the future; `network.toml [relay_policy]` (`max_relays_per_ip`, `guard_min_listed_secs`). Directory protocol version 2.
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

Components: `mask-service` (create/list/show/check/host/stop/verify/fetch; `--network` for the testnet; `--state-dir` for guards), `mask-directory` (Axum, 127.0.0.1:7200, local mode), `mask-authority` (network mode: also stores service descriptors, over Noise), `crates/mask-net/src/hs/` (hidden services), `src/morp.rs` (browser handler, `MorpHandler` with isolation contexts). In local mode the relay directory (`runtime/directory/`, files) and the service directory (HTTP) are separate.

## Hidden Services (v0.5)
Spec and threat model: `docs/MORP_HIDDEN_SERVICES.md`.
- Relay role `rendezvous` (last hop after a middle) acts as introduction point and rendezvous point. Exits are never used for `.morp`.
- Service: per-run intro auth (Ed25519) + intro encryption (X25519) keys per intro point; the identity key never leaves the host. Introductions are encrypted to the service; replays rejected.
- Client: random rendezvous relay + single-use 32-byte cookie; service builds its own circuit to it; rendezvous joins the circuits; service signs the handshake with its identity key; end-to-end ChaCha20-Poly1305 session with counter nonces, multiplexed requests.
- Testing rules: prove routing with the `ConnectPolicy` (deny-by-default, records every outbound connection), the relay `Observer` (every plaintext a relay decrypts), and relay/host counters, not log messages. Every outbound socket in mask-net goes through a `ConnectPolicy` check (since v0.7 also the local directory client).
- Hidden-service hardening (v0.7): per-intro-point replay caches, rotated at `max_introductions_per_intro`; introduction rate limits at relays and services; capped rendezvous builds; `IsolationContext` keeps browser identities apart. Hostile-relay tests live in `crates/mask-net/tests/hostile.rs`; every security fix needs a regression test that fails without it.

## Milestones
- [x] v0.1 — Browser window: dark GTK UI, address bar, HTTPS browsing, ephemeral session.
- [x] v0.2 — Relay network foundation: entry/middle/exit relays on 127.0.0.1, framed structured messages, plaintext onion layers, error propagation, logging, tests.
- [x] v0.3 — MORP v1: Ed25519 relay identities, signed descriptors, ntor-style handshakes, layered ChaCha20-Poly1305 with replay protection, circuit IDs, encrypted replies, tests. Unreviewed.
- [x] v0.4 — Cryptographic `.morp` addresses: Ed25519 service identities, signed expiring descriptors, localhost directory, authenticated encrypted service channel, static site hosting, `morp://` in MASK Browser with no DNS/clearnet fallback. Direct localhost prototype (location not hidden). Unreviewed.
- [x] v0.5 — Relay-routed `.morp` hidden services: rendezvous-role relays, introduction points, rendezvous joins, encrypted introductions, service authentication, end-to-end encrypted multiplexed sessions, descriptor v2 (no location), browser loads full sites via MORP, no-bypass/auth/failure/cleanup tests. Direct v0.4 path removed. Unreviewed, localhost only.
- [x] v0.5 verified (2026-11-01): addresses, relay-only routing, separate joined circuits, no direct connections, safe failure with disconnected and malicious (tampering/black-holing) relays; 141 tests. Report in `docs/PROGRESS.md`.
- [x] v0.6 (2026-11-02) — Distributed MORP testnet: private network scope, Noise-authenticated links, `mask-authority` (allowlist, identity-change refusal, health probes, signed expiring consensus, `.morp` directory), TOML configs (`deploy/`), keepalives, link limits, graceful shutdown, family-aware paths with retries, intro-point re-establishment, browser network mode (`MASK_NETWORK`). Verified with multiple processes and Linux network namespaces (`scripts/netns-testnet.sh`); 194 tests. Docs: `docs/DISTRIBUTED_NETWORK.md`. Unreviewed.
- [x] v0.7 (2026-11-05) — Security hardening: circuit/cipher hardening, rate limits and quotas, per-intro-point replay caches, Sybil/copycat/family defences, consensus format 2, persistent entry guards, diversity-aware paths, isolation contexts, browser leak prevention (content rules, navigation policy, network gate, MORP-only mode) and fingerprinting protections, safe logging; hostile-relay tests, netns packet captures, live browser leak test. Threat model `docs/THREAT_MODEL.md`, mechanisms `docs/SECURITY_MODEL.md`. Report in `docs/PROGRESS.md`. Unreviewed.
- [ ] v0.6/v0.7 LAN trial on separate physical machines (procedure in `docs/DISTRIBUTED_NETWORK.md` §4–§5), recorded in `docs/PROGRESS.md`. Planned as a two-machine trial: the PC plus the Chromebook (see "Testnet Hardware"). v0.7 is not wire-compatible with v0.6: upgrade both machines.
- [ ] Later: multiple authorities with threshold signatures; fixed-size cells and padding; circuit-routed descriptor lookups; encrypted/blinded service descriptors; screen/window-size and font fingerprinting defences; browser circuit status panel; coverage-guided fuzzing; external security review before any public deployment.

## Distributed Testnet Rules (v0.6)
Architecture and operator guide: `docs/DISTRIBUTED_NETWORK.md` (keep in sync with the code).
- No public deployment: relays, authorities, directories, and services must refuse public IP addresses; only loopback and private ranges (RFC 1918, 100.64/10, fc00::/7).
- Every MORP link is authenticated and encrypted (Noise, keys bound to relay identities). Never disable encryption or authentication, not even in tests.
- Relay discovery comes from signed, expiring consensus documents verified against pinned authority keys in `network.toml` (rollback refused); never trust an unsigned relay list on the network. `network.toml` is copied by hand, never downloaded.
- The authority admits only relays in `approved-relays.toml` (nickname bound to one identity and role); identity changes are refused. Clients/relays also pin nickname → identity per process.
- Relays bind to `listen` and publish `advertise`; `family` labels the machine. Paths prefer three distinct families.
- Two modes: local (`runtime/directory/` folder + HTTP `mask-directory`, one machine) and network (`--config relay.toml`, `--network network.toml`, `MASK_NETWORK`). Both must keep working.
- Authority and relay private keys: mode 0600, git-ignored, never committed. Testnet files for real machines live outside the repo (e.g. `~/morp-testnet/`).
- Testing: `tests/testnet.rs` (in-process testnet), `tests/processes.rs` (real binaries), `scripts/netns-testnet.sh` / `tests/netns.rs --ignored` (network namespaces + packet capture, no root).
- The allowlist binds each relay's `family` (required) and optional `operator`; never let a relay choose its own family. The authority refuses relays reusing another identity's address/link key/onion key and more than `max_relays_per_ip` per IP.

## Browser and Leak-Prevention Rules (v0.7)
Policy in `src/privacy.rs` (unit-tested), applied in `src/browser/`. Threat model `docs/THREAT_MODEL.md`; mechanisms and fingerprinting audit `docs/SECURITY_MODEL.md`.
- Never remove or weaken the WebKit content rules, the navigation policy, or the **network gate** (`browser/gate.rs`: while a `.morp` page is shown, all WebKit networking goes to a local black hole, because WebKit pre-connects to clicked links before the navigation policy runs). The browser must refuse to start if the rules cannot be installed.
- A `.morp` page may never cause a clearnet connection or navigation; only the user may open a website (typed). No `morp:` loads from clearnet pages; no `http(s)` with `.morp` hosts anywhere.
- Never log `.morp` addresses the browser visits, page content, request paths, or (at the default level) client IPs at relays. Sanitize remote-supplied text (`protocol::sanitize_remote_text`).
- Re-run `scripts/browser-leak-test.sh` after any WebKitGTK/wry upgrade or browser change; it must pass (DNS canary positive control, empty-capture check).
- Settings are applied by WebKit property name from `privacy::SETTINGS` and read back; deprecated no-op settings are skipped, never relied on.
- Do not claim fingerprinting resistance beyond what `docs/SECURITY_MODEL.md` §9 lists (screen size, cores, fonts, canvas are not protected).

## Testnet Hardware
- **Machine A — main PC** (Arch Linux, KDE Plasma, NVIDIA GPU). Runs everything today. Multi-machine testing on it uses Linux network namespaces (`scripts/netns-testnet.sh`).
- **Machine B — Acer Chromebook 311 (C733), planned.** Not set up yet. Plan: confirm the board name with `crossystem hwid` (believed to be BOBBA, Gemini Lake "Octopus"; verify on mrchromebox.tech), flash MrChromebox UEFI Full ROM (save the stock firmware backup), install EndeavourOS with Xfce. Expected: Celeron N4000/N4020, ~4 GB RAM, ~32 GB eMMC; audio may need the chromebook-linux-audio script (irrelevant for relays).
- Role of machine B: middle + rendezvous relays (headless is fine), family `machine-b`. Machine A keeps the authority, entry relay, hidden service, and MASK Browser.
- Do not build on the Chromebook: build `cargo build --release -p mask-net` on the PC and copy `mask-relay`, `mask-authority`, `mask-service` (both x86_64, Arch-based). The Chromebook needs no Rust or WebKit.
- Keep machine B plugged in with sleep disabled; clocks must agree within 5 minutes (chrony / timesyncd).

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
