# MASK Security Model (v0.7)

> **Experimental and unreviewed. Not Tor-level anonymity.** This document
> describes the mechanisms MASK uses and how each one is tested. Who they
> defend against, and what remains open, is in
> [`THREAT_MODEL.md`](THREAT_MODEL.md).

## 1. Layers

```text
 MASK Browser ──────────────────────────────────────────────────────────────┐
  content rules · navigation policy · network gate · settings · isolation    │
                                                                            ▼
 mask-net client ── guards · path rules · consensus checks · fail closed ── MORP
   │  Noise NK link (pinned/signed link key)                                 │
   ▼                                                                         │
 entry ──Noise IK── middle ──Noise IK── rendezvous ◀── joined ──▶ rendezvous ◀── service
   per-hop ChaCha20-Poly1305 layers (ntor keys)          end-to-end session (service-signed)
```

Every layer fails closed: on any error the connection, circuit, or page
load stops; nothing falls back to a direct or less protected path.

## 2. Cryptography

Only established primitives from RustCrypto/dalek and `snow`; MASK
composes them but invents none.

| Use | Construction |
|---|---|
| Links | Noise `NK` (client → entry, probes, directory) and `IK` (relay → relay), `25519_ChaChaPoly_SHA256`; per-run link keys signed into relay descriptors |
| Circuit hops | ntor-style handshake (X25519, HKDF-SHA256, HMAC-SHA256) against the relay's identity and onion key |
| Onion layers | ChaCha20-Poly1305 per hop and direction; 96-bit nonce = direction ‖ 64-bit counter, never sent |
| Hidden services | per-intro Ed25519 auth keys and X25519 encryption keys; introductions encrypted to the service; service signs the rendezvous handshake with its identity key; end-to-end ChaCha20-Poly1305 session |
| Addresses | Ed25519 public key + SHA3-256 checksum, Base32 |
| Signatures | Ed25519 `verify_strict` (relay descriptors, consensus, service descriptors) |

**Nonce discipline (v0.7).** A `CellCipher` is locked to one job (seal or
open) by its first use, so no (key, nonce) pair can be used for two
messages even by a programming error. After one failed open it refuses all
further cells (the counters can no longer be trusted). Counter exhaustion is
an error, never a wrap. Each key is used in one direction only, and the
direction is also in the nonce and the associated data.

**Keys at rest.** Relay identity keys, service keys, and authority keys are
32-byte files with mode 0600 in 0700 folders; MASK refuses key files that
others can read. They are not encrypted at rest.

## 3. Identities and trust

- **Relays.** Ed25519 identity per relay; descriptors sign nickname, role,
  address, family, onion key, link key, and time.
- **Allowlist** (`approved-relays.toml`, network mode): nickname → identity,
  role, **family**, optional **operator** (v0.7). The authority refuses
  identity changes, other roles, other families, addresses or keys already
  used by another identity, and more than `max_relays_per_ip` relays per IP.
- **Consensus format 2** (v0.7): the authority signs each relay's descriptor
  together with its operator and the time it was first listed (kept across
  restarts in `listing-history.json`). Clients accept a consensus only if a
  pinned authority signed it, for their network, not expired, not valid for
  more than 24 h, newer than the last one, with valid descriptors, no shared
  identity/nickname/address/onion key/link key, and no listing time in the
  future. They then drop relays beyond the per-IP limit and pin
  nickname → identity for the process.
- **Local mode**: the descriptor folder is trusted completely (whoever can
  write to it chooses the relays); relays sharing an address or key with
  another identity are dropped.

## 4. Entry guards and paths

Implemented in `crates/mask-net/src/guards.rs` and `client.rs`.

- Up to **5** sampled guards per component, the first **2** usable ones
  primary; each kept **30-60 days**; a failed guard is skipped for
  **10 minutes**.
- New guards prefer entry relays listed for at least
  `guard_min_listed_secs` (default **1 h**), then relays in a family,
  operator, and /16 not already among the guards.
- **Fail closed**: with every sampled guard down, no new guard is sampled;
  a circuit whose last hop is related (same family or operator) to every
  usable guard is refused (`NetError::NoGuard`).
- Path = guard → middle → last. The guard is never related to the last hop.
  Middles are chosen in tiers: unrelated to both ends and on another /16;
  unrelated; healthy; any.
- Last hops chosen by MASK (rendezvous points, intro points) avoid the
  guard's family and operator.
- Guard files: `runtime/state/client-guards-<net>.json` (CLI,
  `--state-dir`), `<MASK_STATE_DIR>/browser-guards-<net>.json` (browser),
  `runtime/services/<id>/service-guards-<net>.json` (each service). Mode
  0600. Components never share guards.

## 5. Circuit handling

- Any undecryptable or undecodable cell, message out of protocol order,
  relay-only command from a client, cell before `CREATED`, or command from
  the wrong hop **destroys the circuit**, with a `Destroy` reason sent to the
  neighbours. The client side refuses every later call on a dead circuit.
- Only `Error` commands (authenticated by the reporting hop's own layer)
  and timeouts leave a circuit usable.
- Circuit IDs are random per link and stay reserved until the circuit object
  is gone.
- A circuit whose receive queue stays full for 2 s is destroyed instead of
  blocking every other circuit of its link.
- Remote-supplied text (`LinkError`, `RelayCmd::Error`, directory answers)
  is stripped of control and bidi characters and capped at 300 characters.
- Logs name message variants only, never message contents.

## 6. Hidden services

- Intro points: fresh auth and encryption keys per intro point per run;
  `EstablishIntro` signatures are bound to the intro relay.
- **Replay protection** (v0.7): each intro point keeps the client ephemeral
  keys it accepted; after `max_introductions_per_intro` (16 384) it is
  retired and replaced with fresh keys (and the descriptor republished).
  Introductions are decrypted and checked one at a time per intro point.
- Rendezvous cookies are random, single use, and expire after 60 s.
- Sessions: 64 requests in flight, 16 MiB per response, 64 MiB announced
  per session, 8 KiB request paths.
- The service never accepts inbound MORP connections; its only listener is
  the local application on 127.0.0.1.
- Isolation contexts (v0.7): `MorpClient` sessions are keyed by
  (context, address); contexts never share sessions, circuits, rendezvous
  points, cookies, or links.

## 7. Resource limits (defaults)

| Where | Limit | Default | Configure |
|---|---|---|---|
| Relay | links total / per IP | 2048 / 256 | `relay.toml [limits]` |
| Relay | circuits per link / total | 128 / 4096 | `relay.toml [limits]` |
| Relay (entry) | CREATEs per client IP | 16/s, burst 256 | `create_rate_per_ip`, `create_burst_per_ip` |
| Relay (rendezvous) | `Introduce1` per intro point | 8/s, burst 64 | `intro_rate`, `intro_burst` |
| Relay (rendezvous) | intro points / pending rendezvous | 256 / 1024 | code (`Limits`) |
| Relay | IPs tracked by the rate limiter | 8192 (refuses when full of active IPs) | code |
| Links | frame / data per cell / intro payload | 65 519 B / 60 KiB / 4 KiB | protocol |
| Links | connect / handshake / response / idle / keepalive | 5 / 10 / 30 / 300 / 30 s | `Timeouts` |
| Client | receive queue per circuit; stall limit | 64 messages; 2 s | code |
| Client | connect / rendezvous / request | 45 / 20 / 30 s | `ClientConfig` |
| Client | cached sessions | 32 | code |
| Session | in flight / body / buffered / path | 64 / 16 MiB / 64 MiB / 8 KiB | code |
| Service | sessions / pending rendezvous | 64 / 16 | `HostConfig` |
| Service | introductions processed | 10/s, burst 64 | `HostConfig::introduction_rate` |
| Service | introductions per intro point | 16 384, then rotate | `HostConfig` |
| Authority | connections total / per IP | 256 / 32 | `AuthorityConfig` |
| Authority | requests per connection; relays in a consensus | 64; 200 | code |
| Authority | relays per IP | 2 (private), unlimited (loopback) | `network.toml [relay_policy]` |
| Consensus | lifetime | ≤ 24 h | `authority.toml` (checked by clients) |
| Directory client | answer size | 64 KiB | code |
| Browser | concurrent `morp://` requests | 64 | code |

## 8. Failure handling (fail-closed rules)

- No consensus, an expired consensus, or no trusted relay → no circuit.
- No usable guard → no circuit (no other entry relay is tried).
- Introduction or rendezvous failure → error page; never a direct connection.
- A service that cannot prove its address → error page.
- Content rules not installable, or a security setting WebKit does not
  accept → the browser refuses to start.
- Blocked navigation, new window, or download → refused, with a notice.

Tested by `blocked_morp_connections_fail_closed`,
`when_its_guards_are_down_a_client_fails_closed`,
`client_without_a_consensus_reaches_nothing`, `directory_down_fails_closed`,
`relay_failure_shows_an_error_not_a_fallback`, and the netns script
(black-holed entry routes).

## 9. Browser

<a id="browser"></a>Implemented in `src/privacy.rs` (policy, unit-tested)
and `src/browser/` (applied to WebKit).

**Content rules** (WebKit content blockers, compiled at startup):

| Page | May load |
|---|---|
| `.morp` page | `morp:` of any kind is passed to the handler; plus `data:`, `blob:`, `about:`; nothing else |
| clearnet page | anything except `morp:` |
| any page | never `http(s)://…​.morp` or `ws(s)://…​.morp` (DNS leak) |
| MORP-only mode | no `http(s)`/`ws(s)` at all |

Within `.morp` pages the CSP (`'self'`) additionally keeps each page to its
own service, so a session only ever carries one first party.

**Navigation policy** (every navigation, including frames): `morp:` and
`about:blank` allowed; `http(s)` to a `.morp` host refused; from a `.morp`
page, a website only if the user started it (typed address, toolbar
back/forward/reload); other schemes refused; new windows and downloads
refused. Typed addresses are checked before WebKit sees them (WebKit
pre-connects as soon as a load starts).

**Network gate.** While a `.morp` page is shown (always, in MORP-only mode)
WebKit's proxy is a black hole the browser owns on 127.0.0.1: every
`http(s)`/`ws(s)` connection, including speculative ones, ends there and no
hostname is resolved. Opened only for a website navigation the user starts.

**Response headers on `.morp` pages**: CSP (`default-src 'self'`, no
`object`, `connect-src 'self'`, `webrtc 'block'`), Permissions-Policy (all
powerful features off), `X-DNS-Prefetch-Control: off`, CORP/COOP
`same-origin`, `no-store`, `no-referrer`, `nosniff`. The status and content
type from the service are validated.

**Fingerprinting audit** (what a page can read; measured with
`tests/browser_leaks.rs` on WebKitGTK 2.54):

| Surface | MASK v0.7 | Status |
|---|---|---|
| User agent | fixed string (WebKit 605.1.15, Version/18.0, X11 Linux x86_64) | normalised (but identifies MASK users) |
| Language (`Accept-Language`, `navigator.language`) | `en-US` | normalised |
| Time zone | `UTC` (`TZ` forced; `MASK_KEEP_TIMEZONE=1` opts out) | normalised |
| WebRTC (local/public IP via ICE) | `RTCPeerConnection` undefined | removed |
| Media devices, camera, microphone | absent; permission requests denied | removed |
| WebGL (GPU, driver) | off | removed |
| WebAudio | off | removed |
| Encrypted media, plugins | off / none | removed |
| Storage, cookies, cache | ephemeral session; no third-party cookies; ITP on; New identity clears all | limited |
| Geolocation, notifications, clipboard | denied / no script access | removed |
| Screen size | real screen (e.g. 2560×1440) | **not protected** |
| Window size | default 1200×800, user-resizable | **not protected** (no letterboxing) |
| CPU cores (`hardwareConcurrency`) | real value (8 on the test machine) | **not protected** |
| Fonts, canvas, text rendering, emoji | system | **not protected** |
| CSS media features (dark mode, reduced motion, …) | system | **not protected** |
| GTK theme, scrollbars, WebKitGTK version quirks | system | **not protected** |
| `performance.now()` precision | WebKit default | WebKit's own reduction only |
| TLS / HTTP stack (clearnet) | libsoup / GnuTLS | not normalised (clearnet is direct anyway) |

**Isolation.** Each browser identity is one isolation context; "New
identity" makes a fresh one (new circuits and rendezvous points for every
service) and clears all website data. The browser keeps its own entry guards.

## 10. Logging and local files

Never logged by any component: page content, request paths, cookies,
private keys, passwords (MASK has none), the `.morp` addresses the browser
visits (v0.7), message payloads (v0.7: variant names only), or client
addresses at an entry relay at the default level (v0.7: debug only; abuse
refusals still name the address). Remote error text is sanitised before it
is logged or printed.

Logged: relay nicknames, roles, circuit IDs, counts, relay (not client)
addresses, consensus sequences, sanitised errors. `mask-service host`
prints its own address; `fetch`/`verify` print what the user asked for.

Private files: key files (0600), guard files (0600, they reveal the entry
relays a user uses), `listing-history.json` (authority, not secret).
Everything under `runtime/` is git-ignored and must never be committed.

## 11. How it is verified

| What | Where |
|---|---|
| Unit tests: ciphers, handshake, descriptors, consensus checks, guards, paths, rate limits, decoders on random and mutated input, content rules (evaluated with a regex engine), navigation policy | `cargo test --workspace` |
| Scripted hostile relays (hostile entry, hostile next hop), flooding, rate limits | `crates/mask-net/tests/hostile.rs` |
| Tampering and black-holing relays in front of rendezvous points | `tests/malicious_relays.rs` |
| Hidden-service attacks: replays, tampering, lying directory, cookie reuse, intro rotation, rate limits, isolation | `tests/hidden_services.rs` |
| Testnet with an authority: Sybil/copycat/family/per-IP admission, guards, fail closed | `tests/testnet.rs` |
| Separate processes from real config files | `tests/processes.rs` |
| Network namespaces + packet capture: no DNS, no cli↔svc packet, guards only, no plaintext, no client IPs in relay logs, blocked routes fail closed | `scripts/netns-testnet.sh` (`cargo test --test netns -- --ignored`) |
| Real browser vs hostile pages, HTTP/STUN/DNS canaries, namespace with DNS canary as the only resolver, packet capture | `scripts/browser-leak-test.sh` (`tests/browser_leaks.rs`) |

Regression tests for v0.7 fixes were each checked to fail with the fix
removed (mutation checks, recorded in `docs/PROGRESS.md`).

## 12. Known gaps

See [`THREAT_MODEL.md` §4-§5](THREAT_MODEL.md#4-threats-mitigations-and-evidence):
no padding or cover traffic; one authority without threshold signatures;
descriptor lookups seen by the authority; one operator; fingerprinting
surfaces listed above; no coverage-guided fuzzing; no independent review.
