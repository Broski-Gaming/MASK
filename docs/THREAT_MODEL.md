# MASK Threat Model (v0.7)

> **Status: experimental, unreviewed, not anonymous in any strong sense.**
> MASK runs on one machine or a small private LAN, all relays are run by one
> operator, and nothing here has been independently reviewed, formally
> analysed, or fuzzed with coverage guidance. Do not use MASK where your
> safety depends on anonymity. MASK does **not** provide Tor-level
> anonymity, and it does **not** resist global traffic analysis.

This document says *who* MASK tries to defend against, *what* it protects,
and — just as important — what it cannot. The mechanisms are described in
[`SECURITY_MODEL.md`](SECURITY_MODEL.md); protocol details are in
[`MORP.md`](MORP.md), [`MORP_HIDDEN_SERVICES.md`](MORP_HIDDEN_SERVICES.md),
[`MORP_ADDRESSES.md`](MORP_ADDRESSES.md), and
[`DISTRIBUTED_NETWORK.md`](DISTRIBUTED_NETWORK.md).

## 1. System and deployment assumptions

- Components: MASK Browser (WebKitGTK), `mask-net` clients (`mask-service
  fetch/verify`), relays (entry, middle, rendezvous, test-only exit),
  directory authority (network mode) or local directory (local mode),
  hidden-service hosts with a loopback web application.
- Network: loopback (local mode) or private address ranges (RFC 1918,
  100.64/10, fc00::/7). Public addresses are refused everywhere.
- Scale: a handful to a few dozen relays, **one operator**, one authority.
- Trust anchor: `network.toml`, copied by hand to every machine (pinned
  authority keys). `approved-relays.toml` is the authority operator's list.
- The user's own machine (kernel, user account, WebKitGTK, GTK, glibc) is
  trusted. MASK cannot protect against malware running as the user.

## 2. Assets

| Asset | Why it matters |
|---|---|
| **Who visits which `.morp` service** (client IP ↔ service) | the core anonymity property |
| **Where a service runs** (host IP) | service location hiding |
| Page content, request paths, `.morp` addresses in transit | confidentiality |
| Service authenticity (the address owner answers) | no impersonation |
| Unlinkability of the user's clearnet activity and `.morp` activity, and of separate browser identities | cross-context tracking |
| Keys: service identity keys, relay identity keys, authority keys | impersonation if stolen |
| Guard files, logs | reveal which relays/services a user uses |
| Availability of relays, authority, services | denial of service |

## 3. Adversaries

| # | Adversary | Capabilities | In scope? |
|---|---|---|---|
| A1 | Passive observer on one LAN segment | sees packets, sizes, timing | yes |
| A2 | Active attacker on the LAN | drops, delays, injects, MITMs TCP | yes |
| A3 | One malicious or compromised relay | arbitrary relay behaviour with a valid identity | yes |
| A4 | Coordinated relays / Sybil | several approved identities run by one party | yes (limited) |
| A5 | Hostile or compromised directory authority | signs any consensus, sees lookups, answers lies | partly |
| A6 | Malicious hidden service | attacks its clients (content, protocol) | yes |
| A7 | Malicious web content (`.morp` or clearnet page) | JavaScript, HTML, CSS, redirects | yes |
| A8 | Malicious client | floods relays and services, replays | yes |
| A9 | Global passive adversary | sees every link | **no** |
| A10 | Local attacker on the user's machine | reads files, ptrace, screen | **no** (file modes only) |

## 4. Threats, mitigations, and evidence

Each entry: the threat, what v0.7 does, how it is tested, and the residual
risk. "Test:" names refer to tests in the repository.

### 4.1 Traffic correlation

**Threat.** An adversary who watches (or runs) both the client's entry
relay and the service-side end of a circuit can match timing and volume and
link client to service. A1/A2 on the client's and the service's LAN
segments, or A3/A4 at entry and rendezvous.

**Mitigations.**
- Three-hop circuits on each side; the client and the service build
  separate circuits that meet at a rendezvous point.
- **Entry guards** (v0.7): each client keeps 2 primary guards for 30-60
  days instead of a random entry per circuit, so a hostile entry relay sees a
  given client either never or for a long time, instead of eventually.
- **No related ends** (v0.7): a circuit's guard and its last hop are never in
  the same family (machine) or operator; middles avoid the family, operator,
  and /16 network of both ends when possible.
- All links are Noise-encrypted: A1 sees only frame sizes and timing.

**Evidence.** Test: `a_client_reaches_only_its_entry_guard`,
`paths_avoid_a_shared_operator_across_families`,
`middles_avoid_the_family_operator_and_network_of_both_ends`; netns packet
capture: cli connects only to its guards.

**Residual risk — not solved.**
- **No padding, no cover traffic, variable cell sizes.** Timing and volume
  correlation works against MASK. Website fingerprinting (recognising a page
  by its traffic pattern) is likely easy.
- **One operator runs everything.** Families and operators help only if
  they are genuinely different parties; on today's testnet they are not.
- A small network means a small anonymity set: with a few clients, even a
  weak correlation identifies the user.
- **Global adversaries (A9) are out of scope.** No claim of protection
  against global traffic analysis is made; there is no evidence for one.

### 4.2 Compromised relays (A3)

**Threat.** A relay with a valid identity misbehaves: reads what it can,
tampers, replays, drops, delays, lies in errors, floods its neighbours, or
tries to trick clients into revealing more.

**Mitigations.**
- Per-hop ChaCha20-Poly1305 with implicit counters: tampering, replay,
  reordering, and dropping are detected; any failure destroys the circuit.
  v0.7: the cipher refuses all further use after one failure, and a cipher is
  locked to one direction (no nonce reuse even by programming error).
- v0.7: the client destroys a circuit on *any* undecryptable or undecodable
  cell, unexpected message, or command from the wrong hop (a middle cannot
  answer for the last hop). Relays destroy circuits whose next hop sends
  cells before `CREATED`.
- End-to-end encryption between client and service: no relay (not even the
  rendezvous point) sees content or requests. Test: relay `Observer`.
- Remote error text is stripped of control and bidi characters (no terminal
  escape or log injection) and capped.
- One stuck or flooded circuit cannot stall the other circuits of a link
  (bounded wait, then the circuit is destroyed).

**Evidence.** `tests/hostile.rs` (scripted hostile entry and next hop),
`tests/malicious_relays.rs` (tampering and black-holing proxies),
`relays_cannot_read_page_content_or_requests`, cipher unit tests. Each v0.7
fix has a regression test that fails without it.

**Residual risk.** A relay sees its neighbours' addresses, circuit timing,
and volume. An entry learns the client's IP; a rendezvous point learns that
some client and some service are talking. A relay can always drop traffic
(denial of service). Selective denial of service — killing circuits it
cannot correlate so that clients rebuild through relays it controls — is
limited by guards and by "never sample new guards while all are down", but
not eliminated.

### 4.3 Sybil attacks and coordinated identities (A4)

**Threat.** One party runs many relay identities (or makes one machine look
like several) to be on both ends of more circuits.

**Mitigations.**
- Admission is by allowlist: the authority operator approves every relay
  identity by hand (`approved-relays.toml`).
- v0.7: the allowlist **binds each relay's family** (machine) and an
  optional **operator**. A relay declaring another family is refused, so one
  machine cannot pose as several.
- v0.7: the authority refuses a relay that reuses another identity's
  address, link key, or onion key (previously a copycat could borrow a real
  relay's address and link key and be listed, because the real relay
  answered the health probes), and admits at most `max_relays_per_ip`
  relays per IP address (default 2 on private networks).
- v0.7: clients reject a consensus containing shared identities, nicknames,
  addresses, onion keys, or link keys, and cap relays per IP themselves.
- v0.7: guards are chosen preferring relays the authority has listed for at
  least `guard_min_listed_secs` (default 1 h), so a burst of new entry
  relays is not picked; existing guards are kept for weeks regardless of
  new relays.

**Evidence.** Test: `relay_borrowing_another_relays_address_and_link_key_is_never_listed`
(fails without the fix), `approved_relay_claiming_a_machine_of_its_own_is_refused`,
`the_authority_admits_at_most_two_relays_per_address`,
`hostile_consensus_contents_are_rejected`,
`new_guards_prefer_established_and_diverse_entries`.

**Residual risk.** The defences rely on the operator labelling families
and operators honestly; MASK cannot discover that two "different" operators
are the same party. Per-IP limits are weak against an attacker with many
addresses. Listing age is a weak signal on a young network.

### 4.4 Hostile directory information (A5)

**Threat.** The directory lies: forged or stale relay lists, rollback to an
old consensus, a consensus listing only the attacker's relays, different
answers for different clients (partitioning), lies about services, or simply
watching which `.morp` addresses clients look up.

**Mitigations.**
- Consensus documents are signed by an authority key pinned in
  `network.toml`; every relay descriptor inside is self-signed; sequence
  numbers refuse rollback; expired consensuses are not used.
- v0.7: a consensus valid for more than 24 h, with relays "listed in the
  future", or with shared keys/addresses is rejected entirely.
- v0.7: guards limit the damage of a hostile consensus: existing guards are
  kept while they stay listed, and new ones are sampled at most up to 5.
- Service descriptors are signed by the service key inside the address and
  verified by the client; a lying directory can hide a service but not
  impersonate it. Lookups travel over Noise links to a pinned authority.

**Evidence.** `consensus_from_an_impostor_authority_is_rejected`,
`forged_descriptor_from_a_lying_directory_is_rejected`,
`consensus_source_is_empty_until_installed_and_refuses_rollback`,
`hostile_consensus_contents_are_rejected`.

**Residual risk — not solved.** There is **one** authority and no threshold
signature: a compromised authority can list only relays it controls, show
different consensuses to different clients, and withhold any service. The
authority (or anyone who compromises it) sees which `.morp` addresses each
client IP looks up; lookups are not yet routed through circuits, and
descriptors are not encrypted or blinded. Fixing this needs multiple
independent authorities and circuit-routed, blinded descriptors.

### 4.5 Identity spoofing (A2, A3)

**Threat.** Impersonating a relay, an authority, or a service.

**Mitigations.** Relays: Noise IK/NK links with per-run link keys signed
into the descriptor; ntor handshake against the identity and onion key; an
inbound relay link must belong to a trusted relay with the right role;
nickname → identity pinning (allowlist and per process); identity changes
refused. Authorities: pinned identity and link keys. Services: the address
is the Ed25519 key; the service signs the rendezvous handshake.

**Evidence.** `impostor_at_entry_address_is_refused_at_the_link_layer`,
`right_link_key_but_wrong_identity_is_refused_by_ntor`,
`relay_identity_change_is_refused`, `impostor_service_cannot_complete_the_rendezvous`,
v0.7 copycat test.

**Residual risk.** Stolen keys (A10) defeat all of this; keys are protected
only by file permissions (0600/0700), not by encryption at rest.

### 4.6 Protocol abuse and denial of service (A8, A3, A6)

**Threat.** Flooding relays with CREATEs, services with introductions,
filling replay caches, exhausting memory, holding connections open.

**Mitigations (v0.7 additions in bold).** Link limits (total, per IP),
circuit limits (per link, total), handshake and idle timeouts, frame size
caps, **CREATE rate limit per client IP at entry relays**, **introduction
rate limit per intro point at relays**, **service-side introduction rate
limit and cap on concurrent rendezvous builds**, **per-intro-point replay
caches with rotation** (the old service-wide cache could be filled to make a
service refuse every introduction until restart), **session buffer quota**
(64 MiB), **authority per-IP connection limit**, **directory answer size
limit**, **browser cap on concurrent `morp://` requests**.

**Evidence.** `tests/hostile.rs` rate-limit and flooding tests,
`intro_point_rotates_to_fresh_keys_after_its_limit`,
`service_limits_how_fast_it_accepts_introductions`,
`hostile_service_cannot_make_the_client_buffer_without_limit`,
`authority_limits_connections_per_address`.

**Residual risk.** Rate limits trade availability for robustness: an
attacker who exceeds an intro point's budget also blocks honest clients for
a while. No proof-of-work or client puzzles. Limits are per process, not
coordinated across relays.

### 4.7 Browser leaks (A7)

**Threat.** A `.morp` page (or a clearnet page) makes the browser reveal
the user's real IP address, leak a `.morp` name to public DNS, or let one
site learn about the user's activity elsewhere: subresources, fetch,
WebSockets, beacons, `<a ping>`, prefetch, DNS prefetch, WebRTC/ICE,
redirects, navigations, new windows, external protocol handlers, downloads.

**Mitigations (v0.7).**
- WebKit content rules: `.morp` pages load only `morp:` (and inline
  `data:`/`blob:`); clearnet pages cannot load `morp:`; no page may load an
  `http(s)`/`ws(s)` URL whose host ends in `.morp`.
- Navigation policy: a `.morp` page cannot navigate to a website (only the
  user can, by typing); other schemes, new windows, downloads refused.
- **Network gate**: while a `.morp` page is shown (always, in MORP-only
  mode), every WebKit connection goes to a local black hole. This closes a
  leak found by the live test: WebKit pre-connects to a clicked link's host
  *before* the navigation policy runs, which would tell that host the
  user's IP.
- WebRTC, media capture off; strict CSP; DNS prefetching off; MORP-only
  mode refuses all websites.
- No direct connection to services: `.morp` traffic goes only through
  relays (connection policy in tests, network namespaces, packet captures).

**Evidence.** `tests/browser_leaks.rs` + `scripts/browser-leak-test.sh`:
the real browser, hostile pages, HTTP/STUN/DNS canaries, a namespace with no
network but loopback, a DNS canary as the only resolver (with a positive
control), and a packet capture: no connection from a `.morp` page or in
MORP-only mode, no DNS lookup at all, no UDP. Without the network gate the
test fails.

**Residual risk.** Clearnet websites are loaded **directly** (not through
MORP) in normal mode: they always see the user's IP. A user who copies a
link from a `.morp` page into the address bar is not protected. WebKit
internals not exercised by the test page may behave differently; new WebKit
versions may add new speculative behaviour (re-run the leak test after
upgrades). The local MORP directory (local mode) and the browser share a
machine; local processes can see `morp://` requests.

### 4.8 Fingerprinting (A7)

**Threat.** A page combines browser properties into an identifier that
links visits across sites, identities, or sessions.

**Mitigations (v0.7).** Fixed user agent, `en-US`, `TZ=UTC`, WebGL and
WebAudio off, no media devices, no WebRTC, permissions always denied,
ephemeral storage, no third-party cookies, ITP on, "New identity" (new
isolation context, all site data cleared). See the audit table in
[`SECURITY_MODEL.md`](SECURITY_MODEL.md#browser).

**Residual risk — practical protections only.** Screen and window size,
CPU core count, installed fonts, canvas and text rendering, CSS media
features, GTK theme, WebKitGTK version quirks, and performance timing are
**not** normalised. The MASK user agent itself identifies MASK users (a
small population). Fingerprinting resistance comparable to Tor Browser is
not attempted.

### 4.9 Cross-context linking

**Threat.** A service or relay links two activities of the same user:
two browser identities, two sites, CLI and browser.

**Mitigations.** v0.7 isolation contexts: separate sessions, circuits,
rendezvous points, cookies, and links per context; per-service sessions
(content rules keep each `.morp` page to its own service); separate guard
files per component (browser, CLI, each service); "New identity".

**Evidence.** `separate_contexts_never_share_a_session_or_circuit`,
`new_identity_gets_a_new_session_and_rendezvous`.

**Residual risk.** The entry guard is shared by every context of one
component (as in Tor) and knows the client's IP. Timing links contexts used
at the same time.

## 5. What local testing cannot establish

These need real deployments, other operators, or expert review:

- Anonymity against realistic adversaries (traffic analysis, website
  fingerprinting, long-term intersection attacks). Local tests prove only
  routing properties (who connects to whom, who can decrypt what).
- Behaviour with many users and relays run by independent parties; the
  effect of guards and diversity rules on a real population.
- Correctness of the cryptographic design (ntor adaptation, hidden-service
  handshake): needs independent review. Only established primitives are
  used, but their composition is MASK's own.
- Robustness against a fuzzer with coverage guidance, side channels
  (timing of crypto, cache), and WebKitGTK exploits.
- Clock and network failures across real machines over long periods.

## 6. Out of scope

Global passive adversaries; compromised user machines; physical access;
legal compulsion of the operator; clearnet anonymity (there are no exit
relays: clearnet is direct); public deployment (refused by design).
