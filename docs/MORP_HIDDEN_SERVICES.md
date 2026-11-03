# MORP Hidden Services (v0.5, experimental)

> **Status: experimental, unreviewed.** One machine, or a private testnet
> (v0.6, see `docs/DISTRIBUTED_NETWORK.md`), where descriptors are stored at
> the directory authorities and all links are Noise-encrypted.
> Every `.morp` connection now travels through MORP relay circuits, and
> service descriptors no longer contain a network location. This is **not**
> Tor-level anonymity: the network is a handful of relays on one computer,
> the design has not been independently reviewed, and the limitations below
> are significant. Do not rely on it to protect anyone.

Related documents: `docs/MORP.md` (relay circuits and cells),
`docs/MORP_ADDRESSES.md` (address format, directory, browser handling).

Code: `crates/mask-net/src/hs/` (`crypto.rs`, `session.rs`, `service.rs`,
`client.rs`, `app.rs`), the rendezvous-role parts of `relay.rs`,
`service/descriptor.rs`, and the browser's `src/morp.rs`.

The design follows Tor v3 onion services (introduction points, encrypted
introductions, rendezvous points, service authentication at the rendezvous).
MORP's message formats, key derivations, and code are its own; it uses only
established primitives (Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305).

---

## 1. Architecture

```
                     ┌──────────── introduction (once per session) ────────────┐
 client ── entry ── middle ── INTRO POINT ── middle ── entry ── service host
                                   (service's long-lived intro circuit)

 client ── entry ── middle ── RENDEZVOUS POINT ── middle ── entry ── service host
        └──── client circuit ────┘   joined here   └──── service circuit ────┘
                    end-to-end encrypted session through both circuits
```

- Every circuit is a MORP v1 three-hop circuit: entry → middle → last hop.
  The last hop of a hidden-service circuit is a **rendezvous-role relay**
  (`mask-relay --role rendezvous`), which can act as both an introduction
  point and a rendezvous point.
- The client and the service each build their **own** circuits. Neither ever
  opens a connection to the other. The service has no listening socket for
  MORP traffic; its only listener is its local web application on 127.0.0.1.
- Exit relays are never used for `.morp` traffic.

## 2. Keys

| Key | Holder | Lifetime | Published |
|---|---|---|---|
| Service identity (Ed25519) | service host only | permanent (`service.key`, 0600) | public half = the `.morp` address |
| Intro auth key (Ed25519), one per intro point | service host | one host run | in the descriptor and to its intro point |
| Intro encryption key (X25519), one per intro point | service host | one host run | public half in the descriptor |
| Client ephemeral `x` (X25519) | client | one session | `X` inside the encrypted introduction |
| Service ephemeral `y` (X25519) | service | one session | `Y` at the rendezvous |
| Rendezvous cookie (32 random bytes) | client | single use | to the rendezvous point and, encrypted, to the service |

The identity private key never leaves the service host. Introduction points
see only intro auth public keys.

## 3. Protocol

### 3.1 Introduction-point setup (service)

1. Pick up to 3 rendezvous-role relays (default 2) from the relay directory.
2. For each: generate a fresh intro auth key and intro encryption key, build a
   circuit `entry → middle → relay`, and send
   `EstablishIntro { auth_key, Sign(auth, "MORP-v1 establish intro\0" || relay_id || auth_key) }`.
   The signature binds the registration to that relay, so it cannot be
   replayed at another intro point.
3. The relay verifies the signature, refuses duplicates and enforces a limit,
   records `auth_key → this circuit`, and replies `IntroEstablished`.
4. Publish a **v2 descriptor** signed by the identity key, listing each intro
   point as `(relay identity, auth_key, enc_key)`. It contains **no IP
   address, port, or other location**.

### 3.2 Connecting (client)

1. Validate the address; look up and verify the descriptor (signature by the
   address's key, freshness, 1–3 well-formed intro points). Never trust the
   directory.
2. Choose a rendezvous-role relay at random (preferring one that is not an
   intro point of this service). Build `entry → middle → rendezvous` and send
   `EstablishRendezvous { cookie }` with a fresh random 32-byte cookie.
3. For an intro point (tried in turn): build `entry → middle → intro` and send
   `Introduce1 { auth_key, payload }` where
   ```
   x random, X = x·G
   k = HKDF-SHA256(salt = "MORP-v1 introduce\0", ikm = x·ENC,
                   info = service_key || auth_key || ENC || X)
   payload = X || ChaCha20-Poly1305(k, {version, rendezvous relay id, cookie})
   ```
   The intro point forwards `payload` unchanged to the service's intro
   circuit as `Introduce2` and replies `IntroduceAck`. It cannot decrypt the
   payload, so it learns neither the rendezvous point nor the cookie.
4. Wait (up to 20 s) on the rendezvous circuit for `Rendezvous2`.

### 3.3 Rendezvous (service)

1. Decrypt `Introduce2` with the intro encryption key. Reject anything that
   fails to decrypt (tampering) and any `X` already seen (replay; the cache
   lasts for the host run, which is also the life of the intro keys).
2. Build a **new** circuit `entry → middle → <the client's rendezvous relay>`.
3. Send `Rendezvous1 { cookie, Y || sig }` with
   `sig = Sign(identity, "MORP-v1 hidden service e2e\0" || service_key || X || Y || cookie)`.
4. The rendezvous point matches the cookie (single use; expires after 60 s;
   removed whether or not it matches), **joins** the two circuits, and sends
   the client `Rendezvous2 { Y || sig }`.

### 3.4 Client verification and session keys

The client verifies `sig` with the public key inside the `.morp` address.
An impostor that does not hold the identity key cannot produce it, even if it
somehow decrypted the introduction (tested). Both sides derive
```
c2s || s2c = HKDF-SHA256(salt = "MORP-v1 hidden service e2e\0", ikm = x·Y,
                         info = "MORP-v1 e2e keys" || service_key || X || Y || cookie)
```
Fresh `x` and `y` give per-session keys and forward secrecy.

### 3.5 End-to-end session

After the join, the rendezvous point re-seals every `Stream { bytes }` cell
from one circuit onto the other. `bytes` is one end-to-end frame:

- sealed with ChaCha20-Poly1305 under `c2s` or `s2c`;
- nonce = 64-bit counter per direction (never sent), so replayed, reordered,
  dropped, or modified frames fail authentication and end the session;
- client frames: `Request { id, method, path }`;
- service frames: `Head { id, status, content_type, length }` then
  `Body { id, ≤32 KiB chunk }`.

Request IDs allow up to 64 requests in flight, so a page's HTML, CSS,
JavaScript, and images load in parallel over one session. Responses are
capped at 16 MiB. The browser reuses the session for later requests to the
same address and builds a new one if the circuits close.

### 3.6 Service side: the local application

The host forwards each request (GET/HEAD) to its local web application on
127.0.0.1 and returns the response (status, content type, body). The local
application is either the built-in static server (`--site`) or your own
loopback app (`--app 127.0.0.1:PORT`). Clients never contact it.

## 4. Relay behaviour (rendezvous role)

| Command | Accepted when | Effect |
|---|---|---|
| `EstablishIntro` | last hop, circuit unused, valid signature, under limit (256) | register `auth_key` |
| `Introduce1` | last hop, unused circuit, payload ≤ 4 KiB, key registered | forward as `Introduce2`; reply `IntroduceAck` (else `Error UnknownService`) |
| `EstablishRendezvous` | last hop, unused circuit, under limit (1024), cookie unused | park circuit under cookie |
| `Rendezvous1` | last hop, unused circuit, cookie valid and unexpired | join circuits; send `Rendezvous2` to the client |
| `Stream` | circuit joined | re-seal onto the partner circuit |

When either joined circuit closes, the partner is destroyed too. Intro
registrations and cookies are removed when their circuits close. Links that
carry circuits are kept open while idle (intro circuits are silent for long
periods); links with no circuits close after the idle timeout.

## 5. What each party learns

| Party | Learns | Does not learn |
|---|---|---|
| Directory | which addresses are published and looked up; intro relay identities and public intro keys | service location; anything about sessions |
| Client's entry | the client's (local) address; that it builds circuits | which service; content |
| Middle relays | their neighbours | endpoints; content |
| Intro point | that some client introduced itself to the service with `auth_key` | the rendezvous point, cookie, or content; the service's location |
| Rendezvous point | that two circuits joined; cell sizes and timing | which service, content, either endpoint's location |
| Service | that a client connected | the client's location |

## 6. Threat model

### Intended protections (prototype level)

- **Service identity:** only the holder of the identity key can publish a
  valid descriptor or complete a rendezvous. Forged descriptors (even from a
  lying directory), impostor services, and stale or replayed descriptors are
  rejected.
- **No published location:** descriptors list intro relays and keys only.
- **No direct connections:** client and service connect only to MORP relays
  (tested with a deny-by-default connection policy and observed with `ss`).
- **Confidentiality and integrity end to end:** relays, including the
  rendezvous point, see only ciphertext (tested with an observer of every
  plaintext each relay decrypts).
- **Replay and tampering:** of cells, introductions, and session frames.
- **Single-use rendezvous:** cookies cannot be reused or guessed (256 bits).

### Not protected against

- **Everything is on one machine.** All relays, the directory, the client,
  and the service share 127.0.0.1. Locally, "location hiding" means only that
  the descriptor and protocol do not reveal the service's port; anyone with
  access to the machine can see every process and socket.
- **Small network.** With one entry, one middle, and two rendezvous relays,
  a single operator controls every hop. Real anonymity needs many
  independent relays.
- **Traffic analysis.** Variable cell sizes, no padding, no cover traffic.
  An observer of both ends (or a colluding entry on each side) can correlate
  timing and volume.
- **Unauthenticated, unencrypted links.** Relay-to-relay links are plain TCP
  (see `docs/MORP.md`): link observers see sizes and timing and can cut
  circuits. Cell contents remain encrypted.
- **No guard relays, no path diversity rules, no families.** Repeated
  circuits through attacker relays are not prevented.
- **Directory trust and privacy.** The directory is a single server that sees
  every lookup. Descriptors are signed but not encrypted (Tor v3 encrypts
  them and blinds keys so directories cannot enumerate services).
- **Denial of service.** Intro points can be flooded with introductions;
  there is no proof-of-work or rate limiting beyond simple caps.
- **Intro point loss.** Since v0.6 a host that loses an intro circuit builds
  a new intro point at another rendezvous-role relay and republishes its
  descriptor; clients holding the old descriptor may fail once until they
  fetch the new one.
- **Browser-level risks.** WebKit fingerprinting and exploits; `.morp` pages
  are confined to their own origin by CSP, but JavaScript runs.
- **Unreviewed design and code.** No independent review, formal analysis, or
  fuzzing.

## 7. Limits and timeouts (defaults)

| Item | Value |
|---|---|
| Intro points per service | 1–3 (default 2) |
| Intro registrations per relay | 256 |
| Pending rendezvous per relay | 1024; cookie TTL 60 s |
| Introduction payload | ≤ 4 KiB |
| Client connection setup | 45 s total; rendezvous wait 20 s |
| Requests in flight per session | 64 |
| Response size | ≤ 16 MiB |
| Concurrent sessions per service | 64 |
| Replay cache per service run | 100 000 introductions |

## 8. Running it

See `README.md` ("Host a hidden `.morp` website"). In short: start the
directory, an entry, a middle, and at least one rendezvous relay; then
`mask-service host <address> --site <folder>`; then open the address in
MASK Browser.
