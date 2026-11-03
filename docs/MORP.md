# MORP — MASK Onion Routing Protocol (version 3, experimental)

> **Status: experimental, unreviewed. One machine, or a private testnet of
> machines you control (never public addresses).** Sections 1–10 describe
> the circuit protocol (unchanged since v1 except where noted); §11 and §12
> list what versions 2 and 3 changed. Multi-machine operation is described
> in `docs/DISTRIBUTED_NETWORK.md`.
> MORP has not been independently reviewed or analysed. It must not be used
> to protect anyone's identity, communications, or safety. This document
> describes what it is designed to do and, just as importantly, what it does
> not do.

MORP is MASK's own circuit and cell protocol. Its cryptographic building
blocks are established primitives and an established handshake design; MASK
does not invent any cryptographic algorithms. Where MORP follows Tor's
design this document says so.

Code: `crates/mask-net/` (`crypto/`, `protocol.rs`, `transport.rs`,
`relay.rs`, `client.rs`, `descriptor.rs`, `trust.rs`, `scope.rs`,
`authority/`).

---

## 1. Goals (for this version)

1. A client builds a three-hop circuit: **entry → middle → exit**.
2. Each hop is authenticated against a relay identity the client already
   trusts, and shares fresh keys with the client that no other hop knows.
3. Data is wrapped in one layer of authenticated encryption per hop. Each
   relay can remove exactly one layer and learns only what it needs to
   forward the rest.
4. Replies are encrypted once per hop on the way back.
5. Tampering, replay, reordering, and dropping of cells are detected.
6. Many circuits share one TCP link, distinguished by circuit IDs.

## 2. Primitives

| Purpose | Primitive | Crate |
|---|---|---|
| Relay identity, descriptor signatures | Ed25519 (strict verification) | `ed25519-dalek` 3 |
| Key agreement | X25519 | `x25519-dalek` 3 |
| Key derivation | HKDF-SHA256 | `hkdf`, `sha2` |
| Handshake authentication | HMAC-SHA256 | `hmac` |
| Layer encryption | ChaCha20-Poly1305 (IETF, 96-bit nonce) | `chacha20poly1305` |
| Randomness | OS CSPRNG (`getrandom`) | `getrandom` |
| Secret wiping | `zeroize` on drop for keys | `zeroize` |
| Link encryption (v3) | Noise `NK` / `IK`, 25519 + ChaCha20-Poly1305 + SHA-256 | `snow` 0.10 (RustCrypto/dalek backends only) |

## 3. Keys and descriptors

Each relay has:

- **Identity key** (Ed25519). Long-term. Stored as 32 raw bytes in
  `<data_dir>/identity.key`, created with mode `0600` in a `0700` directory.
  The relay refuses to start if the file is readable by group or others. The
  public key is the relay's **node ID**.
- **Onion key** (X25519). Generated fresh at every start, kept only in memory.
- **Link key** (X25519, v3). Also fresh each start, memory only; the Noise
  static key for its links (§4).

At startup a relay signs a **descriptor**:

```
signature = Ed25519-Sign(identity_key,
    "MORP-v3 relay descriptor\0" ||
    postcard(version, nickname, role, address, node_id, onion_key,
             link_key, family, published))
```

In local mode it writes the descriptor as JSON to the directory folder
(default `runtime/directory/`) and deletes it on clean shutdown. In network
mode it uploads it to the directory authorities, which list it in the signed
consensus (see `docs/DISTRIBUTED_NETWORK.md`). Clients verify every
signature with `verify_strict`, drop invalid or out-of-scope descriptors,
and choose a path (§9).

## 4. Links

A link is one TCP connection between neighbours (client↔entry,
entry↔middle, middle↔last hop). Since version 3 **every link is a Noise
session**; there is no plaintext mode and nothing to negotiate.

**Framing:** `u16 big-endian length || bytes` (at most 65 535, the Noise
message limit).

```
initiator → responder:  kind (1 byte) || Noise message 1
responder → initiator:  Noise message 2
then:                   Noise transport messages, each = one postcard(LinkMsg)
                        of at most 65 519 bytes
prologue = "MORP link v3\0" || kind      (changing the kind breaks the handshake)
```

| kind | pattern | used by | authenticated |
|---|---|---|---|
| 1 Client | `Noise_NK_25519_ChaChaPoly_SHA256` | client / hidden-service host → entry | responder only (client stays anonymous at the link layer) |
| 2 Relay | `Noise_IK_25519_ChaChaPoly_SHA256` | relay → next relay | both sides |
| 3 Probe | NK | authority health checks | responder |
| 4 Directory | NK | requests to a directory authority | responder |

The responder's static key is its **link key**: an X25519 key generated
fresh each run and bound to the relay's Ed25519 identity by the signed
descriptor (authority link keys are pinned in `network.toml`). For IK the
responder learns the initiator's link key in message 1 and **closes without
answering** unless it belongs to a trusted relay (§4.1) whose role may open
that link (an entry may link to a middle; a middle to an exit or rendezvous
relay). Entries accept client links; middles, exits, and rendezvous relays
do not.

**MORP handshake (inside Noise):**

```
opener → acceptor:  Hello   { version: 3, role }
acceptor → opener:  Welcome { version: 3, role }
               or:  LinkError { code, detail }   and close
```

The declared role must follow client → entry → middle → last hop and, on
relay links, must equal the role of the relay the Noise handshake
authenticated.

**Keepalive:** a quiet outbound link sends `Ping { nonce }`; the peer answers
`Pong`. Two intervals without any message after a `Ping` (default interval
30 s) mark the link dead, destroying its circuits. This detects machines
that vanish without closing TCP. Inbound links that carry no circuits close
after the idle timeout (300 s).

### 4.1 Trusted relays and EXTEND

Each relay has a trusted relay set (`trust.rs`): the descriptor folder (one
machine) or the relays in the newest valid consensus signed by a pinned
directory authority (network mode). An `EXTEND` names the next hop's address
and, inside its CREATE request, its identity. The relay extends only if
that identity is a trusted relay **published at that address**, inside the
network scope, not itself, and of a role it may extend to; otherwise it
answers `Error(ExtendRejected)`. A relay cannot be used to connect to
arbitrary hosts.

**Link messages:**

| Message | Meaning |
|---|---|
| `Create { circ, request }` | Open circuit `circ` on this link (ntor handshake). |
| `Created { circ, reply }` | Handshake reply. |
| `Relay { circ, cell }` | One onion cell. Away from the client on a relay's inbound link, toward the client on its outbound link. |
| `Destroy { circ, reason }` | Tear down `circ` (authenticated by the link). |
| `LinkError { code, detail }` | Fatal link error, then close. |
| `Ping { nonce }` / `Pong { nonce }` | Keepalive (v3). |

**Circuit IDs** are random non-zero `u32`s chosen by the side that opened the
link, unique on that link. A relay maps `(inbound link, inbound ID)` to
`(outbound link, outbound ID)`; the IDs on the two links are unrelated.

## 5. Handshake (adapted from Tor's ntor)

MORP uses the one-way authenticated key exchange of Tor's **ntor**
handshake (Goldberg, Stebila, Ustaoglu, 2013; tor-spec §5.1.4), with
HKDF-SHA256 in place of Tor's KDF and a MORP-specific protocol string.

Notation: `ID` = relay node ID, `B = b·G` = relay onion key,
`PROTOID = "MORP-ntor-x25519-sha256-v1"`.

```
Client: x ← random, X = x·G
        CREATE(ID, B, X) ──────────────────────────────────────────▶
Relay:  reject unless ID and B are its own (DESTROY WrongRelay)
        y ← random, Y = y·G
        secret_input = y·X || b·X || ID || B || X || Y || PROTOID
        verify || Kf || Kb = HKDF-SHA256(salt = PROTOID,
                                         ikm  = secret_input,
                                         info = "MORP-v1 key expansion", 96 bytes)
        AUTH = HMAC-SHA256(verify, ID || B || Y || X || PROTOID || "server")
        ◀────────────────────────────────────────── CREATED(Y, AUTH)
Client: secret_input = x·Y || x·B || ID || B || X || Y || PROTOID
        derive the same values; compare AUTH in constant time
```

Both sides reject all-zero Diffie-Hellman outputs (low-order points).

**Properties:**
- Only the holder of `b` can compute `b·X`, so a correct `AUTH` proves to
  the client that it shares keys with the relay named in the descriptor.
  An entry that forwards an EXTEND to an impostor is detected.
- The relay does not authenticate the client (one-way, as in Tor).
- Fresh `x` and `y` per circuit give forward secrecy for circuit keys once
  the ephemeral secrets are erased.

**Extending:** for hops 2 and 3 the client sends `EXTEND(next address,
CREATE request)` sealed for the current last hop. That hop opens a link to
the next relay (or reuses an existing one), sends `CREATE` with a new
circuit ID, and returns the `CREATED` reply to the client as `EXTENDED`
sealed with its backward key. The client checks `AUTH` itself.

## 6. Onion layers

Each hop *i* has a forward key `Kf_i` (client → relay) and backward key
`Kb_i` (relay → client). Each key is used in one direction only.

**Layer plaintext** (`LayerBody`, postcard-encoded):

- `Relay(bytes)`: another sealed cell for a hop further along (forward), or
  from one (backward).
- `Cmd(RelayCmd)`: a command for this hop (forward) or from it (backward):
  `Extend`, `Extended`, `Data`, `Error`.

**Sending to hop k** (0 = entry):

```
c = Seal(Kf_k, Cmd(command))
for j = k-1 down to 0:
    c = Seal(Kf_j, Relay(c))
send Relay { circ, cell: c } to the entry
```

**At each relay**, a forward cell is opened with that hop's `Kf`:
- `Relay(inner)` → send `inner` to the next hop on the mapped circuit ID;
- `Cmd(Extend)` → extend (entry and middle only);
- `Cmd(Data)` → handled only by an exit at the end of the circuit (currently
  an echo test service); otherwise `Error(NotAllowed)` is returned.

**Backward:** a relay seals its own reply as `Seal(Kb_i, Cmd(reply))` and
wraps every cell arriving from the next hop as `Seal(Kb_i, Relay(cell))`.
The client opens with `Kb_0, Kb_1, …` until it reaches a `Cmd`, which tells
it which hop sent the reply.

### Nonces, authentication, and replay protection

ChaCha20-Poly1305 with:

```
nonce = 0x00 0x00 0x00 || direction (0x01 forward, 0x02 backward) || counter (u64 big-endian)
AAD   = "MORP-v1 cell" || direction
```

- Each side keeps one 64-bit counter per key, starting at 0. Nonces are
  never sent on the wire.
- The sender increments after every seal. The receiver opens only with the
  next expected counter and increments only on success.
- Keys are unique per circuit, hop, and direction, so a (key, nonce) pair is
  never reused. Reaching `2^64 − 1` is an error, not a wrap.
- Because TCP delivers in order, a **replayed**, **reordered**, **dropped**,
  or **modified** cell fails verification. Any failure destroys the circuit
  (`Destroy AuthenticationFailed`) because the counters are no longer in step.

## 7. Errors and teardown

- `RelayCmd::Error { code, detail }` is sealed by the hop that hit the
  problem and returned to the client. The circuit stays open up to that hop,
  so a failed EXTEND can be retried with another relay.
- `Destroy` propagates in both directions and removes the circuit from every
  relay's table. When a link closes, every circuit using it is destroyed.
- Error details include the reporting relay's nickname and role to make
  debugging easier. That leaks topology and should be removed before MORP
  is used with real users.

Limits: 64 KiB frames, 60 KiB of application data per `Data` command,
128 circuits per inbound link, 4096 circuits per relay, and connect,
handshake, response, and idle timeouts.

---

## 8. Threat model

### What MORP v1 tries to protect against

| Adversary | Intended protection |
|---|---|
| **A single curious relay** | The entry knows the client's address and the middle's address, not the exit or the data. The middle knows only the entry and the exit. The exit sees the data and the middle, but not the client. No single relay sees both the client and the data. |
| **A relay that modifies, replays, reorders, or drops cells** | Detected by the AEAD and counters at the next hop that opens the cell, or at the client; the circuit is torn down. |
| **A relay that forwards EXTEND to an impostor** | Detected: the impostor cannot produce a valid ntor `AUTH` for the identity in the descriptor. |
| **Later theft of a relay's identity key** | Does not expose past circuit keys (ephemeral X25519 per circuit). |
| **Someone who edits a descriptor in transit** | The Ed25519 signature fails and the client skips it. |

### What MORP v1 does **not** protect against

- **A global or large passive observer.** Anyone who watches traffic at
  both the client side and the exit side can link them by timing and
  volume. Tor does not defend against this either.
- **Colluding entry and exit.** If both are run by the same party,
  end-to-end timing correlation de-anonymizes the client.
- **Traffic analysis by size.** Cells are variable-length and shrink by one
  layer at each hop, so message sizes and each relay's position are
  visible. There are no fixed-size cells, padding, or cover traffic.
- **Link-level traffic analysis.** Since v3 links are Noise-encrypted and
  authenticated, so a network attacker can no longer read circuit IDs,
  impersonate a relay, or inject `Destroy`. It still sees connection
  endpoints, frame sizes, and timing, and can drop or delay traffic
  (denial of service).
- **A malicious directory.** In local mode whoever can write to the
  descriptor folder chooses the relays. In network mode a single compromised
  directory authority can list relays it controls (there is no multi-
  authority vote or threshold signature yet).
- **Sybil attacks.** In network mode only allowlisted identities are
  admitted, but the operator who writes the allowlist controls every relay.
- **Denial of service.** The limits are basic, there is no
  congestion control, and one slow next hop can delay other extensions.
- **The client's own machine, or the destination.** The exit currently runs
  only an echo test service. When real exits exist, traffic after the exit
  is only as private as the application protocol (for example, HTTPS).
- **Side channels.** Timing of cryptographic operations and memory handling
  have not been audited. Secrets are zeroized on drop where the libraries
  allow, but copies may remain (for example in serialization buffers).

## 9. Known limitations (implementation)

- Network scope `loopback` (default) or `private`; public addresses are
  always refused for listening, advertising, extending, and accepting.
- Exactly three hops with fixed roles; path selection prefers three
  different families and avoids recently failed relays, but there are no
  guard nodes or bandwidth weighting.
- One outstanding request per circuit; no streams or flow control.
- Onion keys rotate only when a relay restarts; descriptors have no expiry.
- Error details reveal relay names (debugging aid).
- No formal analysis, fuzzing, or third-party review has been done.

## 10. Before MORP could be trusted

At minimum: an independent cryptographic and protocol review; fixed-size
cells with padding; consensus documents agreed and signed by several
independent authorities; guard selection; fuzzing of all parsers; and a
removal of debugging detail from errors. (Authenticated, encrypted links
were added in version 3.) Until then, MASK must not be described as anonymous or secure.

---

## 11. Changes in MORP version 2 (MASK v0.5)

- `MORP_VERSION` is 2; v1 and v2 nodes refuse each other at the link
  handshake.
- New relay role **rendezvous**: a last-hop relay (after a middle) that acts
  as hidden-service introduction point and rendezvous point. Middles may
  extend to exits or rendezvous relays.
- New relay commands: `EstablishIntro`, `IntroEstablished`, `Introduce1`,
  `IntroduceAck`, `Introduce2`, `EstablishRendezvous`,
  `RendezvousEstablished`, `Rendezvous1`, `Rendezvous2`, `Stream`; new error
  codes `UnknownService`, `BadCookie`, `Rejected`, `ResourceLimit`. See
  `docs/MORP_HIDDEN_SERVICES.md`.
- Idle links are closed only when they carry no circuits (introduction
  circuits are quiet for long periods).
- Relays expose statistics, an observer hook for tests, a clean shutdown,
  and a connection policy that every outbound connection is checked against.

## 12. Changes in MORP version 3 (MASK v0.6)

- `MORP_VERSION` is 3. Links are Noise sessions (§4); a v2 (plaintext) peer
  is closed after its first frame without an answer.
- Relay descriptors (`"MORP-v3 relay descriptor\0"`) also sign a per-run
  **link key** and an operator-chosen **family** (machine label). Nicknames
  and families are `a-z 0-9 - _`, at most 32 characters. Roles are written
  in lowercase in JSON and TOML.
- Relays accept relay links and extend only to relays in their trusted set
  (§4.1). Clients reach only entry relays.
- Network scope (`scope.rs`): `loopback` or `private` (RFC 1918, 100.64/10,
  fc00::/7, loopback). Public, unspecified (`0.0.0.0`), link-local, and
  multicast addresses are refused everywhere.
- Directory authorities and signed consensus documents (`authority/`); see
  `docs/DISTRIBUTED_NETWORK.md`.
- Keepalives (`Ping`/`Pong`), per-IP and total link limits, `DestroyReason::
  RelayShutdown`, and `LinkErrorCode::{Unauthenticated, ResourceLimit}`.
- Graceful shutdown: on SIGINT/SIGTERM a relay destroys every circuit,
  telling both neighbours, flushes, and closes its links.
- Paths choose the entry and middle together, preferring three distinct
  families, and skip relays that failed in the last 60 s; circuit builds are
  retried on fresh paths.
