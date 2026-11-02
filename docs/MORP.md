# MORP — MASK Onion Routing Protocol (version 1, experimental)

> **Status: experimental, unreviewed, localhost only.**
> MORP has not been independently reviewed or analysed. It must not be used
> to protect anyone's identity, communications, or safety. This document
> describes what it is designed to do and, just as importantly, what it does
> not do.

MORP is MASK's own circuit and cell protocol. Its cryptographic building
blocks are established primitives and an established handshake design; MASK
does not invent any cryptographic algorithms. Where MORP follows Tor's
design this document says so.

Code: `crates/mask-net/` (`crypto/`, `protocol.rs`, `transport.rs`,
`relay.rs`, `client.rs`, `descriptor.rs`).

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

## 3. Keys and descriptors

Each relay has:

- **Identity key** (Ed25519). Long-term. Stored as 32 raw bytes in
  `<data_dir>/identity.key`, created with mode `0600` in a `0700` directory.
  The relay refuses to start if the file is readable by group or others. The
  public key is the relay's **node ID**.
- **Onion key** (X25519). Generated fresh at every start, kept only in memory.

At startup a relay signs a **descriptor**:

```
signature = Ed25519-Sign(identity_key,
    "MORP-v1 relay descriptor\0" ||
    postcard(version, nickname, role, address, node_id, onion_key, published))
```

and writes it as JSON to the directory folder (default `runtime/directory/`).
On clean shutdown it deletes its descriptor. Clients load every descriptor,
verify each signature with `verify_strict`, skip invalid files, and choose
one entry, one middle, and one exit at random.

## 4. Links

A link is one TCP connection between neighbours (client↔entry,
entry↔middle, middle↔exit).

**Framing:** every message is `u32 big-endian length || postcard(LinkMsg)`.
Frames over 64 KiB are rejected before the body is read.

**Link handshake:**

```
opener → acceptor:  Hello   { version: 1, role }
acceptor → opener:  Welcome { version: 1, role }
               or:  LinkError { code, detail }   and close
```

Roles must follow client → entry → middle → exit. The declared role is
**not authenticated**; it is a sanity check against misconfiguration, not a
security boundary.

**Link messages:**

| Message | Meaning |
|---|---|
| `Create { circ, request }` | Open circuit `circ` on this link (ntor handshake). |
| `Created { circ, reply }` | Handshake reply. |
| `Relay { circ, cell }` | One onion cell. Away from the client on a relay's inbound link, toward the client on its outbound link. |
| `Destroy { circ, reason }` | Tear down `circ`. |
| `LinkError { code, detail }` | Fatal link error, then close. |

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
- **Link-level attackers.** Links are plain TCP, not TLS. An observer of a
  link sees circuit IDs, cell sizes, timing, and handshake public keys, and
  can inject `Destroy` messages or close the link (denial of service).
  Cell contents remain encrypted and authenticated.
- **A malicious directory.** Whoever can write to the directory folder
  chooses which relays (and keys) clients use. There are no directory
  authorities, consensus, or descriptor expiry.
- **Sybil attacks.** Nothing limits how many relays one party runs.
- **Denial of service.** The limits are basic, there is no
  congestion control, and one slow next hop can delay other extensions.
- **The client's own machine, or the destination.** The exit currently runs
  only an echo test service. When real exits exist, traffic after the exit
  is only as private as the application protocol (for example, HTTPS).
- **Side channels.** Timing of cryptographic operations and memory handling
  have not been audited. Secrets are zeroized on drop where the libraries
  allow, but copies may remain (for example in serialization buffers).

## 9. Known limitations (implementation)

- Localhost only: relays refuse to listen on, or extend to, non-loopback
  addresses.
- Exactly three hops with fixed roles; path selection is uniform random per
  role with no guard nodes, families, or bandwidth weighting.
- One outstanding request per circuit; no streams or flow control.
- Onion keys rotate only when a relay restarts; descriptors have no expiry.
- Error details reveal relay names (debugging aid).
- No formal analysis, fuzzing, or third-party review has been done.

## 10. Before MORP could be trusted

At minimum: an independent cryptographic and protocol review; authenticated
and encrypted links (TLS 1.3 or Noise); fixed-size cells with padding;
signed, expiring directory information from multiple authorities; guard
selection; fuzzing of all parsers; and a removal of debugging detail from
errors. Until then, MASK must not be described as anonymous or secure.
