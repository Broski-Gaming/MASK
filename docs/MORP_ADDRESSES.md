# MORP Addresses and Services (v0.4, experimental)

> **Status: experimental, unreviewed, localhost only.**
> In v0.4 a `.morp` address proves *who* a service is, not *where* it is.
> Services are reached over a direct localhost connection; their location
> is **not hidden** and MASK is **not anonymous**. Introduction points and
> rendezvous circuits (which hide the service's location) are planned for
> v0.5.

MASK supports **only cryptographic `.morp` addresses** for services. There
are no friendly names, aliases, DNS records, registrars, or manually chosen
names, and none will be added. An address is computed from a key; it cannot
be picked, bought, transferred, or pointed at a different key.

Code: `crates/mask-net/src/address.rs`, `service/`, `directory/`;
browser: `src/morp.rs`, `src/address.rs`.

---

## 1. Address format

```
morp://<id>.morp/

id       = lowercase( base32_nopad( PUBKEY || CHECKSUM || VERSION ) )   56 characters
PUBKEY   = 32-byte Ed25519 public key of the service
CHECKSUM = SHA3-256( "MORP address checksum v1" || PUBKEY || VERSION )[0..2]
VERSION  = 0x01
```

- 32 + 2 + 1 = 35 bytes = 280 bits = exactly 56 Base32 characters (RFC 4648
  alphabet `a–z`, `2–7`, no padding).
- The structure follows Tor's v3 onion addresses. The checksum domain
  separator (`"MORP address checksum v1"` instead of `".onion checksum"`) and
  the version byte (`0x01` instead of `0x03`) are MORP's own, so a `.morp`
  id never validates as a `.onion` id or the other way round (tested).
- Example (test vector, Ed25519 seed = 32 × `0x01`):
  `rkeohxlubhyzl7ks3mwtzos5olfgocn7dwkbeg7toseadnapn5oipcyb.morp`
  (`crates/mask-net/tests/vectors/address_seed01.txt`, cross-checked with an
  independent implementation).

### Validation (all must pass, in this order)

1. Exactly 56 characters.
2. Only lowercase `a–z` and `2–7` (uppercase is rejected, not folded).
3. Version byte is `0x01`.
4. Checksum matches. A single mistyped character is caught.
5. The 32 bytes decode to a valid Ed25519 point that is not of small order.

In URLs: scheme must be `morp://`; host must be `<id>.morp`; ports and user
names are rejected; the fragment is dropped; the path and query are passed
to the service.

Addresses are deterministic: the same public key always gives the same
address.

## 2. Service identity

```
mask-service create
```

1. Generates 32 random bytes from the OS CSPRNG → Ed25519 signing key.
2. Computes the address from the public key.
3. Creates `runtime/services/<id>/` (mode `0700`) and writes the seed to
   `service.key` (mode `0600`, `O_CREAT|O_EXCL`, never overwritten).

The folder is named by the address, so no human-chosen name exists. On
load, MASK refuses a key file that group or others can access, and refuses
a folder whose name is not the address of the key inside it.

**The key is the identity.** Anyone with `service.key` can impersonate the
service; losing it loses the address forever. `runtime/` is git-ignored.

## 3. Service descriptors

A descriptor tells clients how to reach a service:

```
signature = Ed25519-Sign(service key,
    "MORP-v1 service descriptor\0" ||
    postcard(version=1, public_key, revision, published, expires, endpoint))
```

| Field | Meaning |
|---|---|
| `address` | The `.morp` host; contains the public key that must verify the signature. |
| `revision` | Strictly increasing (milliseconds since epoch at signing). |
| `published`, `expires` | Validity window, at most 3 hours; hosts republish every third of it (default lifetime 1 hour). |
| `endpoint` | v0.4: `DirectLoopback(127.0.0.1:port)` — the service's **real** location. |

A descriptor is accepted only if the signature verifies with the key inside
its own address, it is not expired, not dated more than 5 minutes in the
future, its lifetime is ≤ 3 hours, and the endpoint is a loopback address.
Because the key is the address, a descriptor can never reassign an address
to another key.

**Withdrawal:** `Ed25519-Sign(key, "MORP-v1 service withdrawal\0" || public_key || revision)`.

## 4. Directory (`mask-directory`)

Localhost HTTP service (Axum, default `127.0.0.1:7200`, loopback only),
descriptors held in memory.

| Request | Behaviour |
|---|---|
| `GET /v1/services/{id}` | Re-verifies, then returns the descriptor; drops it if expired. 404 if none. |
| `PUT /v1/services/{id}` | 400 malformed or `{id}` ≠ descriptor address; 422 bad signature / expired / not yet valid / non-loopback; 409 revision not newer than stored or withdrawn; 507 full. |
| `DELETE /v1/services/{id}` | Requires a valid signed withdrawal at least as new as the stored revision; remembers the revision so the old descriptor cannot be replayed. |

There is **no** endpoint that lists services, registers names, or stores
keys. Body size is capped at 8 KiB. Clients verify every descriptor
themselves; the directory is not trusted for authenticity.

## 5. Service channel

Clients connect to the descriptor's endpoint and run a signed ephemeral
Diffie-Hellman handshake (the server-authentication pattern of TLS 1.3 /
SIGMA):

```
client → service: ClientHello { version, service public key, X = x·G }
service:          refuse unless the key is its own
service → client: ServerHello { Y = y·G, Ed25519-Sign(key, DOMAIN || key || X || Y) }
client:           verify with the key inside the .morp address
both:             c2s || s2c = HKDF-SHA256(salt = DOMAIN, ikm = x·Y,
                                           info = "MORP-v1 service channel keys" || key || X || Y)
```

Afterwards all requests and responses are sealed with ChaCha20-Poly1305
using the same counter-nonce scheme as MORP cells (tampering, replay, and
reordering are detected). Responses are sent as a head plus 32 KiB body
chunks; clients accept at most 16 MiB.

This proves, **on every connection**, that the server holds the address's
private key. A process that takes over a stopped service's port, or a
descriptor pointing at the wrong place, is detected (tested).

## 6. Hosting

```
mask-service host <address> --site <folder>
```

Serves static files (HTML, CSS, JS, images, fonts, …) by GET only. Path
handling: percent-decoding, `..` refused, hidden files not served, NUL and
backslash refused, final path canonicalised and required to stay inside the
site folder (symlinks cannot escape). The host publishes its descriptor,
refreshes it, and withdraws it on Ctrl+C or `mask-service stop <address>`.
Logs record status codes and sizes, not paths.

## 7. Browser integration

`morp://` is handled only by MASK Browser's Wry custom-protocol handler
(`with_asynchronous_custom_protocol`):

1. Validate the address. Invalid → error, nothing contacted.
2. Look it up in the local directory. Never DNS.
3. Verify the descriptor.
4. Open the service channel and check the identity proof.
5. Fetch the path; return the page, or a local error page (not found,
   unavailable, identity failure, directory down).

Safety rules:
- Typing `<id>.morp` opens `morp://<id>.morp/`.
- `http(s)://…​.morp` is refused in the address bar and blocked by the
  navigation handler (links, redirects, scripts), so `.morp` names are not
  sent to public DNS by navigation.
- `.morp` pages get a Content-Security-Policy that limits them to their own
  service (`default-src 'self'`, `connect-src 'self'`, `form-action 'self'`)
  plus inline/data/blob content. A test page that tried `<img>` and `fetch()`
  to an outside address made **no** network connection.
- `.mask` and other named addresses are refused.
- Normal `https://` browsing is unchanged.

---

## 8. Threat model

### What v0.4 protects against

| Threat | Protection |
|---|---|
| Typos and corrupted addresses | Checksum, version, and key validation before any lookup. |
| Someone claiming an address they do not own | Descriptors and the channel handshake must be signed by the address's own key. |
| A malicious or compromised directory serving a fake descriptor | Clients verify signatures themselves; a fake descriptor fails. |
| A process squatting a stopped service's port | The channel handshake fails without the private key. |
| Replay of an old descriptor | Directory requires strictly newer revisions and remembers withdrawals; descriptors expire within 3 hours. |
| Tampering with traffic on the local link | Channel traffic is authenticated and encrypted. |
| `.morp` names leaking to public DNS via navigation | Address bar and navigation handler refuse `http(s)` for `.morp`. |
| A `.morp` page contacting the internet | Restrictive CSP on every `.morp` response. |
| Path traversal on the host | Canonicalised paths confined to the site folder. |

### What v0.4 does **not** protect against

- **Service location.** The descriptor contains the service's real
  `127.0.0.1:port`. Anyone who can read the directory learns where the
  service runs. Cryptographic addresses alone **do not hide server IP
  addresses**. That is the job of introduction points and rendezvous
  circuits (v0.5).
- **Client anonymity.** The browser connects directly; the service sees the
  connection. Relays are not used for `.morp` traffic yet.
- **Directory availability and privacy.** The directory can refuse to serve
  descriptors, log which addresses are looked up, and see every published
  endpoint. It is a single, in-memory, unauthenticated-reader server.
  Addresses are looked up in plaintext over local HTTP.
- **Denial of service.** Anyone on the machine can publish many descriptors
  (each needs its own key) or flood the directory.
- **Stolen service keys.** Whoever holds `service.key` *is* the service.
  There is no revocation beyond withdrawing the descriptor.
- **Other local processes.** Anything running as the same user can read
  key files and observe loopback traffic metadata.
- **DNS leaks outside navigation.** Sub-resources requested by ordinary
  `https://` pages for `*.morp` hosts are not intercepted; the `.morp` TLD
  does not exist in public DNS, but such a request could still reveal the
  name to a resolver.
- **Web content risks.** `.morp` pages run JavaScript (restricted to their
  own origin by CSP). WebKit fingerprinting, timing, and browser exploits are
  out of scope.
- **Unreviewed design.** No independent cryptographic or security review,
  fuzzing, or formal analysis has been done.

## 9. Limitations (implementation)

- Directory is in-memory: restarting it forgets all descriptors (hosts
  republish within a third of their lifetime, or restart them).
- One request per channel connection from the browser; no connection reuse.
- GET only; no request bodies, uploads, or streaming; 16 MiB response cap.
- No descriptor encryption (Tor v3 encrypts descriptors so the directory
  cannot read them; MORP v0.4 does not).
- No key backup, rotation, or offline identity keys.
