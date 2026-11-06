# MASK v0.6/v0.7 — Distributed MORP Network (private testnet)

> **v0.7 additions** are marked *(v0.7)*: relay families and operators bound
> in the allowlist, Sybil/copycat refusals, consensus format 2, persistent
> entry guards, path diversity, rate limits, and packet-capture checks. The
> threat model and every mechanism are in `docs/THREAT_MODEL.md` and
> `docs/SECURITY_MODEL.md`. **v0.7 is not compatible with v0.6 binaries**
> (consensus format 2, directory protocol 2): upgrade every machine.

> **Status: experimental and unreviewed.** v0.6 lets MORP relays, a
> directory authority, a hidden service, and MASK Browser run on **several
> Linux machines that you control, on a trusted private network**. It does
> **not** make MASK anonymous: one operator runs every relay and the
> authority, so that operator can see everything a relay can. Spreading
> traffic over several machines is not anonymity. Never expose MORP to the
> internet. Public addresses are refused by design.

Related documents: `docs/MORP.md` (circuit and link protocol, version 3),
`docs/MORP_HIDDEN_SERVICES.md` (introduction and rendezvous),
`docs/MORP_ADDRESSES.md` (cryptographic `.morp` addresses, unchanged),
`deploy/` (example configuration files and systemd units).

---

## 1. Architecture

```
                 network.toml (copied by hand to every machine)
                 = network name + scope + authority address and PINNED keys
                                        │
           ┌────────────────────────────┴───────────────────────────────┐
           ▼                                                            ▼
  ┌──────────────────┐  ① signed relay descriptor (Noise NK)   ┌──────────────┐
  │ mask-authority   │◄────────────────────────────────────────│  mask-relay  │ × N
  │  allowlist       │  ② health probe: Noise handshake proves │ entry/middle/│
  │  health probes   │────────────────────────────────────────►│ rendezvous   │
  │  signs consensus │  ③ signed, expiring consensus           └──────┬───────┘
  │  .morp directory │────────────────────────────────────────►       │
  └───────▲──────────┘                                       Noise IK relay links
          │ ③ consensus, ④ service descriptor (Noise NK)               │
          │                                                            │
  ┌───────┴──────────┐   Noise NK to an ENTRY only            ┌───────┴──────┐
  │ MASK Browser     │───────────────► relays ◄───────────────│ mask-service │
  │ (MASK_NETWORK=…) │      client circuit ─┐   ┌─ service    │ host         │
  └──────────────────┘                      ▼   ▼   circuit   └──────────────┘
                                     rendezvous relay joins them
```

| Component | Binary | What it does |
|---|---|---|
| Directory authority | `mask-authority run` | Admits relays on its allowlist, probes their health, signs the consensus, stores `.morp` service descriptors. |
| Relay | `mask-relay --config relay.toml` | Entry, middle, rendezvous (hidden-service intro/rendezvous point), or exit (echo test only). Uploads its descriptor every minute, refreshes the consensus. |
| Hidden service | `mask-service --network network.toml host …` | Builds intro circuits, publishes its descriptor to the authority, answers introductions with its own circuit to the client's rendezvous point. Re-establishes lost intro points. |
| Client | MASK Browser with `MASK_NETWORK=…`, or `mask-service --network … fetch / verify` | Fetches the consensus, looks up the descriptor, builds circuits. |

### Trust anchor: `network.toml`

Every machine gets the **same** `network.toml`, copied by you (USB stick,
`scp`). It names the network, its scope, and each authority's address,
**Ed25519 identity** (which signs the consensus), and **X25519 link key**
(its Noise key). Nothing is trusted that cannot be traced back to these
pinned keys. Never download `network.toml` from the network.

*(v0.7)* An optional `[relay_policy]` table sets network-wide numbers that
the authority and every client apply alike: `max_relays_per_ip` (default 2
in the private scope, unlimited in loopback) and `guard_min_listed_secs`
(default 3600: new entry guards prefer relays listed at least this long).

### Links

Every MORP connection is a Noise session (`docs/MORP.md` §4):

- client / hidden-service host → entry relay: `Noise_NK` (the client knows the
  entry's link key from the consensus; the entry does not learn who the
  client is beyond its IP address);
- relay → relay: `Noise_IK` (both relays authenticated; a relay refuses any
  peer whose link key is not in its consensus with the right role);
- anything → authority, and authority → relay health probes: `Noise_NK`
  against the pinned / published key.

Each relay's link key is fresh every run and signed into its descriptor
together with its identity, so completing a handshake proves the peer is
the relay listed in the consensus. Tampering with any frame closes the link.
There is no unencrypted fallback.

### Discovery: the signed consensus

1. A relay uploads its self-signed descriptor (address, role, family, onion
   key, link key) to every authority, at start and every 60 s.
2. The authority admits it only if the nickname is in
   `approved-relays.toml` **with the same identity key, role, and family**
   *(family: v0.7)*, the address is inside the network scope, and the
   timestamp is within the allowed clock skew. A descriptor with an approved
   nickname but another key is refused as an **identity change** (counted
   and logged). *(v0.7)* Also refused: a relay using the address, link key,
   or onion key of another admitted relay (a copycat would otherwise borrow
   that relay's health probes and be listed), and more than
   `max_relays_per_ip` relays on one IP address.
3. The authority probes the relay at its advertised address with a Noise
   handshake against its link key, every `probe_interval_secs` (20 s). Two
   failures in a row take it out of the consensus until it answers again; a
   relay that stops uploading for 5 minutes is forgotten.
4. Every `consensus_interval_secs` (60 s), and soon after any change, the
   authority signs a consensus: network name, sequence number,
   `valid_after`, `fresh_until`, `valid_until` (600 s), and the running
   relays' descriptors. *(v0.7, format 2)* Each entry also carries the
   relay's **operator** (from the allowlist) and the time the authority first
   listed it (kept in `listing-history.json` in its data folder).
5. Clients, relays, and hosts accept a consensus only if a pinned authority
   signed it, it is for their network, it is not expired (5 min clock skew
   allowed), every descriptor's own signature verifies, and it is **newer
   than the one they have** (no rollback). *(v0.7)* It must also be valid for
   at most 24 h, list nobody "in the future", and contain no two relays
   sharing an identity, nickname, address, onion key, or link key; clients
   drop relays beyond `max_relays_per_ip`. They also pin each nickname to
   the identity they first saw and refuse changes for as long as they run.

### Paths

- Circuits are entry → middle → last hop, as before. Relays extend only to
  relays in their consensus, at the published address, inside the scope.
- *(v0.7)* The entry is always one of the client's **entry guards**: 2
  primary guards (up to 5 sampled over time), kept for 30-60 days in a
  private file (`runtime/state/client-guards-<network>.json` for
  `mask-service fetch/verify`, `browser-guards-…` in `MASK_STATE_DIR` for the
  browser, `service-guards-…` next to each service key). When all guards are
  down the client keeps retrying them (and fails until one is back) instead
  of trying other entry relays; guards unlisted for 7 days are dropped.
- *(v0.7)* The guard is never in the last hop's **family** (machine) or
  **operator**; the middle prefers a family, operator, and /16 network
  different from both. MASK-chosen last hops (rendezvous and intro points)
  avoid the guard's family and operator.
- A relay that fails while building a circuit is avoided for 60 s and the
  circuit is retried on a fresh path (3 attempts).

### Hidden services across machines

Unchanged protocol (v0.5): the client's rendezvous circuit and the
service's own circuit meet at a rendezvous-role relay; introductions go
through a separate circuit to an intro point; the session is end-to-end
encrypted. New in v0.6: the descriptor lives on the authority (over Noise),
and a host whose intro circuit dies (relay or machine lost) builds a new
intro point at another rendezvous relay and republishes, instead of exiting.

**No direct browser-to-service connection exists or can be configured.** The
host never listens on the network: its only listening socket is its local
app on `127.0.0.1`. The browser only ever connects to the authority and to
entry relays.

### Health, limits, shutdown

| | Default | Where |
|---|---|---|
| Keepalive on quiet links | ping every 30 s, dead after ~2 more silent intervals | `keepalive_secs` in relay.toml |
| Inbound links | 2048 total, 256 per IP | `[limits]` in relay.toml |
| Circuits | 4096 total, 128 per link | `[limits]` |
| Handshake / connect timeout | 10 s / 5 s | built in |
| Idle link without circuits | closed after 300 s | built in |
| Authority connections | 256 (32 per IP, v0.7); 64 requests each; 30 s idle | built in |
| CREATEs per client IP (entries) *(v0.7)* | 16/s, burst 256 | `create_rate_per_ip`, `create_burst_per_ip` in `[limits]` |
| Introductions per intro point *(v0.7)* | 8/s, burst 64 | `intro_rate`, `intro_burst` in `[limits]` |
| Consensus refresh | every 30 s, and early (≤ every 2 s) when a relay is unknown | `consensus_refresh_secs` |

**Shutdown:** `Ctrl+C` or `SIGTERM` (systemd) makes a relay destroy every
circuit, telling both neighbours (`RelayShutdown`), flush, and close its
links; the authority drops it after two failed probes. Stop a hidden-service
host first: it withdraws its descriptor.

**Monitoring:** `mask-authority status --network network.toml` lists every
relay with role, address, family, operator *(v0.7)*, whether it is running,
probe failures, probe age, and how long it has been listed *(v0.7)*, plus
refused identity changes and unapproved uploads.

### Network scope

`scope = "private"` allows loopback and private ranges: 10.0.0.0/8,
172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 (Tailscale-style VPNs), and
fc00::/7. Every listen, advertise, extend, authority, and accepted peer
address is checked. **Public addresses, `0.0.0.0`, `::`, link-local, and
multicast are always refused**; there is no public scope.

---

## 2. What this protects, and what it does not

| Threat | v0.6 |
|---|---|
| Someone on the LAN reading MORP traffic | Encrypted twice: Noise per link, plus the onion layers per hop. They see endpoints, sizes, timing. |
| Someone on the LAN impersonating a relay or the authority | Fails the Noise handshake (pinned / signed keys). |
| Injecting or altering cells or `Destroy` on a link | Noise authentication fails; the link closes. |
| A relay rejoining with a new key under an approved name | Refused by the authority (and by clients that saw the old key). |
| *(v0.7)* One machine posing as several, or a relay copying another's address/keys | Refused: families are bound in the allowlist; shared addresses/keys refused by the authority and rejected by clients. |
| *(v0.7)* A flood of new entry relays | Existing guards are kept; new guards prefer long-listed relays; at most 5 guards ever sampled. |
| A machine that is not on the allowlist | Never listed in the consensus; relays refuse its links. |
| Forged, expired, rolled-back, or other-network consensus | Rejected. |
| Using a relay to connect to arbitrary hosts | Refused: relays extend only to trusted relays at their published addresses. |
| A relay or machine disappearing | Probes drop it; keepalives tear down its circuits; clients and hosts route around it; lost intro points are replaced. |
| A malicious relay tampering or black-holing | Circuits fail safely (v0.5 tests still pass over Noise). |
| **The operator** | **Not protected.** One person runs every relay and the authority. |
| **A compromised authority** | Can list relays it controls (single authority; no threshold signatures yet). |
| **Traffic analysis** | Not protected: variable cell sizes, no padding, no cover traffic. |
| **Anonymity** | **None claimed.** A handful of relays run by one person on one LAN cannot provide it. |

---

## 3. Example layout: three Arch Linux machines

| Machine | Address | Runs | Family |
|---|---|---|---|
| A | 192.168.1.10 | authority `auth1` :7300, `entry1` :7101, `rv1` :7104, MASK Browser | `machine-a` |
| B | 192.168.1.11 | `middle1` :7102, `rv2` :7104 | `machine-b` |
| C | 192.168.1.12 | `entry2` :7101, `middle2` :7102, hidden service | `machine-c` |

Replace the addresses with your machines' (`ip -4 addr` shows them; give
each machine a fixed DHCP lease in your router). Two machines also work
(fewer families; paths then reuse a machine), and so does a VPN such as
WireGuard or Tailscale (use the VPN addresses; 100.64/10 is allowed).

---

## 4. Setup, step by step

Commands marked **[A]**, **[B]**, **[C]** run on that machine. Each runs in
the MASK project folder unless it says otherwise.

### 4.1 On every machine: install and build

```sh
sudo pacman -S --needed rustup base-devel pkgconf webkit2gtk-4.1 gtk3 libsoup3 git chrony
rustup default stable
git clone https://github.com/Broski-Gaming/MASK.git
cd MASK
cargo build --release --workspace
```

Clocks must agree within 5 minutes (consensus and descriptors expire):

```sh
sudo systemctl enable --now chronyd
chronyc tracking            # "System time" should be within a few ms
```

Make a folder for the testnet files (keys go here too; it is outside the
repository so nothing can be committed by accident):

```sh
mkdir -p ~/morp-testnet && chmod 700 ~/morp-testnet
```

### 4.2 Firewall: open MORP ports to the LAN only

If you use a firewall, allow 7101–7104 and 7300 from your LAN and nothing
else. With nftables (adjust the subnet):

```sh
sudo nft -f deploy/nftables-morp.nft
```

With `ufw`: `sudo ufw allow from 192.168.1.0/24 to any port 7101:7104 proto tcp`
and the same for 7300. Do **not** forward these ports on your router.

### 4.3 [A] Create the authority's keys

```sh
./target/release/mask-authority keys --data-dir ~/morp-testnet/authority \
    --name auth1 --address 192.168.1.10:7300
```

It prints an `[[authority]]` block. Create `~/morp-testnet/network.toml`
from `deploy/network.toml`, pasting that block in place of the example
block. `authority.key` and `link.key` stay in `~/morp-testnet/authority/`
(mode 0600): back them up privately, never share or commit them.

### 4.4 Copy `network.toml` to every machine

```sh
# [A]
scp ~/morp-testnet/network.toml 192.168.1.11:morp-testnet/
scp ~/morp-testnet/network.toml 192.168.1.12:morp-testnet/
```

Check it arrived unchanged: `sha256sum ~/morp-testnet/network.toml` must
print the same value on every machine.

### 4.5 Relay configs and identities

On each machine, copy the relay examples into `~/morp-testnet/` and edit
`nickname`, `role`, `listen` (that machine's address), `family` (one label
per machine), and `data_dir` (for example `relays/entry1`, relative to the
file):

```sh
# [A]
cp deploy/relay-entry1.toml ~/morp-testnet/relay-entry1.toml
cp deploy/relay-rv2.toml    ~/morp-testnet/relay-rv1.toml    # then edit: rv1, 192.168.1.10, machine-a
```

Print each relay's identity (this creates its `identity.key`, mode 0600):

```sh
./target/release/mask-relay --config ~/morp-testnet/relay-entry1.toml --print-identity
```

Send every printed `[[relay]]` block to machine A (they are public keys, not
secrets) and collect them in `~/morp-testnet/approved-relays.toml` on A
(see `deploy/approved-relays.toml`). *(v0.7)* Each block includes the
relay's `family`; check it is the right machine label, and optionally add
`operator = "…"` (who runs that machine).

### 4.6 [A] Start the authority

```sh
cp deploy/authority.toml ~/morp-testnet/      # edit listen and data_dir = "authority"
./target/release/mask-authority run --config ~/morp-testnet/authority.toml
```

### 4.7 Start the relays

One terminal tab per relay (Konsole: Ctrl+Shift+T):

```sh
# [A]
./target/release/mask-relay --config ~/morp-testnet/relay-entry1.toml
./target/release/mask-relay --config ~/morp-testnet/relay-rv1.toml
# [B]
./target/release/mask-relay --config ~/morp-testnet/relay-middle1.toml
./target/release/mask-relay --config ~/morp-testnet/relay-rv2.toml
# [C]
./target/release/mask-relay --config ~/morp-testnet/relay-entry2.toml
./target/release/mask-relay --config ~/morp-testnet/relay-middle2.toml
```

Check from any machine:

```sh
./target/release/mask-authority status --network ~/morp-testnet/network.toml
```

Every relay should say `running yes`, and the last line should read
`Verified consensus: … 6 relay(s), signed by auth1.`

### 4.8 [C] Host a hidden website

```sh
./target/release/mask-service --services-dir ~/morp-testnet/services create
#   → Address: morp://<56 characters>.morp/
./target/release/mask-service --network ~/morp-testnet/network.toml \
    --services-dir ~/morp-testnet/services \
    host morp://<56 characters>.morp/ --site examples/morp-site
```

To move an existing service (for example one in `runtime/services/`) to
machine C, copy its folder `runtime/services/<id>/` privately (it contains
`service.key`). The address stays the same: it is derived from the key.

### 4.9 [A] Open it in MASK Browser

```sh
MASK_NETWORK=~/morp-testnet/network.toml ./target/release/mask-browser morp://<56 characters>.morp/
```

From a terminal instead: `mask-service --network ~/morp-testnet/network.toml
verify <address>` prints the circuit it used.

### 4.10 [A] Check there is no direct connection

While the page is open:

```sh
ss -tnp | grep mask-browser
```

You should see connections only to entry relays (`:7101`) and, briefly,
the authority (`:7300`), and never to machine C's service. On C,
`ss -tlnp | grep mask-service` shows the service listening only on
`127.0.0.1`.

### 4.11 Stopping

Stop the host first (Ctrl+C; it withdraws its descriptor), then the relays,
then the authority. To run permanently, install the binaries to
`/usr/local/bin`, the configs to `/etc/mask/`, and use
`deploy/systemd/mask-relay@.service` and `mask-authority.service` (hardened:
`DynamicUser`, `ProtectSystem=strict`, `NoNewPrivileges`; keys in
`/var/lib/mask/`).

### 4.12 Changing the network

- **Add a relay:** create its config, `--print-identity`, add the block to
  `approved-relays.toml`, restart the authority, start the relay.
- **Replace a relay's key** (reinstall, lost key): the authority refuses
  the new key ("identity change refused") until you update its `identity`
  line and restart the authority. Running clients and relays keep refusing
  the new key until they restart.
- **Remove a relay:** delete its block and restart the authority.

---

## 5. Testing

### Automated (one machine, part of `cargo test`)

```sh
cargo test --workspace
```

- `crates/mask-net/tests/testnet.rs`: a whole network-mode testnet in one
  process. Each relay has its own loopback address and family, with a real
  authority, consensus, hidden service, and client. It proves:
  - the site loads and the three hops use three families;
  - circuits are joined at the rendezvous point;
  - the client connected only to entries and the authority (connection
    policy);
  - no relay decrypted page content or the request (observer);
  - unapproved relays, identity changes, wrong roles, and public or
    unspecified addresses are refused;
  - an impostor authority is rejected;
  - a stopped relay leaves the consensus and clients route around it;
  - lost intro points are re-established elsewhere;
  - keepalives detect a vanished next hop;
  - graceful shutdown tells clients;
  - per-IP link limits hold.
- `tests/processes.rs`: the real binaries in separate processes, set up
  with `mask-authority keys`, `mask-relay --print-identity`, and TOML files:
  - `fetch` and `verify` succeed through the relays;
  - every process exits cleanly on SIGTERM;
  - the withdrawn service becomes unreachable.
- `tests/morp.rs`, `tests/hidden_services.rs`, `tests/malicious_relays.rs`:
  the v0.5 suites, now over Noise links, plus link tests:
  - plaintext and v0.5 frames are dropped;
  - impostors fail the handshake;
  - untrusted relay links are refused;
  - relays refuse to extend outside the trusted set or the scope.
- Unit tests:
  - scope classification;
  - Noise NK/IK, wrong key, tampered frame, kind-byte tampering;
  - consensus forgery, tampering, expiry, wrong network;
  - rollback and identity pinning;
  - config parsing (including the `deploy/` examples);
  - family-aware paths.

### Linux network namespaces (one machine, real routing)

```sh
cargo build --workspace
scripts/netns-testnet.sh                         # PASS/FAIL checks
cargo test -p mask-net --test netns -- --ignored # the same, via cargo
scripts/netns-testnet.sh --browser               # also opens MASK Browser in the client namespace
```

No root is needed: the script creates an unprivileged user namespace, a
bridge on `10.77.0.0/24`, and one network namespace per "machine":
authority, three relay machines (two relays each), service, and client.

- **Isolation:** the client and service namespaces only get routes to the
  authority and the entry relays, so a direct client → service connection is
  impossible, not merely unused.
- **Checks:** the page loads from the client, the service authenticates,
  separate circuits are joined, and no log contains page content.
- **Failover:** it then cuts one relay machine's virtual cable (no TCP FIN).
  The authority must drop those relays, keepalives must notice them, and the
  site must still load.
- **Shutdown:** finally it sends SIGTERM to everything and requires clean
  exits.
- *(v0.7)* **Packet capture:** `tcpdump` records everything on the bridge.
  Checks: no DNS packet at all; not one packet between client and service;
  client and service open TCP connections only to the authority and their
  own entry guards (read from their 0600 guard files); page content,
  requests, and the `.morp` address never appear in clear; no relay log
  contains the client's or the service's IP address.
- *(v0.7)* **Fail closed:** the client's routes to every entry relay are
  black-holed and the fetch must fail ("no usable entry guard") instead of
  finding another way.

Set `MASK_NETNS_KEEP=1` to keep the logs.

### Browser leak test (one machine, real browser) *(v0.7)*

```sh
scripts/browser-leak-test.sh
```

Runs MASK Browser in a namespace whose only network is loopback and whose
only DNS resolver is a canary (systemd-resolved is hidden: its socket is not
confined by network namespaces). Hostile `.morp` and clearnet pages try
every leak a page has; HTTP, STUN, and DNS canaries and a packet capture
must see nothing escape. See `docs/SECURITY_MODEL.md` §9.

### On real machines

Follow §4, then:

1. `mask-authority status` shows every relay running.
2. `mask-service --network … verify <address>` on a machine that hosts no
   relays prints a circuit through other machines.
3. MASK Browser loads the site. `ss -tnp | grep mask-browser` shows only
   entry relays and the authority.
4. Unplug (or `sudo ip link set <dev> down`) a relay machine. Within about
   a minute `status` shows its relays as not running and the site still
   loads (if enough relays remain).
5. Record the results in `docs/PROGRESS.md`.

---

## 6. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `is outside the allowed network scope` | A public, `0.0.0.0`, or out-of-range address in a config. Use the machine's private address. |
| `identity change refused` | The relay's `identity.key` changed. Update `approved-relays.toml` (§4.12). |
| `is not on this authority's allowlist` | Add the printed block to `approved-relays.toml` and restart the authority. |
| `the keys in network.toml … are not this authority's keys` | `network.toml` was made from a different `mask-authority keys` run. |
| `no valid consensus` / `consensus rejected: expired` / `not valid yet` | Authority unreachable, or clocks differ by more than 5 minutes (`chronyc tracking`). |
| `peer closed the connection during the link handshake` | Wrong `network.toml` (other authority keys), or the relay is not in the peer's consensus yet (wait up to 30 s). |
| Relay `running NO` in `status` | Firewall, wrong `listen`/`advertise`, or the relay is down. |
| Browser: "Service not found" | The host is not running or not yet published. |
| Browser page area blank but the window title shows the page title | Known WebKitGTK rendering issue on some NVIDIA setups (also seen with v0.4/v0.5); the page was fetched. |

---

## 7. Limitations (v0.7)

- One authority signs alone: no voting or threshold signatures between
  several authorities (each authority signs its own; clients use the
  newest valid one).
- Entry guards exist (v0.7), but with one operator they only help once
  relays are run by genuinely different people.
- Descriptor lookups go to the authority directly (over Noise), not through
  a circuit, so the authority learns which addresses an IP asks for.
- Relay link keys rotate only on restart; the allowlist is reloaded only on
  restart.
- Variable cell sizes, no padding: traffic analysis is easy.
- Identity pinning in clients lasts only for the process lifetime; the
  durable pin is the authority's allowlist.
- Tested on one machine with network namespaces; a run on separate
  physical machines is still to be recorded (§5, "On real machines").
- Unreviewed. Not anonymous.
