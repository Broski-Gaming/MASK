# MASK — Multi-hop Anonymous Service Kit

An experimental privacy browser and onion-routing network, written in Rust.
This is vibecoded, it is an experiment I am doing to see how well AI can replicate its own
version of tor.

> **Status: v0.7 development build. MASK is not anonymous and has not been
> security reviewed.** Normal websites are loaded directly over your internet
> connection. `.morp` hidden services are reached only through MORP relay
> circuits, on one computer or on a private testnet of machines you control
> (never public addresses), but the design is unreviewed, one person runs
> every relay, and it is **not** Tor-level anonymity. Do not rely on MASK for
> privacy or safety.

## What works

**Browser**
- MASK Browser window (GTK3 + WebKitGTK via [Wry](https://github.com/tauri-apps/wry))
- Dark interface with back, forward, reload, and an address bar
- Opens `https://` and `http://` websites; bare domains default to `https://`
- Opens cryptographic `morp://<id>.morp` hidden services through MORP relays
- Rejects other schemes (`file:`, `javascript:`, `data:`, ...) and named `.mask` addresses
- Ephemeral session: cookies, cache, and site storage are discarded on exit
- Leak prevention (v0.7): `.morp` pages can load only from their own service and
  cannot send you to a website; no page can load `morp:` from the clearnet or
  look up a `.morp` name in DNS; while a `.morp` page is open, the browser makes
  no direct connection at all (network gate); WebRTC, WebGL, WebAudio, media
  capture, and permission requests are off; fixed user agent, `en-US`, UTC
- **New identity** button: new MORP circuits for every service, all site data cleared
- **MORP-only mode** (`MASK_MORP_ONLY=1`): every website is refused
- Details and remaining fingerprinting surfaces: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md);
  threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

**`.morp` hidden services (v0.5)** — [docs/MORP_HIDDEN_SERVICES.md](docs/MORP_HIDDEN_SERVICES.md)
- Addresses are derived from Ed25519 keys (56 characters + `.morp`); no names, aliases, or DNS
  ([docs/MORP_ADDRESSES.md](docs/MORP_ADDRESSES.md))
- Services register introduction points; descriptors contain **no address or port**
- Client and service each build their own relay circuit; a rendezvous relay joins them
- The service proves it owns its address; requests and responses are end-to-end
  encrypted, so relays (including the rendezvous point) cannot read them
- Pages with CSS, JavaScript, and images load in parallel over one session
- No direct browser-to-website connection and no fallback: failures show an error page

**Relay network — MORP** — [docs/MORP.md](docs/MORP.md)
- Entry, middle, exit, and rendezvous relays as separate processes
- Ed25519 relay identities, signed relay descriptors, ntor-style handshakes
- Layered ChaCha20-Poly1305 encryption with replay protection; many circuits per link
- Every link is Noise-encrypted and authenticated (v0.6); relays accept and
  extend only to trusted relays

**Distributed testnet (v0.6)** — [docs/DISTRIBUTED_NETWORK.md](docs/DISTRIBUTED_NETWORK.md)
- Relays, a directory authority, hidden services, and the browser on several
  Linux machines on a private LAN or VPN; public addresses are refused
- Directory authority: relay allowlist (identity changes refused), health
  probes, signed expiring consensus, `.morp` descriptor directory
- TOML configs for operators (`deploy/`), systemd units, graceful shutdown,
  keepalives, connection limits, family-aware paths, intro-point recovery
- Tested with multiple processes and Linux network namespaces
  (`scripts/netns-testnet.sh`)

**Hardening (v0.7)**
- Persistent entry guards; paths never put the entry and last hop in one family
  or operator, and middles avoid both ends' family, operator, and network
- Relay families and operators bound in the allowlist; relays copying another
  relay's address or keys refused; relays per IP capped; consensus format 2
- Circuits destroyed on any bad or out-of-place cell; ciphers refuse reuse after
  a failure and can only seal or only open; rate limits for circuit creation and
  introductions; per-intro-point replay caches; session and connection quotas
- Scripted hostile-relay tests, packet captures in network namespaces, and a
  live browser leak test with DNS, HTTP, and STUN canaries

## Install

MASK needs **Rust 1.85 or newer** (edition 2024) and the **WebKitGTK 4.1**,
**GTK 3**, and **libsoup 3** development packages. Distribution Rust packages
are often older than 1.85, so the official `rustup` installer is recommended.

> MASK is developed and tested on Arch Linux. The commands for other
> distributions use their standard package names but have not been tested
> by the project. If a package is not found, search your package manager for
> "webkit2gtk 4.1" development files.

### Arch Linux / Manjaro / EndeavourOS
```sh
sudo pacman -S --needed rustup base-devel pkgconf webkit2gtk-4.1 gtk3 libsoup3
rustup default stable
```

### Debian 12+ / Ubuntu 22.04+ / Linux Mint / Pop!_OS
```sh
sudo apt update
sudo apt install build-essential pkg-config curl \
    libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Fedora
```sh
sudo dnf install gcc gcc-c++ make pkgconf-pkg-config \
    webkit2gtk4.1-devel gtk3-devel libsoup3-devel rustup
rustup-init
```

### openSUSE Tumbleweed
```sh
sudo zypper install -t pattern devel_basis
sudo zypper install pkg-config webkit2gtk3-devel gtk3-devel libsoup-devel rustup
rustup default stable
```
(On openSUSE, `webkit2gtk3-devel` provides the WebKitGTK **4.1** API.)

### Void Linux
```sh
sudo xbps-install -S base-devel pkg-config webkit2gtk-devel gtk+3-devel libsoup3-devel rustup
rustup-init
```

### Gentoo
```sh
sudo emerge --ask net-libs/webkit-gtk:4.1 x11-libs/gtk+:3 net-libs/libsoup:3.0 dev-util/pkgconf
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### NixOS / Nix
```sh
nix-shell -p cargo rustc pkg-config webkitgtk_4_1 gtk3 libsoup_3
```

After installing, open a new terminal so `cargo` is on your `PATH`, then:
```sh
git clone https://github.com/Broski-Gaming/MASK.git
cd MASK
cargo build
```

What the packages are for: WebKitGTK renders web pages, GTK draws the window
and toolbar, libsoup is WebKit's HTTP library, and `pkg-config` plus the
compiler toolchain let Cargo find and link them. The network programs need
only Rust.

## Run the browser

```sh
cargo run                         # start page
cargo run -- https://example.com  # open an address directly
MASK_MORP_ONLY=1 cargo run        # refuse every website, allow only morp://
```

Environment variables: `MASK_NETWORK` (testnet `network.toml`),
`MASK_MORP_ONLY=1`, `MASK_STATE_DIR` (the browser's entry guards, default
`runtime/state`), `MASK_KEEP_TIMEZONE=1` (do not report UTC to pages),
`MASK_DIRECTORY` / `MASK_RELAY_DIRECTORY` (local mode).

## Host a hidden `.morp` website

Open **seven terminal tabs** (Konsole: Ctrl+Shift+T) in the project folder.

```sh
# 1: service directory
cargo run -p mask-net --bin mask-directory

# 2–5: relays (two rendezvous relays: one can be an intro point, one a rendezvous point)
cargo run -p mask-net --bin mask-relay -- --role entry
cargo run -p mask-net --bin mask-relay -- --role middle
cargo run -p mask-net --bin mask-relay -- --role rendezvous --name rendezvous1 --listen 127.0.0.1:7104
cargo run -p mask-net --bin mask-relay -- --role rendezvous --name rendezvous2 --listen 127.0.0.1:7105

# 6: create an identity (once), then host a site through the relays
cargo run -p mask-net --bin mask-service -- create
#   → Address: morp://<56 characters>.morp/
cargo run -p mask-net --bin mask-service -- host <address> --site examples/morp-site

# 7: open it in MASK Browser
cargo run -- morp://<56 characters>.morp/
```

The toolbar shows **"MORP service · via relay circuits · experimental"**.

Other commands:

```sh
cargo run -p mask-net --bin mask-service -- verify <address>   # reach it through relays and check its identity
cargo run -p mask-net --bin mask-service -- fetch <address> /  # fetch one page through relays (like curl)
cargo run -p mask-net --bin mask-service -- list               # your services
cargo run -p mask-net --bin mask-service -- show <address>     # details
cargo run -p mask-net --bin mask-service -- check <address>    # validate offline
cargo run -p mask-net --bin mask-service -- stop <address>     # stop a running host
cargo run -p mask-net --bin mask-service -- host <address> --app 127.0.0.1:8080  # serve your own local app
```

- The address is generated from the key and can never be chosen or changed.
  `runtime/services/<id>/service.key` **is** the service; keep it private and
  backed up. `runtime/` is git-ignored: never commit it.
- Relays keep their identity keys in `runtime/relays/` and publish
  descriptors to `runtime/directory/`, which the host and browser read.
- Stopping a host (Ctrl+C or `stop`) withdraws its descriptor.
- Entry guards (v0.7) are kept in private files: `runtime/state/` for
  `fetch`/`verify` (`--state-dir`) and the browser, and next to each service
  key for hosts. Deleting a guard file makes that component choose new guards.
- The service directory keeps descriptors in memory; if you restart it,
  restart your hosts too. If a relay used as an intro point stops, the host
  builds a new intro point at another rendezvous relay and republishes.

This is **local mode** (one computer). To run across several machines, see
[docs/DISTRIBUTED_NETWORK.md](docs/DISTRIBUTED_NETWORK.md): relays then use
`--config relay.toml`, and `mask-service`/`mask-browser` use
`--network network.toml` / `MASK_NETWORK=network.toml`.

## Relay test client (echo through an exit)

```sh
cargo run -p mask-net --bin mask-relay -- --role exit     # with entry and middle running
cargo run -p mask-net --bin mask-client -- -m "hello MASK" --circuits 2
```

## Development checks

```sh
cargo fmt --all
cargo check
cargo clippy --workspace --all-targets
cargo test --workspace            # browser and network tests
scripts/netns-testnet.sh          # testnet in network namespaces + packet capture (no root)
scripts/browser-leak-test.sh      # real browser vs hostile pages, DNS/HTTP/STUN canaries (needs a desktop)
```

## Project layout

```
Cargo.toml                 workspace + browser crate (mask)
src/                       browser
  main.rs                  entry point
  address.rs               address bar parsing and validation
  morp.rs                  morp:// handler (relay-routed, no DNS, fails closed)
  privacy.rs               leak-prevention and anti-fingerprinting policy (content rules, navigation)
  browser/                 window, toolbar, theme, start page, content filter, network gate
tests/browser_leaks.rs     the real browser against hostile pages (opt-in: --ignored)
crates/mask-net/           network (no GUI dependencies)
  src/
    address.rs             .morp address format and validation
    hs/                    hidden services: crypto, session, service host, client, local app
    service/               service keys, signed descriptors, static site serving
    directory/             localhost service directory (server + client)
    authority/             directory authority, signed consensus, authority client
    trust.rs               trusted relay set (folder or consensus), identity pins, health
    guards.rs              persistent entry guards
    limits.rs              rate limits (token buckets)
    scope.rs               allowed addresses (loopback / private, never public)
    config.rs              TOML configuration files
    crypto/                relay keys, ntor-style handshake, layer encryption
    relay.rs               entry / middle / exit / rendezvous relay
    client.rs              circuit building and layered encryption
    descriptor.rs          signed relay descriptors and path selection
    protocol.rs            link messages and relay commands
    transport.rs           Noise-encrypted links and connection policy
    bin/                   mask-relay, mask-client, mask-service, mask-directory, mask-authority
  tests/morp.rs            relay routing, failure, and tampering tests
  tests/hidden_services.rs hidden-service routing, no-bypass, auth, failure, cleanup tests
  tests/malicious_relays.rs on-path tampering and black-holing relay tests
  tests/hostile.rs         scripted hostile relays, flooding, rate limits
  tests/testnet.rs         network-mode testnet in one process (authority, consensus, failures)
  tests/processes.rs       the real binaries as separate processes with TOML configs
  tests/netns.rs           runs scripts/netns-testnet.sh (opt-in: --ignored)
deploy/                    example network/relay/authority configs, systemd units, nftables
scripts/netns-testnet.sh   testnet across Linux network namespaces + packet capture (no root)
scripts/browser-leak-test.sh browser leak test in an isolated namespace
examples/morp-site/        example website
docs/                      MORP, addresses, hidden services, distributed network, threat and
                           security models, progress notes
```

## Troubleshooting

- **Blank page area or crash on start** (seen with some GPU drivers):
  `WEBKIT_DISABLE_DMABUF_RENDERER=1 cargo run`
- **`Address already in use`**: another program is on that port. Stop it or
  use `--listen 127.0.0.1:PORT`.
- **"MORP directory unavailable"**: start `mask-directory`.
- **"MORP circuit failed"**: an entry, middle, or rendezvous relay is not
  running, or `runtime/directory/` holds a stale descriptor (a relay was
  killed without Ctrl+C). Restart the relay or delete the stale `.json`.
- **"Service not found"**: no host is publishing that address.
- **"Service unavailable"**: the host is not reachable through its intro
  points (stopped, or its intro relay just restarted; the host replaces lost
  intro points within a few seconds).
- **"Service identity could not be verified"**: whatever answered could not
  prove it owns the address's key; nothing from it was displayed.
- The browser prints MORP errors in the terminal; set `RUST_LOG=debug` for more.
- **Key file refused**: `chmod 600` the `identity.key` or `service.key` named
  in the error.
- **"relay circuit failed: … Connection refused"** while a relay is down: if
  it is this client's entry guard, MASK keeps retrying that same guard (and
  works again as soon as it is back) but deliberately never switches to other
  entry relays because of failures. Start the entry relay again.
- **"no usable entry guard: … is not listed"** (v0.7): this client's guards
  are no longer in the relay list (for example the relays were recreated
  with new identities). Unlisted guards are dropped after 7 days; to choose
  new guards now, delete the guard file (`runtime/state/*-guards-*.json`, or
  `service-guards-*.json` next to a service key).
- **"Blocked: a .morp page tried to open the website …"** (v0.7): links from
  `.morp` pages to websites are not followed (websites see your IP address).
  Type the address yourself if you mean to open it.
- **"family is required"** (v0.7): add `family = "<machine label>"` to each
  relay in `approved-relays.toml` (`mask-relay --print-identity` prints it).
