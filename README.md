# MASK — Multi-hop Anonymous Service Kit

An experimental privacy browser and onion-routing network, written in Rust.

> **Status: v0.5 development build. MASK is not anonymous and has not been
> security reviewed.** Normal websites are loaded directly over your internet
> connection. `.morp` hidden services are reached only through MORP relay
> circuits, but everything runs on one computer, the design is unreviewed,
> and it is **not** Tor-level anonymity. Do not rely on MASK for privacy or
> safety.

## What works

**Browser**
- MASK Browser window (GTK3 + WebKitGTK via [Wry](https://github.com/tauri-apps/wry))
- Dark interface with back, forward, reload, and an address bar
- Opens `https://` and `http://` websites; bare domains default to `https://`
- Opens cryptographic `morp://<id>.morp` hidden services through MORP relays
- Rejects other schemes (`file:`, `javascript:`, `data:`, ...) and named `.mask` addresses
- Ephemeral session: cookies, cache, and site storage are discarded on exit

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
- Entry, middle, exit, and rendezvous relays as separate processes on 127.0.0.1
- Ed25519 relay identities, signed relay descriptors, ntor-style handshakes
- Layered ChaCha20-Poly1305 encryption with replay protection; many circuits per link

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
```

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
- The service directory keeps descriptors in memory; if you restart it,
  restart your hosts too. If a relay stops, hosts using it as an intro
  point exit and must be restarted.

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
cargo test                # browser and network tests
```

## Project layout

```
Cargo.toml                 workspace + browser crate (mask)
src/                       browser
  main.rs                  entry point
  address.rs               address bar parsing and validation
  morp.rs                  morp:// handler (relay-routed, no DNS, fails closed)
  browser/                 window, toolbar, theme, start page
crates/mask-net/           network (no GUI dependencies)
  src/
    address.rs             .morp address format and validation
    hs/                    hidden services: crypto, session, service host, client, local app
    service/               service keys, signed descriptors, static site serving
    directory/             localhost service directory (server + client)
    crypto/                relay keys, ntor-style handshake, layer encryption
    relay.rs               entry / middle / exit / rendezvous relay
    client.rs              circuit building and layered encryption
    descriptor.rs          signed relay descriptors and path selection
    protocol.rs            link messages and relay commands
    transport.rs           framed TCP links and connection policy
    bin/                   mask-relay, mask-client, mask-service, mask-directory
  tests/morp.rs            relay routing, failure, and tampering tests
  tests/hidden_services.rs hidden-service routing, no-bypass, auth, failure, cleanup tests
examples/morp-site/        example website
docs/                      MORP, addresses, hidden services, progress notes
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
  points (stopped, or its intro relay restarted). Restart the host.
- **"Service identity could not be verified"**: whatever answered could not
  prove it owns the address's key; nothing from it was displayed.
- The browser prints MORP errors in the terminal; set `RUST_LOG=debug` for more.
- **Key file refused**: `chmod 600` the `identity.key` or `service.key` named
  in the error.
