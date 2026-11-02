# MASK — Multi-hop Anonymous Service Kit

An experimental privacy browser and onion-routing network, written in Rust.

> **Status: v0.4 development build. MASK is not anonymous and has not been
> security reviewed.** Websites are loaded directly over your normal internet
> connection. The relay network (MORP) and `.morp` services run only on
> localhost. `.morp` addresses prove a service's identity but, in this
> version, do **not** hide where it runs. Do not rely on MASK for privacy or
> safety.

## What works

**Browser**
- MASK Browser window (GTK3 + WebKitGTK via [Wry](https://github.com/tauri-apps/wry))
- Dark interface with back, forward, reload, and an address bar
- Opens `https://` and `http://` websites; bare domains default to `https://`
- Opens cryptographic `morp://<id>.morp` services (see below)
- Rejects other schemes (`file:`, `javascript:`, `data:`, ...) and named `.mask` addresses
- Ephemeral session: cookies, cache, and site storage are discarded on exit

**`.morp` services (v0.4, direct localhost prototype)**

MASK supports **only cryptographic `.morp` addresses**: a service's address
is derived from its Ed25519 public key. There are no names, aliases, or DNS.
Specification, threat model, and limitations:
[docs/MORP_ADDRESSES.md](docs/MORP_ADDRESSES.md).

- `mask-service create` generates an identity and its 56-character address
- Addresses carry a SHA3-256 checksum and version; typos are rejected
- Private keys stored with mode 0600 in `runtime/services/<id>/`
- Signed, expiring service descriptors in a localhost directory (`mask-directory`)
- The service proves it owns its address on every connection; traffic is encrypted
- Static websites (HTML, CSS, JavaScript, images) open in MASK Browser
- No DNS, no clearnet fallback; failures show local error pages
- **Not hidden:** the browser connects directly to the service on 127.0.0.1;
  relays are not used yet (introduction points and rendezvous circuits: v0.5)

**Relay network — MORP v1 (v0.3, localhost prototype)**

MORP (MASK Onion Routing Protocol) is described in detail, including its
threat model and limitations, in [docs/MORP.md](docs/MORP.md).

- Three relay roles in separate processes: entry, middle, exit
- Ed25519 relay identities (key file kept with mode 0600) and signed descriptors
- Per-hop key agreement with an ntor-style handshake (X25519, HKDF-SHA256, HMAC-SHA256)
- Layered ChaCha20-Poly1305 encryption: each relay can remove only its own layer
- Replies encrypted once per hop on the way back
- Counter-based nonces: replayed, reordered, or modified cells destroy the circuit
- Circuit IDs: many circuits share one link
- Errors returned to the client; connection logging without message contents
- Refuses to listen on, or extend to, anything except loopback addresses

The network is not connected to the browser yet.

## Requirements (Arch Linux)

```sh
sudo pacman -S --needed rustup base-devel pkgconf webkit2gtk-4.1 gtk3 libsoup3
rustup default stable
```

- `webkit2gtk-4.1`: the web engine that renders pages
- `gtk3`: the window toolkit
- `libsoup3`: HTTP library used by WebKitGTK
- `pkgconf` and `base-devel`: let Cargo find and link the system libraries

The relay network needs only Rust; it does not use GTK or WebKit.

## Run the browser

```sh
cargo run                 # debug build
cargo run --release       # optimized build
```

## Run the relay network

Open **four Konsole tabs** (Ctrl+Shift+T) in the project folder.

```sh
# Tab 1
cargo run -p mask-net --bin mask-relay -- --role entry

# Tab 2
cargo run -p mask-net --bin mask-relay -- --role middle

# Tab 3
cargo run -p mask-net --bin mask-relay -- --role exit

# Tab 4: build a circuit through all three and send messages
cargo run -p mask-net --bin mask-client -- -m "hello MASK" -m "second message"
```

What happens:
- Each relay creates (first run) or loads its identity key from
  `runtime/relays/<role>/identity.key` and publishes a signed descriptor to
  `runtime/directory/<role>.json`. The `runtime/` folder is git-ignored;
  never commit it.
- The client reads `runtime/directory/`, verifies the signatures, builds an
  encrypted circuit hop by hop, and prints each reply.
- `--circuits 3` builds several circuits over one entry link.
- Stopping a relay with Ctrl+C removes its descriptor (its onion key is gone).

Default ports: entry `127.0.0.1:7101`, middle `7102`, exit `7103`
(change with `--listen 127.0.0.1:PORT`).
More detail in the logs: add `RUST_LOG=debug` before `cargo run`.

## Host and open a `.morp` website

Open **three Konsole tabs** in the project folder.

```sh
# Tab 1: the localhost service directory
cargo run -p mask-net --bin mask-directory

# Tab 2: create an identity (once) and host the example site
cargo run -p mask-net --bin mask-service -- create
#   → prints: Address: morp://<56 characters>.morp/
cargo run -p mask-net --bin mask-service -- host <address> --site examples/morp-site

# Tab 3: open it in MASK Browser (or type the address in the address bar)
cargo run -- morp://<56 characters>.morp/
```

Other commands:

```sh
cargo run -p mask-net --bin mask-service -- list              # your services
cargo run -p mask-net --bin mask-service -- show <address>    # details
cargo run -p mask-net --bin mask-service -- check <address>   # validate offline
cargo run -p mask-net --bin mask-service -- verify <address>  # directory + live identity proof
cargo run -p mask-net --bin mask-service -- stop <address>    # stop a running host
```

- The address is generated from the key and can never be chosen or changed.
  Keep `runtime/services/<id>/service.key` private and backed up; it **is**
  the service. `runtime/` is git-ignored: never commit it.
- Stopping a host (Ctrl+C or `stop`) withdraws its descriptor, so browsers
  show "Service not found".
- The directory keeps descriptors in memory; if you restart it, restart
  your hosts too.

## Development checks

```sh
cargo fmt --all
cargo check
cargo clippy --workspace --all-targets
cargo test                # runs browser and network tests
```

## Project layout

```
Cargo.toml                 workspace + browser crate (mask)
src/                       browser
  main.rs                  entry point
  lib.rs                   crate root
  address.rs               address bar parsing and validation
  morp.rs                  morp:// protocol handler (no DNS, fails closed)
  browser/
    mod.rs                 window, toolbar, and web view
    theme.rs               dark GTK styling
    start_page.rs          built-in start page
crates/mask-net/           network: MORP relays + .morp services (no GUI deps)
  src/
    address.rs             .morp address format and validation
    service/               service keys, descriptors, channel, site hosting, fetch
    directory/             localhost service directory (server + client)
    crypto/keys.rs         Ed25519 identity + X25519 onion keys, key file
    crypto/ntor.rs         ntor-style handshake
    crypto/onion.rs        per-hop ChaCha20-Poly1305 with counter nonces
    descriptor.rs          signed relay descriptors, directory, path choice
    identity.rs            node IDs and roles
    protocol.rs            link messages and onion-layer contents
    transport.rs           framed TCP links shared by many circuits
    relay.rs               entry / middle / exit relay
    client.rs              circuit building and layered encryption
    bin/mask-relay.rs      relay command
    bin/mask-client.rs     test client command
    bin/mask-service.rs    create / host / stop / verify .morp services
    bin/mask-directory.rs  service directory command
  tests/morp.rs            end-to-end routing, failure, and tampering tests
  tests/services.rs        .morp directory, hosting, identity, failure tests
examples/morp-site/        example website for a .morp service
docs/MORP.md               MORP specification, threat model, limitations
docs/MORP_ADDRESSES.md     .morp address and service specification, threat model
docs/PROGRESS.md           milestone progress notes
```

## Troubleshooting

If the browser's page area is blank or it crashes on start (seen with some
GPU drivers), try:

```sh
WEBKIT_DISABLE_DMABUF_RENDERER=1 cargo run
```

If a relay says `Address already in use`, another relay (or program) is on
that port. Stop it, or pick another port with `--listen`.

If the client reports `WrongRelay` or `ExtendRejected`, a descriptor in
`runtime/directory/` is stale (for example, a relay was killed without
Ctrl+C and then restarted elsewhere). Restart that relay to republish its
descriptor, or delete the stale `.json` file.

If a relay refuses to start because `identity.key` is accessible by other
users, fix the permissions with `chmod 600 runtime/relays/<name>/identity.key`.

If MASK Browser shows **"MORP directory unavailable"**, start
`mask-directory`. **"Service not found"** means no host is currently
publishing that address. **"Service identity could not be verified"** means
something answered at the published endpoint without the address's private
key; nothing from it was displayed.
