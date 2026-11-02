# MASK — Multi-hop Anonymous Service Kit

An experimental privacy browser and onion-routing network, written in Rust.

> **Status: v0.3 development build. MASK is not anonymous and has not been
> security reviewed.** The browser connects directly to websites over your
> normal internet connection and does not use the relay network yet. The
> relay network (MORP) runs only on localhost and is an unreviewed
> experiment. Do not rely on MASK for privacy or safety.

## What works

**Browser (v0.1)**
- MASK Browser window (GTK3 + WebKitGTK via [Wry](https://github.com/tauri-apps/wry))
- Dark interface with back, forward, reload, and an address bar
- Opens `https://` and `http://` websites; bare domains default to `https://`
- Rejects other schemes (`file:`, `javascript:`, `data:`, ...)
- Ephemeral session: cookies, cache, and site storage are discarded on exit

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
  browser/
    mod.rs                 window, toolbar, and web view
    theme.rs               dark GTK styling
    start_page.rs          built-in start page
crates/mask-net/           relay network: MORP (no GUI dependencies)
  src/
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
  tests/morp.rs            end-to-end routing, failure, and tampering tests
docs/MORP.md               MORP specification, threat model, limitations
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
