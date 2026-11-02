# MASK — Multi-hop Anonymous Service Kit

An experimental privacy browser and onion-routing network, written in Rust.

> **Status: v0.2 development build. MASK is not anonymous and not secure.**
> The browser connects directly to websites over your normal internet
> connection. The relay network runs only on localhost and does **not**
> encrypt anything yet: every relay can read every message and the whole
> route. Do not rely on MASK for privacy or safety.

## What works

**Browser (v0.1)**
- MASK Browser window (GTK3 + WebKitGTK via [Wry](https://github.com/tauri-apps/wry))
- Dark interface with back, forward, reload, and an address bar
- Opens `https://` and `http://` websites; bare domains default to `https://`
- Rejects other schemes (`file:`, `javascript:`, `data:`, ...)
- Ephemeral session: cookies, cache, and site storage are discarded on exit

**Relay network (v0.2, localhost prototype)**
- Three relay roles in separate processes: entry, middle, exit
- Test messages routed client → entry → middle → exit and the reply routed back
- Length-prefixed framed TCP with structured (postcard/serde) messages
- Onion-shaped payloads: each relay peels one layer to learn only its next hop
  (layers are **plaintext** for now; encryption is the next milestone)
- Per-relay node IDs, handshake with protocol version and role checks
- Errors (unreachable hop, timeout, wrong role, malformed data) reported back to the client
- Connection logging (sizes only, never message contents)
- Refuses to listen on, or forward to, anything except loopback addresses

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

# Tab 4: send messages through all three
cargo run -p mask-net --bin mask-client -- -m "hello MASK" -m "second message"
```

Default ports: entry `127.0.0.1:7101`, middle `7102`, exit `7103`.
Use `--listen 127.0.0.1:PORT` on a relay and `--entry/--middle/--exit` on the
client to change them. Stop a relay with Ctrl+C.

More detail in the logs: `RUST_LOG=debug cargo run -p mask-net --bin mask-relay -- --role entry`.

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
crates/mask-net/           relay network (no GUI dependencies)
  src/
    identity.rs            node IDs and roles
    protocol.rs            wire messages and onion layers
    transport.rs           framed TCP connections and handshake
    relay.rs               entry / middle / exit relay server
    client.rs              onion builder and test client
    bin/mask-relay.rs      relay command
    bin/mask-client.rs     test client command
  tests/routing.rs         end-to-end routing and failure tests
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
