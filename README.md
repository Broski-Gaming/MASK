# MASK — Multi-hop Anonymous Service Kit

An experimental privacy browser and onion-routing network, written in Rust.

> **Status: v0.1 development build. MASK is not anonymous.**
> The browser connects directly to websites over your normal internet
> connection. Onion routing and `.mask` hidden services are not implemented
> yet. Do not rely on MASK for privacy or safety.

## What works in v0.1

- MASK Browser window (GTK3 + WebKitGTK via [Wry](https://github.com/tauri-apps/wry))
- Dark interface with back, forward, reload, and an address bar
- Opens `https://` and `http://` websites; bare domains default to `https://`
- Rejects other schemes (`file:`, `javascript:`, `data:`, ...)
- Ephemeral session: cookies, cache, and site storage are discarded on exit

## Requirements (Arch Linux)

```sh
sudo pacman -S --needed rustup base-devel pkgconf webkit2gtk-4.1 gtk3 libsoup3
rustup default stable
```

- `webkit2gtk-4.1`: the web engine that renders pages
- `gtk3`: the window toolkit
- `libsoup3`: HTTP library used by WebKitGTK
- `pkgconf` and `base-devel`: let Cargo find and link the system libraries

## Build and run

```sh
cargo run                 # debug build
cargo run --release       # optimized build
```

The binary is `target/debug/mask-browser` (or `target/release/mask-browser`).

## Development checks

```sh
cargo fmt
cargo check
cargo clippy --all-targets
cargo test
```

## Project layout

```
src/
  main.rs              entry point
  lib.rs               crate root
  address.rs           address bar parsing and validation
  browser/
    mod.rs             window, toolbar, and web view
    theme.rs           dark GTK styling
    start_page.rs      built-in start page
```

## Troubleshooting

If the page area is blank or the browser crashes on start (seen with some
GPU drivers), try:

```sh
WEBKIT_DISABLE_DMABUF_RENDERER=1 cargo run
```
