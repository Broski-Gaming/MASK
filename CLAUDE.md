# MASK — Project Context

## Project Overview
MASK stands for Multi-hop Anonymous Service Kit.

MASK is an experimental privacy browser and independent onion-routing network inspired by Tor.

The goal is to build a working browser, encrypted multi-hop routing network, and custom hidden-service ecosystem.

## Development Environment
- Operating system: Arch Linux
- Desktop environment: KDE Plasma
- Terminal: Konsole
- Programming language: Rust
- Package manager: Cargo
- Version control: Git
- Default Git branch: main

## Technology Stack
- Rust for all core application code
- Tokio for asynchronous networking
- Wry and WebKitGTK for browser rendering
- RustCrypto libraries for cryptography
- Axum for network APIs
- Serde for configuration

## MASK Network
MASK will eventually support:
- Encrypted multi-hop routing
- Entry, middle, and exit relay nodes
- SOCKS5 proxy connections
- Independent relay identities
- Private `.mask` addresses
- Cryptographically generated service identities
- Hidden websites hosted by MASK users
- Introduction points and rendezvous circuits

## Browser Features
- Custom dark interface
- Tabs and address bar
- Normal HTTPS website browsing
- `.mask` website browsing
- Network connection status
- Relay and circuit information
- Privacy settings

## Development Rules
1. Write the project in Rust, not Python.
2. Build one feature at a time.
3. Start with a working localhost prototype.
4. Prefer well-maintained libraries.
5. Write automated tests.
6. Use `cargo fmt`, `cargo check`, and `cargo test`.
7. Explain installation and terminal commands clearly.
8. Preserve existing project files and Git history.
9. Never commit passwords, tokens, or private keys.
10. Do not claim real anonymity until the implementation has been independently evaluated.

## Development Goal
Build MASK into a functional experimental network and browser with its own onion-style hidden services.

Prioritize reliability, understandable architecture, and security testing over adding features quickly.
