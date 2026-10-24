# ADR 0003: One Rust cryptographic core for every client

- Status: accepted
- Date: 2026-10-24

## Context

Password managers that implement cryptography separately per platform risk subtle differences and multiply the audit effort.

## Decision

All cryptography and security-critical parsing live in `crates/core`. The web client and the extension use it as WebAssembly (`crates/core-wasm`, built with `wasm-bindgen`). The CLI and server link it natively. Desktop (Tauri) and mobile apps will use UniFFI bindings.

## Consequences

One implementation to test, fuzz and audit. Browser builds need the `wasm32-unknown-unknown` target and a `wasm-bindgen-cli` matching the `wasm-bindgen` version in `Cargo.lock`. The WebAssembly module adds about 85 kB (gzip) to the web client and the extension.
