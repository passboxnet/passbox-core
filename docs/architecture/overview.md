# Architecture overview

```
               ┌────────────────────┐   ┌────────────────────┐   ┌──────────────┐
               │ Web client (React) │   │ Chrome extension   │   │ pbx CLI      │
               │ apps/web           │   │ apps/extension     │   │ crates/cli   │
               └─────────┬──────────┘   └─────────┬──────────┘   └──────┬───────┘
                         │ WebAssembly            │ WebAssembly         │ native
                         ▼                        ▼                     ▼
               ┌──────────────────────────────────────────────────────────────┐
               │ passbox-core (crates/core): all cryptography, data model     │
               └──────────────────────────────────────────────────────────────┘
                         │ HTTPS + JSON, encrypted payloads only
                         ▼
               ┌──────────────────────────────────────────────────────────────┐
               │ passbox-server (crates/server): accounts, sync, sharing,     │
               │ SSO/SCIM, audit log. Never sees plaintext or usable keys.    │
               └──────────────────────────────────────────────────────────────┘
                         │
                         ▼
                 SQLite (single user) / PostgreSQL (teams, enterprise)
```

## Principles

1. **Headless first.** The server is a pure HTTP API described in [`docs/api/openapi.yaml`](../api/openapi.yaml). The web client, the extension, the CLI and later the desktop and mobile apps are equal clients of that API.
2. **One cryptographic core.** `crates/core` is the only place with cryptographic code. Browsers use it through `crates/core-wasm`; desktop and mobile will use it through UniFFI bindings.
3. **Zero knowledge against a malicious server.** The server stores ciphertext and public keys. Clients authenticate everything they receive and never trust server-supplied security parameters (see [cryptography.md](cryptography.md)).
4. **Offline first.** Clients keep an encrypted local copy of the vault and sync changes by revision.
5. **One binary to self-host.** The server embeds or serves the web client, so a single container is a complete installation.

## Components

| Component | Technology | Notes |
| --- | --- | --- |
| Server | Rust, axum, tokio | Configured with flags or `PASSBOX_*` environment variables |
| Core | Rust, RustCrypto crates | `#![forbid(unsafe_code)]` workspace-wide |
| Web client | React 19, Vite, Tailwind CSS 4 | Loads the core as WebAssembly |
| Extension | Manifest V3, React | Keys only in `chrome.storage.session`; server URL can be preset through enterprise policy (`managed_schema.json`) |
| Website | Next.js, static export | Shares the design tokens of `packages/ui` |
| CLI | Rust, clap | Binary name `pbx` |

## Current state

Implemented: core primitives (Argon2id + Secret Key derivation, XChaCha20-Poly1305 envelopes, Secret Key format, TOTP/HOTP, password and PIN generator), server skeleton (`/health`, `/api/v1/meta`, static web client), web client UI preview with sample data, extension popup with generator, website, CI, Dockerfile.

Next: accounts and login (OPAQUE), vault and item storage with sync, sharing keys, autofill and passkeys in the extension.
