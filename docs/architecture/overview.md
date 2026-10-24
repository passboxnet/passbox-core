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
| Desktop | Tauri 2 | Wraps the built web client; tray, global shortcut, lock on sleep. See [desktop.md](../desktop.md) |
| Website | Next.js, static export | Shares the design tokens of `packages/ui` |
| CLI | Rust, clap | Binary name `pbx` |

## Server

- **Database:** SQLite (default, single file) or PostgreSQL, selected by `PASSBOX_DATABASE_URL`. One code path serves both through the sqlx `Any` driver and portable SQL migrations in [`crates/server/migrations`](../../crates/server/migrations). Binary values are stored as Base64url text and timestamps as Unix milliseconds.
- **Sync:** a global change counter. Every write takes the next value inside its transaction; `GET /api/v1/sync?since=<cursor>` returns everything with a higher value. Deleted items remain as tombstones without data.
- **Concurrency:** optimistic. A write names the revision it creates, which must be exactly one higher than the stored revision, otherwise the server answers `409 Conflict` with the current revision.

## Client

[`packages/client`](../../packages/client) contains the platform-neutral client logic used by the web app (and later the extension): sign-up, sign-in, unlock, sync, conflict handling and the item schema. It calls the Rust core through WebAssembly and keeps all keys inside WebAssembly memory.

## Current state

Implemented:

- Core: Argon2id + Secret Key derivation, OPAQUE login, key hierarchy with context-bound XChaCha20-Poly1305 encryption, TOTP/HOTP, password and PIN generator
- Server: registration, login, sessions, vaults, items, incremental sync on SQLite and PostgreSQL
- Web client: sign-up with Emergency Kit, sign-in on new devices, unlock, logins/notes/cards with TOTP, favorites, tags, search, generator, auto-lock after 15 minutes, periodic sync
- Extension popup with generator, website, CLI tools, CI, Dockerfile

Next: offline cache in the clients, sharing (account key pairs and vault membership), autofill and passkeys in the extension, Watchtower, import from other password managers, rate limiting.
