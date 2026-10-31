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
                 PostgreSQL (roles and row level security per tenant)
```

## Principles

1. **Headless first.** The server is a pure HTTP API described in [`docs/api/openapi.yaml`](https://github.com/passboxnet/passbox-server/blob/main/docs/api/openapi.yaml). The web client, the extension, the CLI and later the desktop and mobile apps are equal clients of that API.
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
| Extension | Manifest V3, React | Vault in the service worker, unlocked keys only in `chrome.storage.session`; server URL can be preset through enterprise policy (`managed_schema.json`). See [extension.md](extension.md) |
| Desktop | Tauri 2 | Wraps the built web client; tray, global shortcut, lock on sleep. See [desktop.md](https://github.com/passboxnet/passbox-desktop/blob/main/docs/desktop.md) |
| Website | Next.js, static export | Shares the design tokens of `packages/ui` |
| Rust client | Rust (`crates/client`) | Native client logic with encrypted offline cache; used by the CLI, iOS and Android |
| Bindings | UniFFI (`crates/ffi`) | Swift and Kotlin bindings of the Rust client |
| iOS / iPadOS | SwiftUI, AuthenticationServices | AutoFill extension, Face ID / Touch ID unlock. See [ios.md](https://github.com/passboxnet/passbox-ios/blob/main/docs/ios.md) |
| Android | Kotlin, Jetpack Compose | Autofill service, biometric unlock. See [android.md](https://github.com/passboxnet/passbox-android/blob/main/docs/android.md) |
| CLI | Rust, clap | Binary name `pbx`. See [cli.md](https://github.com/passboxnet/passbox-cli/blob/main/docs/cli.md) |

## Server

- **Database:** PostgreSQL only ([ADR 0007](../adr/0007-postgresql-only.md)), migrations in [`crates/server/migrations`](https://github.com/passboxnet/passbox-server/tree/main/migrations) with native types (`BYTEA` ciphertext, `JSONB`, `BOOLEAN`, `BIGINT` Unix milliseconds) and compile-time checked queries (`sqlx::query!`, cache in `.sqlx/`). Handlers never get a pool: `crate::db::Db` opens a transaction that names its context (`as_account`, `public`, `as_org`, `system`), and row level security on every tenant table limits each statement to that context. See [database-security.md](database-security.md).
- **Operations:** `passbox-server migrate` (or `PASSBOX_AUTO_MIGRATE`), `/health` and `/ready`, Prometheus metrics on `PASSBOX_METRICS_BIND` (`crates/server/src/metrics.rs`).
- **Sync:** a global change counter. Every write takes the next value inside its transaction; `GET /api/v1/sync?since=<cursor>` returns everything with a higher value. Deleted items remain as tombstones without data.
- **Instance administration:** `crates/server/src/instance.rs` holds the instance settings (registration mode, name, help address, default mail language, master password policy) as a JSON document in `instance_state`, decides who may register, and knows who is an instance admin (first account, `PASSBOX_ADMIN_EMAILS`). `api/admin.rs` serves `/api/v1/admin/*` behind the `AdminSession` extractor and writes the hash-chained `admin_events` log; record new admin actions with `admin::record` or, inside a write transaction, `admin::record_in`.
- **Mail:** see [Sending mail](#sending-mail-from-server-modules).
- **Concurrency:** optimistic. A write names the revision it creates, which must be exactly one higher than the stored revision, otherwise the server answers `409 Conflict` with the current revision.

## Sending mail from server modules

Modules never talk to SMTP. They queue a mail with the `Mailer` in `AppState` (`crates/server/src/mail`), and a background task sends it with retries:

```rust
use crate::mail::{Locale, Mailer, Template};

// To an account, in its language (or the instance default); adds `email` to the parameters:
state.mailer.enqueue_for_account(&account_id, Template::NewDevice, json!({ "device": name, "ip": ip, "time": now })).await?;

// To any address, in a given language:
state.mailer.enqueue("ada@example.com", Template::Invitation, Locale::De, json!({
    "inviter": admin_email, "organization": org_name, "link": link, "expiresAt": expires_at,
})).await?;

// Only if a transaction commits (for example together with an invitation row):
Mailer::enqueue_in(&mut tx, &to, Template::Invitation, locale, &params).await?;
tx.commit().await?;
state.mailer.wake();
```

- **Templates** (`mail/templates.rs`, English and German with "Sie", text and HTML): `Invitation` (`inviter`, `link`, `expiresAt`, optional `organization`), `NewDevice`, `MasterPasswordChanged` (`device`, `ip`, `time`), `TwoFactorChanged` (plus `change`: `enabled`, `disabled` or `changed`), `EmergencyAccess` (`requester`, `event`, `link`) and `Recovery` (`event`, `link`) as placeholders for C1/C3, and `Test`. Missing parameters render as empty text. Add a template by extending the enum and `render`, with both languages. Never put secrets other than single-use links into parameters; they are stored until the mail is sent.
- **Links:** build them from `state.mailer.public_url()` (`PASSBOX_PUBLIC_URL`, no trailing slash) and the web app's hash routes, for example `{public_url}/#/?invite=…`. It is `None` when not configured; then offer the link to the acting user instead (as instance invitations do).
- **Language:** `Locale::parse`, `mail::request_locale` (explicit value or `Accept-Language`); accounts store theirs in `accounts.locale` (`/api/v1/account/preferences`).
- Queuing never fails a request because the mail server is down. Security notifications should log a failure to queue rather than fail the request (see `api/notify.rs`).

## Clients

There are two implementations of the client logic, which talk to the same API and share the item format:

- [`packages/client`](../../packages/client) (TypeScript) for the web app, the desktop app and the extension. It calls the Rust core through WebAssembly and keeps all keys inside WebAssembly memory.
- [`crates/client`](../../crates/client) (Rust) for the CLI and the native mobile apps (through [`crates/ffi`](../../crates/ffi)). It adds an encrypted offline cache, so these clients unlock and read without a connection, and an *unlock key* for biometric unlock that skips Argon2id.

Both are covered by integration tests against a real server; the Watchtower heuristics have shared test cases.

## Current state

Implemented:

- **Core:** Argon2id + Secret Key derivation, OPAQUE login, key hierarchy with context-bound XChaCha20-Poly1305 encryption, keyring session export, account key pairs (X-Wing, Ed25519), key directory verification, organization and shared vault verification, ES256 passkeys, TOTP/HOTP, password and PIN generator
- **Server:** registration, login, sessions, vaults, items, incremental sync on PostgreSQL with row level security, CORS for non-browser-origin clients, key directory, organizations (family and team) with invitations and roles, groups and shared vaults (see [sharing.md](sharing.md)), instance administration (registration modes, invitations, disabling accounts, hash-chained admin log), mail over SMTP with a durable outbox, and single sign-on with OpenID Connect, SSO unlock on trusted devices and SCIM 2.0 provisioning (see [sso.md](sso.md))
- **Web client:** sign-up with Emergency Kit, sign-in on new devices, unlock, logins/notes/cards with TOTP and custom fields, vaults, favorites, tags, search, command palette, Watchtower, generator, settings, auto-lock, periodic sync, configurable server
- **Extension:** sign-in and unlock, inline autofill (logins, multi-step forms, one-time codes, password suggestions), save and update prompts, passkeys with browser fallback
- **Desktop (Windows, macOS, Linux):** Tauri 2 shell around the web client with tray, global shortcut and lock on sleep
- **iOS / iPadOS:** native SwiftUI app with AutoFill credential provider, Face ID / Touch ID, iPad split view
- **Android:** native Compose app with autofill service, biometric unlock and inline suggestions
- **CLI:** sign-in, list/get/read, secret references and `pbx run`
- Website, CI for every platform, Dockerfile

Not yet: offline cache and offline unlock in the browser clients, screens for sharing (the client APIs exist), import from other password managers, passkeys on mobile, SSO in the native apps, SAML ([ADR 0005](../adr/0005-saml-deferred.md)), rate limiting, signed releases, an external security audit.
