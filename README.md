# Passbox core

The shared foundation of [Passbox](https://passbox.net), an open-source password manager with passkeys, a built-in authenticator and single sign-on: the cryptographic core and every library the apps and the server build on.

> **Status: early development.** The cryptographic design is a draft and has not been audited. Do not store real secrets in Passbox yet.

| Path | Description |
| --- | --- |
| [`crates/core`](crates/core) | Cryptographic core in Rust: key derivation, encryption, Secret Key, TOTP, password generator. All cryptography lives here |
| [`crates/core-wasm`](crates/core-wasm) | WebAssembly bindings of the core (`@passbox/core-wasm`) for the web vault and the extension |
| [`crates/client`](crates/client) | Rust client with encrypted offline cache, used by the CLI and the mobile apps |
| [`crates/ffi`](crates/ffi) | Swift and Kotlin bindings of the Rust client (UniFFI) |
| [`crates/ai`](crates/ai) | AI gateway for native clients |
| [`packages/client`](packages/client) | Platform-neutral client logic in TypeScript: sign-up, sign-in, unlock, sync, item schema |
| [`packages/api-client`](packages/api-client) | Typed TypeScript client for the server API |
| [`packages/ui`](packages/ui) | Design system (React, Tailwind CSS tokens) |
| [`packages/i18n`](packages/i18n), [`packages/ai`](packages/ai), [`packages/brand-icons`](packages/brand-icons), [`packages/site-icons`](packages/site-icons) | Translations, AI features, icons |
| [`docs`](docs) | Architecture, decisions (ADRs) and design system |

## Development

Requirements: Rust (stable), Node.js 22+, pnpm 10 (`corepack enable`) and `wasm-bindgen-cli` in the version from `Cargo.lock`:

```sh
cargo install wasm-bindgen-cli --version 0.2.129 --locked
pnpm install
pnpm build:wasm
cargo test --workspace
pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

The integration tests of the clients against a running server live in [passboxnet/server](https://github.com/passboxnet/server).

## Releases

A tag `vX.Y.Z` publishes a GitHub release with an npm tarball of every `@passbox/*` package and a `SHA256SUMS` file, with a build provenance attestation. Until the packages are on npm, other repositories install them by URL:

```json
"@passbox/ui": "https://github.com/passboxnet/core/releases/download/v0.1.0/passbox-ui-0.1.0.tgz"
```

Rust crates are used as a git dependency on the tag:

```toml
passbox-core = { git = "https://github.com/passboxnet/core", tag = "v0.1.0" }
```

## Repositories

| Repository | Contents |
| --- | --- |
| [passboxnet/core](https://github.com/passboxnet/core) | Cryptographic core (Rust), WebAssembly build, Rust client, Swift/Kotlin bindings, AI gateway, shared TypeScript packages (`@passbox/*`) |
| [passboxnet/server](https://github.com/passboxnet/server) | Server (API, sync, web vault hosting), container image, Docker Compose for self-hosting |
| [passboxnet/web](https://github.com/passboxnet/web) | Web vault (React, Vite) and browser end-to-end tests |
| [passboxnet/browser-extension](https://github.com/passboxnet/browser-extension) | Browser extension with autofill and passkeys |
| [passboxnet/desktop](https://github.com/passboxnet/desktop) | Desktop app for Windows, macOS and Linux (Tauri) |
| [passboxnet/ios](https://github.com/passboxnet/ios) | iOS and iPadOS app |
| [passboxnet/android](https://github.com/passboxnet/android) | Android app |
| [passboxnet/cli](https://github.com/passboxnet/cli) | `pbx` command-line client and MCP server |

## Security

Read [SECURITY.md](SECURITY.md) to report a vulnerability and [docs/architecture/cryptography.md](docs/architecture/cryptography.md) for the design.

## License

[MIT](LICENSE)
