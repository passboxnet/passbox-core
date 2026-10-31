# Contributing to Passbox

Thanks for your interest in Passbox! This document explains how the repository is organized and what we expect from changes.

## Conventions

- **Language:** code, comments, commit messages and technical documentation are written in English.
- **Repositories:** Passbox is split into several repositories (see the [README](README.md#repositories)). This one, passboxnet/core, holds the cryptographic core and the shared Rust and TypeScript libraries. The apps and the server depend on its releases, never the other way round. Shared code goes into `packages/` or `crates/`.
- **Cryptography lives only in `crates/core`.** Clients call it natively or through WebAssembly. Do not add cryptographic code in TypeScript.
- **No secrets in logs, errors or `Debug` output.** Secret types redact themselves; keep it that way.
- **PostgreSQL only** ([ADR 0007](docs/adr/0007-postgresql-only.md)). The server and its database live in [passboxnet/server](https://github.com/passboxnet/server). Every table with tenant data has row level security; follow the checklist in [database-security.md](docs/architecture/database-security.md#checklist-adding-a-table) when you add one there.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm lint
pnpm build:wasm && pnpm typecheck && pnpm test && pnpm build
```

The integration tests of the clients against a running server, and the setup of a test database, are in [passboxnet/server](https://github.com/passboxnet/server). The browser end-to-end tests are in [passboxnet/web](https://github.com/passboxnet/web).

Significant design decisions are recorded as ADRs in [`docs/adr`](docs/adr). Add one when you change the architecture, the cryptography or a public interface.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
