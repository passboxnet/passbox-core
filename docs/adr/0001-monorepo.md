# ADR 0001: One monorepo to start with

- Status: Superseded. Passbox is now split into separate repositories (see the [README](../../README.md#repositories)).

## Context

Passbox consists of a Rust server, a Rust cryptographic core, a React web client, a browser extension, desktop and mobile apps, a website and a CLI. These parts changed together while the data model and API were still moving.

## Decision

Keep everything in one repository with a Cargo workspace (`crates/`) and a pnpm workspace (`apps/`, `packages/`, `crates/core-wasm`). Split into separate repositories once the system works end to end.

To keep the split cheap:

- apps never import from each other,
- shared TypeScript code lives in `packages/`, shared Rust code in `crates/`,
- the server and its clients only communicate through the HTTP API and the core library.

## Consequences

One CI pipeline checked everything, and cross-cutting changes landed in a single commit. The repository grew large, and contributors needed both Rust and Node.js toolchains.

The split has since happened. This repository, passboxnet/core, holds the cryptographic core and the shared libraries. The other repositories are passboxnet/server, passboxnet/web, passboxnet/cli, passboxnet/browser-extension, passboxnet/desktop, passboxnet/ios and passboxnet/android. They depend on tagged releases of passboxnet/core.
