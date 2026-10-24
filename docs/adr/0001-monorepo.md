# ADR 0001: One monorepo to start with

- Status: accepted
- Date: 2026-10-24

## Context

Passbox consists of a Rust server, a Rust cryptographic core, a React web client, a Chrome extension, a website and a CLI. These parts change together while the data model and API are still moving.

## Decision

Keep everything in one repository with a Cargo workspace (`crates/`) and a pnpm workspace (`apps/`, `packages/`, `crates/core-wasm`). Split into separate repositories once the system works end to end.

To keep a later split cheap:

- apps never import from each other,
- shared TypeScript code lives in `packages/`, shared Rust code in `crates/`,
- the server and its clients only communicate through the HTTP API and the core library.

## Consequences

One CI pipeline checks everything, and cross-cutting changes land in a single commit. The repository becomes larger, and contributors need both Rust and Node.js toolchains.
