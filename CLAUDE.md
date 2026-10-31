# Notes for AI coding agents

- Code, comments, commits and technical docs: **English**.
- Passbox is split into repositories (see README). This one holds the core and the shared libraries; apps depend on its releases, never the other way round.
- All cryptography belongs in `crates/core`. Web and extension use it via `@passbox/core-wasm`.
- License is MIT. Self-hosting must always include every feature.
- Checks: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `pnpm lint`, `pnpm build:wasm && pnpm typecheck && pnpm test && pnpm build`.
- No AI attribution in commits or PRs (`git config core.hooksPath .githooks`).
