# Security Policy

## Cryptographic design

The cryptographic design is documented in [docs/architecture/cryptography.md](docs/architecture/cryptography.md).

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report them privately through [GitHub Security Advisories](https://github.com/passboxnet/core/security/advisories/new).

Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version or commit.

We will acknowledge your report within three working days and keep you informed until it is resolved. We are happy to credit you in the advisory.

## Scope

In scope: everything in this repository, including the cryptographic core, its WebAssembly build, the Rust client and its bindings, the shared TypeScript packages and the build and release pipeline. The server and the apps live in their own repositories (see the [README](README.md#repositories)); report issues in them through the security advisories of the affected repository.

Especially welcome are findings where a malicious or compromised server can read, modify, swap or roll back vault data. Passbox is designed to resist that.
