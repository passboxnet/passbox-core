# ADR 0004: SQLite and PostgreSQL through one portable code path

- Status: Superseded by [ADR 0007](0007-postgresql-only.md) (PostgreSQL only)

## Context

Self-hosters want a single container without a separate database. Teams and enterprises want PostgreSQL with backups, replication and high availability.

## Decision

The server supports both through the sqlx `Any` driver with one set of portable migrations:

- only `TEXT` and `BIGINT` columns; binary data as unpadded Base64url text, timestamps as Unix milliseconds,
- `$1, $2, ...` placeholders, each used once and in ascending order (accepted by both backends),
- no backend-specific SQL beyond what both support (`ON CONFLICT`, `RETURNING`).

The integration tests in `crates/server/tests/api.rs` run against SQLite always and against PostgreSQL when `PASSBOX_TEST_DATABASE_URL` is set (CI does this).

## Consequences

No compile-time checked queries and some storage overhead from Base64. In exchange there is one implementation to maintain and test. If a backend needs specific tuning later, it can get its own queries behind the same functions.
