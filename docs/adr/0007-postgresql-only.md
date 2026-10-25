# ADR 0007: PostgreSQL only, with row level security

- Status: accepted
- Date: 2026-10-25
- Supersedes: [ADR 0004](0004-database.md)

## Context

ADR 0004 kept SQLite and PostgreSQL behind the sqlx `Any` driver. The cost turned out higher than expected:

- Queries could not be checked at compile time, and every column was `TEXT` or `BIGINT` (binary data as Base64url text, flags as integers, documents as JSON text), so the database enforced almost nothing.
- Tenant isolation lived only in Rust. One missing `WHERE account_id = $1` in any of several hundred queries would expose another tenant's rows. For the hosted service this is the main question: how is one customer separated from another below the application?
- SQLite has no roles and no row level security, so a second line of defence could not be built on the portable path.

Passbox was not released yet, so no installation has data to convert.

## Decision

- **PostgreSQL 15 or newer is the only database.** The sqlx `Any` driver and SQLite are removed; the server uses `PgPool`.
- **One fresh baseline** (`crates/server/migrations/0001_baseline.sql`) replaces migrations 0001–0013, with native types: `BYTEA` for ciphertext and keys, `BOOLEAN`, `JSONB`, `BIGINT` Unix milliseconds, `TEXT` ids checked by `passbox.valid_id`, `CHECK` constraints for enumerations and sizes, foreign keys with `ON DELETE` and indexes for every lookup. Signed canonical objects stay Base64url text because clients verify them byte for byte. The HTTP API is unchanged.
- **Row level security** (`0002_rls.sql`) on every table with tenant data, `ENABLE` and `FORCE`, with three roles (`crates/server/sql/roles.sql`): `passbox_migrator` owns the schema, `passbox_app` serves requests and `passbox_worker` runs background jobs; neither of the last two can bypass the policies. Every request runs in a transaction that names its context first (`crate::db::Db`); there is no other way to the pool. Details: [database-security.md](../architecture/database-security.md).
- **Compile-time checked queries** with the sqlx macros (`query!`, `query_scalar!`) and a committed offline cache in `.sqlx/`; CI builds with `SQLX_OFFLINE=true`.
- **Tests run on PostgreSQL only.** `PASSBOX_TEST_DATABASE_URL` points at a superuser; every test run creates a database of its own with the production roles and drops it afterwards.
- Operations: `passbox-server migrate`, `PASSBOX_AUTO_MIGRATE`, separate URLs per role, `/ready` and Prometheus metrics on `PASSBOX_METRICS_BIND`.

## Consequences

- Self-hosting needs a PostgreSQL server next to the container. The single-container SQLite setup for a home server is gone; the Docker Compose setup has to run PostgreSQL as well.
- A new table is not finished until it has a policy and grants (checklist in database-security.md); the RLS tests fail for a table without forced row level security.
- Changing a query that a macro checks needs a database to refresh `.sqlx/` (see CONTRIBUTING.md).
- Migrations from before this ADR cannot be applied to the new baseline; development databases have to be recreated.
