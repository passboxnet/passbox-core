# Database security

How Passbox keeps tenants apart in PostgreSQL, what row level security adds to the application's own checks, and what it does not protect. Background: [ADR 0007](../adr/0007-postgresql-only.md). The schema is in [`crates/server/migrations`](../../crates/server/migrations), the roles in [`crates/server/sql/roles.sql`](../../crates/server/sql/roles.sql) and the Rust side in [`crates/server/src/db.rs`](../../crates/server/src/db.rs).

## Layers

From the outside in:

1. **End-to-end encryption.** Vault contents, item data, names, attachments and private keys are encrypted by the clients ([cryptography.md](cryptography.md)). A row that leaks to the wrong tenant is ciphertext that only the owner's keys open. Row level security protects metadata (who shares what with whom, emails, audit logs, counts) and makes sure one tenant cannot change or delete another tenant's data.
2. **Application checks.** Every handler authenticates the caller (session, service account, SCIM or events token) and checks membership and permissions (`api/access.rs`) before it touches data. This is the layer that decides; it answers `403` or `404`.
3. **Transaction context.** Handlers never see a connection pool. They open a transaction through `Db`, which first states on whose behalf it runs (below). The settings are transaction-local, so a pooled connection carries nothing to its next user, and they work behind a transaction-mode connection pooler such as PgBouncer.
4. **Row level security.** Every table with tenant data has `ENABLE` and `FORCE ROW LEVEL SECURITY` and policies that compare rows with the context. A query that forgets `WHERE account_id = $1` still sees only the caller's rows; an `INSERT` or `UPDATE` that names another tenant fails with a policy violation.
5. **Roles and grants.** The server's roles cannot bypass the policies, do not own the tables, and get only the privileges they need (`passbox_app` cannot change `accounts.instance_admin`; `passbox_worker` sees only the tables of the background jobs).
6. **Operator controls.** TLS to the database, passwords or certificates per role, network access, backups. See [self-hosting.md](../self-hosting.md#database).

## Roles

| Role | URL | Attributes | Used for |
| --- | --- | --- | --- |
| `passbox_migrator` | `PASSBOX_MIGRATION_DATABASE_URL` | owner of the schema, `BYPASSRLS` | migrations (`passbox-server migrate`, or at start with `PASSBOX_AUTO_MIGRATE`); owner of the `SECURITY DEFINER` helper functions |
| `passbox_app` | `PASSBOX_DATABASE_URL` | `NOBYPASSRLS`, not an owner | every request, server start (secrets), the mail queue |
| `passbox_worker` | `PASSBOX_WORKER_DATABASE_URL` | `NOBYPASSRLS`, not an owner, grants on job tables only | mail delivery, webhooks, attachment cleanup, breach monitoring, audit retention |

`roles.sql` creates or repairs the roles and is safe to run again; it sets no passwords. Run it as a superuser before the first migration, because the migrations grant privileges only to roles that exist. Forcing row level security on the owner needs `BYPASSRLS` on the migrator (only a superuser can grant it): without it the migration warns, leaves the tables unforced, and the server warns at every start that the policies do not apply to its role. The same warning appears when `PASSBOX_DATABASE_URL` points at a superuser or the owner.

## Contexts

`Db` offers one method per kind of caller. Each sets the four transaction-local settings `passbox.account_id`, `passbox.context`, `passbox.org_id` and `passbox.system` (all four every time, so contexts never mix). A transaction without a context sees no tenant rows at all.

| Method | Settings | Who | Sees |
| --- | --- | --- | --- |
| `as_account(id)` | `account_id` | a signed-in account (sessions, service accounts' owners) | its own rows, its organizations, vaults shared with it |
| `as_admin(id)` | `account_id`, `context = 'admin'` | an instance admin; only `AdminSession::tx` calls it, after checking the flag or `PASSBOX_ADMIN_EMAILS` | additionally accounts (without credentials), invitations, instance settings, the admin log, the mail queue |
| `public(Public::Auth)` | `context = 'auth'` | sign-up, sign-in, second factor, recovery, SSO sign-in, new devices | credential tables by email or token hash; nothing in vaults, items, keys or organizations |
| `public(Public::Meta)` | `context = 'meta'` | `/api/v1/meta` | instance settings |
| `public(Public::ShareLink)` | `context = 'share_link'` | the signed-out share-link viewer | nothing directly; `passbox.share_link_*` functions return one link by ID and check its access hash |
| `as_org(Scim, org)` | `context = 'scim'`, `org_id` | a SCIM token of `org` | that organization's members, SCIM users and groups; ending access of its members |
| `as_org(Events, org)` | `context = 'org_events'`, `org_id` | the events API token of `org` | that organization's audit log |
| `as_org(Sso, org)` | `context = 'sso'`, `org_id` | the SSO flow of `org` after the provider answered | that organization's SSO configuration, identities and members |
| `system(Job::…)` | `system` | server start (`secrets`), the mail queue (`outbox`), `/metrics` (`metrics`), background jobs (`worker:<job>`) | only the rows of that job, for example `worker:mail` the mail queue |

Signed-out flows switch to the account once its credential is verified (`db::switch_to_account`), so the rest of a sign-in or sign-up transaction runs with that account's rights only.

## Definer functions

Some flows legitimately need a little of another tenant's data: a session lookup by token hash, the public keys of the people one shares with, an invitation preview, the email of the person who wrote an audit entry, the first-admin claim, the instance usage numbers for admins. These go through `SECURITY DEFINER` functions in the `passbox` schema, owned by the migrator, with `SET search_path = pg_catalog, public`. Rules for them:

- one narrow question each, with the narrowest return value (a boolean, an ID, a few columns); never `SETOF` a whole table,
- they check the caller's context themselves (for example `passbox.in_auth()` or `passbox.account_id()`), so calling them from the wrong context returns nothing,
- `EXECUTE` is revoked from `PUBLIC` and granted only to the server's roles.

Policies use the same kind of functions for membership (`passbox.my_orgs()`, `passbox.my_vaults()`, `passbox.is_org_admin(org)`), which keeps policies fast and stops them from recursing into each other. Two views, `account_directory` (id and email of related accounts) and `public_keys`, expose the columns other members may see.

## What row level security protects

- **Forgotten filters.** A query without its tenant condition returns only the caller's rows instead of everyone's.
- **Writes across tenants.** `WITH CHECK` refuses rows that name another account, vault or organization, and `UPDATE`/`DELETE` cannot reach rows the caller cannot see.
- **Privilege escalation through data.** An account cannot make itself instance admin (column grant), join an organization without an invitation, or write into another organization's audit chain.
- **Machine credentials.** A SCIM or events token, even with a bug in its handler, stays inside its organization.
- **Background jobs.** A bug in, say, the webhook sender cannot read vault items: the worker role has no privileges on them.

## What it does not protect

- **A compromised server process.** The server sets the context; code running in it can set any context. Row level security limits mistakes, not an attacker with code execution. End-to-end encryption is what protects vault contents then.
- **The database owner, superusers and backups.** The migrator bypasses the policies, as does anyone with superuser access or a backup. Protect those credentials and backups separately.
- **Wrong decisions in the application.** If the application calls `as_account` with the wrong ID, the policies enforce that wrong ID. They also do not check roles inside an organization (who may share or manage); `api/access.rs` does.
- **Definer functions.** They bypass the policies by design. Review them like authentication code.
- **Availability and resource use.** A tenant can still create many rows within its own scope; rate limits and quotas live in the application.
- **Side channels.** Unique constraints and timing can reveal that a value exists elsewhere (for example an email or SSO domain already in use); the API answers those cases deliberately and uniformly.

## Coverage

All 68 tenant tables and the two global breach catalogue tables have `ENABLE` and `FORCE ROW LEVEL SECURITY`. `counters` (the global change sequences) has no tenant data and no policy; `_sqlx_migrations` belongs to sqlx. The policies, grouped:

| Tables | Who sees and changes rows |
| --- | --- |
| `accounts` | the account itself; the auth context (sign-in, sign-up); instance admins read and update (`disabled_at` and other granted columns only) |
| `sessions`, `device_tokens`, `two_factor_totp`, `webauthn_credentials`, `recovery_codes`, `account_recovery`, `account_events`, `trusted_devices`, `trusted_device_requests`, `sso_proofs`, `two_factor_challenges`, `device_links`, `recovery_sessions` | the account itself; the auth context where a flow needs it; admins of the account's organizations, instance admins and the organization's SCIM context read security status or end sessions (`passbox.manages_account`) |
| `login_attempts`, `recovery_attempts`, `sso_flows`, `sso_tickets` | the auth context only |
| `account_keys`, `key_log` | the account itself; others through `public_keys` and the key log functions |
| `vaults`, `items`, `item_versions`, `item_moves`, `attachments`, `vault_keys`, `vault_members`, `vault_manifests` | accounts with access to the vault (`passbox.my_vaults()`), writes only with write access (`passbox.my_writable_vaults()`); attachments also the cleanup job |
| `organizations`, `org_members`, `org_keys`, `org_groups`, `group_members`, `group_versions`, `org_policies`, `org_settings`, `org_invitations`, `org_security_reports`, `org_recovery_*`, `org_webhooks`, `org_event_tokens`, `org_audit_heads`, `org_audit_events` | members of the organization (admin-only tables check `passbox.is_org_admin`); invitees read their invitation; the events context, the webhook job and audit retention their organization's rows |
| `org_sso`, `sso_domains`, `sso_identities`, `scim_tokens`, `scim_users`, `scim_groups`, `scim_group_members` | members (admins write); the SSO and SCIM contexts of that organization |
| `service_accounts`, `service_account_grants`, `service_account_events`, `agent_grants`, `agent_events` | the owning account; whoever manages the account (`passbox.manages_account`) reads `service_accounts` |
| `emergency_grants`, `access_requests` | the two parties |
| `share_links` | the owner; the viewer only through definer functions |
| `breach_monitor_emails`, `breach_monitor_results` | the account itself; the breach monitoring job |
| `site_breaches`, `site_breach_catalog` | global public data (Have I Been Pwned's breach list): every named context reads; only the `worker:breach_catalog` job writes; `passbox_app` has `SELECT` only |
| `instance_state`, `instance_invites`, `admin_events` | instance admins; the meta context reads settings, the auth context reads and uses invitations; an account may append admin events it is the actor of |
| `mail_outbox` | every transaction with a context queues; instance admins read the status; the mail job delivers |
| `server_secrets` | the `secrets` system context at start only |

The exact policies are in `0002_rls.sql`; `crates/server/tests/api/rls.rs` checks that every table is forced and tries reads, writes and inserts across tenants, the escalation to instance admin, and each signed-out and machine context.

## For the hosted service

The hosted service runs the same code: one database, one schema, row level security per account and organization. The contexts make further isolation possible without changing handlers: a database per large customer (routing by organization before `Db` opens the transaction), separate worker credentials per job, and `pg_stat_statements` and logs per role. Settings are transaction-local, so a transaction-mode pooler in front of PostgreSQL works.

## Checklist: adding a table

1. Create it in a new migration (never edit a released one) with native types, `CHECK` constraints, foreign keys with `ON DELETE` and the indexes its queries need. IDs use `passbox.valid_id`.
2. In the same migration: `ALTER TABLE … ENABLE ROW LEVEL SECURITY; ALTER TABLE … FORCE ROW LEVEL SECURITY;` and at least one policy per context that needs the table, with `USING` and `WITH CHECK`. Use the membership functions (`passbox.my_vaults()`, `passbox.is_org_member(org)`), not subqueries on other tenant tables.
3. Grants: `GRANT SELECT, INSERT, UPDATE, DELETE ON … TO passbox_app` (inside `IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_app')`, as in `0002_rls.sql`), narrower if possible; `passbox_worker` only if a background job needs it, and only the privileges it uses.
4. If a signed-out flow or another tenant needs a value from it, add a narrow `SECURITY DEFINER` function in the `passbox` schema with a fixed `search_path` and a context check, and revoke `EXECUTE` from `PUBLIC`.
5. Query it only through a `Db` context, with `query!` macros; refresh `.sqlx/` (CONTRIBUTING.md).
6. Extend `tests/api/rls.rs` with a cross-tenant read and write attempt for the table. The forced-RLS check already fails for a table without `FORCE`.
