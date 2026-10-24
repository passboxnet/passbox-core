# Service accounts

> **Draft.** Not reviewed by cryptographers and not audited. Formats may still change before the first release that ships them.

Wave F2 as implemented. The planning sketch is in [docs/planning/feature-gap.md](../planning/feature-gap.md) §5.8 (German); where this document differs, this document is what the code does.

A service account is a machine identity for CI pipelines, servers, scripts and AI agents. It has no master password. It belongs to the account that created it (its **owner**), has its own key pair, and can read (or read and write) the vaults the owner selected, until it expires or is revoked.

## Keys and token

All cryptography is in [`crates/core/src/service_account.rs`](../../crates/core/src/service_account.rs).

```
token      = "pbx_sa_" || id || "_" || base64url(secret)                    secret: 32 random bytes
auth_key   = HKDF-SHA256(ikm = secret, info = "passbox/v1/sa-auth|{id}")     sent to the server
auth_hash  = hex(SHA-256(base64url(auth_key)))                              stored by the server
wrap_key   = HKDF-SHA256(ikm = secret, info = "passbox/v1/sa-wrap|{id}")     never leaves the client

public     = canonical("passbox/v1/sa-public-key", id, owner_id, enc_pk (X-Wing), created_at)
public_sig = Ed25519(owner.sig_sk, public)
private    = XChaCha20-Poly1305(wrap_key,
               canonical("passbox/v1/sa-private", enc_seed, owner_id, owner_sig_pk),
               aad = "passbox/v1/sa-private|{id}")
```

- The **server never sees the secret**. It authenticates requests (`Authorization: Bearer sa.{id}.{auth_key}`) by comparing the hash of `auth_key`. `auth_key` and `wrap_key` are independent HKDF outputs, so knowing `auth_key` (the server, or a database dump) does not help decrypt `private`.
- The secret has 256 bits of entropy, so no password hashing is needed.
- The owner's client creates the key pair and the token, shows the token once, and keeps nothing. A lost token cannot be recovered; create a new service account.

## Vault access

```
sealed    = Seal(enc_pk, vault_key, purpose = "sa-vault-key",
                 context = canonical("passbox/v1/sa-vault-key-context", id, vault_id, epoch))
grant     = canonical("passbox/v1/sa-vault-grant", id, key_hash(public), vault_id, epoch,
                      permission (read|write), sealed_hash, owner_id, granted_at)
grant_sig = Ed25519(owner.sig_sk, grant)
```

- **Only the owner's keys count.** The owner's signing key travels inside `private`, which only the token holder can decrypt. The service account opens a vault key only with a grant signed by that key and matching the sealed bytes, so a server that sealed a key of its choosing to the (public) service account key, to feed it fake items, fails.
- **The public key cannot be swapped.** The owner signs it at creation and checks the signature before sealing more vault keys later (adding a vault or renewing after a rotation).
- **Never more than the owner.** On every request the server limits the service account to the lower of its grant and the owner's current access: if the owner loses access to a shared vault (or can only view it), so does the service account, at once.
- **Key rotation.** When a shared vault's key is rotated (a member was removed), the service account keeps the old epoch's key but cannot read items re-encrypted with the new one. The web app shows "Renew access" for such grants; renewing seals the current key. This is deliberate: a rotation is the cryptographic removal step, and continuing access should be a visible decision.
- **Revocation and expiry** are enforced by the server (no ciphertext is served, writes are refused, sealed keys are deleted on revocation). A sealed key cannot be taken back cryptographically: someone who kept a copy of the token and the server's data could still decrypt what they already downloaded. Rotate the vault key (remove and re-add a member, or create a new vault) if a token leaked and the vault holds long-lived secrets.

## Server

Migration [`0011_service_accounts_agents.sql`](../../crates/server/migrations/0011_service_accounts_agents.sql): `service_accounts`, `service_account_grants` (one row per vault and key epoch), `service_account_events`. The name is visible to the server (like a device name).

Owner endpoints (signed-in session): `GET/POST /api/v1/service-accounts`, `PUT/DELETE /service-accounts/{id}`, `PUT /service-accounts/{id}/grants`, `DELETE /service-accounts/{id}/grants/{vault_id}`, `POST /service-accounts/{id}/revoke`, `GET /service-accounts/{id}/events`.

Service account endpoints: `GET /api/v1/service-account` (everything it can read: its encrypted private key, grants, vaults with the effective permission, items), `PUT/DELETE /service-account/items/{id}`, and the agent endpoints (`/service-account/agent-grants`, `/service-account/agent-events`, see [ai-agents.md](ai-agents.md)).

Checks: uploads must parse; the public key and each grant must be signed by the owner's published key and name the service account, vault, epoch and sealed bytes of the request; grants need the vault's current epoch and, for `write`, the owner's write access. Limits: 50 service accounts per account, 200 grants per service account, 600 requests per service account and minute. Every read and write is logged in `service_account_events`; creation, access changes, revocation and deletion appear in the owner's activity.

## Clients

- Rust: `passbox_client::ServiceAccountClient` (connect with a token, list vaults and items, create/update/trash/delete items), and `Client::create_service_account`, `grant_service_account`, `service_accounts`, `revoke_service_account` for owners.
- CLI: `PASSBOX_SERVICE_ACCOUNT_TOKEN` (with `PASSBOX_SERVER`) switches every vault command to the service account; see [cli.md](../cli.md).
- Web: **Developer → Service accounts** (`apps/web/src/developer`): create (name, vaults with read or read/write, expiry), copy the token once, add or renew vault access, see activity, revoke, delete. TypeScript API in `packages/client` (`createServiceAccount`, `grantServiceAccount`, …).

## Not yet built

- Organization-owned service accounts managed by admins (today a service account belongs to one person and is limited by their access), IP restrictions, token rotation in place (create a new one, then revoke the old).
- OIDC federation for CI (exchange a GitHub Actions OIDC token for short-lived access instead of storing a token).
