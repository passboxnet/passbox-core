# Organization administration: admin console, policies, audit log, reports, SIEM

> **Draft.** Not reviewed by cryptographers and not audited. Formats may still change before the first release that ships them.

This document describes wave D of [docs/planning/feature-gap.md](../planning/feature-gap.md) as implemented: D1 (admin console), D2 (signed policies), D3 (organization audit log), D4 (offboarding), D5 (events API and webhooks) and D6 (reports). It builds on organizations, groups and shared vaults ([sharing.md](sharing.md)) and on recovery through the organization ([recovery.md](recovery.md)).

The cryptography is in [`crates/core`](../../crates/core): `policy` (signed policies, verification, pinning, combination) and `audit` (the hash chain, signed client events). The web app and the extension use it through `@passbox/core-wasm`, the native clients through `crates/client` and `crates/ffi`. Everything described here is part of the self-hosted server; there is no separate edition.

## What the server can and cannot do

The server stays untrusted for confidentiality and integrity of vault contents. For administration that means:

| A malicious or compromised server **cannot** | because |
| --- | --- |
| loosen a policy, invent one, or change a single rule | policies are Ed25519-signed by an owner or admin and verified against the organization's verified roster |
| bring back an older, looser policy on a device that saw a newer one, or make it forget the policy | clients pin the newest verified version with its rules; a lower version (rollback), a different policy with the same version (fork), an invalid one or none at all leave the pinned rules in force and raise a warning |
| invent "viewed", "revealed", "copied" or "filled" events | client events are signed with the member's account key; the server and every reader of an export can check the signature |
| change or delete audit entries unnoticed by someone holding an earlier export or a SIEM copy | entries are hash-chained; a change breaks the chain at that entry, a deletion leaves a gap, retention records the hash the remaining chain links to |
| learn vault names, item titles or passwords through reports | reports are server metadata plus numbers that members' apps compute locally |

What it **can** still do (honest list):

- **Withhold.** It can keep a newer policy from a device that has not seen it yet, and the first policy a new device sees is trusted on first use, like the roster it is checked against. It can stop writing audit entries or drop client events before storing them.
- **Rewrite the audit log from a point on.** Whoever controls the database can recompute every hash after a change. The chain only makes tampering visible to someone with an earlier head: export regularly or connect a SIEM (D5).
- **Enforcement happens in the apps.** A modified app can ignore a policy (fill without logging, export anyway). The server additionally enforces what it sees itself: it refuses turning two-factor sign-in off for members of an organization that requires it, and it refuses new personal vaults and new items in personal vaults when an organization turned them off.
- **Client events are only as complete as the apps.** A modified or old app can stay silent. This holds for every zero-knowledge password manager.
- **Metadata.** The server sees who belongs to which organization, group and vault, roles, sign-in times, when items change and, with item usage on, which item IDs are used when.

## D1: Admin console

Owners and admins of an organization open it from the organization page ("Admin console") or the sidebar ("Admin: {name}"); route `#/org/{id}/admin/{section}`. Families get the same console without groups and integrations. Sections:

| Section | What it shows and does |
| --- | --- |
| Overview | members, two-factor coverage, recovery enrollment, average security score, vaults and pending key rotations, policy version and verification, audit chain status, and a "needs your attention" list (people waiting for confirmation, recovery requests, vaults waiting for a new key, a broken chain, a policy that needs re-signing, members without required two-factor sign-in, no policy, no recovery, unused vaults) |
| Members | table with role, status, two-factor, recovery enrollment, last sign-in and security score; filters (waiting, without two-factor, paused) and search; invite, confirm (security code comparison), change role, pause and lift the pause, offboard (D4); pending invitations with revoke |
| Groups | the existing group management (create, rename, members, delete) |
| Vaults | every shared vault with people, managers, items, last activity and badges (no access for you, waiting for a new key, unused); who can open it and through which group; manage access and replace the key where this account manages the vault; create shared vaults |
| Policies | D2, see below |
| Activity log | D3, see below |
| Reports | D6, see below |
| Recovery | setting up the recovery key, adding approvers, enrollment coverage, pending requests with approval |
| Integrations | D5: events API tokens and webhooks |
| Settings | audit log retention, renaming, leaving or deleting the organization |

Vault names are encrypted with vault keys. The console shows the names of vaults the admin is a member of and "Vault …abc123 (no access)" otherwise; this is the zero-knowledge boundary, not a gap.

## D2: Policies

### Object

```
policy = canonical("passbox/v1/org-policy",
           org_id, version (u64, from 1), prev_hash (32 bytes, zero for version 1),
           rules: [(name, value)] sorted by name, unique, at most 64,
           signer_id, created_at)
signature = Ed25519(signer.sig_sk, "passbox/v1/signature\0" || policy)
```

Rules are string pairs, so new rules do not need a new object format: a client that does not know a rule still verifies the signature, enforces the rules it knows and reports the rest (`unknownRules`, banner "update the app"). Known rules and their enforcement:

| Rule | Values | Enforced by |
| --- | --- | --- |
| `require_two_factor` | `true`/`false` | apps ask members to turn it on (banner, settings); **server** refuses turning it off (`403 policy_violation`); reports list members without it |
| `min_password_score` | `0`–`4` | apps compare the zxcvbn score of the master password entered at unlock (the password never leaves the device); banner asks for a stronger one; reports show "meets the policy" per member |
| `max_auto_lock_minutes` | `0` (no limit) to `1440` | web and desktop app clamp the auto-lock setting; the extension keeps the limit also while locked and after restarts |
| `forbid_export` | bool | export leaves the organization's vaults out (export runs on the device) |
| `forbid_external_sharing` | bool | no app function takes items out of an organization's vaults today ("Share" only copies personal items into shared vaults); `canMoveBetween` in the TS client is the check for moving and copying (B5) and share links (B7) when they arrive |
| `share_links` | `allowed`/`restricted`/`forbidden` | `PolicyRules::check_share_link` (core, wasm `shareLinkProblem`) for share links (B7); the share link implementation calls it before creating a link |
| `share_link_max_days`, `share_link_max_views` | `1`–`365`, `0` = unlimited (only with `restricted`) | as above |
| `require_recovery_enrollment` | bool (`true` in the first policy of every organization created since 25.10.2026, see [recovery.md](recovery.md)) | banner with one-click enrollment; reports and the recovery section list who is missing |
| `allow_personal_vault` | bool, default `true` | apps do not create personal vaults or new items in them; **server** refuses both (`403 policy_violation`); existing items stay readable so they can be moved |
| `report_item_usage` | bool, default `false` | members' apps sign and upload "viewed", "revealed", "copied" and "filled" events for this organization's vaults; members see that it is on ("Policy" on the organization page) |
| `allow_agent_reveal` | bool, default `false` | members may let AI agents see values of this organization's items (`passbox_reveal`), each time with an explicit tick in the approval; checked by the approving app's core, the agent broker and the server (403 `policy_violation` / `agent_reveal_not_allowed`). Policies signed before the rule existed, and organizations without a policy, forbid it ([ADR 0006](../adr/0006-ai-principles.md)) |

### Verification and pinning

`verify_policy` checks that the policy parses, names the organization, has the version of the record and is signed by an **active, verified owner or admin** of the verified roster. `Keyring::evaluate_sharing` runs it on every sync (`sharing.policies` in `GET /api/v1/sync?sharing=1`, the newest version of every organization) and keeps the newest verified version with its rules in the trust store (`TrustStore.policies`):

- a newer verified version replaces the pin (`source: "verified"`);
- an older version (`policy_rollback`), another policy with the same version (`policy_conflict`), an invalid one (`policy_invalid`) or none (`policy_missing`) keep the pinned rules (`source: "pinned"`) and raise a warning;
- a policy that verified before but whose signer is no longer an active admin (`policy_needs_resign`) keeps working on devices that pinned it; new devices cannot verify it. The console offers "Sign again", and offboarding an admin who signed the policy re-signs it automatically (same rules, next version).

`EffectivePolicy` combines the policies of organizations the account is a confirmed (or paused) member of: account-wide rules take the strictest value (two-factor required if any organization requires it, the highest minimum score, the lowest auto-lock limit, personal vaults off if any organization turns them off); rules about an organization's own vaults stay per organization (`exportBlockedOrgs`, `externalSharingBlockedOrgs`, `itemUsageOrgs`, `recoveryEnrollmentOrgs`).

Signing (`Keyring::sign_org_policy`) uses the pinned version as predecessor; the server only accepts `version = current + 1` with `prev_hash = hash(current)` (otherwise `409`, the client syncs and retries once). The server also validates every rule value and stores the parsed rules for its own enforcement; clients never trust that copy.

Tests: `policy::tests` (rules, canonical encoding, combination, rollback, forgery, missing policy, signer roles), server `org_admin` integration test (upload, conflicts, forged signatures, sync delivery, enforcement), TS `admin.integration.test.ts` (sign, verify, enforce, re-sign after offboarding).

## D3: Audit log

### Entries and the chain

Per organization, `org_audit_events` (migration 0009) with a head row (`org_audit_heads`) that serializes appends:

```
hash(n) = hex(SHA-256("passbox/v1/audit-hash\0" || canonical("passbox/v1/audit-entry",
            prev_hash, org_id, seq, id, created_at, actor_id, actor_email, device_name,
            client_kind, ip, action, target_type, target_id, details, client_event, client_signature)))
prev_hash(1) = ""          prev_hash(n) = hash(n-1)
```

`passbox_core::audit::verify_chain(entries, anchor)` recomputes the chain: consecutive sequence numbers, links and hashes; `anchor` is the hash the first entry must link to (`""` for entry 1, the head of an earlier export, or the `prunedHash` after retention). It runs on the server (`GET /orgs/{id}/audit/verify`), in the web app on the device ("Check on this device" downloads the whole log and checks it with WebAssembly), and anywhere with the core (wasm `verifyAuditChain`, FFI `verify_audit_chain`).

### What is logged

Server events are written in the same transaction as the change wherever possible:

| Category | Actions |
| --- | --- |
| Sign-ins (from the account activity log, mirrored into every organization the account is an active member of) | `member_signed_in`, `member_sign_in_failed`, `member_two_factor_failed`, `member_sessions_revoked`, `member_sessions_ended` |
| Account security (mirrored) | `member_password_changed`, `member_two_factor_added`/`_removed`/`_disabled`, `member_recovery_codes_regenerated`, `member_recovery_code_used`, `member_account_recovery_code_created`/`_removed`, `member_device_added`, `member_emergency_access_used` |
| Membership | `member_invited`, `invitation_revoked`, `member_joined`, `member_confirmed`, `member_role_changed`, `member_reattested`, `member_suspended`, `member_reactivated`, `member_removed`, `member_left` |
| Groups | `group_created`, `group_renamed`, `group_deleted`, `group_member_added`, `group_member_removed`, `group_key_rotated` |
| Vault access | `vault_created`, `vault_renamed`, `vault_access_granted`, `vault_access_revoked`, `vault_key_rotated` |
| Writes | `item_created`, `item_updated`, `item_deleted` (shared vaults only), `vault_items_written` (re-encryption batches) |
| Recovery | `recovery_key_created`, `recovery_admin_added`, `recovery_enrolled`, `recovery_withdrawn`, `recovery_requested`, `recovery_request_approved`, `recovery_request_denied`, `recovery_completed` |
| Administration | `org_created`, `org_renamed`, `org_key_rotated`, `policy_updated`, `settings_updated`, `audit_exported`, `event_token_created`/`_revoked`, `webhook_created`/`_deleted` |
| Item usage (client events) | `item_viewed`, `secret_revealed`, `item_copied`, `item_filled` |

Item contents never appear: targets are IDs (accounts, vaults, groups, items), details are small JSON objects (roles, counts, field names such as `password`).

### Client events

With `report_item_usage` on, the apps sign each event with the account key:

```
client event = canonical("passbox/v1/client-audit-event",
                 org_id, account_id, key_version, action, vault_id, item_id, field, occurred_at, nonce (16 bytes))
```

The web app reports opening an item, revealing a hidden field, copying (username, password, one-time code, previous passwords, other fields) and large type; the extension reports filling. Events are signed at once, queued per account in local storage (they contain only IDs) and uploaded in batches of up to 200 (`POST /orgs/{id}/audit/client-events`), also after the next unlock. The server checks the signature against the uploader's published key, that the vault belongs to the organization and the uploader can open it, that the time is within the last 7 days (and at most 10 minutes ahead), and drops duplicates by nonce. The signed event is stored with the entry, so readers can verify it independently (wasm `verifyClientEvent`).

### Reading, filters, export, retention

- `GET /orgs/{id}/audit?before|after&limit&action&actor&target&from&to&source`: admins; `action` is an exact action, a prefix ending in `*` or a comma-separated list; `source` is `server` or `client`.
- `GET /orgs/{id}/audit/export?format=json|csv&…`: up to 100,000 entries, oldest first. JSON (`format: "passbox-audit-log"`, `version: 1`, `head`, `events`) is verifiable; CSV quotes every field and neutralizes spreadsheet formulas. Exports are logged themselves (`audit_exported`).
- Retention (`PUT /orgs/{id}/settings { auditRetentionDays }`, 0 = forever or 30–3650): a background task deletes older entries hourly and records `pruned_seq`/`pruned_hash`, so the remaining chain still verifies.
- Deleting the organization deletes its log. The owner's account activity keeps `org_deleted`.

## D4: Offboarding

"Offboard…" in the members section, or `PassboxClient.offboardMember(orgId, accountId, { handovers, endSessions })`:

1. **Review.** The dialog lists the vaults the member can open (directly or through groups), their groups, and vaults where the member is the **only manager**.
2. **Hand over.** For each such vault the admin can choose a successor; the admin's device grants `manage` with a new signed manifest version. This needs the vault key on the admin's device, so the admin must be a member of the vault. Where the admin has no access, the dialog says so: ask the member to share the vault with a successor first; otherwise the vault keeps its members and stays readable, but only admins who are members can change who has access.
3. **End sessions** (team organizations, on by default): the server deletes every session of the account (`POST /orgs/{id}/members/{aid}/end-sessions`, logged as `member_sessions_ended`). Sessions belong to the whole account, so this also ends access to the member's personal vaults until they sign in again; nothing is deleted. Only the owner can sign out admins; nobody can sign out the owner.
4. **Remove.** The server ends access at once (memberships, sealed keys, escrow, recovery grants) and marks the affected vaults `rotationPending`. The admin's device then rotates the groups and vaults it manages (new epoch, items re-encrypted), re-attests members the removed admin had attested, rotates the organization key and, if the removed admin signed the policy, signs it again.

**What rotation requires.** Replacing a vault key needs a device that holds the current key and may sign the vault's member list: a `manage` member of the vault, or an admin who is a member. Vaults the offboarding admin cannot manage stay `rotationPending`; the console shows them ("waiting for a new key"), and the first of their managers to unlock rotates them automatically. Until then the removed member has no server access, but the old key still decrypts items they may have downloaded before. Rotation protects new and changed items only; the dialog ends with "change the passwords they had access to".

**Escrow-based handover is not implemented.** With recovery through the organization, an admin who holds the recovery key could in principle open a member's escrowed account key, unwrap the member's own copies of vault keys and grant them to a successor, even for vaults the admin is not a member of. This needs (a) an admin endpoint that delivers a vault's manifest chain and the member's wrapped keys to a non-member admin, (b) a core function that opens the escrow and adds the vault keys to the admin's keyring for one signed manifest change, and (c) a policy decision, because it lets admins reach vaults they were never given. It is documented as an open issue.

## D6: Reports

`GET /orgs/{id}/reports` (admins) returns, from server metadata:

- **Members:** role, status, joined, two-factor (TOTP, security keys), recovery enrollment (escrow for the current recovery key), last sign-in, groups, number of vaults they can open, and the last security aggregate.
- **Vaults:** creation, key epoch, rotation pending, item count, last write, last logged use, members and managers, and `unused` (no writes and no logged use for 90 days).
- **Access:** the effective role per person and vault with the path (`direct` and/or group IDs).
- **Counts:** `memberCount` (confirmed members who are not guests, the billable members of the hosted service), `guestCount` (confirmed guests: free and view-only), `serviceAccountCount` (active service accounts of the members: free, fair use) and `agentLimitPerMember` (0 = unlimited). The overview shows members, guests and agents as separate tiles; the members list says "n members · m guests (free, view-only, not counted as members)". Recovery enrollment shares are computed over members, not guests.

**Security aggregates.** Once a day after unlocking, each member's app sends every team organization it is a confirmed member of `PUT /orgs/{id}/security-report { score, total, weak, reused, unsecured, passwordMeetsPolicy }`, computed by the Watchtower analysis over the logins the member can see in personal vaults and the organization's vaults. Only numbers leave the device; the server checks ranges. The web console shows a security table with "only problems", an access matrix (view/edit/manage, through groups), unused vaults and a CSV export of the security table.

## D5: Events API and webhooks

**Pull.** An admin creates a token (Integrations → New token, `POST /orgs/{id}/event-tokens`); it is shown once and stored as SHA-256. A collector calls

```
GET /api/v1/org-events?after={seq}&limit={1..1000}
Authorization: Bearer pbxe_…
→ { orgId, events: [AuditRecord…] (oldest first), head: { seq, hash, prunedSeq, prunedHash }, nextAfter, hasMore }
```

and stores `nextAfter`. Each entry carries `prevHash` and `hash`, so the collector keeps an independent copy of the chain and can alert when `prevHash` of the first new entry differs from the last stored `hash`. Tokens are limited to 120 requests per minute and can be revoked at once.

**Push.** An admin registers an HTTPS URL (`POST /orgs/{id}/webhooks { url, fromStart }`) and receives a signing secret once. A background task POSTs batches of up to 100 new entries:

```
POST {url}
Content-Type: application/json
X-Passbox-Timestamp: 1792834007
X-Passbox-Signature: v1=<hex HMAC-SHA256(secret, "{timestamp}.{body}")>

{ "orgId": "…", "webhookId": "…", "events": [ … ], "head": { … } }
```

Verify the signature with the secret and reject timestamps older than a few minutes. A 2xx answer advances the cursor; anything else is retried with exponential backoff (30 s doubling, at most 1 h); the console shows failures and the last error. Webhook URLs must use HTTPS and resolve to public addresses; redirects are not followed. Self-hosters with a SIEM in the same network set `PASSBOX_WEBHOOK_ALLOW_PRIVATE=true` (then plain HTTP is allowed too). The address check runs before each delivery; DNS rebinding between the check and the connection is a residual risk on servers that allow organization admins they do not trust.

### SIEM guides

- **Splunk.** Either a scripted or modular input that calls the pull API every minute and writes each entry as one JSON event (`sourcetype=passbox:audit`, `_time` from `createdAt` in milliseconds), keeping `nextAfter` in a checkpoint file; or an HTTP Event Collector behind a small relay that checks `X-Passbox-Signature` and forwards `events[]` as HEC events. Useful searches: `action=member_sign_in_failed | stats count by actorEmail, ip`, `action=item_copied targetId=…`.
- **Microsoft Sentinel.** Use the Codeless Connector Framework (or a Logic App) with a REST API poller: paging by `after`/`nextAfter`, header `Authorization: Bearer pbxe_…`, into a custom table `PassboxAudit_CL`. Map `createdAt` with `datetime(1970-01-01) + createdAt * 1ms`. Analytic rule example: more than 10 `member_sign_in_failed` per `actorId` in 15 minutes.
- **Elastic.** Filebeat/Elastic Agent `httpjson` input with `request.url: https://passbox.example.com/api/v1/org-events`, `request.transforms` setting `after` from `[[.last_response.body.nextAfter]]`, `response.split.target: body.events`, into an index or data stream `logs-passbox.audit-*`; or point a webhook at a Logstash `http` input that verifies the signature.
- **Graylog, Wazuh** and others: any HTTP poller or webhook receiver works the same way.

## Storage (migration 0009)

Tables (migration [`0001_baseline.sql`](../../crates/server/migrations/0001_baseline.sql), policies in `0002_rls.sql`): `org_policies` (every version, signed, with the parsed rules), `org_audit_heads`, `org_audit_events` (indexes per organization and time, actor and action; unique client nonce), `org_settings` (retention), `org_security_reports`, `org_event_tokens` (token hashes), `org_webhooks` (URL, secret, cursor, backoff, last status).

## API summary

| Endpoint | Who |
| --- | --- |
| `GET /orgs/{id}/policy` (`current`, `history` for admins) · `PUT /orgs/{id}/policy` | members · owners and admins |
| `GET /orgs/{id}/audit` · `/audit/verify` · `/audit/export` | owners and admins |
| `POST /orgs/{id}/audit/client-events` | confirmed members, with `report_item_usage` |
| `GET /orgs/{id}/reports` · `PUT /orgs/{id}/security-report` | owners and admins · confirmed members |
| `GET`/`PUT /orgs/{id}/settings` | owners and admins |
| `POST /orgs/{id}/members/{aid}/end-sessions` | owners and admins of teams |
| `GET`/`POST /orgs/{id}/event-tokens` · `DELETE …/{tid}` · `GET`/`POST /orgs/{id}/webhooks` · `DELETE …/{wid}` | owners and admins |
| `GET /org-events` | events API token |

## Client APIs

| | TypeScript (`PassboxClient`) | Rust (`passbox_client::Client`) / FFI | WebAssembly |
| --- | --- | --- | --- |
| Policies | `getSnapshot().policies`, `.effectivePolicy`, `policies()`, `orgPolicy()`, `effectivePolicy()`, `setOrgPolicy()`, `policyHistory()`, `unlockPasswordScore` | `org_policies`, `effective_policy`, `set_org_policy` | `signOrgPolicy`, `verifyOrgPolicy`, `orgPolicy`, `effectivePolicy`, `shareLinkProblem` |
| Audit | `orgAdmin.audit/verifyAudit/exportAuditCsv`, `exportAuditLog()` (verifies on the device), `verifyAuditExport()`, `reportItemUsage()`, `flushItemUsage()` | `verify_audit_chain` (free function) | `signClientEvents`, `verifyAuditChain`, `verifyClientEvent` |
| Offboarding, reports | `offboardMember()`, `orgAdmin.reports/endSessions`, `reportSecurityAggregates()` | – | – |
| Helpers | `clampAutoLock`, `canExportVault`, `canMoveBetween`, `policyTasks`, `securityAggregate`, `AUDIT_CATEGORIES`, `PolicyViolationError` | – | – |

## Open issues

- Escrow-based vault handover (see D4) and a policy rule that allows or forbids it.
- Signed policies for extension autofill rules and passkey unlock (listed in the planning document, not yet rules).
- Mobile and desktop apps read `effective_policy` through the FFI but do not show the admin console or report item usage yet.
- Webhook delivery checks the address before connecting but does not pin the resolved address; organizations whose admins are not trusted by the instance should keep private addresses disallowed and use an egress proxy.
- Audit entries are written by the server; there are no external witnesses for the chain head yet beyond exports and SIEM copies.
