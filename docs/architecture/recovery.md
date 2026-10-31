# Account recovery, emergency access and adding devices

> **Draft.** Not reviewed by cryptographers and not audited. Formats may still change before the first release that ships them.

This document describes waves C1 (recovery through an organization or family), C2 (personal recovery code), C3 (emergency access) and C4 (adding a device with a code) as implemented. The planning sketch is in docs/planning/feature-gap.md §5.3 (German); where this document differs, this document is what the code does. It builds on the key hierarchy in [cryptography.md](cryptography.md) and the key pairs, key directory and organizations in [sharing.md](sharing.md).

All cryptography is in [`crates/core`](../../crates/core): `recovery::code`, `recovery::org`, `emergency` and `device_link`. The web app and the extension use it through `@passbox/core-wasm` and [`packages/client`](../../packages/client) (`PassboxClient`), the native apps through [`crates/client`](../../crates/client) and the FFI ([`crates/ffi/src/recovery.rs`](../../crates/ffi/src/recovery.rs)). The server ([`crates/server/src/api/recovery.rs`](https://github.com/passboxnet/server/blob/main/src/api/recovery.rs), `org_recovery.rs`, `emergency.rs`, `device_links.rs`, migration [`0001_baseline.sql`](https://github.com/passboxnet/server/blob/main/migrations/0001_baseline.sql)) stores sealed data and enforces who gets it when.

## What recovery means here

Passbox cannot reset a master password: nobody but the user knows it, and the account key is wrapped with a key derived from the master password **and** the Secret Key. Every recovery path therefore needs a second, independent way to the **account key**:

| Path | Who holds the second way | What the user needs | What happens afterwards |
| --- | --- | --- | --- |
| Recovery code (C2) | The user (Emergency Kit) | email, recovery code, second factor if 2FA is on | new master password, **new Secret Key**, new recovery code, all sessions revoked |
| Organization recovery (C1) | Admins who hold the organization's recovery key | email, a device, an out-of-band identity check by an admin | same as above |
| Emergency access (C3) | A trusted person | (the trusted person's own account) | read access to chosen vaults; no account takeover |

The account key itself never changes during a recovery, so vaults, items, shared vault copies, key pairs and organization memberships stay as they are. What changes is how the account key is wrapped (new AUK from the new master password and the new Secret Key), the OPAQUE record, and the recovery code record.

## Personal recovery code (C2)

```text
R           = 32 random bytes, shown as R1- + 11 groups of 5 Crockford Base32 characters
              (32 bytes + 2-byte checksum SHA-256("passbox/v1/recovery-code-checksum\0" || R)[0..2])
wrap_key    = HKDF-SHA256(ikm = R, info = "passbox/v1/recovery-code")
auth_secret = HKDF-SHA256(ikm = R, info = "passbox/v1/recovery-code/opaque")
wrapped     = XChaCha20-Poly1305(wrap_key, account_key, aad = "passbox/v1/recovery-wrap|{account_id}")
```

- **Setup** (opt-in at sign-up and in Settings → Recovery; needs a login in the last 10 minutes): the client generates `R`, registers a **second OPAQUE record** whose password is `auth_secret` (credential identifier `recovery|{account_id}`, the same server OPAQUE keys and context as the login) and uploads `wrapped`. The code is shown once, in the Emergency Kit (screen, PDF and print), and confirmed by typing its last four characters. Creating a new code replaces the old one; the account gets a mail (`recovery_code_created`).
- **Recovery** (signed out): the client runs an OPAQUE login with `auth_secret` against `recovery/code/start` and `/finish`. Only after the OPAQUE proof does the server return `wrapped` (and the account's key pairs), so a person who only knows the email gets nothing, and the server learns nothing about `R`. A wrong code is detected by the client (OPAQUE fails locally), like a wrong master password; the server also rejects forged finalizations and counts them. Unknown emails and accounts without a code run against a fake record, so the answers look the same.
- **Second factor:** when the account uses two-factor sign-in, `finish` returns `twoFactorMethods` instead of `wrapped`; the client sends a TOTP code or a two-factor recovery code to `recovery/two-factor` first (same replay protection and lockout as sign-in). Security keys are not offered on this path yet; an account whose only remaining second factor is a security key gets `recovery_needs_security_key`.
- **Verification on the device:** the client unwraps the account key and checks that it opens the account's own key pairs (`Keyring::load_account_keys`, which also checks the private keys against the public bundle). A server that returned some other wrapped key is detected before anything is changed.
- **New credentials** (`recovery/complete/start` and `/finish`, with the single-use recovery token, 15 minutes): new KDF salt, new Secret Key, new master password, a new OPAQUE record, the account key wrapped with the new AUK, and a new recovery code (a new second OPAQUE record and wrap). The server deletes every session, device token, device link and pending recovery session of the account and the old recovery record, then returns a session for the recovering device. The new Emergency Kit (new Secret Key and recovery code) opens right away. The account gets a `recovery_used` mail and the event `account_recovered_code`.

**What the code protects against and what not.** `R` has 256 bits of entropy, so the stored OPAQUE record and `wrapped` cannot be attacked offline, even with a full database copy. Whoever has `R` and the email (and the second factor, if 2FA is on) can take over the account: the Emergency Kit with a recovery code must be kept like cash, and the UI says so. The 2FA requirement means a stolen Emergency Kit alone is not enough for accounts with two-factor sign-in.

## Organization recovery (C1)

```text
recovery bundle = { org_id, key_version, enc_pk (X-Wing), creator_id, created_at }  signed by an owner/admin
recovery grant  = { org_id, key_version, account_id, account_bundle_hash, sealed_hash,
                    granter_id, granted_at }                                         signed by an owner/admin
                  sealed: the recovery private seed, purpose "org-recovery-key",
                  context (org_id, key_version, account_id)
escrow          = { org_id, account_id, account_bundle_hash, key_version,
                    recovery_bundle_hash, sealed_hash, created_at }                  signed by the member
                  sealed: the member's account key, purpose "recovery-escrow",
                  context (org_id, account_id, key_version)
approval        = { request_id, org_id, account_id, ephemeral_key_hash,
                    sealed_hash, approver_id, approved_at }                          signed by the approving admin
                  sealed: the account key for the requesting device, purpose "recovery-transfer",
                  context (request_id, account_id)
request code    = 4 groups of 5 digits from SHA-256("passbox/v1/recovery-request-code\0" || ephemeral_pk)
```

All objects use the canonical encoding and signatures of [sharing.md](sharing.md#canonical-encoding-and-domain-separation) (own type tags, so a signature over one type never verifies as another); sealing is the X-Wing sealing described there.

**On by default (since 25.10.2026).** Every organization created from now on, family or team, gets recovery set up right away: the creating client creates the recovery key (below), signs the organization's first policy with `require_recovery_enrollment = true` (`PolicyRules::new_org_defaults`, otherwise restricting nothing) and enrolls the creator. Members are enrolled automatically: the client seals the escrow as part of joining, as soon as an admin confirmed the membership (the server accepts escrows only from confirmed members), at the latest on the next unlock (`enrollRequiredOrgRecovery` / `enroll_required_org_recovery`, called after accepting, from the policy banner and after unlock). **Consent is explicit and honest:** the invitation preview carries `recovery: true` when the organization has recovery set up and its policy requires it, and the web app shows before "Accept invitation" that the organization's admins can restore the member's access, that the approving admin's device briefly holds the account key and could technically read the member's data, and that every recovery is logged and mailed. The create dialog tells the creator the same. **Guests are never enrolled** and policies that require recovery do not apply to them (an organization must not be able to take over an external person's account); the preview says `recovery: false` for them.

**Setup.** An owner or admin turns recovery on for an organization that does not have it yet (Settings → Recovery → "Set up recovery"; organizations created before 25.10.2026 keep the opt-in flow). Their client creates the recovery key pair, signs the public bundle and seals the private seed to itself. Admins who hold the key can seal it for other verified admins (`grant_org_recovery`); the server checks that the target is a confirmed owner or admin. Demoting or removing an admin deletes their copy on the server.

**Per member.** A member turns on "Allow recovery through {organization}" (or is enrolled automatically, above). Their client verifies the recovery bundle against the organization's verified roster (signed by a verified owner or admin, right organization and version), seals the account key to it and signs the escrow. The confirmation dialog says honestly that an approving admin could technically read the member's data. Where the policy requires recovery, the switch cannot be turned off; otherwise turning it off deletes the escrow (and cancels open requests). Removing a member from the organization deletes their escrow.

**Turning it off org-wide.** Admins can turn recovery off for everyone (`DELETE /api/v1/orgs/{id}/recovery`, `turnOffOrgRecovery`, Administration → Recovery): the recovery key, every admin's copy and every member's escrow are deleted and open requests cancelled. The server refuses with 403 `recovery_required` while the policy requires recovery, so admins first turn off "Require recovery" in the policy (a signed change members can see). Setting recovery up again later creates a new key; members then enroll again.

**Flow.**

1. The member's new device ("Forgot your master password?" → "Request recovery") creates an ephemeral X-Wing key pair, sends its public key with the email (`recovery/org/request`, no session) and keeps the private seed and a request token on the device (`localStorage` / the native store) until the request is approved, completed or expires (48 hours). The device shows the **request code**. The server answers the same for unknown emails and accounts without an escrow, and rate limits requests (10 per IP and 3 per email per hour); a new request replaces an open one.
2. The server mails the member (`recovery`) and the admins who hold the recovery key (`recovery_requested`, with a link to `#/recovery-requests`).
3. An admin opens the request in Passbox. The approval dialog asks them to verify the person **out of band** (call a number they already know, or talk in person; not contact details from the request) and to compare the request code the member reads to them with the one Passbox shows. Only then is "Approve" enabled.
4. The admin's client verifies the escrow (signed by the member's verified key, naming the current recovery key), opens the recovery key with its own key, opens the escrow, re-seals the account key to the ephemeral key and signs the approval. **The approving admin's client holds the member's account key in memory while it does this.** The server checks the approval's IDs, the ephemeral key hash and that it covers the sealed bytes, and mails the member (`recovery_approved`).
5. The member's device polls (`recovery/org/status` with its request token), checks the approval (request, account, its own ephemeral key, sealed hash, the approver's self-signed bundle), opens the account key, checks that it opens the account's key pairs, and sets new credentials exactly like after a recovery code (new master password, new Secret Key, new recovery code, all sessions revoked). The member and all recovery admins get `recovery_used`; the member's activity log shows `account_recovered_org`, the admins' `org_member_recovered`.

**Why the request code.** The server forwards the ephemeral public key from the device to the admin. A malicious server could substitute its own key and receive the account key. The request code is derived from the ephemeral key alone (not from server-chosen data), so to make the codes match the server would have to find a key pair whose code collides with the member's: about 2⁶⁶ attempts within the request's lifetime. The admin's client computes the code from the key it is about to seal to; the member's device from its own key.

**Families** use the same mechanism: the organizer is the owner; recovery is on from the start and family members are enrolled when they join (guests excepted).

## Emergency access (C3)

```text
grant  = { grant_id, grantor_id, grantor_bundle_hash, grantee_id, grantee_bundle_hash,
           scope = "vaults", wait_ms, vaults: [(vault_id, key_epoch)] sorted, version,
           sealed_hash, created_at }                                                signed by the grantor
sealed = Seal(grantee bundle, canonical("passbox/v1/emergency-keys", [(vault_id, key_epoch, key)]),
              purpose "emergency-access", context (grant_id, grantor_id, grantee_id, version))
```

1. **Invite.** The grantor adds a trusted person by email with a waiting period of 1 to 30 days (default 7). The server mails them (`emergency_access_invited`); they need a Passbox account.
2. **Accept.** The trusted person, signed in with that email, accepts.
3. **Confirm.** The grantor's client looks the trusted person up in the [key directory](sharing.md#key-directory-a4-first-version) (pinning the key, warning on changes) and shows the fingerprint to compare. The grantor chooses **personal** vaults; the client seals their keys (all key epochs it holds) to the trusted person's verified key and signs the grant. The server checks the IDs, the signature, the grantee's current key, that the signed waiting period equals the stored one and that the vaults are the grantor's personal vaults.
4. **Request.** The trusted person requests access. The grantor gets a mail (`emergency_access`, with the release date) and sees the countdown in Settings → Emergency access, where they can **decline** (also after the release, which ends access) or **allow now**.
5. **Release.** After the waiting period without a decline (or after "allow now"), `GET /emergency/grants/{id}/access` returns the sealed keys, the signed grant and the vaults' current ciphertexts. The trusted person's client looks the grantor up in the key directory, checks the grantor's signature and that the grant names its own current key, opens the keys and decrypts the vaults read-only (nothing is stored). The first access mails the grantor (`emergency_access_used`).

**Re-sealing.** On every unlock the grantor's client checks each confirmed grant (`emergency_reseal_needed`): if a chosen vault was deleted, the vault keys have new epochs, or the grantor's own key changed, it seals again with the next `version` (the server only accepts growing versions). Personal vaults have one key epoch today, so this mostly covers deleted vaults; it is in place for vault key rotation.

**Scope.** Only read access to chosen personal vaults is implemented. "Full takeover" (sealing the account key so the trusted person can set a new master password) was left out on purpose: it would give a third party the whole account, including organization memberships. Shared vaults are excluded because they belong to their organization.

**What the server enforces.** Confidentiality does not depend on the server: the keys are sealed to the trusted person's verified key. The **waiting period is enforced by the server**: a malicious server could release the sealed keys early, but only to the person the grantor chose and verified (as with Bitwarden). Declining or removing the contact stops future access; what the trusted person already opened they may have kept.

## Adding a device with a code (C4)

```text
code       = short_id (4 chars, chosen by the server) || secret (12 chars, chosen by the device; never sent)
             shown as XXXX-XXXX-XXXX-XXXX, Crockford Base32 (about 60 secret bits)
mac_key    = HKDF-SHA256(ikm = secret, salt = short_id, info = "passbox/v1/device-link")
claim mac  = HMAC-SHA256(mac_key, canonical("passbox/v1/device-link-claim", short_id, ephemeral_pk))
payload    = Seal(ephemeral_pk, {"email", "accountId", "secretKey"}, purpose "device-link", context (short_id))
```

1. A signed-in device (Settings → Recovery → "Add a device") opens a link (10 minutes) and shows the code, plus a QR code with `passbox-link:v1?server=<url>&code=<code>` for the mobile apps.
2. The new device ("Use a code from another device") types the code, creates an ephemeral X-Wing key pair and claims the link with its public key and the MAC (no session). The first claim wins; the server rate limits claims per IP.
3. The signed-in device polls the link, shows the new device's name and IP and asks "Was that you?". Approving checks the MAC (a server that swapped in its own ephemeral key would have to know the secret) and uploads the sealed payload.
4. The new device receives the payload once and asks for the **master password**, which is never transferred. It then signs in normally (with a second factor if the account uses one).

## Threat model

The server is untrusted for confidentiality, as in [cryptography.md](cryptography.md#goals). For recovery:

| A malicious or compromised server **cannot** | because |
| --- | --- |
| read a recovery code, account key, vault key or the payload of a device link | they are wrapped with keys derived from the code, sealed to recipients' X-Wing keys, or sealed to ephemeral keys |
| guess a recovery code offline from its database | `R` has 256 bits; the OPAQUE record and the wrap reveal nothing usable |
| hand someone the recovery wrap who only knows the email | it is released only after an OPAQUE login with the code (and the second factor); this is server-enforced, but the wrap is useless without `R` anyway |
| make a recovering device accept a wrong account key | the device checks that the key opens the account's own key pairs before changing anything |
| make a member escrow to a key the server controls | the recovery bundle must be signed by a verified owner or admin of the organization's signed roster |
| make an admin approve for a device the server controls, unnoticed | the request code the admin compares is derived from the ephemeral key; a substitute key gives a different code |
| forge an escrow, an approval or an emergency grant | they are signed by the member, the approving admin and the grantor; signatures are checked against verified keys |
| make a grantor seal vault keys to a key the server controls | the grantee's key comes from the key directory (pinned, changes are flagged) and the grantor can compare fingerprints |
| take over a new device through the device code | the claim is authenticated with a MAC under a secret the server never sees; the master password is never sent |

What it **can** still do (honest list):

- **Release emergency access early.** The waiting period is enforced by the server. It can also withhold the release, a decline or a request.
- **Deny service.** Refuse or delay recoveries, drop mails, claim device links first (the user then sees an error and shows a new code).
- **See metadata:** who set up a recovery code (not the code), who escrowed with which organization, who requested recovery when and from which IP, who trusts whom, waiting periods and which vault IDs are in a grant.
- **Trust on first use** in the key directory applies as in [sharing.md](sharing.md#goals-and-threat-model): if the grantor never compares fingerprints and the server shows a fake key on first contact, the grantor seals to the server's key. Fingerprints are shown for exactly this reason.

Trust that remains by design:

- **An approving admin can read the member's data.** Their client holds the member's account key while it re-seals it; a malicious admin client could keep it. This is the price of any admin recovery (1Password and Bitwarden are the same). Mitigations: members are told before they join (and can decline the invitation), guests are never enrolled, admins can turn recovery off org-wide, every approval needs an out-of-band check and the code comparison, every recovery is logged and mailed to the member and all recovery admins. Multi-admin approval (Shamir k-of-n) is not implemented yet.
- **A former recovery admin keeps what they had.** Demoting or removing an admin deletes their copy on the server, but they could have kept the recovery private key. The recovery key must then be rotated and members must escrow again; rotation exists in the protocol (key versions) but has no UI yet.
- **Whoever has the Emergency Kit with a recovery code** (and the second factor, if 2FA is on) can recover the account.

## Server storage and limits

Migration [`0001_baseline.sql`](https://github.com/passboxnet/server/blob/main/migrations/0001_baseline.sql): `account_recovery` (second OPAQUE record and wrap), `recovery_attempts`, `recovery_sessions` (token hashes, single use, 15 minutes), `org_recovery_keys`, `org_recovery_grants`, `org_recovery_escrows`, `org_recovery_requests` (token hashes, 48 hours), `emergency_grants`, `device_links` (claim token hashes, 10 minutes). Every request runs in a transaction that names its context first (`crate::db::Db`), and the tables have forced row level security ([database-security.md](database-security.md)).

Rate limits (in memory, per server process): recovery-code logins share the per-IP authentication limit and count failures per (email, IP) (10), per email (20) and per IP (100) in 15 minutes; the second factor uses the two-factor limits; organization recovery requests are limited to 10 per IP and 3 per email per hour; emergency invitations to 20 per account per hour and 20 contacts per account; device link claims to 10 per IP per minute and 5 open links per account.

Events (`account_events`): `account_recovery_code_created`/`_removed`, `account_recovery_failed`, `account_recovered_code`, `account_recovered_org`, `login_recovered`, `org_recovery_enabled`, `org_recovery_admin_added`, `org_recovery_enrolled`/`_withdrawn`, `org_recovery_requested`/`_approved`/`_denied`, `org_member_recovered`, `emergency_contact_added`/`_removed`, `emergency_invitation_accepted`, `emergency_access_confirmed`/`_requested`/`_approved`/`_denied`/`_used`, `device_link_created`/`_approved`.

Mails (English and German, `crates/server/src/mail/templates.rs`): `recovery_code_created`, `recovery_used`, `recovery`, `recovery_requested`, `recovery_approved`, `recovery_denied`, `emergency_access_invited`, `emergency_access`, `emergency_access_approved`, `emergency_access_denied`, `emergency_access_used`.

## Client APIs

| Operation | TypeScript (`PassboxClient`) | Rust (`passbox_client::Client`) / FFI (`PassboxClient`) |
| --- | --- | --- |
| Recovery code | `recoveryStatus`, `createRecoveryCode` (recent login), `removeRecoveryCode`, `recoveryOptions` (cached for the locked screen), `refreshRecoveryOptions` | `recovery_status`, `create_recovery_code(password)`, `remove_recovery_code(password)`; FFI `is_recovery_code` |
| Recover | `startCodeRecovery`, `completeRecoveryTwoFactor`, `recoveryReady`, `finishRecovery` → `{ secretKey, recoveryCode }`, `cancelRecovery` | same in snake case |
| Organization | `orgRecovery`, `setUpOrgRecovery`, `addRecoveryAdmin`, `enrollOrgRecovery`, `withdrawOrgRecovery`, `recoveryRequests` (with `requestCode`), `approveRecoveryRequest`, `denyRecoveryRequest` | same |
| Requesting device | `requestOrgRecovery`, `pendingOrgRecovery`, `checkOrgRecovery`, `cancelOrgRecovery` | same |
| Emergency access | `emergencyContacts`, `addEmergencyContact`, `acceptEmergencyInvitation`, `confirmEmergencyContact` (returns the fingerprint), `requestEmergencyAccess`, `approveEmergencyAccess`, `denyEmergencyAccess`, `removeEmergencyContact`, `openEmergencyAccess`, `resealEmergencyAccess` (after unlock) | same |
| Device code | `startDeviceLink`, `deviceLinkStatus`, `approveDeviceLink`, `cancelDeviceLink`, `claimDeviceLink`, `pollDeviceLink`, `isDeviceCode` | same; FFI `is_device_code` |

Endpoints are listed in [docs/api/openapi.yaml](https://github.com/passboxnet/server/blob/main/docs/api/openapi.yaml) under the tags `recovery`, `emergency` and `devices`.

## Tests

- Core: known-answer test of the recovery code encoding and derivation (computed independently with Python's `hashlib`/`hmac`), checksum and typo handling, wrong code, wrong account, tampering (`recovery::code`); organization recovery end to end, a swapped ephemeral key, forged approvals, bundles and escrows (`recovery::org::tests`); emergency access, tampering, wrong recipients and waiting-period bounds (`emergency`); device links with a swapped key and wrong codes (`device_link`).
- Server: `crates/server/tests/api/recovery.rs` (PostgreSQL with row level security): recovery code with and without a second factor, fake answers for unknown emails, single-use tokens, revoked sessions, rate limits; organization recovery with forged approvals, wrong request tokens, denial and opt-out; emergency access with signed waiting period checks, versions, decline, release after the waiting period and removal; device links.
- Rust client: `crates/client/tests/recovery.rs`. TypeScript: `packages/client/src/recovery.integration.test.ts`. Swift and Kotlin bindings: `RecoveryIntegrationTests.swift`, `FfiRecoveryTest.kt`. Web: unit tests and `e2e/tests/recovery.spec.ts` (recovery code, emergency access).

## Open issues

- Multi-admin approval (Shamir k-of-n of the recovery key). (A policy that makes the escrow mandatory exists, `require_recovery_enrollment`, and is on for new organizations.)
- The mobile apps do not call `enroll_required_org_recovery` yet (the FFI has it); members using only a mobile app are enrolled on their next web or desktop unlock.
- Rotating the organization recovery key (protocol supports key versions; no UI) after a recovery admin leaves.
- Security keys as the second factor of a recovery by code.
- Emergency "full takeover" (deliberately not implemented, see above), reminder mails during the waiting period, and a mail when the waiting period ends without action.
- Device codes: QR scanning in the web app, and handing over a session (the new device always needs the master password).
- Mobile UIs (the FFI is complete).
