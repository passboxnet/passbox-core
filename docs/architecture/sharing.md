# Key pairs, key directory, organizations and sharing

> **Draft.** Not reviewed by cryptographers and not audited. Formats may still change before the first release that ships them.

This document describes waves A1 (account key pairs), A4 (key directory, first version), B1 (organizations, invitations, roles), B2 (shared vaults), B3 (groups), B4 (families), B5 (moving items between vaults), B7 (share links), B8 (guests) and B9 (access requests) as implemented. The planning sketch is in docs/planning/feature-gap.md §5.1–5.2 (German); where this document differs, this document is what the code does.

All cryptography is in [`crates/core`](../../crates/core): `identity` (key pairs, sealing, signatures), `canon` (canonical encoding), `directory` (key log), `sharing/*` (signed objects, verification, request builders). The TypeScript client uses it through `@passbox/core-wasm`, the native clients through `crates/client` and `crates/ffi`. The server stores and serves; it verifies uploads only to keep garbage out, never as a security boundary for clients.

## Goals and threat model

The server is untrusted for confidentiality and integrity of vault contents (see [cryptography.md](cryptography.md)). For sharing that means:

| A malicious or compromised server **cannot** | because |
| --- | --- |
| read shared vault keys, items, organization or group names | keys are sealed to members' X-Wing keys; names are encrypted with the organization key |
| make a client seal a key to a key the server controls, for a member the client already verified | members' keys are attested by the owner or an admin and pinned on first sight; the confirming admin looks the key up in the key directory and can compare fingerprints |
| add a member to a vault, raise a role or hand out a key | vault members come from a hash-chained manifest signed by a manager or admin; keys are only opened with a grant signed by the manifest's signer that matches the manifest entry and the sealed bytes |
| swap an organization for another one (for example during an invitation) | the organization's genesis hash is pinned on first contact and carried in the invitation link (`#org=`) |
| roll back a vault's member list to an earlier version, or fork its history | clients pin the latest manifest version and hash and require the chain to contain it |
| show a client one key for an account and later deny it, or replace a key the client pinned | the key log is append-only and hash-chained; clients keep the last verified head and check consistency |
| keep a removed member reading new data | removal rotates the vault key (new epoch); the server deletes the removed member's keys and memberships at once |

What it **can** still do (known limits, honest list):

- **Withhold and delay.** It can hide new items, a new manifest version, a removal or a re-attestation (rollback within what the client has not seen yet). The planned signed revision chain (A5) and head gossip address this.
- **Split view in the key directory.** Two clients that never compare heads can be shown different logs. There are no external witnesses or head gossip yet; the log is a hash chain, not a Merkle tree, so proofs are linear in the number of entries since the client's last head (bounded by 10,000 per lookup).
- **First contact (TOFU).** The first time a client sees an organization without an invitation link fragment, or an account's key, it trusts what it is shown. Comparing fingerprints out of band (`confirmMember` returns it, `ownFingerprint` shows one's own) removes this.
- **Metadata.** It sees who is in which organization, group and vault, roles, emails of members (to members), sizes, times and access patterns.
- **Server-side authorization.** Roles are enforced by the server (403), *and* signed. A server that ignored its own role checks could let a view-only member overwrite ciphertext; other clients would still decrypt only what was encrypted with the vault key (which that member has), so this is a denial-of-integrity limited to members who hold the key. View-only is a convenience boundary against honest servers, not a cryptographic one: anyone who can read a vault key can produce valid item ciphertexts.
- **Suspension** is server-side only. Removal is the cryptographic operation.
- **What a removed member saw**, they may have kept. Rotation protects new and changed data only; the web app says so when removing someone and suggests changing those passwords.
- **A compromised admin** (or owner) can attest a key of their choice and share vaults they manage. The design narrows trust to the owner and admins instead of the server; it does not remove it.

## Account key pairs (A1)

Each account has two key pairs, generated in the core on sign-up or on the first unlock after the update (migration of existing accounts; both clients do it in `sync` when `GET /api/v1/account/keys` answers 404):

- **Encryption:** X-Wing (draft-connolly-cfrg-xwing-kem, X25519 + ML-KEM-768 with a SHA3-256 combiner), RustCrypto `x-wing` 0.1.1, pinned exactly. The private key is a 32-byte seed from which both component keys are expanded with SHAKE256. Decapsulation rejects non-contributory X25519 shares. X-Wing was chosen over a hand-made combiner or HPKE with a separate ML-KEM because it is a single, analyzed hybrid KEM with published test vectors (checked in `identity::tests::xwing_draft_vector`) and is secure as long as either component holds.
- **Signing:** Ed25519 (`ed25519-dalek` 3.0.0, pinned exactly, strict verification, no precomputed tables to keep the WebAssembly small). A post-quantum or hybrid signature (ML-DSA) can be added with a new key version; signatures only need to be unforgeable now, not in the future, which makes them less urgent than encryption ("harvest now, decrypt later").

Both crates use `rand_core` 0.10 like the rest of the workspace; the core never passes them an RNG: seeds and encapsulation randomness come from `getrandom` (`random::bytes`), which works in browsers through the existing `wasm_js` bridge. MSRV stays 1.87 (the crates need 1.85).

```
private = XChaCha20-Poly1305(account_key, 0x01 | enc_seed (32) | sig_seed (32),
                             aad = "passbox/v1/account-keypair|{account_id}|{key_version}")
bundle  = canonical("passbox/v1/public-bundle", account_id, key_version, enc_pk (1216 B), sig_pk (32 B), created_at)
self_sig = Ed25519(sig_sk, "passbox/v1/signature\0" || bundle)
```

`Keyring::load_account_keys` refuses private keys that do not match the published public keys, so the server can substitute neither half. Private keys never leave the keyring (Rust) or WebAssembly memory; session exports (extension) include them, encrypted like the other keys (session format version 2, version 1 still imports).

**Fingerprint** of a bundle: SHA-512 over `"passbox/v1/fingerprint\0" || len(account_id) || account_id || sig_pk || enc_pk`, shown as 12 groups of five digits (about 199 bits). Organizations have a shorter fingerprint of their genesis hash (8 groups).

### Canonical encoding and domain separation

Every signed or hashed object uses `canon`: a type tag string followed by length-prefixed fields (`u32` lengths, `u64` integers, all big-endian), decoding rejects trailing bytes. Objects travel as Base64url of these bytes; receivers never trust a separate JSON copy. Tags (`passbox/v1/public-bundle`, `passbox/v1/org-genesis`, `passbox/v1/member-attestation`, `passbox/v1/org-key-grant`, `passbox/v1/group-bundle`, `passbox/v1/group-key-grant`, `passbox/v1/vault-manifest`, `passbox/v1/vault-grant`, `passbox/v1/key-log-entry`, `passbox/v1/key-log-head`) separate the domains: a signature over one type never verifies as another. Hashes: `SHA-256("passbox/v1/object-hash\0" || canonical)`; sealed bytes: `SHA-256("passbox/v1/sealed-hash\0" || sealed)`.

### Sealing

```
(ct, ss) = X-Wing.Encaps(recipient.enc_pk)
k        = HKDF-SHA256(ikm = ss, info = "passbox/v1/seal|{purpose}")
aad      = "passbox/v1/seal|{purpose}\0" || 0x01 0x01 || recipient_key_hash || context
sealed   = 0x01 (version) | 0x01 (X-Wing) | ct (1120 B) | XChaCha20-Poly1305 envelope
```

Purposes are `vault-key`, `group-key` and `org-key`; contexts are canonical encodings of (vault, epoch, principal), (group, key version, account) and (organization, epoch, account). Sealing is anonymous; the sender is authenticated by a signed grant covering the sealed hash. Known-answer, round-trip and tamper tests are in `identity::tests`.

## Key directory (A4, first version)

The server keeps an append-only log (`key_log`) of published bundles:

```
entry_hash(n) = object_hash(canonical("passbox/v1/key-log-entry", n, account_id, key_version, bundle_hash, entry_hash(n-1)))
head          = canonical("passbox/v1/key-log-head", size, entry_hash(size), timestamp), Ed25519-signed
```

The log signing key is generated on first start and stored with the other server secrets (`server_secrets.key_log_signing_key`); heads are signed on every request. Appends are serialized through a counter row.

A lookup (`GET /api/v1/keys/{id}?since=n`) returns the bundle, its entry and all entries up to the head. `DirectoryState::verify_lookup` checks the head signature against the pinned log key, that the head did not shrink, that the entries chain without gaps, pass through the client's last verified head (consistency) and end at the new head (inclusion), that the bundle matches its entry and that no newer entry exists for the account. Then the head advances. A key that differs from the pinned one is reported as `changed`; it is not pinned and sharing to it is refused (`KeyChanged`) until `acceptKeyChange`.

Clients use the directory when an admin confirms a member (mandatory: `confirm_member` refuses unless the member's key was looked up and pinned) and for **self-monitoring**: `verifyOwnKey` fails if the directory lists another key for the own account.

Tests: `directory::tests` (forks, rollback, forged heads, tampered entries, outdated keys, key change).

## Organizations, members, invitations (B1, B4)

```
genesis     = { org_id, kind (family|team), owner_id, owner_bundle_hash, created_at }   signed by the owner
attestation = { org_id, account_id, key_version, bundle_hash, role, attester_id, created_at }   signed by the owner or an admin
org key     = random 256-bit key per epoch, sealed per member with a signed org-key grant
metadata    = XChaCha20-Poly1305(org key, {"name": ...}, aad = "passbox/v1/org-meta|{org_id}|{epoch}")
```

**Roster verification** (`verify_roster`): the genesis must be signed by the key whose hash it names (the owner's bundle); its hash is pinned per organization. A member is verified if their attestation matches their bundle and is signed by an already verified, confirmed owner or admin (fixed point over the roster). `owner` is reserved for the genesis owner. Unverified members are shown with the reason and never receive keys. Verified members' keys are pinned (TOFU); a later different attested key raises `key_changed` (and `own_key_changed` for the account itself).

**Flow.**

1. Invite (admins; only the owner invites or confirms admins): `POST /orgs/{id}/invitations {email, role, linkFragment}`. The server stores the SHA-256 of a random 256-bit token (7 days), queues an `invitation` mail through the mailer (`Template::Invitation`, link `{public_url}/invite/{token}#org={root}`; the organization's name is encrypted, so the mail names the inviter) and returns the token once. The client returns the link `{linkBase}/invite/{token}#org={root}`. Rate limits: 50 invitations per hour per account and per IP, 500 pending per organization, 30 previews/acceptances per IP and minute.
2. Accept: the invitee signs up (a pending organization invitation also allows registering on `invite_only` servers, with the token as `inviteToken`) or signs in; the client publishes key pairs, pins the organization root from the link fragment and calls `POST /invitations/accept`. The account's email must equal the invited email. Status `accepted`.
3. Confirm: an admin's client looks the member up in the key directory (and may compare the returned fingerprint with the member), signs an attestation and seals the organization key: `confirmed`. In a family, the organizer's client also shares the family vault with `edit`.
4. Role change: a new attestation (`PUT /orgs/{id}/members/{aid}`).
5. Suspend/reactivate: server-side only.
6. Remove: `DELETE /orgs/{id}/members/{aid}` ends access at once (memberships, sealed keys) and marks affected vaults `rotationPending`. The admin's client then rotates the removed member's groups and the vaults it manages (items re-encrypted), re-attests members the removed admin had attested (prepared before the removal, while that attestation still verified), and rotates the organization key. Vaults the admin cannot manage stay `rotationPending` for their managers (`rotatePendingVaults`).

**Family** (`kind = family`): created with its family vault (name from the client, encrypted); the creator is the organizer (owner).

## Shared vaults (B2)

Shared vaults belong to an organization (`vaults.org_id`); personal vaults keep working exactly as before (epoch 0, version-1 associated data, `vaults.encrypted_key` wrapped with the account key). Personal vaults cannot be shared; share by creating a shared vault and moving items into it (B5, below).

```
vault key (epoch e ≥ 1) sealed per principal:
  grant    = { vault_id, org_id, key_epoch, manifest_version, principal_type, principal_id,
               principal_key_hash, role, sealed_hash, granter_id, granted_at }   signed by the granter
manifest v = { vault_id, org_id, version, key_epoch, members: [(type, id, role, key_hash)] sorted,
               prev_hash = hash(v-1), signer_id, created_at }   signed by the signer
own copy  = XChaCha20-Poly1305(account key, vault key, aad = "passbox/v1/vault-key|{account}|{vault}|{epoch}")
metadata  = aad "passbox/v2/vault-meta|{vault_id}|{epoch}"
item      = aad "passbox/v2/item|{vault_id}|{item_id}|{revision}|{epoch}"   (personal: v1 unchanged)
```

**Manifest chain verification** (`verify_manifest_chain`): versions are consecutive from 1 with correct `prev_hash` links; the pinned version is in the chain with the pinned hash. A version is verified if it is signed by an active, verified organization admin (an anchor) or by a `manage` member of the verified previous version whose key matches that version's entry (bundles of former members come from `signers`). The latest version must be verified. Managers through groups cannot sign (their authority would not be checkable); a manager must be a direct member or an admin who is a member.

**Grant verification** (`verify_vault_grant`): the grant names a verified manifest version with the same epoch, is signed by that version's signer, matches its entry for the principal (role, key hash) and covers exactly the sealed bytes. Only then is the key opened. After the first open, a member stores its own wrapped copy (`PUT /vaults/{id}/keys/{epoch}/wrapped`); later unlocks need no asymmetric operation and the server can no longer swap that key.

**Roles.** `view` reads, `edit` writes items, `manage` changes members and rotates. The server enforces them on every write (403) and requires the current key epoch (409 with `currentKeyEpoch`). The client shows the role from the verified manifest and warns (`role_mismatch`) when the server's differs.

**Sharing / role change** (`POST /vaults/{id}/members`): the next manifest version (current members plus the change; the server checks it equals its own member list after the change and that every entry names a confirmed member or group with its current key) plus the current epoch's key sealed for the principal. **Removal is rotation** (`POST /vaults/{id}/rotate`): new epoch, keys sealed for every remaining member (members who left the organization are dropped too), new manifest, metadata re-encrypted; then the client re-encrypts items in batches of 100 (`POST /vaults/{id}/items/batch`, each item next revision, current epoch; conflicts are retried once after a sync). Old epochs stay readable for items not re-encrypted yet. A member added after a rotation only gets the current epoch; items still at an older epoch become readable once re-encrypted.

**Sync.** `GET /api/v1/sync?sharing=1` adds shared vault rows (`orgId`, `keyEpoch`, no `encryptedKey`) and items (`keyEpoch`) through the same cursor, plus `sharing`: full lists of organizations, groups and vault access; changed rosters (whole member list), sealed organization/group/vault keys for the account and its groups, whole manifest chains of vaults whose members changed, and signer bundles. A vault the account gained access to after the cursor is sent from scratch. Without `sharing=1` the response is exactly the old one (older apps never see shared vaults). Clients drop shared vaults and items they lost access to; if a verified vault's current key cannot be opened (for example after invalid data), they fetch everything once more.

## Groups (B3)

A group is a principal with its own X-Wing key pair. Its public bundle `{group_id, org_id, key_version, enc_pk, creator_id, created_at}` is signed by an admin; its private seed is sealed for each member with a signed group-key grant. Vault keys are sealed to the group. Adding a member is one sealing, regardless of the number of vaults. Only admins who are members of the group can add members (they need the group key), so the creator is always a member. Removing a member rotates the group key (new version, sealed for the remaining members) and marks the group's vaults for rotation; the client rotates them (the manifest then names the group's new key hash). Members see the verified member list from the signed grants; others see the server's list. Group names are encrypted with the organization key.

## Moving items between vaults (B5)

Moving is a re-encryption on the device, not a copy: the item keeps its ID, creation date, attachments and history.

1. The client reads the item's history (`GET /items/{id}/versions`), decrypts every version it can with the source vault's key and encrypts it again for the target vault (bound to the target vault ID, its revision and the target's current key epoch). The version being replaced is added to that history.
2. It encrypts the current data as the next revision for the target vault and sends everything in one request: `POST /api/v1/items/move { targetVaultId, keyEpoch, items: [{ id, revision, encryptedData, versions: [{ revision, encryptedData }] }] }` (at most 100 items, all or nothing; clients send larger moves in batches and retry a conflict once after a sync).
3. The server requires write access to the source and the target vault and the target's current epoch, replaces the item's history with the re-encrypted versions (keeping their times and devices; versions the device could not read are dropped), moves the attachments (counted against the target's quota), records `item_moved` in the audit logs of both organizations and stores a row in `item_moves`.
4. **Sync** sends a tombstone (`deleted: true`, the old `vaultId`) for every item that left a vault the account can see, before the other items. Devices that only see the old vault drop the item; devices that see both remove the old copy and add the new one. New clients additionally ignore a tombstone whose vault differs from the vault they have the item in.

Policies apply: `forbid_external_sharing` keeps an organization's items in its vaults (403 `policy_violation`, checked by the server and before by the clients), and moving into a personal vault needs personal vaults to be allowed.

**Permission preview.** Before moving, clients show who gains and who loses access: `movePreview(ids, vaultId)` (TypeScript) compares the verified member lists of the source and target vaults, groups expanded to their members; a personal vault counts as "only you". People who lose access may have seen the item before (the app says so and suggests changing its password). The web app offers "Move to another vault" in the item menu and for a selection of items; the "Share" action of a personal item moves it into a shared vault and offers to move it back. Rust and FFI: `move_items(ids, vault_id)` / `moveItems(ids, vaultId)`; the iOS and Android apps use it instead of copy and trash.

## Share links for people without an account (B7)

A share link carries a snapshot (selected fields of an item, or free text), encrypted on the sender's device (`passbox_core::share_link`):

```
k_link  = random(32)                                          → only in the URL fragment: {base}/s/{link_id}#{k_link}
ikm     = k_link  ||  Argon2id(passphrase, salt)               (passphrase optional; salt random(16); 64 MiB, 3 passes)
enc_key = HKDF-SHA256(ikm, "passbox/v1/link-key|{link_id}")
auth    = HKDF-SHA256(ikm, "passbox/v1/link-auth|{link_id}")
blob    = XChaCha20-Poly1305(enc_key, snapshot, aad = "passbox/v1/link|{link_id}")
server  ← { blob, SHA-256("passbox/v1/link-auth-hash\0" || auth), salt, expiresAt (≤ 365 days), maxViews, label encrypted with the account key }
```

The viewer page (`/s/{id}`, part of the web app, no account needed) shows whether a passphrase is needed (`GET /api/v1/public/share-links/{id}`), asks before opening because opening counts a view, derives `auth` and fetches the blob (`POST …/open { auth }`), and decrypts in the browser. The server only answers with the blob for the right `auth`: knowing the link ID alone (for example from a log) reveals nothing and uses up no views. A wrong passphrase is refused without a view; after 10 wrong attempts the link is deleted. The server cannot try passphrases offline because it never sees `k_link`. The last allowed view deletes the link, and so does its creator (`DELETE /api/v1/share-links/{id}`, Settings → Share links in the web app). Expired links are deleted. Public endpoints are rate-limited per IP.

Snapshots never contain passkeys, password history, attachments or one-time password secrets. **Policies (D2):** `share_links = forbidden` or `restricted` (longest lifetime, most views) apply to links for items of the organization's vaults; the client applies them in the dialog and the server checks the vault the client names. A modified client could create a link without naming the vault: like export, this rule guards honest clients, it is not a cryptographic boundary. Not implemented yet: limiting a link to an email address (with a confirmation code), files in links, links from the mobile apps and the extension.

## Guests (B8)

Guests are organization members with the role `guest`, for external people (clients of an agency, a babysitter in a family). Decided on 25.10.2026: **guests are unlimited, always free and view-only.**

- **What they see:** only the vaults shared with them (directly; they do not see groups), and the roster shows them only themselves and the owners and admins. In a family they do not get the family vault.
- **What they can do:** open, copy and fill items of those vaults, nothing else. They cannot create or change items, vaults, attachments, share links or invitations, ask for more than `view`, or give service accounts access to those vaults.
- **Server enforcement:** `access::shared_role` caps a guest's role at `view` whatever the signed manifest says (for example after a member was made a guest), so every write path that requires write access answers 403 with the code **`guest_view_only`** and a message that says what to do (ask an admin to become a member). The same code is returned for share links for the organization's vaults, access requests above `view`, service account grants on them, and for sharing a vault with a guest with more than `view` (`POST /vaults/{id}/members`). Invitations, groups and shared vaults already need an admin.
- **Client enforcement:** the core caps the verified role at `OrgRole::max_vault_role()` (no `role_mismatch` warning for capped guests) and `share_vault` refuses more than `view` for a guest. The web app replaces edit, share and link actions with "You are a guest" and an explanation, and the sharing dialog only offers `view` for guests.
- **Not billable:** guests never count as members. The organization report has `memberCount` (confirmed, not guests) and `guestCount`; the admin overview and members list show both separately, and the instance admin settings show members and guests (accounts that are only guests) separately.
- **Recovery:** guests are never enrolled in organization recovery, and a policy that requires recovery does not apply to them (an organization must not be able to take over an external person's account).

As with other roles, this is enforced by honest servers and clients; a guest holds the vault key and could produce valid ciphertexts, which other clients would accept (see "Server-side authorization" above).

## Access requests (B9)

A confirmed member of an organization who opens a link to one of its shared vaults without access (`#/vault/{id}`; managers copy it in the vault's sharing dialog) can ask for access with a role (`POST /api/v1/vaults/{id}/access-requests`, one pending request per vault, 20 per day). Everyone else gets 404, so outsiders cannot tell whether the vault exists. Managers of the vault (and organization admins who are members of it) see pending requests (`GET /api/v1/access-requests` → `incoming`) in the vault's sharing dialog. **Approving** is a normal share, signed by the manager's client after it checked the requester's key (`shareVault`); afterwards the client marks the request approved (`POST …/approve`, which the server refuses until the requester actually has access). **Declining** (`POST …/deny`) and withdrawing (`DELETE …`) only change the status. Requests and decisions are in the organization's audit log (`vault_access_requested`, `vault_access_request_approved`, `vault_access_request_denied`).

## Server storage

Migration [`0001_baseline.sql`](https://github.com/passboxnet/server/blob/main/migrations/0001_baseline.sql): `account_keys`, `key_log`, `organizations`, `org_members`, `org_invitations` (token hashes only), `org_keys`, `org_groups`, `group_versions`, `group_members`, `vault_members`, `vault_keys`, `vault_manifests`; new columns `vaults.org_id`, `vaults.key_epoch`, `vaults.rotation_pending`, `items.key_epoch`. Security-relevant changes are recorded in `account_events` (`keys_published`, `org_created`, `org_invitation_created`, `org_invitation_accepted`, `org_membership_confirmed`, `org_role_changed`, `org_membership_suspended`/`reactivated`/`removed`, `vault_shared`, `vault_unshared`, `vault_key_rotated`, `group_joined`, `group_left`, ...).

Server checks on uploads (`api/signed.rs`): objects must parse, name the IDs of the request, be signed by the uploader's published key and match the server's member lists. Every endpoint checks membership and role (`api/access.rs`); non-members get 404.

## Client APIs

TypeScript (`PassboxClient`, `packages/client`) and Rust (`passbox_client::Client`, FFI `PassboxClient`) offer the same operations:

| Operation | TypeScript | Rust / FFI |
| --- | --- | --- |
| State | `getSnapshot().orgs`, `.sharedVaults`, `.sharingWarnings`, `vaults[].orgId/role/keyEpoch`; `orgs()`, `org()`, `sharedVaults()`, `vaultAccess()`, `vaultMembers()`, `groups()` | `orgs`, `org`, `shared_vaults`, `sharing_warnings`, `vault_access`, `vault_members`, `groups` |
| Keys | `ownFingerprint`, `lookupKey`, `verifyOwnKey`, `acceptKeyChange` | `own_fingerprint`, `lookup_key`, `verify_own_key`, `accept_key_change` |
| Organizations | `createFamily`, `createTeam`, `renameOrg`, `deleteOrg`, `leaveOrg` | same in snake case |
| Invitations | `invite` (returns link), `invitations`, `revokeInvitation`, `previewInvitation`, `acceptInvitation` (link or token) | same |
| Members | `confirmMember` (returns fingerprint), `setMemberRole`, `suspendMember`, `reactivateMember`, `removeMember` (rotates keys) | same |
| Shared vaults | `createSharedVault`, `shareVault`, `unshareVault`, `rotateVaultKey`, `rotatePendingVaults`, `reencryptVault` | same (`rotate_vault_key` in the FFI takes no removals) |
| Groups | `createGroup`, `renameGroup`, `deleteGroup`, `addGroupMember`, `removeGroupMember` | same |

Key pairs are created for existing accounts on the next unlock. The trust store (pins, organization roots, directory head, manifest pins) is persisted per account (`passbox.trust.{accountId}` in the TS storage, `trust` in the native store).

## Open issues

- Signed revision chain per vault (A5) to detect withheld or rolled-back items; head gossip/witnesses and a Merkle tree for the key directory.
- Account key rotation (key version 2) and owner transfer are not implemented; the server refuses a second bundle.
- Re-anchoring: if every admin who signed a vault's manifests leaves before any later admin signs a version, older grants can become unverifiable; members with own copies are unaffected, others need a re-grant.
- Group-delivered vault keys are opened through the group key on every unlock (no own copy).
- The roster is delivered whole when it changes; very large organizations need paging.
- Server-side validation of shared vault manifests checks entries against current keys; a member whose key changed blocks role changes until re-attested.
- Moving items re-encrypts the item and its history but not its attachment blobs (their keys move inside the item); a member removed from the old vault who kept the item still has the file keys.
- Access request notifications are shown in the web app only; there is no mail yet.
