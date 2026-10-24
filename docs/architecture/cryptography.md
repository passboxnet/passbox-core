# Cryptography

> **Draft.** This design has not been reviewed by cryptographers or audited. It will change.

## Goals

1. The server can never read vault contents, item metadata or keys.
2. A malicious or compromised server cannot modify, swap, replay or roll back data without clients noticing, and cannot trick clients into sharing with keys it controls.
3. A stolen copy of the server database does not allow offline guessing of master passwords.
4. Every client uses the same implementation (`crates/core`).

## Master keys (implemented)

Two keys are derived from two secrets:

```
k_password  = Argon2id(master_password, salt, params)                  32 bytes
k_secret    = HKDF-SHA256(ikm = secret_key, salt = account_id,
                          info = "passbox/v1/auk/secret-key")          32 bytes
master      = k_password XOR k_secret
AUK         = HKDF-SHA256(ikm = master, info = "passbox/v1/auk")
auth_secret = HKDF-SHA256(ikm = master, info = "passbox/v1/opaque-password")
```

- **Secret Key:** 128 random bits generated on the first device and never sent to the server. It is shown as `P1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX` (Crockford Base32) and stored in the Emergency Kit. Clients keep it on trusted devices (in the browser: `localStorage`), so users type it once per device.
- **Account Unlock Key (AUK)** decrypts the account key (see key hierarchy).
- **auth_secret** is the password input of the OPAQUE login. The server never receives anything derived from the master password alone.
- **Argon2id parameters** are stored with the account. Clients enforce a minimum of 64 MiB memory and 3 passes and reject anything weaker, regardless of what the server sends. New accounts use 128 MiB, 3 passes, parallelism 4 (about 0.6 s in a browser).

Code: [`crates/core/src/kdf.rs`](../../crates/core/src/kdf.rs), [`crates/core/src/secret_key.rs`](../../crates/core/src/secret_key.rs).

## Login with OPAQUE (implemented)

Passbox uses OPAQUE (RFC 9807) with ristretto255, 3DH and SHA-512 (`opaque-ke`). Since Argon2id already ran, the OPAQUE key stretching function is the identity. Every login is bound to the context string `passbox/v1/login`.

- Registration stores an OPAQUE record per account (keyed by the account ID). A stolen record is useless for guessing passwords without the Secret Key.
- Login is a two-round protocol. The server keeps the login state between the rounds in the database (5 minutes, single use) and issues a random 256-bit session token after verifying the client. Only the SHA-256 hash of the token is stored. Sessions last 30 days.
- Unknown emails get a stable fake prelogin answer and a fake OPAQUE response, so the API does not reveal which accounts exist. (Sign-up does reveal whether an email is taken.)
- The web client performs a full OPAQUE login on every unlock and keeps the session token in memory only.
- Online guessing is rate limited. Because every unlock is a login, a successful login also returns a random 256-bit device token (stored by the client, SHA-256 hash on the server, replaced on every login). A login that presents it is exempt from the per-email lockout, so failed attempts by someone who only knows the email cannot lock the user out of their devices. Without a device token, failures are limited per (email, IP) pair and, as a backstop, per email; see [Security behavior](../self-hosting.md#security-behavior).

Code: [`crates/core/src/opaque.rs`](../../crates/core/src/opaque.rs), [`crates/server/src/api/auth.rs`](../../crates/server/src/api/auth.rs).

## Login two-factor authentication (implemented)

A second step after OPAQUE protects server sessions (session takeover, compliance requirements). It does not change any key: the vault stays protected by the master password and the Secret Key alone, and offline unlock on native clients needs no second factor.

- **TOTP:** 160-bit secret, SHA-1, 6 digits, 30 seconds (what every authenticator app supports). The server checks the current step ±1 in constant time and stores the last accepted step, so each code works once. The secret is stored as an XChaCha20-Poly1305 envelope under the server's `two_factor_key` with the associated data `passbox/v1/server/totp-secret|{account_id}`. The key sits in `server_secrets` next to the other server secrets, so this protects against leaks of single tables or exports, not against a full database copy (see known gaps).
- **Recovery codes:** 10 codes of 80 random bits each, shown once as `XXXX-XXXX-XXXX-XXXX` (Crockford Base32; O, I and L are read as 0, 1 and 1). The server stores `SHA-256("passbox/v1/recovery-code|{account_id}|{code}")`; with 80 bits per code a fast hash is enough. A used code is deleted.
- **WebAuthn (security keys and passkeys):** the server is the relying party. `crates/core/src/webauthn.rs` verifies registrations and assertions for ES256 (`p256`) and Ed25519 (`ed25519-dalek`): clientData type, challenge (32 random bytes, single use), origin (https on the RP ID or a subdomain, http only for `localhost`, no cross-origin), RP ID hash, user presence and the signature over `authenticatorData || SHA-256(clientDataJSON)`. A signature counter that does not increase is rejected (synced passkeys that always report 0 are accepted). Attestation statements are not verified: Passbox asks for `"none"` and does not restrict authenticator models. The RP ID is the host the web vault is served from; the credential is bound to it, so a phishing page on another origin cannot get a usable assertion. `webauthn-rs` was not used because it requires OpenSSL (`openssl-sys`, a C library that complicates the static and cross builds) and is MPL-2.0; the verifier is small, uses the RustCrypto crates already in the core, has a bounded CBOR decoder, and is tested against the core's own authenticator, Ed25519 signatures and malformed input.
- **Challenges** (login, key registration, checks before turning 2FA off) are random 256-bit tokens, stored as SHA-256 hashes, valid for 5 minutes and single use.
- **Remember this device:** the device token (see above) gets a `two_factor_until` timestamp (30 days) that carries over when the token is rotated. It only skips the second step; the password is always needed.

Code: [`crates/core/src/two_factor.rs`](../../crates/core/src/two_factor.rs), [`crates/core/src/webauthn.rs`](../../crates/core/src/webauthn.rs), [`crates/server/src/api/two_factor.rs`](../../crates/server/src/api/two_factor.rs).

## Key hierarchy (implemented)

```
AUK ──wraps──▶ account key ──wraps──▶ vault key (personal) ──encrypts──▶ vault metadata, items
                    ├──wraps──▶ account key pairs (X-Wing, Ed25519)
                    └──wraps──▶ own copies of shared vault keys (per key epoch)
account X-Wing key ──opens──▶ sealed vault, group and organization keys
group X-Wing key   ──opens──▶ vault keys sealed to the group
```

All keys are 256-bit XChaCha20-Poly1305 keys generated by the client. Each ciphertext is bound to its context through associated data:

| Ciphertext | Associated data |
| --- | --- |
| Account key | `passbox/v1/account-key|{account_id}` |
| Vault key | `passbox/v1/vault-key|{account_id}|{vault_id}` |
| Vault metadata | `passbox/v1/vault-meta|{vault_id}` |
| Item | `passbox/v1/item|{vault_id}|{item_id}|{revision}` |
| Account private keys | `passbox/v1/account-keypair|{account_id}|{key_version}` |
| Own copy of a shared vault key | `passbox/v1/vault-key|{account_id}|{vault_id}|{key_epoch}` |
| Shared vault metadata | `passbox/v2/vault-meta|{vault_id}|{key_epoch}` |
| Shared vault item | `passbox/v2/item|{vault_id}|{item_id}|{revision}|{key_epoch}` |
| Organization metadata | `passbox/v1/org-meta|{org_id}|{epoch}` |
| Group metadata | `passbox/v1/group-meta|{org_id}|{group_id}|{epoch}` |

Personal vaults keep epoch 0 and the version-1 associated data; items of shared vaults use version 2, which adds the key epoch, so an item cannot be presented under another key epoch after a rotation.

A server therefore cannot move an item into another vault, swap two items or serve an old item under a newer revision number. Clients create all IDs themselves before encrypting.

Plaintexts are JSON. Items use the version-1 schema in [`packages/client/src/items.ts`](../../packages/client/src/items.ts) (category, title, typed fields, notes, tags, favorite).

Code: [`crates/core/src/keyring.rs`](../../crates/core/src/keyring.rs).

## Account key pairs, key directory and sharing (implemented)

Every account has an X-Wing (hybrid X25519 + ML-KEM-768) encryption key pair and an Ed25519 signing key pair, created in the core and stored encrypted with the account key. Public bundles are canonically encoded and self-signed; keys are sealed to them with X-Wing + HKDF-SHA256 + XChaCha20-Poly1305 bound to a purpose, a context and the recipient key. Published bundles go into an append-only, hash-chained key log with a signed head; clients pin the log key, the last verified head and the keys of people they share with, and report key changes. Organizations are rooted in a genesis signed by the owner; admins attest members' keys; shared vaults have a signed, hash-chained member manifest and signed grants for sealed keys; removing a member rotates the vault key (new key epoch). Design, formats and threat model: [sharing.md](sharing.md).

Code: [`crates/core/src/identity.rs`](../../crates/core/src/identity.rs), [`crates/core/src/directory.rs`](../../crates/core/src/directory.rs), [`crates/core/src/sharing`](../../crates/core/src/sharing).

## Extension sessions (implemented)

Manifest V3 service workers are stopped when idle, which would drop the unlocked keyring. `Keyring::export_session` serializes the account key, vault keys (all epochs), group and organization keys and the account key pairs (format version 2; version 1 still imports) and encrypts them with XChaCha20-Poly1305 under a fresh random 256-bit session key, bound to `passbox/v1/session|{account_id}`; `Keyring::import_session` restores them. Every export uses a new session key.

The extension keeps the session key, the encrypted blob and the server session token only in `chrome.storage.session` (memory only, cleared when the browser closes, not readable by content scripts). Locking, auto-lock (after the configured idle time, and when the screen locks) and signing out delete it. Holding both values is equivalent to holding the unlocked keys, so this protects against the keys reaching disk, not against code running inside the extension.

Code: [`crates/core/src/keyring.rs`](../../crates/core/src/keyring.rs), [`apps/extension/src/background/vault.ts`](../../apps/extension/src/background/vault.ts).

## Export files (implemented)

Encrypted exports (`.pbx-export`) use a key derived from a password chosen for the file: `HKDF-SHA256(Argon2id(password, salt, params), "passbox/v1/export")`, with the account's `KdfParams` bounds (minimum enforced on decryption, plus a maximum). The JSON header (format, version, KDF algorithm and parameters, salt, cipher) is the associated data of the XChaCha20-Poly1305 envelope. See [docs/import-export.md](../import-export.md).

Code: [`crates/core/src/export.rs`](../../crates/core/src/export.rs).

## Passkeys (implemented)

Passbox acts as a WebAuthn authenticator for ES256 (ECDSA P-256 with SHA-256, COSE algorithm −7, RustCrypto `p256`):

- **Registration:** a random 16-byte credential ID and a new P-256 key. The authenticator data contains the SHA-256 of the RP ID, the flags UP, BE, BS and AT (UV only when the user entered the master password in the last five minutes, see below), a zero signature counter, a Passbox AAGUID, the credential ID and the COSE public key. The attestation object uses the `"none"` format, encoded with a small deterministic CBOR encoder in the core.
- **Assertion:** an ECDSA signature (DER) over `authenticatorData || SHA-256(clientDataJSON)`. Passkeys are synced, so the counter stays 0, as with other synced passkey providers.
- **User verification:** the UV flag means "the user proved who they are for this operation". Passbox sets it only when the master password was entered (sign-in, unlock or a re-check) in the last five minutes. When a relying party sets `userVerification: "required"` and the last entry is older, the dialog asks for the master password first; the extension checks it locally by opening the account key with the derived keys. Otherwise the flag stays 0.
- **Storage:** the PKCS#8 private key lives in the login item's `passkeys` array and is encrypted like every other item field. Clients never display it.
- **Origin rules:** the extension takes the calling origin from the browser (never from the page), requires https (http only on `localhost`), and accepts an RP ID only if it equals the origin's host or is a registrable suffix of it (never a public suffix, per the Public Suffix List). It builds `clientDataJSON` itself.

Code: [`crates/core/src/passkey.rs`](../../crates/core/src/passkey.rs), [`apps/extension/src/background/passkeys.ts`](../../apps/extension/src/background/passkeys.ts).

## Changing the master password (implemented)

The account key stays the same, so vaults and items are untouched. The client derives new master keys (new salt; the Secret Key stays), registers new OPAQUE credentials and uploads the account key wrapped with the new AUK (`Keyring::wrap_account_key`). The server only accepts this from a session created by a login within the last 10 minutes and signs out every other device.

## Account recovery, emergency access and device codes (implemented)

The master password cannot be reset. Recovery works through a second, independent way to the account key; the account key itself never changes. Details, formats and the threat model are in [recovery.md](recovery.md).

- **Personal recovery code:** 256 random bits (`R1-…`, Crockford Base32 with a checksum) in the Emergency Kit. It wraps the account key with `HKDF(R, "passbox/v1/recovery-code")` and authenticates through a second OPAQUE record. A recovery sets a new master password, a **new Secret Key** and a new recovery code and signs out every device. Not to be confused with the two-factor recovery codes above, which only replace a second factor.
- **Organization recovery:** an organization X-Wing recovery key, sealed to recovery admins; members opt in by sealing their account key to it (signed escrow). An approved request is re-sealed to an ephemeral key of the requesting device after an out-of-band identity check. The approving admin's client holds the member's account key briefly.
- **Emergency access:** a vault-key bundle sealed to a trusted person's directory key (fingerprint checked), released by the server after a signed waiting period (1–30 days) unless the owner denies it. The server enforces the waiting period.
- **Device codes:** the Secret Key and email move to a new device over an X-Wing seal with a code-derived MAC; the master password is never transferred.

## Known gaps

- A server can still withhold changes or replay an entire older state of an item (old revision with its matching ciphertext). The signed revision chain below closes this.
- Vault metadata is not bound to a revision yet.
- Server secrets (OPAQUE server keys, prelogin key, two-factor key, key log signing key) are stored unencrypted in the database. They protect against account enumeration, server impersonation, second-factor bypass and key log forgery towards new clients, not vault confidentiality. Loading them from outside the database (environment, KMS) is planned.
- Sharing limits (withholding, split view of the key directory, trust on first use, metadata) are listed in [sharing.md](sharing.md#goals-and-threat-model).

## Encryption envelope (implemented)

All symmetric encryption uses XChaCha20-Poly1305 with a random 192-bit nonce:

```
version (1 byte) | algorithm (1 byte) | nonce (24 bytes) | ciphertext + tag (16 bytes)
```

The header bytes are authenticated together with caller-supplied associated data. Callers bind each ciphertext to its context, for example `item_id | vault_id | revision`, so ciphertexts cannot be moved between items or replayed under another revision. Unknown versions or algorithms are rejected, which prevents downgrades.

Code: [`crates/core/src/aead.rs`](../../crates/core/src/aead.rs).

## Planned

| Topic | Plan |
| --- | --- |
| Key directory | Merkle tree with efficient proofs, head gossip between clients and external witnesses (the hash-chained log is implemented) |
| Key rotation | Account key version 2 and owner transfer; hybrid ML-DSA signatures |
| Rollback protection | Signed revision chain per vault; clients remember the latest revision they have seen |
| Metadata | Titles, URLs, tags and field names are encrypted; the server only sees IDs, sizes, timestamps and revisions |
| SSO unlock | Trusted device keys (TPM, Secure Enclave or WebAuthn PRF); organization recovery split across administrators with Shamir secret sharing (single-admin organization recovery is implemented, see [recovery.md](recovery.md)) |
| Passkey unlock | WebAuthn PRF extension as an alternative to the master password |
