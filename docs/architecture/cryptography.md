# Cryptography

> **Draft.** This design has not been reviewed by cryptographers or audited. It will change.

## Goals

1. The server can never read vault contents, item metadata or keys.
2. A malicious or compromised server cannot modify, swap, replay or roll back data without clients noticing, and cannot trick clients into sharing with keys it controls.
3. A stolen copy of the server database does not allow offline guessing of master passwords.
4. Every client uses the same implementation (`crates/core`).

## Account Unlock Key (implemented)

The Account Unlock Key (AUK) is derived from two secrets:

```
k_password = Argon2id(master_password, salt, params)                  32 bytes
k_secret   = HKDF-SHA256(ikm = secret_key, salt = account_id,
                         info = "passbox/v1/auk/secret-key")          32 bytes
AUK        = k_password XOR k_secret
```

- **Secret Key:** 128 random bits generated on the first device and never sent to the server. It is shown as `P1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX` (Crockford Base32) and stored in the Emergency Kit.
- **Argon2id parameters** are stored with the account. Clients enforce a minimum of 64 MiB memory and 3 passes and reject anything weaker, regardless of what the server sends. New accounts use 128 MiB, 3 passes, parallelism 4.

Code: [`crates/core/src/kdf.rs`](../../crates/core/src/kdf.rs), [`crates/core/src/secret_key.rs`](../../crates/core/src/secret_key.rs).

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
| Login | OPAQUE (RFC 9807), so the server never stores a password-equivalent verifier. Separate from the AUK derivation. |
| Key hierarchy | AUK → account keyset (encryption and signing key pairs) → vault keys → item keys |
| Sharing | Hybrid X25519 + ML-KEM-768 key encapsulation for wrapping vault keys; Ed25519 signatures |
| Key directory | Append-only, verifiable log of public keys (key transparency), so the server cannot substitute keys when users share |
| Rollback protection | Signed revision chain per vault; clients remember the latest revision they have seen |
| Metadata | Titles, URLs, tags and field names are encrypted; the server only sees IDs, sizes, timestamps and revisions |
| SSO unlock | Trusted device keys (TPM, Secure Enclave or WebAuthn PRF) plus organization recovery split across administrators with Shamir secret sharing |
| Passkey unlock | WebAuthn PRF extension as an alternative to the master password |
