//! The client's key hierarchy and the encryption of vault data.
//!
//! ```text
//! AUK ──wraps──▶ account key ──wraps──▶ vault key (personal, epoch 0) ──encrypts──▶ vault metadata, items
//!                    │
//!                    ├──wraps──▶ account key pairs (X-Wing encryption, Ed25519 signing)
//!                    └──wraps──▶ own copies of shared vault keys (epoch ≥ 1)
//!
//! account encryption key ──opens──▶ sealed vault, group and organization keys
//! group encryption key   ──opens──▶ vault keys sealed to the group
//! ```
//!
//! Every ciphertext is bound to its context through associated data (see
//! [`crate::aead`]). Items are bound to their vault, ID and revision (and,
//! in shared vaults, key epoch), so a server cannot move an item to another
//! vault, swap two items or present an older revision under a newer revision
//! number.
//!
//! Private keys (account key pairs, group keys) never leave the keyring;
//! callers ask it to sign, seal and open.
//!
//! Plaintexts are JSON documents. Their schema is owned by the clients; the
//! keyring only checks that they are valid JSON.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aead::{KEY_LEN, SymmetricKey};
use crate::identity::{EncryptionKey, SignatureKey, SignedBundle};
use crate::sharing::state::SharingState;
use crate::{Error, Result, encoding, id};

fn account_key_aad(account_id: &str) -> Vec<u8> {
    format!("passbox/v1/account-key|{account_id}").into_bytes()
}

/// Personal vault keys (epoch 0) keep the original format; own copies of
/// shared vault keys also bind the key epoch.
fn vault_key_aad(account_id: &str, vault_id: &str, epoch: u32) -> Vec<u8> {
    if epoch == 0 {
        format!("passbox/v1/vault-key|{account_id}|{vault_id}").into_bytes()
    } else {
        format!("passbox/v1/vault-key|{account_id}|{vault_id}|{epoch}").into_bytes()
    }
}

pub(crate) fn vault_meta_aad(vault_id: &str, epoch: u32) -> Vec<u8> {
    if epoch == 0 {
        format!("passbox/v1/vault-meta|{vault_id}").into_bytes()
    } else {
        format!("passbox/v2/vault-meta|{vault_id}|{epoch}").into_bytes()
    }
}

/// Items of personal vaults (epoch 0) use the version-1 associated data;
/// items of shared vaults use version 2, which adds the key epoch.
pub(crate) fn item_aad(vault_id: &str, item_id: &str, revision: u64, epoch: u32) -> Vec<u8> {
    if epoch == 0 {
        format!("passbox/v1/item|{vault_id}|{item_id}|{revision}").into_bytes()
    } else {
        format!("passbox/v2/item|{vault_id}|{item_id}|{revision}|{epoch}").into_bytes()
    }
}

fn session_aad(account_id: &str) -> Vec<u8> {
    format!("passbox/v1/session|{account_id}").into_bytes()
}

fn keypair_aad(account_id: &str, key_version: u32) -> Vec<u8> {
    format!("passbox/v1/account-keypair|{account_id}|{key_version}").into_bytes()
}

pub(crate) fn org_meta_aad(org_id: &str, epoch: u32) -> Vec<u8> {
    format!("passbox/v1/org-meta|{org_id}|{epoch}").into_bytes()
}

pub(crate) fn group_meta_aad(org_id: &str, group_id: &str, epoch: u32) -> Vec<u8> {
    format!("passbox/v1/group-meta|{org_id}|{group_id}|{epoch}").into_bytes()
}

/// Version byte of the session export plaintext. Version 1 holds the
/// account key and personal vault keys only; version 2 adds typed entries.
const SESSION_VERSION_1: u8 = 1;
const SESSION_VERSION: u8 = 2;
/// Version byte of the encrypted account private keys.
const KEYPAIR_VERSION: u8 = 1;
/// Key version of account key pairs created by this version.
pub const ACCOUNT_KEY_VERSION: u32 = 1;

pub(crate) fn key_from_plaintext(bytes: Vec<u8>) -> Result<SymmetricKey> {
    let bytes = Zeroizing::new(bytes);
    let key: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidData("key has the wrong length".into()))?;
    Ok(SymmetricKey::from_bytes(key))
}

fn seed_from_plaintext(bytes: &[u8]) -> Result<EncryptionKey> {
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        bytes
            .try_into()
            .map_err(|_| Error::InvalidData("key has the wrong length".into()))?,
    );
    Ok(EncryptionKey::from_seed(&seed))
}

pub(crate) fn ensure_json(bytes: &[u8]) -> Result<()> {
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes)
        .map(|_| ())
        .map_err(|_| Error::InvalidData("plaintext is not valid JSON".into()))
}

/// A newly created vault, ready to be uploaded. All fields are Base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVault {
    pub id: String,
    pub encrypted_key: String,
    pub encrypted_meta: String,
}

/// The account's key pairs, ready to be published (`PUT /api/v1/account/keys`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeysUpload {
    pub key_version: u32,
    /// Base64url canonical public bundle.
    pub bundle: String,
    pub bundle_signature: String,
    /// Private keys encrypted with the account key.
    pub encrypted_private: String,
}

/// The account's own key pairs.
pub(crate) struct AccountKeys {
    pub(crate) enc: EncryptionKey,
    pub(crate) sig: SignatureKey,
    pub(crate) bundle: SignedBundle,
}

/// Holds the decrypted account key, vault keys and key pairs of an unlocked
/// account. Keys are wiped from memory when the keyring is dropped.
pub struct Keyring {
    pub(crate) account_id: String,
    account_key: SymmetricKey,
    /// Vault keys by vault ID and key epoch (0 for personal vaults).
    pub(crate) vault_keys: HashMap<(String, u32), SymmetricKey>,
    pub(crate) account: Option<AccountKeys>,
    /// Group private keys by group ID and key version.
    pub(crate) group_keys: HashMap<(String, u32), EncryptionKey>,
    /// Organization keys by organization ID and epoch.
    pub(crate) org_keys: HashMap<(String, u32), SymmetricKey>,
    /// Verified sharing state (public data only).
    pub(crate) sharing: SharingState,
}

impl core::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("account_id", &self.account_id)
            .field("vaults", &self.vault_keys.len())
            .field("has_key_pairs", &self.account.is_some())
            .finish_non_exhaustive()
    }
}

impl Keyring {
    pub(crate) fn from_account_key(account_id: &str, account_key: SymmetricKey) -> Self {
        Self {
            account_id: account_id.to_owned(),
            account_key,
            vault_keys: HashMap::new(),
            account: None,
            group_keys: HashMap::new(),
            org_keys: HashMap::new(),
            sharing: SharingState::default(),
        }
    }

    /// Creates the keyring for a new account. Returns the keyring and the
    /// account key encrypted with the AUK, for upload.
    pub fn create(auk: &SymmetricKey, account_id: &str) -> Result<(Self, String)> {
        let account_key = SymmetricKey::generate()?;
        let encrypted = auk.encrypt(account_key.as_bytes(), &account_key_aad(account_id))?;
        Ok((
            Self::from_account_key(account_id, account_key),
            encoding::encode(&encrypted),
        ))
    }

    /// Unlocks an existing account. Fails with [`Error::InvalidCredentials`]
    /// if the AUK is wrong.
    pub fn unlock(
        auk: &SymmetricKey,
        account_id: &str,
        encrypted_account_key: &str,
    ) -> Result<Self> {
        let envelope = encoding::decode(encrypted_account_key)?;
        let plaintext = auk
            .decrypt(&envelope, &account_key_aad(account_id))
            .map_err(|_| Error::InvalidCredentials)?;
        Ok(Self::from_account_key(
            account_id,
            key_from_plaintext(plaintext)?,
        ))
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn account_key(&self) -> &SymmetricKey {
        &self.account_key
    }

    /// Encrypts the account key with the wrapping key of a recovery code
    /// (see [`crate::recovery::code`]), as the second copy the server keeps
    /// for account recovery.
    pub fn wrap_account_key_for_recovery(&self, wrap_key: &SymmetricKey) -> Result<String> {
        let encrypted = wrap_key.encrypt(
            self.account_key.as_bytes(),
            &crate::recovery::code::wrap_aad(&self.account_id),
        )?;
        Ok(encoding::encode(&encrypted))
    }

    /// Opens the recovery copy of the account key. Fails with
    /// [`Error::InvalidCredentials`] for a wrong code.
    pub fn unlock_with_recovery(
        wrap_key: &SymmetricKey,
        account_id: &str,
        wrapped_account_key: &str,
    ) -> Result<Self> {
        let envelope = encoding::decode(wrapped_account_key)?;
        let plaintext = wrap_key
            .decrypt(&envelope, &crate::recovery::code::wrap_aad(account_id))
            .map_err(|_| Error::InvalidCredentials)?;
        Ok(Self::from_account_key(
            account_id,
            key_from_plaintext(plaintext)?,
        ))
    }

    /// Encrypts the account key with a new Account Unlock Key, for changing
    /// the master password. Vault keys and items stay as they are.
    pub fn wrap_account_key(&self, auk: &SymmetricKey) -> Result<String> {
        let encrypted = auk.encrypt(
            self.account_key.as_bytes(),
            &account_key_aad(&self.account_id),
        )?;
        Ok(encoding::encode(&encrypted))
    }

    // --- Account key pairs ------------------------------------------------------

    /// Generates the account's encryption and signing key pairs (for new
    /// accounts, and for existing accounts on their first unlock after the
    /// update) and returns them for publishing. The keyring uses them right
    /// away. Fails if the keyring already has key pairs.
    pub fn create_account_keys(&mut self, created_at: i64) -> Result<AccountKeysUpload> {
        if self.account.is_some() {
            return Err(Error::InvalidData(
                "the account already has key pairs".into(),
            ));
        }
        let enc = EncryptionKey::generate()?;
        let sig = SignatureKey::generate()?;
        let bundle = SignedBundle::create(
            &self.account_id,
            ACCOUNT_KEY_VERSION,
            &enc,
            &sig,
            created_at,
        );
        let mut plaintext = Zeroizing::new(Vec::with_capacity(65));
        plaintext.push(KEYPAIR_VERSION);
        plaintext.extend_from_slice(enc.seed());
        plaintext.extend_from_slice(&*sig.seed());
        let encrypted = self.account_key.encrypt(
            &plaintext,
            &keypair_aad(&self.account_id, ACCOUNT_KEY_VERSION),
        )?;
        let upload = AccountKeysUpload {
            key_version: ACCOUNT_KEY_VERSION,
            bundle: bundle.encoded(),
            bundle_signature: bundle.encoded_signature(),
            encrypted_private: encoding::encode(&encrypted),
        };
        self.account = Some(AccountKeys { enc, sig, bundle });
        Ok(upload)
    }

    /// Loads the account's key pairs from the server. Fails unless the
    /// private keys decrypt with the account key and match the public
    /// bundle, so a server cannot substitute either half.
    pub fn load_account_keys(
        &mut self,
        bundle: &str,
        bundle_signature: &str,
        encrypted_private: &str,
    ) -> Result<()> {
        let bundle = SignedBundle::parse(bundle, bundle_signature)?;
        if bundle.bundle.account_id != self.account_id {
            return Err(Error::InvalidData(
                "key bundle belongs to another account".into(),
            ));
        }
        let plaintext = Zeroizing::new(self.account_key.decrypt(
            &encoding::decode(encrypted_private)?,
            &keypair_aad(&self.account_id, bundle.bundle.key_version),
        )?);
        if plaintext.len() != 65 || plaintext[0] != KEYPAIR_VERSION {
            return Err(Error::InvalidData("unsupported private key format".into()));
        }
        let enc = seed_from_plaintext(&plaintext[1..33])?;
        let sig_seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(plaintext[33..65].try_into().expect("32 bytes"));
        let sig = SignatureKey::from_seed(&sig_seed);
        if enc.public_key() != bundle.bundle.enc_pk || sig.public_key() != bundle.bundle.sig_pk {
            return Err(Error::InvalidData(
                "the published public keys do not match the private keys".into(),
            ));
        }
        self.account = Some(AccountKeys { enc, sig, bundle });
        Ok(())
    }

    pub fn has_account_keys(&self) -> bool {
        self.account.is_some()
    }

    /// The account's own signed public bundle.
    pub fn own_bundle(&self) -> Option<&SignedBundle> {
        self.account.as_ref().map(|a| &a.bundle)
    }

    pub(crate) fn account_keys(&self) -> Result<&AccountKeys> {
        self.account
            .as_ref()
            .ok_or_else(|| Error::MissingKey("account key pairs".into()))
    }

    // --- Vaults -------------------------------------------------------------------

    /// Creates a new personal vault with the given metadata (JSON) and adds its key.
    pub fn create_vault(&mut self, meta_json: &str) -> Result<NewVault> {
        ensure_json(meta_json.as_bytes())?;
        let vault_id = id::new_id()?;
        let vault_key = SymmetricKey::generate()?;
        let encrypted_key = self.account_key.encrypt(
            vault_key.as_bytes(),
            &vault_key_aad(&self.account_id, &vault_id, 0),
        )?;
        let encrypted_meta =
            vault_key.encrypt(meta_json.as_bytes(), &vault_meta_aad(&vault_id, 0))?;
        self.vault_keys.insert((vault_id.clone(), 0), vault_key);
        Ok(NewVault {
            id: vault_id,
            encrypted_key: encoding::encode(&encrypted_key),
            encrypted_meta: encoding::encode(&encrypted_meta),
        })
    }

    /// Decrypts a personal vault key received from the server and adds it.
    pub fn add_vault(&mut self, vault_id: &str, encrypted_key: &str) -> Result<()> {
        self.add_wrapped_vault_key(vault_id, 0, encrypted_key)
    }

    /// Adds a vault key of `epoch` wrapped with this account's key (personal
    /// vaults use epoch 0; shared vaults keep an own copy per epoch).
    pub fn add_wrapped_vault_key(
        &mut self,
        vault_id: &str,
        epoch: u32,
        wrapped_key: &str,
    ) -> Result<()> {
        let envelope = encoding::decode(wrapped_key)?;
        let plaintext = self
            .account_key
            .decrypt(&envelope, &vault_key_aad(&self.account_id, vault_id, epoch))?;
        self.vault_keys
            .insert((vault_id.to_owned(), epoch), key_from_plaintext(plaintext)?);
        Ok(())
    }

    /// Wraps a vault key with this account's key, as the member's own copy.
    pub fn wrap_vault_key(&self, vault_id: &str, epoch: u32) -> Result<String> {
        let key = self.vault_key(vault_id, epoch)?;
        let envelope = self.account_key.encrypt(
            key.as_bytes(),
            &vault_key_aad(&self.account_id, vault_id, epoch),
        )?;
        Ok(encoding::encode(&envelope))
    }

    /// Whether the personal vault key (epoch 0) is known.
    pub fn has_vault(&self, vault_id: &str) -> bool {
        self.has_vault_key(vault_id, 0)
    }

    pub fn has_vault_key(&self, vault_id: &str, epoch: u32) -> bool {
        self.vault_keys.contains_key(&(vault_id.to_owned(), epoch))
    }

    pub(crate) fn vault_key(&self, vault_id: &str, epoch: u32) -> Result<&SymmetricKey> {
        self.vault_keys
            .get(&(vault_id.to_owned(), epoch))
            .ok_or_else(|| Error::MissingKey(format!("vault {vault_id} (key epoch {epoch})")))
    }

    pub(crate) fn insert_vault_key(&mut self, vault_id: &str, epoch: u32, key: SymmetricKey) {
        self.vault_keys.insert((vault_id.to_owned(), epoch), key);
    }

    pub fn encrypt_vault_meta(&self, vault_id: &str, meta_json: &str) -> Result<String> {
        self.encrypt_vault_meta_at(vault_id, 0, meta_json)
    }

    pub fn decrypt_vault_meta(&self, vault_id: &str, encrypted_meta: &str) -> Result<String> {
        self.decrypt_vault_meta_at(vault_id, 0, encrypted_meta)
    }

    /// Encrypts vault metadata with the key of `epoch` (0 for personal vaults).
    pub fn encrypt_vault_meta_at(
        &self,
        vault_id: &str,
        epoch: u32,
        meta_json: &str,
    ) -> Result<String> {
        ensure_json(meta_json.as_bytes())?;
        let envelope = self
            .vault_key(vault_id, epoch)?
            .encrypt(meta_json.as_bytes(), &vault_meta_aad(vault_id, epoch))?;
        Ok(encoding::encode(&envelope))
    }

    pub fn decrypt_vault_meta_at(
        &self,
        vault_id: &str,
        epoch: u32,
        encrypted_meta: &str,
    ) -> Result<String> {
        let plaintext = self.vault_key(vault_id, epoch)?.decrypt(
            &encoding::decode(encrypted_meta)?,
            &vault_meta_aad(vault_id, epoch),
        )?;
        into_json_string(plaintext)
    }

    /// Encrypts item data (JSON) for the given revision of a personal vault item.
    pub fn encrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        revision: u64,
        data_json: &str,
    ) -> Result<String> {
        self.encrypt_item_at(vault_id, 0, item_id, revision, data_json)
    }

    /// Decrypts item data. Fails if the ciphertext does not belong to exactly
    /// this vault, item and revision.
    pub fn decrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        revision: u64,
        encrypted: &str,
    ) -> Result<String> {
        self.decrypt_item_at(vault_id, 0, item_id, revision, encrypted)
    }

    /// Encrypts item data with the vault key of `epoch` (0 for personal
    /// vaults, which keeps the version-1 associated data).
    pub fn encrypt_item_at(
        &self,
        vault_id: &str,
        epoch: u32,
        item_id: &str,
        revision: u64,
        data_json: &str,
    ) -> Result<String> {
        ensure_json(data_json.as_bytes())?;
        let envelope = self.vault_key(vault_id, epoch)?.encrypt(
            data_json.as_bytes(),
            &item_aad(vault_id, item_id, revision, epoch),
        )?;
        Ok(encoding::encode(&envelope))
    }

    pub fn decrypt_item_at(
        &self,
        vault_id: &str,
        epoch: u32,
        item_id: &str,
        revision: u64,
        encrypted: &str,
    ) -> Result<String> {
        let plaintext = self.vault_key(vault_id, epoch)?.decrypt(
            &encoding::decode(encrypted)?,
            &item_aad(vault_id, item_id, revision, epoch),
        )?;
        into_json_string(plaintext)
    }

    // --- Organization and group metadata -------------------------------------------

    pub(crate) fn org_key(&self, org_id: &str, epoch: u32) -> Result<&SymmetricKey> {
        self.org_keys
            .get(&(org_id.to_owned(), epoch))
            .ok_or_else(|| Error::MissingKey(format!("organization {org_id} (epoch {epoch})")))
    }

    /// Decrypts an organization's metadata (JSON, for example the name).
    pub fn decrypt_org_meta(&self, org_id: &str, epoch: u32, encrypted: &str) -> Result<String> {
        let plaintext = self
            .org_key(org_id, epoch)?
            .decrypt(&encoding::decode(encrypted)?, &org_meta_aad(org_id, epoch))?;
        into_json_string(plaintext)
    }

    pub fn encrypt_org_meta(&self, org_id: &str, epoch: u32, meta_json: &str) -> Result<String> {
        ensure_json(meta_json.as_bytes())?;
        let envelope = self
            .org_key(org_id, epoch)?
            .encrypt(meta_json.as_bytes(), &org_meta_aad(org_id, epoch))?;
        Ok(encoding::encode(&envelope))
    }

    /// Decrypts a group's metadata, encrypted with the organization key.
    pub fn decrypt_group_meta(
        &self,
        org_id: &str,
        group_id: &str,
        epoch: u32,
        encrypted: &str,
    ) -> Result<String> {
        let plaintext = self.org_key(org_id, epoch)?.decrypt(
            &encoding::decode(encrypted)?,
            &group_meta_aad(org_id, group_id, epoch),
        )?;
        into_json_string(plaintext)
    }

    pub fn encrypt_group_meta(
        &self,
        org_id: &str,
        group_id: &str,
        epoch: u32,
        meta_json: &str,
    ) -> Result<String> {
        ensure_json(meta_json.as_bytes())?;
        let envelope = self.org_key(org_id, epoch)?.encrypt(
            meta_json.as_bytes(),
            &group_meta_aad(org_id, group_id, epoch),
        )?;
        Ok(encoding::encode(&envelope))
    }
}

/// Entry kinds of a version-2 session export.
const ENTRY_VAULT: u8 = 1;
const ENTRY_GROUP: u8 = 2;
const ENTRY_ORG: u8 = 3;
const ENTRY_ACCOUNT_ENC: u8 = 4;
const ENTRY_ACCOUNT_SIG: u8 = 5;
const ENTRY_BUNDLE: u8 = 6;
const ENTRY_BUNDLE_SIGNATURE: u8 = 7;

fn push_entry(out: &mut Vec<u8>, kind: u8, id: &str, epoch: u32, key: &[u8]) -> Result<()> {
    let too_long = || Error::InvalidData("session entry is too long".into());
    out.push(kind);
    out.extend_from_slice(
        &u16::try_from(id.len())
            .map_err(|_| too_long())?
            .to_be_bytes(),
    );
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(key.len())
            .map_err(|_| too_long())?
            .to_be_bytes(),
    );
    out.extend_from_slice(key);
    Ok(())
}

impl Keyring {
    /// Exports the unlocked key hierarchy, encrypted under a fresh random
    /// session key, so a short-lived process (for example a browser extension
    /// service worker) can restore it after a restart without the master
    /// password.
    ///
    /// Returns the session key and the encrypted blob (Base64url). Both must
    /// be kept in memory-only storage and discarded when the vault locks; each
    /// call creates a new session key. The blob is bound to the account ID.
    /// It contains the account key, vault keys, group and organization keys
    /// and the account key pairs; the sharing state is rebuilt by a sync.
    pub fn export_session(&self) -> Result<(SymmetricKey, String)> {
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            1 + KEY_LEN + self.vault_keys.len() * (9 + 26 + KEY_LEN) + 3000,
        ));
        plaintext.push(SESSION_VERSION);
        plaintext.extend_from_slice(self.account_key.as_bytes());
        let mut vaults: Vec<&(String, u32)> = self.vault_keys.keys().collect();
        vaults.sort();
        for key_id in vaults {
            push_entry(
                &mut plaintext,
                ENTRY_VAULT,
                &key_id.0,
                key_id.1,
                self.vault_keys[key_id].as_bytes(),
            )?;
        }
        let mut groups: Vec<&(String, u32)> = self.group_keys.keys().collect();
        groups.sort();
        for key_id in groups {
            push_entry(
                &mut plaintext,
                ENTRY_GROUP,
                &key_id.0,
                key_id.1,
                self.group_keys[key_id].seed(),
            )?;
        }
        let mut orgs: Vec<&(String, u32)> = self.org_keys.keys().collect();
        orgs.sort();
        for key_id in orgs {
            push_entry(
                &mut plaintext,
                ENTRY_ORG,
                &key_id.0,
                key_id.1,
                self.org_keys[key_id].as_bytes(),
            )?;
        }
        if let Some(account) = &self.account {
            push_entry(&mut plaintext, ENTRY_ACCOUNT_ENC, "", 0, account.enc.seed())?;
            push_entry(
                &mut plaintext,
                ENTRY_ACCOUNT_SIG,
                "",
                0,
                &*account.sig.seed(),
            )?;
            push_entry(
                &mut plaintext,
                ENTRY_BUNDLE,
                "",
                0,
                account.bundle.canonical(),
            )?;
            push_entry(
                &mut plaintext,
                ENTRY_BUNDLE_SIGNATURE,
                "",
                0,
                account.bundle.signature(),
            )?;
        }
        let session_key = SymmetricKey::generate()?;
        let envelope = session_key.encrypt(&plaintext, &session_aad(&self.account_id))?;
        Ok((session_key, encoding::encode(&envelope)))
    }

    /// Restores a keyring exported with [`Keyring::export_session`]. Fails if
    /// the session key, the account ID or the blob do not match.
    pub fn import_session(
        session_key: &SymmetricKey,
        account_id: &str,
        blob: &str,
    ) -> Result<Self> {
        let envelope = encoding::decode(blob)?;
        let plaintext = Zeroizing::new(session_key.decrypt(&envelope, &session_aad(account_id))?);
        let malformed = || Error::InvalidData("malformed session export".into());
        let (&version, rest) = plaintext.split_first().ok_or_else(malformed)?;
        if version != SESSION_VERSION && version != SESSION_VERSION_1 {
            return Err(Error::InvalidData(
                "unsupported session export version".into(),
            ));
        }
        let (account_key, mut rest) = take_key(rest).ok_or_else(malformed)?;
        let mut keyring = Self::from_account_key(account_id, account_key);
        if version == SESSION_VERSION_1 {
            while !rest.is_empty() {
                let (len, after_len) = rest.split_at_checked(2).ok_or_else(malformed)?;
                let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
                let (id, after_id) = after_len.split_at_checked(len).ok_or_else(malformed)?;
                let id = core::str::from_utf8(id)
                    .map_err(|_| malformed())?
                    .to_owned();
                let (key, after_key) = take_key(after_id).ok_or_else(malformed)?;
                keyring.vault_keys.insert((id, 0), key);
                rest = after_key;
            }
            return Ok(keyring);
        }
        let (mut enc, mut sig, mut bundle, mut bundle_sig) = (None, None, None, None);
        while !rest.is_empty() {
            let (&kind, after_kind) = rest.split_first().ok_or_else(malformed)?;
            let (len, after_len) = after_kind.split_at_checked(2).ok_or_else(malformed)?;
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            let (id, after_id) = after_len.split_at_checked(len).ok_or_else(malformed)?;
            let id = core::str::from_utf8(id)
                .map_err(|_| malformed())?
                .to_owned();
            let (epoch, after_epoch) = after_id.split_at_checked(4).ok_or_else(malformed)?;
            let epoch = u32::from_be_bytes(epoch.try_into().expect("4 bytes"));
            let (len, after_len) = after_epoch.split_at_checked(2).ok_or_else(malformed)?;
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            let (key, after_key) = after_len.split_at_checked(len).ok_or_else(malformed)?;
            rest = after_key;
            let fixed = || -> Result<[u8; 32]> { key.try_into().map_err(|_| malformed()) };
            match kind {
                ENTRY_VAULT => {
                    keyring
                        .vault_keys
                        .insert((id, epoch), SymmetricKey::from_bytes(fixed()?));
                }
                ENTRY_GROUP => {
                    keyring
                        .group_keys
                        .insert((id, epoch), EncryptionKey::from_seed(&fixed()?));
                }
                ENTRY_ORG => {
                    keyring
                        .org_keys
                        .insert((id, epoch), SymmetricKey::from_bytes(fixed()?));
                }
                ENTRY_ACCOUNT_ENC => enc = Some(EncryptionKey::from_seed(&fixed()?)),
                ENTRY_ACCOUNT_SIG => sig = Some(SignatureKey::from_seed(&fixed()?)),
                ENTRY_BUNDLE => bundle = Some(key.to_vec()),
                ENTRY_BUNDLE_SIGNATURE => bundle_sig = Some(key.to_vec()),
                _ => return Err(malformed()),
            }
        }
        match (enc, sig, bundle, bundle_sig) {
            (Some(enc), Some(sig), Some(bundle), Some(bundle_sig)) => {
                let bundle = SignedBundle::from_parts(&bundle, &bundle_sig)?;
                keyring.account = Some(AccountKeys { enc, sig, bundle });
            }
            (None, None, None, None) => {}
            _ => return Err(malformed()),
        }
        Ok(keyring)
    }
}

fn take_key(bytes: &[u8]) -> Option<(SymmetricKey, &[u8])> {
    let (key, rest) = bytes.split_at_checked(KEY_LEN)?;
    Some((SymmetricKey::from_bytes(key.try_into().ok()?), rest))
}

pub(crate) fn into_json_string(plaintext: Vec<u8>) -> Result<String> {
    ensure_json(&plaintext)?;
    String::from_utf8(plaintext).map_err(|_| Error::InvalidData("plaintext is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (SymmetricKey, Keyring, String) {
        let auk = SymmetricKey::generate().unwrap();
        let (keyring, encrypted) = Keyring::create(&auk, "acc").unwrap();
        (auk, keyring, encrypted)
    }

    #[test]
    fn unlock_with_the_right_auk() {
        let (auk, _, encrypted) = setup();
        assert_eq!(
            Keyring::unlock(&auk, "acc", &encrypted)
                .unwrap()
                .account_id(),
            "acc"
        );
    }

    #[test]
    fn rewrapped_account_key_unlocks_with_the_new_auk_only() {
        let (old_auk, mut keyring, _) = setup();
        let vault = keyring.create_vault("{}").unwrap();
        let new_auk = SymmetricKey::generate().unwrap();
        let rewrapped = keyring.wrap_account_key(&new_auk).unwrap();
        assert!(Keyring::unlock(&old_auk, "acc", &rewrapped).is_err());
        let mut unlocked = Keyring::unlock(&new_auk, "acc", &rewrapped).unwrap();
        unlocked.add_vault(&vault.id, &vault.encrypted_key).unwrap();
    }

    #[test]
    fn unlock_fails_with_wrong_auk_or_account() {
        let (auk, _, encrypted) = setup();
        let other = SymmetricKey::generate().unwrap();
        assert_eq!(
            Keyring::unlock(&other, "acc", &encrypted).err(),
            Some(Error::InvalidCredentials)
        );
        assert_eq!(
            Keyring::unlock(&auk, "other", &encrypted).err(),
            Some(Error::InvalidCredentials)
        );
    }

    #[test]
    fn vault_and_item_round_trip_after_unlock() {
        let (auk, mut keyring, encrypted) = setup();
        let vault = keyring.create_vault(r#"{"name":"Private"}"#).unwrap();
        let item = keyring
            .encrypt_item(&vault.id, "item1", 1, r#"{"title":"GitHub"}"#)
            .unwrap();

        let mut other_device = Keyring::unlock(&auk, "acc", &encrypted).unwrap();
        assert!(!other_device.has_vault(&vault.id));
        other_device
            .add_vault(&vault.id, &vault.encrypted_key)
            .unwrap();
        assert_eq!(
            other_device
                .decrypt_vault_meta(&vault.id, &vault.encrypted_meta)
                .unwrap(),
            r#"{"name":"Private"}"#
        );
        assert_eq!(
            other_device
                .decrypt_item(&vault.id, "item1", 1, &item)
                .unwrap(),
            r#"{"title":"GitHub"}"#
        );
    }

    #[test]
    fn items_are_bound_to_their_context() {
        let (_, mut keyring, _) = setup();
        let vault = keyring.create_vault("{}").unwrap();
        let second = keyring.create_vault("{}").unwrap();
        let item = keyring.encrypt_item(&vault.id, "item1", 2, "{}").unwrap();

        assert!(keyring.decrypt_item(&vault.id, "item2", 2, &item).is_err());
        assert!(keyring.decrypt_item(&vault.id, "item1", 1, &item).is_err());
        assert!(keyring.decrypt_item(&second.id, "item1", 2, &item).is_err());
    }

    #[test]
    fn vault_keys_are_bound_to_vault_id() {
        let (_, mut keyring, _) = setup();
        let a = keyring.create_vault("{}").unwrap();
        let b = keyring.create_vault("{}").unwrap();
        assert!(keyring.add_vault(&b.id, &a.encrypted_key).is_err());
    }

    #[test]
    fn session_export_round_trips() {
        let (_, mut keyring, _) = setup();
        let vault = keyring.create_vault(r#"{"name":"Private"}"#).unwrap();
        let second = keyring.create_vault("{}").unwrap();
        let item = keyring.encrypt_item(&vault.id, "item1", 3, "{}").unwrap();

        let (session_key, blob) = keyring.export_session().unwrap();
        let restored = Keyring::import_session(&session_key, "acc", &blob).unwrap();
        assert_eq!(restored.account_id(), "acc");
        assert!(restored.has_vault(&vault.id) && restored.has_vault(&second.id));
        assert_eq!(
            restored.decrypt_item(&vault.id, "item1", 3, &item).unwrap(),
            "{}"
        );
        // The restored keyring can still unwrap vault keys from the server.
        let mut restored = restored;
        restored
            .add_vault(&second.id, &second.encrypted_key)
            .unwrap();
    }

    #[test]
    fn session_export_uses_a_fresh_key_each_time() {
        let (_, keyring, _) = setup();
        let (key_a, blob_a) = keyring.export_session().unwrap();
        let (key_b, blob_b) = keyring.export_session().unwrap();
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
        assert_ne!(blob_a, blob_b);
        assert!(Keyring::import_session(&key_a, "acc", &blob_b).is_err());
    }

    #[test]
    fn session_export_is_bound_to_key_and_account() {
        let (_, keyring, _) = setup();
        let (session_key, blob) = keyring.export_session().unwrap();
        let other = SymmetricKey::generate().unwrap();
        assert_eq!(
            Keyring::import_session(&other, "acc", &blob).unwrap_err(),
            Error::Decryption
        );
        assert_eq!(
            Keyring::import_session(&session_key, "someone-else", &blob).unwrap_err(),
            Error::Decryption
        );
        let mut tampered = encoding::decode(&blob).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            Keyring::import_session(&session_key, "acc", &encoding::encode(&tampered)).is_err()
        );
        assert!(Keyring::import_session(&session_key, "acc", "not base64!").is_err());
    }

    #[test]
    fn session_import_rejects_malformed_plaintext() {
        let session_key = SymmetricKey::generate().unwrap();
        for plaintext in [
            vec![],
            vec![3; 1 + KEY_LEN],
            vec![SESSION_VERSION; 10],
            [vec![SESSION_VERSION], vec![0; KEY_LEN], vec![0, 5, b'a']].concat(),
        ] {
            let blob = encoding::encode(
                &session_key
                    .encrypt(&plaintext, &session_aad("acc"))
                    .unwrap(),
            );
            assert!(matches!(
                Keyring::import_session(&session_key, "acc", &blob),
                Err(Error::InvalidData(_))
            ));
        }
    }

    #[test]
    fn rejects_non_json_and_unknown_vaults() {
        let (_, mut keyring, _) = setup();
        assert!(keyring.create_vault("not json").is_err());
        assert!(matches!(
            keyring.encrypt_item("missing", "i", 1, "{}"),
            Err(Error::MissingKey(_))
        ));
    }
}
