//! The client's key hierarchy and the encryption of vault data.
//!
//! ```text
//! AUK ──wraps──▶ account key ──wraps──▶ vault key ──encrypts──▶ vault metadata, items
//! ```
//!
//! Every ciphertext is bound to its context through associated data (see
//! [`crate::aead`]). Items are bound to their vault, ID and revision, so a
//! server cannot move an item to another vault, swap two items or present an
//! older revision under a newer revision number.
//!
//! Plaintexts are JSON documents. Their schema is owned by the clients; the
//! keyring only checks that they are valid JSON.

use std::collections::HashMap;

use crate::aead::{KEY_LEN, SymmetricKey};
use crate::{Error, Result, encoding, id};

fn account_key_aad(account_id: &str) -> Vec<u8> {
    format!("passbox/v1/account-key|{account_id}").into_bytes()
}

fn vault_key_aad(account_id: &str, vault_id: &str) -> Vec<u8> {
    format!("passbox/v1/vault-key|{account_id}|{vault_id}").into_bytes()
}

fn vault_meta_aad(vault_id: &str) -> Vec<u8> {
    format!("passbox/v1/vault-meta|{vault_id}").into_bytes()
}

fn item_aad(vault_id: &str, item_id: &str, revision: u64) -> Vec<u8> {
    format!("passbox/v1/item|{vault_id}|{item_id}|{revision}").into_bytes()
}

fn session_aad(account_id: &str) -> Vec<u8> {
    format!("passbox/v1/session|{account_id}").into_bytes()
}

/// Version byte of the session export plaintext.
const SESSION_VERSION: u8 = 1;

fn key_from_plaintext(bytes: Vec<u8>) -> Result<SymmetricKey> {
    let mut bytes = zeroize::Zeroizing::new(bytes);
    let key: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidData("key has the wrong length".into()))?;
    bytes.iter_mut().for_each(|b| *b = 0);
    Ok(SymmetricKey::from_bytes(key))
}

fn ensure_json(bytes: &[u8]) -> Result<()> {
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

/// Holds the decrypted account key and vault keys of an unlocked account.
/// Keys are wiped from memory when the keyring is dropped.
pub struct Keyring {
    account_id: String,
    account_key: SymmetricKey,
    vault_keys: HashMap<String, SymmetricKey>,
}

impl core::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("account_id", &self.account_id)
            .field("vaults", &self.vault_keys.len())
            .finish_non_exhaustive()
    }
}

impl Keyring {
    /// Creates the keyring for a new account. Returns the keyring and the
    /// account key encrypted with the AUK, for upload.
    pub fn create(auk: &SymmetricKey, account_id: &str) -> Result<(Self, String)> {
        let account_key = SymmetricKey::generate()?;
        let encrypted = auk.encrypt(account_key.as_bytes(), &account_key_aad(account_id))?;
        let keyring = Self {
            account_id: account_id.to_owned(),
            account_key,
            vault_keys: HashMap::new(),
        };
        Ok((keyring, encoding::encode(&encrypted)))
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
        Ok(Self {
            account_id: account_id.to_owned(),
            account_key: key_from_plaintext(plaintext)?,
            vault_keys: HashMap::new(),
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
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

    /// Creates a new vault with the given metadata (JSON) and adds its key.
    pub fn create_vault(&mut self, meta_json: &str) -> Result<NewVault> {
        ensure_json(meta_json.as_bytes())?;
        let vault_id = id::new_id()?;
        let vault_key = SymmetricKey::generate()?;
        let encrypted_key = self.account_key.encrypt(
            vault_key.as_bytes(),
            &vault_key_aad(&self.account_id, &vault_id),
        )?;
        let encrypted_meta = vault_key.encrypt(meta_json.as_bytes(), &vault_meta_aad(&vault_id))?;
        self.vault_keys.insert(vault_id.clone(), vault_key);
        Ok(NewVault {
            id: vault_id,
            encrypted_key: encoding::encode(&encrypted_key),
            encrypted_meta: encoding::encode(&encrypted_meta),
        })
    }

    /// Decrypts a vault key received from the server and adds it.
    pub fn add_vault(&mut self, vault_id: &str, encrypted_key: &str) -> Result<()> {
        let envelope = encoding::decode(encrypted_key)?;
        let plaintext = self
            .account_key
            .decrypt(&envelope, &vault_key_aad(&self.account_id, vault_id))?;
        self.vault_keys
            .insert(vault_id.to_owned(), key_from_plaintext(plaintext)?);
        Ok(())
    }

    pub fn has_vault(&self, vault_id: &str) -> bool {
        self.vault_keys.contains_key(vault_id)
    }

    fn vault_key(&self, vault_id: &str) -> Result<&SymmetricKey> {
        self.vault_keys
            .get(vault_id)
            .ok_or_else(|| Error::MissingKey(format!("vault {vault_id}")))
    }

    pub fn encrypt_vault_meta(&self, vault_id: &str, meta_json: &str) -> Result<String> {
        ensure_json(meta_json.as_bytes())?;
        let envelope = self
            .vault_key(vault_id)?
            .encrypt(meta_json.as_bytes(), &vault_meta_aad(vault_id))?;
        Ok(encoding::encode(&envelope))
    }

    pub fn decrypt_vault_meta(&self, vault_id: &str, encrypted_meta: &str) -> Result<String> {
        let plaintext = self.vault_key(vault_id)?.decrypt(
            &encoding::decode(encrypted_meta)?,
            &vault_meta_aad(vault_id),
        )?;
        into_json_string(plaintext)
    }

    /// Encrypts item data (JSON) for the given revision.
    pub fn encrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        revision: u64,
        data_json: &str,
    ) -> Result<String> {
        ensure_json(data_json.as_bytes())?;
        let envelope = self
            .vault_key(vault_id)?
            .encrypt(data_json.as_bytes(), &item_aad(vault_id, item_id, revision))?;
        Ok(encoding::encode(&envelope))
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
        let plaintext = self.vault_key(vault_id)?.decrypt(
            &encoding::decode(encrypted)?,
            &item_aad(vault_id, item_id, revision),
        )?;
        into_json_string(plaintext)
    }
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
    pub fn export_session(&self) -> Result<(SymmetricKey, String)> {
        let mut plaintext = zeroize::Zeroizing::new(Vec::with_capacity(
            1 + KEY_LEN + self.vault_keys.len() * (2 + 26 + KEY_LEN),
        ));
        plaintext.push(SESSION_VERSION);
        plaintext.extend_from_slice(self.account_key.as_bytes());
        let mut vault_ids: Vec<&String> = self.vault_keys.keys().collect();
        vault_ids.sort();
        for vault_id in vault_ids {
            let id = vault_id.as_bytes();
            let len = u16::try_from(id.len())
                .map_err(|_| Error::InvalidData("vault ID is too long".into()))?;
            plaintext.extend_from_slice(&len.to_be_bytes());
            plaintext.extend_from_slice(id);
            plaintext.extend_from_slice(self.vault_keys[vault_id].as_bytes());
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
        let plaintext =
            zeroize::Zeroizing::new(session_key.decrypt(&envelope, &session_aad(account_id))?);
        let malformed = || Error::InvalidData("malformed session export".into());
        let (&version, rest) = plaintext.split_first().ok_or_else(malformed)?;
        if version != SESSION_VERSION {
            return Err(Error::InvalidData(
                "unsupported session export version".into(),
            ));
        }
        let (account_key, mut rest) = take_key(rest).ok_or_else(malformed)?;
        let mut vault_keys = HashMap::new();
        while !rest.is_empty() {
            let (len, after_len) = rest.split_at_checked(2).ok_or_else(malformed)?;
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            let (id, after_id) = after_len.split_at_checked(len).ok_or_else(malformed)?;
            let id = core::str::from_utf8(id)
                .map_err(|_| malformed())?
                .to_owned();
            let (key, after_key) = take_key(after_id).ok_or_else(malformed)?;
            vault_keys.insert(id, key);
            rest = after_key;
        }
        Ok(Self {
            account_id: account_id.to_owned(),
            account_key,
            vault_keys,
        })
    }
}

fn take_key(bytes: &[u8]) -> Option<(SymmetricKey, &[u8])> {
    let (key, rest) = bytes.split_at_checked(KEY_LEN)?;
    Some((SymmetricKey::from_bytes(key.try_into().ok()?), rest))
}

fn into_json_string(plaintext: Vec<u8>) -> Result<String> {
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
            vec![2; 1 + KEY_LEN],
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
