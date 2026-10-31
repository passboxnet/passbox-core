//! Moving items between vaults, the archive, file attachments, item
//! templates and SSH keys (additive API). See
//! `docs/architecture/sharing.md` and `docs/architecture/attachments.md`.
//!
//! All calls are blocking: run them on a background task.

use passbox_client as client;

use crate::{Item, ItemData, PassboxClient, PassboxError, Result, data_from_ffi, data_to_ffi};

/// A file attached to an item. The file key stays inside the client.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    /// Media type, for example `application/pdf` or `image/jpeg`.
    pub media_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Unix milliseconds.
    pub created_at: i64,
}

pub(crate) fn attachment_to_ffi(a: client::Attachment) -> Attachment {
    Attachment {
        id: a.id,
        name: a.name,
        media_type: a.media_type,
        size: a.size,
        created_at: a.created_at,
    }
}

/// The result of `move_items`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MoveResult {
    /// Items now in the target vault.
    pub moved: Vec<String>,
    /// Items that already were in the target vault.
    pub skipped: Vec<String>,
}

/// A new SSH key pair (Ed25519, OpenSSH formats).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshKeyPair {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----` … (unencrypted; the vault
    /// protects it).
    pub private_key: String,
    /// `ssh-ed25519 AAAA… comment`, for `authorized_keys`.
    pub public_key: String,
    /// `SHA256:…`.
    pub fingerprint: String,
}

#[uniffi::export]
impl PassboxClient {
    /// Moves items into another vault: re-encrypted on this device for the
    /// target vault, keeping their IDs, creation dates, attachments and the
    /// history this device can read. Everyone with access to the target
    /// vault sees them afterwards; people with access only to the old vault
    /// no longer do. Show that before calling (`vault_members`).
    pub fn move_items(&self, item_ids: Vec<String>, vault_id: String) -> Result<MoveResult> {
        let outcome = self.inner.move_items(&item_ids, &vault_id)?;
        Ok(MoveResult {
            moved: outcome.moved,
            skipped: outcome.skipped,
        })
    }

    /// Archives an item: hidden from `items`, search and autofill, but
    /// kept in its vault (`archived_items`).
    pub fn archive_item(&self, id: String) -> Result<()> {
        Ok(self.inner.archive_item(&id)?)
    }

    pub fn unarchive_item(&self, id: String) -> Result<()> {
        Ok(self.inner.unarchive_item(&id)?)
    }

    /// Archived items, most recently archived first.
    pub fn archived_items(&self) -> Result<Vec<Item>> {
        Ok(self
            .inner
            .archived_items()?
            .into_iter()
            .map(crate::item_to_ffi)
            .collect())
    }

    /// Encrypts a file on this device, uploads it and attaches it to the
    /// item. Fails with `Server` (`quota_exceeded`, `file_too_large`) when
    /// the server's limits do not allow it.
    pub fn add_attachment(
        &self,
        item_id: String,
        name: String,
        media_type: String,
        data: Vec<u8>,
    ) -> Result<Attachment> {
        Ok(attachment_to_ffi(self.inner.add_attachment(
            &item_id,
            &name,
            &media_type,
            &data,
        )?))
    }

    /// Downloads and decrypts an attachment. Write it to a private cache
    /// file to open or share it, and delete that file afterwards.
    pub fn attachment_data(&self, item_id: String, attachment_id: String) -> Result<Vec<u8>> {
        Ok(self.inner.attachment_data(&item_id, &attachment_id)?)
    }

    /// Removes an attachment from the item and deletes the file.
    pub fn remove_attachment(&self, item_id: String, attachment_id: String) -> Result<()> {
        Ok(self.inner.remove_attachment(&item_id, &attachment_id)?)
    }
}

/// A new item of a category given by its stored name (`wifi`, `passport`,
/// `sshKey`, …) with that category's template fields.
#[uniffi::export]
pub fn new_item_data_named(category_name: String, title: String) -> ItemData {
    let category = client::ItemCategory::parse(&category_name);
    let mut data = client::ItemData::new(category, title);
    data.set_category_name(&category_name);
    data_to_ffi(data)
}

/// Every category name this version knows, in menu order.
#[uniffi::export]
pub fn item_category_names() -> Vec<String> {
    client::ItemCategory::ALL
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect()
}

/// The text of a Wi-Fi QR code (`WIFI:T:WPA;S:…;P:…;;`) for a Wi-Fi item,
/// or `None` without a network name.
#[uniffi::export]
pub fn wifi_qr_payload(data: ItemData) -> Result<Option<String>> {
    Ok(client::model::wifi_qr_payload(&data_from_ffi(data)?))
}

/// Generates an Ed25519 SSH key pair. `comment` is usually `user@host`.
#[uniffi::export]
pub fn generate_ssh_key(comment: String) -> Result<SshKeyPair> {
    let pair = passbox_core::ssh::generate_ed25519(&comment)?;
    Ok(SshKeyPair {
        private_key: pair.private_key,
        public_key: pair.public_key,
        fingerprint: pair.fingerprint,
    })
}

/// The public key line and fingerprint of an OpenSSH Ed25519 private key.
#[uniffi::export]
pub fn ssh_public_key(private_key: String) -> Result<SshKeyPair> {
    let (public_key, fingerprint) =
        passbox_core::ssh::public_key_of(&private_key).map_err(|e| PassboxError::InvalidData {
            message: e.to_string(),
        })?;
    Ok(SshKeyPair {
        private_key: String::new(),
        public_key,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ItemCategory;

    #[test]
    fn categories_survive_the_bindings() {
        for name in ["environment", "wifi", "sshKey", "spaceship"] {
            let mut data = client::ItemData::new(client::ItemCategory::Note, "x");
            data.set_category_name(name);
            let ffi = data_to_ffi(data);
            assert_eq!(ffi.category, ItemCategory::Other);
            assert_eq!(ffi.category_name, name);
            assert!(!ffi.extra_json.contains("category"));
            // An app that keeps the record as it is saves the same category.
            assert_eq!(data_from_ffi(ffi.clone()).unwrap().category_name(), name);
            // One that drops the name saves "other".
            let mut bare = ffi;
            bare.category_name = String::new();
            assert_eq!(data_from_ffi(bare).unwrap().category_name(), "other");
        }
        let login = data_to_ffi(client::ItemData::new(client::ItemCategory::Login, "x"));
        assert_eq!(login.category, ItemCategory::Login);
        assert_eq!(login.category_name, "login");
        let named = new_item_data_named("passport".into(), "P".into());
        assert_eq!(named.category_name, "passport");
        assert!(
            named
                .fields
                .iter()
                .any(|f| f.format.as_deref() == Some("date"))
        );
        assert!(item_category_names().contains(&"sshKey".to_owned()));
    }

    #[test]
    fn ssh_keys() {
        let pair = generate_ssh_key("me@laptop".into()).unwrap();
        let again = ssh_public_key(pair.private_key.clone()).unwrap();
        assert_eq!(again.public_key, pair.public_key);
        assert!(ssh_public_key("nope".into()).is_err());
    }
}
