//! Moving items between vaults, the archive and file
//! attachments.

use passbox_core::{file_crypto, id};
use serde_json::json;

use super::{Client, now_ms};
use crate::model::{Attachment, ItemData};
use crate::{Error, Result};

/// Items per move request (the server's limit).
const MOVE_BATCH: usize = 100;

/// What [`Client::move_items`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveOutcome {
    /// Items now in the target vault.
    pub moved: Vec<String>,
    /// Items that were already there.
    pub skipped: Vec<String>,
}

impl Client {
    // --- Archive ------------------------------------------------------------------

    /// Archives an item: it disappears from [`Client::items`], search and
    /// autofill but stays in its vault ([`Client::archived_items`]).
    pub fn archive_item(&self, item_id: &str) -> Result<()> {
        self.set_archived(item_id, Some(now_ms()))
    }

    /// Takes an item out of the archive.
    pub fn unarchive_item(&self, item_id: &str) -> Result<()> {
        self.set_archived(item_id, None)
    }

    fn set_archived(&self, item_id: &str, at: Option<i64>) -> Result<()> {
        let current = self.item(item_id)?;
        let mut data = current.data;
        data.set_archived_at(at);
        self.write_item(&current.vault_id, item_id, current.revision + 1, &data)
    }

    // --- Moving -------------------------------------------------------------------

    /// Moves items into another vault. Each item is re-encrypted with the
    /// target vault's key on this device and keeps its ID, creation date,
    /// attachments and the versions of its history this device can read.
    /// Everyone with access to the target vault can see the items
    /// afterwards; people who only had the old vault lose them. Items that
    /// changed meanwhile are retried once after a sync; moves are all or
    /// nothing per batch of 100.
    pub fn move_items(&self, item_ids: &[String], vault_id: &str) -> Result<MoveOutcome> {
        let mut outcome = MoveOutcome::default();
        let mut pending = Vec::new();
        for item_id in item_ids {
            let item = self.item(item_id)?;
            if item.vault_id == vault_id {
                outcome.skipped.push(item_id.clone());
            } else if !pending.contains(item_id) {
                pending.push(item_id.clone());
            }
        }
        for batch in pending.chunks(MOVE_BATCH) {
            match self.move_batch(batch, vault_id) {
                Err(Error::Conflict) => {
                    self.sync()?;
                    self.move_batch(batch, vault_id)?;
                }
                other => other?,
            }
            outcome.moved.extend(batch.iter().cloned());
        }
        if !outcome.moved.is_empty() {
            self.sync()?;
        }
        Ok(outcome)
    }

    fn move_batch(&self, item_ids: &[String], vault_id: &str) -> Result<()> {
        // The history comes from the server; read it before encrypting.
        let mut histories = Vec::with_capacity(item_ids.len());
        for item_id in item_ids {
            histories.push(self.with_token(|token| self.api.item_versions(token, item_id))?);
        }
        let (epoch, items) = {
            let guard = self.lock_session();
            let session = guard.as_ref().ok_or(Error::Locked)?;
            let target = session
                .vaults
                .get(vault_id)
                .ok_or_else(|| Error::NotFound(vault_id.to_owned()))?;
            let epoch = target.key_epoch;
            let mut items = Vec::with_capacity(item_ids.len());
            for (item_id, history) in item_ids.iter().zip(histories) {
                let item = session
                    .items
                    .get(item_id)
                    .ok_or_else(|| Error::NotFound(item_id.clone()))?;
                let revision = item.revision + 1;
                let json = serde_json::to_string(&item.data)?;
                let encrypted = session
                    .keyring
                    .encrypt_item_at(vault_id, epoch, item_id, revision, &json)?;
                // The version being replaced stays in the history.
                let mut versions = vec![json!({
                    "revision": item.revision,
                    "encryptedData": session.keyring.encrypt_item_at(
                        vault_id, epoch, item_id, item.revision, &json,
                    )?,
                })];
                for record in history {
                    let Ok(plain) = session.keyring.decrypt_item_at(
                        &item.vault_id,
                        record.key_epoch,
                        item_id,
                        record.revision,
                        &record.encrypted_data,
                    ) else {
                        continue;
                    };
                    if record.revision >= item.revision {
                        continue;
                    }
                    versions.push(json!({
                        "revision": record.revision,
                        "encryptedData": session.keyring.encrypt_item_at(
                            vault_id, epoch, item_id, record.revision, &plain,
                        )?,
                    }));
                }
                items.push(json!({
                    "id": item_id,
                    "revision": revision,
                    "encryptedData": encrypted,
                    "versions": versions,
                }));
            }
            (epoch, items)
        };
        self.with_token(|token| {
            self.api.request(
                "POST",
                "/api/v1/items/move",
                token,
                Some(json!({
                    "targetVaultId": vault_id,
                    "keyEpoch": epoch,
                    "items": items,
                })),
            )
        })
        .map(drop)
    }

    // --- Attachments --------------------------------------------------------------

    /// Encrypts `data` on this device, uploads it and adds it to the item.
    /// Returns the new attachment.
    pub fn add_attachment(
        &self,
        item_id: &str,
        name: &str,
        media_type: &str,
        data: &[u8],
    ) -> Result<Attachment> {
        let name = name.trim();
        if name.is_empty() || name.len() > 255 {
            return Err(Error::InvalidData(
                "a file name has 1 to 255 characters".into(),
            ));
        }
        let attachment_id = id::new_id()?;
        let key = file_crypto::generate_key()?;
        let blob = file_crypto::encrypt_file(&file_crypto::parse_key(&key)?, &attachment_id, data)?;
        self.with_token(|token| {
            self.api
                .upload_attachment(token, &attachment_id, item_id, blob.clone())
        })?;
        let attachment = Attachment {
            id: attachment_id.clone(),
            name: name.to_owned(),
            media_type: if media_type.is_empty() {
                "application/octet-stream".into()
            } else {
                media_type.to_owned()
            },
            size: data.len() as u64,
            key,
            created_at: now_ms(),
        };
        let saved = self.change_attachments(item_id, |list| list.push(attachment.clone()));
        if let Err(e) = saved {
            // Do not leave a blob behind that no item refers to.
            let _ = self.delete_blob(&attachment_id);
            return Err(e);
        }
        Ok(attachment)
    }

    /// Downloads and decrypts an attachment.
    pub fn attachment_data(&self, item_id: &str, attachment_id: &str) -> Result<Vec<u8>> {
        let attachment = self
            .item(item_id)?
            .data
            .attachments()
            .into_iter()
            .find(|a| a.id == attachment_id)
            .ok_or_else(|| Error::NotFound(attachment_id.to_owned()))?;
        let blob = self.with_token(|token| self.api.download_attachment(token, attachment_id))?;
        let data = file_crypto::decrypt_file(
            &file_crypto::parse_key(&attachment.key)?,
            attachment_id,
            &blob,
        )?;
        if data.len() as u64 != attachment.size {
            return Err(Error::InvalidData(
                "the attachment does not have the expected size".into(),
            ));
        }
        Ok(data)
    }

    /// Removes an attachment from the item and deletes its file.
    pub fn remove_attachment(&self, item_id: &str, attachment_id: &str) -> Result<()> {
        self.change_attachments(item_id, |list| list.retain(|a| a.id != attachment_id))?;
        match self.delete_blob(attachment_id) {
            Ok(()) | Err(Error::Server { status: 404, .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn delete_blob(&self, attachment_id: &str) -> Result<()> {
        self.with_token(|token| {
            self.api.request(
                "DELETE",
                &format!("/api/v1/attachments/{attachment_id}"),
                token,
                None,
            )
        })
        .map(drop)
    }

    fn change_attachments(
        &self,
        item_id: &str,
        change: impl Fn(&mut Vec<Attachment>),
    ) -> Result<()> {
        let mut attempt = 0;
        loop {
            let current = self.item(item_id)?;
            let mut data: ItemData = current.data.clone();
            let mut list = data.attachments();
            change(&mut list);
            data.set_attachments(&list);
            match self.write_item(&current.vault_id, item_id, current.revision + 1, &data) {
                Err(Error::Conflict) if attempt == 0 => attempt += 1,
                other => return other,
            }
        }
    }
}
