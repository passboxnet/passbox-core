//! Emergency access: read access to chosen vaults for a trusted
//! person after a waiting period.
//!
//! ```text
//! grant  = { grant_id, grantor_id, grantor_bundle_hash, grantee_id, grantee_bundle_hash,
//!            scope, wait_ms, vaults: [(vault_id, key_epoch)] sorted, version,
//!            sealed_hash, created_at }                       signed by the grantor
//! sealed = Seal(grantee.enc_pk, keys, purpose "emergency-access",
//!               context = (grant_id, grantor_id, grantee_id, version))
//! keys   = canonical("passbox/v1/emergency-keys", [(vault_id, key_epoch, key)])
//! ```
//!
//! The grantor's client looks the grantee up in the key directory first
//! (and the grantor can compare fingerprints), so it never seals to a key the
//! server chose. The server keeps the sealed keys back until the grantee
//! asked and the waiting period passed without the grantor declining: the
//! waiting period is enforced by the server (see
//! `docs/architecture/recovery.md`). The grantee's client verifies the
//! grantor's signature with the grantor's key from the directory and
//! opens the keys. Only personal vaults are offered; shared vaults belong to
//! their organization.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aead::SymmetricKey;
use crate::canon::{Reader, Writer};
use crate::identity::{HASH_LEN, SignedBundle, sealed_hash};
use crate::keyring::{Keyring, into_json_string, item_aad, key_from_plaintext, vault_meta_aad};
use crate::sharing::objects::{Canonical, Signed};
use crate::{Error, Result, encoding};

pub const PURPOSE: &str = "emergency-access";
/// The only scope so far: read access to the listed vaults.
pub const SCOPE_VAULTS: &str = "vaults";
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// Allowed waiting periods, in days.
pub const MIN_WAIT_DAYS: u64 = 1;
pub const MAX_WAIT_DAYS: u64 = 30;

fn denied(message: impl Into<String>) -> Error {
    Error::InvalidData(message.into())
}

fn context(grant_id: &str, grantor_id: &str, grantee_id: &str, version: u64) -> Vec<u8> {
    Writer::new("passbox/v1/seal-context/emergency-access")
        .str(grant_id)
        .str(grantor_id)
        .str(grantee_id)
        .u64(version)
        .finish()
}

/// The signed emergency access agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyGrant {
    pub grant_id: String,
    pub grantor_id: String,
    pub grantor_bundle_hash: [u8; HASH_LEN],
    pub grantee_id: String,
    pub grantee_bundle_hash: [u8; HASH_LEN],
    pub scope: String,
    pub wait_ms: u64,
    pub vaults: Vec<(String, u32)>,
    pub version: u64,
    pub sealed_hash: [u8; HASH_LEN],
    pub created_at: i64,
}

impl Canonical for EmergencyGrant {
    const TAG: &'static str = "passbox/v1/emergency-grant";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.grant_id)
            .str(&self.grantor_id)
            .bytes(&self.grantor_bundle_hash)
            .str(&self.grantee_id)
            .bytes(&self.grantee_bundle_hash)
            .str(&self.scope)
            .u64(self.wait_ms)
            .count(self.vaults.len());
        for (vault, epoch) in &self.vaults {
            w.str(vault).u64(u64::from(*epoch));
        }
        w.u64(self.version)
            .bytes(&self.sealed_hash)
            .i64(self.created_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let grant_id = r.string()?;
        let grantor_id = r.string()?;
        let grantor_bundle_hash = r.array()?;
        let grantee_id = r.string()?;
        let grantee_bundle_hash = r.array()?;
        let scope = r.string()?;
        let wait_ms = r.u64()?;
        let count = r.count()?;
        let mut vaults = Vec::with_capacity(count.min(1000));
        for _ in 0..count {
            vaults.push((r.string()?, r.u32()?));
        }
        Ok(Self {
            grant_id,
            grantor_id,
            grantor_bundle_hash,
            grantee_id,
            grantee_bundle_hash,
            scope,
            wait_ms,
            vaults,
            version: r.u64()?,
            sealed_hash: r.array()?,
            created_at: r.i64()?,
        })
    }
}

/// `POST /api/v1/emergency/grants/{id}/confirm` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyGrantUpload {
    pub grant: String,
    pub grant_signature: String,
    pub sealed_keys: String,
    pub vault_ids: Vec<String>,
    pub version: u64,
    /// The grantee's fingerprint the grantor saw (for display).
    pub fingerprint: String,
}

/// What the grantor's client needs to know about a stored grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyGrantInfo {
    pub grant_id: String,
    pub grantor_id: String,
    pub grantee_id: String,
    pub wait_days: u64,
    pub vault_ids: Vec<String>,
    pub version: u64,
}

fn encode_keys(entries: &[(String, u32, &SymmetricKey)]) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::new("passbox/v1/emergency-keys");
    w.count(entries.len());
    for (vault, epoch, key) in entries {
        w.str(vault).u64(u64::from(*epoch)).bytes(key.as_bytes());
    }
    Zeroizing::new(w.finish())
}

/// Vault keys released to a grantee. They never leave this object; it
/// decrypts the grantor's vault metadata and items.
pub struct EmergencyKeys {
    pub grantor_id: String,
    pub grant: EmergencyGrant,
    keys: HashMap<(String, u32), SymmetricKey>,
}

impl core::fmt::Debug for EmergencyKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EmergencyKeys")
            .field("grantor_id", &self.grantor_id)
            .field("vaults", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl EmergencyKeys {
    fn key(&self, vault_id: &str, epoch: u32) -> Result<&SymmetricKey> {
        self.keys
            .get(&(vault_id.to_owned(), epoch))
            .ok_or_else(|| Error::MissingKey(format!("vault {vault_id} (key epoch {epoch})")))
    }

    pub fn vault_ids(&self) -> Vec<String> {
        let set: BTreeSet<&String> = self.keys.keys().map(|(v, _)| v).collect();
        set.into_iter().cloned().collect()
    }

    pub fn decrypt_vault_meta(
        &self,
        vault_id: &str,
        epoch: u32,
        encrypted: &str,
    ) -> Result<String> {
        let plaintext = self.key(vault_id, epoch)?.decrypt(
            &encoding::decode(encrypted)?,
            &vault_meta_aad(vault_id, epoch),
        )?;
        into_json_string(plaintext)
    }

    pub fn decrypt_item(
        &self,
        vault_id: &str,
        epoch: u32,
        item_id: &str,
        revision: u64,
        encrypted: &str,
    ) -> Result<String> {
        let plaintext = self.key(vault_id, epoch)?.decrypt(
            &encoding::decode(encrypted)?,
            &item_aad(vault_id, item_id, revision, epoch),
        )?;
        into_json_string(plaintext)
    }
}

impl Keyring {
    /// The bundle of `account_id` from this session's last directory
    /// lookup, if it matches the pinned key.
    fn looked_up(&self, account_id: &str) -> Result<&SignedBundle> {
        let bundle =
            self.sharing.lookups.get(account_id).ok_or_else(|| {
                denied(format!("look {account_id} up in the key directory first"))
            })?;
        match self.sharing.trust.pins.get(account_id) {
            Some(pin) if pin.bundle_hash == encoding::encode(&bundle.hash()) => Ok(bundle),
            _ => Err(Error::KeyChanged(account_id.to_owned())),
        }
    }

    /// Seals the keys of `vault_ids` (all key epochs this keyring holds)
    /// for the grantee and signs the agreement. Look the grantee up in the
    /// key directory first. `version` must grow with every re-seal.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_emergency_access(
        &self,
        grant_id: &str,
        grantee_id: &str,
        wait_days: u64,
        vault_ids: &[String],
        version: u64,
        now: i64,
    ) -> Result<EmergencyGrantUpload> {
        if !(MIN_WAIT_DAYS..=MAX_WAIT_DAYS).contains(&wait_days) {
            return Err(denied("the waiting period must be 1 to 30 days"));
        }
        if grantee_id == self.account_id {
            return Err(denied("you cannot be your own emergency contact"));
        }
        let grantee = self.looked_up(grantee_id)?;
        let own = self.account_keys()?;
        let wanted: BTreeSet<&str> = vault_ids.iter().map(String::as_str).collect();
        let mut entries: Vec<(String, u32, &SymmetricKey)> = self
            .vault_keys
            .iter()
            .filter(|((vault, _), _)| wanted.contains(vault.as_str()))
            .map(|((vault, epoch), key)| (vault.clone(), *epoch, key))
            .collect();
        entries.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        let missing: Vec<&str> = wanted
            .iter()
            .filter(|v| !entries.iter().any(|e| e.0 == **v))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(Error::MissingKey(format!("vaults {}", missing.join(", "))));
        }
        let sealed = grantee.seal(
            PURPOSE,
            &context(grant_id, &self.account_id, grantee_id, version),
            &encode_keys(&entries),
        )?;
        let grant = Signed::sign(
            EmergencyGrant {
                grant_id: grant_id.to_owned(),
                grantor_id: self.account_id.clone(),
                grantor_bundle_hash: own.bundle.hash(),
                grantee_id: grantee_id.to_owned(),
                grantee_bundle_hash: grantee.hash(),
                scope: SCOPE_VAULTS.to_owned(),
                wait_ms: wait_days * DAY_MS,
                vaults: entries.iter().map(|e| (e.0.clone(), e.1)).collect(),
                version,
                sealed_hash: sealed_hash(&sealed),
                created_at: now,
            },
            &own.sig,
        );
        Ok(EmergencyGrantUpload {
            grant: grant.encoded(),
            grant_signature: grant.encoded_signature(),
            sealed_keys: encoding::encode(&sealed),
            vault_ids: wanted.iter().map(|v| (*v).to_owned()).collect(),
            version,
            fingerprint: grantee.fingerprint(),
        })
    }

    /// Reads one of this account's own grants (signature checked).
    pub fn emergency_grant_info(&self, grant: &str, signature: &str) -> Result<EmergencyGrantInfo> {
        let grant = Signed::<EmergencyGrant>::parse(grant, signature)?;
        grant.verify(&self.account_keys()?.bundle.bundle.sig_pk)?;
        let g = &grant.value;
        let mut vault_ids: Vec<String> = g.vaults.iter().map(|(v, _)| v.clone()).collect();
        vault_ids.dedup();
        Ok(EmergencyGrantInfo {
            grant_id: g.grant_id.clone(),
            grantor_id: g.grantor_id.clone(),
            grantee_id: g.grantee_id.clone(),
            wait_days: g.wait_ms / DAY_MS,
            vault_ids,
            version: g.version,
        })
    }

    /// Whether a stored grant must be sealed again: the chosen vaults have
    /// key epochs the grant does not cover (rotation), a vault is gone, or
    /// this account's key changed. The grantor's client checks this on
    /// unlock and calls [`Keyring::seal_emergency_access`] with the next
    /// version.
    pub fn emergency_reseal_needed(
        &self,
        grant: &str,
        signature: &str,
        vault_ids: &[String],
    ) -> Result<bool> {
        let grant = Signed::<EmergencyGrant>::parse(grant, signature)?;
        let own = self.account_keys()?;
        if grant.verify(&own.bundle.bundle.sig_pk).is_err()
            || grant.value.grantor_bundle_hash != own.bundle.hash()
        {
            return Ok(true);
        }
        let wanted: BTreeSet<&str> = vault_ids.iter().map(String::as_str).collect();
        let mut current: Vec<(String, u32)> = self
            .vault_keys
            .keys()
            .filter(|(vault, _)| wanted.contains(vault.as_str()))
            .cloned()
            .collect();
        current.sort();
        Ok(current != grant.value.vaults)
    }

    /// Opens released emergency access as the grantee. Look the grantor up
    /// in the key directory first: their signature is checked with that key.
    pub fn open_emergency_access(
        &self,
        grant: &str,
        signature: &str,
        sealed_keys: &str,
    ) -> Result<EmergencyKeys> {
        let grant = Signed::<EmergencyGrant>::parse(grant, signature)?;
        let g = grant.value.clone();
        let grantor = self.looked_up(&g.grantor_id)?;
        let own = self.account_keys()?;
        let sealed = encoding::decode(sealed_keys)?;
        if g.grantee_id != self.account_id
            || g.grantee_bundle_hash != own.bundle.hash()
            || g.grantor_bundle_hash != grantor.hash()
            || g.sealed_hash != sealed_hash(&sealed)
            || g.scope != SCOPE_VAULTS
        {
            return Err(denied("the emergency access grant does not match"));
        }
        grant.verify(&grantor.bundle.sig_pk)?;
        let plaintext = own.enc.open(
            &own.bundle.hash(),
            PURPOSE,
            &context(&g.grant_id, &g.grantor_id, &g.grantee_id, g.version),
            &sealed,
        )?;
        let mut r = Reader::new(&plaintext, "passbox/v1/emergency-keys")?;
        let count = r.count()?;
        let mut keys = HashMap::new();
        let mut listed = Vec::with_capacity(count.min(1000));
        for _ in 0..count {
            let vault = r.string()?;
            let epoch = r.u32()?;
            let key = key_from_plaintext(r.bytes()?.to_vec())?;
            listed.push((vault.clone(), epoch));
            keys.insert((vault, epoch), key);
        }
        r.finish()?;
        if listed != g.vaults {
            return Err(denied("the sealed keys do not match the grant"));
        }
        Ok(EmergencyKeys {
            grantor_id: g.grantor_id.clone(),
            grant: g,
            keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing::tests::{Server, account};

    fn pair() -> (Server, Keyring, Keyring, String, String) {
        let mut server = Server::default();
        let mut grantor = account();
        let mut grantee = account();
        server.publish(&mut grantor);
        server.publish(&mut grantee);
        let vault = grantor.create_vault(r#"{"name":"Private"}"#).unwrap();
        let item = grantor
            .encrypt_item(&vault.id, "item1", 3, r#"{"title":"Bank"}"#)
            .unwrap();
        (server, grantor, grantee, vault.id, item)
    }

    #[test]
    fn grantee_reads_the_vault_after_release() {
        let (server, mut grantor, mut grantee, vault_id, item) = pair();
        let ids = vec![vault_id.clone()];
        // The grantee's key must come from the directory.
        assert!(
            grantor
                .seal_emergency_access("g1", grantee.account_id(), 7, &ids, 1, 5)
                .is_err()
        );
        let lookup = grantor
            .verify_directory_lookup(
                grantee.account_id(),
                &server.lookup(grantee.account_id(), 0),
            )
            .unwrap();
        let upload = grantor
            .seal_emergency_access("g1", grantee.account_id(), 7, &ids, 1, 5)
            .unwrap();
        assert_eq!(upload.fingerprint, lookup.fingerprint);
        let info = grantor
            .emergency_grant_info(&upload.grant, &upload.grant_signature)
            .unwrap();
        assert_eq!(info.wait_days, 7);
        assert_eq!(info.vault_ids, ids);
        assert!(
            !grantor
                .emergency_reseal_needed(&upload.grant, &upload.grant_signature, &ids)
                .unwrap()
        );

        grantee
            .verify_directory_lookup(
                grantor.account_id(),
                &server.lookup(grantor.account_id(), 0),
            )
            .unwrap();
        let keys = grantee
            .open_emergency_access(&upload.grant, &upload.grant_signature, &upload.sealed_keys)
            .unwrap();
        assert_eq!(keys.vault_ids(), ids);
        assert_eq!(
            keys.decrypt_item(&vault_id, 0, "item1", 3, &item).unwrap(),
            r#"{"title":"Bank"}"#
        );
        // Bound to the item's revision like the grantor's own copy.
        assert!(keys.decrypt_item(&vault_id, 0, "item1", 4, &item).is_err());

        // A new vault in the scope requires sealing again.
        let second = grantor.create_vault(r#"{"name":"Second"}"#).unwrap();
        let more = vec![vault_id.clone(), second.id.clone()];
        assert!(
            grantor
                .emergency_reseal_needed(&upload.grant, &upload.grant_signature, &more)
                .unwrap()
        );
    }

    #[test]
    fn tampering_and_wrong_recipients_fail() {
        let (server, mut grantor, mut grantee, vault_id, _) = pair();
        let ids = vec![vault_id];
        grantor
            .verify_directory_lookup(
                grantee.account_id(),
                &server.lookup(grantee.account_id(), 0),
            )
            .unwrap();
        let upload = grantor
            .seal_emergency_access("g1", grantee.account_id(), 7, &ids, 1, 5)
            .unwrap();
        // Without the grantor's key from the directory the grant cannot be checked.
        assert!(
            grantee
                .open_emergency_access(&upload.grant, &upload.grant_signature, &upload.sealed_keys)
                .is_err()
        );
        grantee
            .verify_directory_lookup(
                grantor.account_id(),
                &server.lookup(grantor.account_id(), 0),
            )
            .unwrap();
        let mut sealed = encoding::decode(&upload.sealed_keys).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(
            grantee
                .open_emergency_access(
                    &upload.grant,
                    &upload.grant_signature,
                    &encoding::encode(&sealed)
                )
                .is_err()
        );
        // A grant signed by someone else (the grantee itself here) is refused.
        let mut forged = Signed::<EmergencyGrant>::parse(&upload.grant, &upload.grant_signature)
            .unwrap()
            .value;
        forged.wait_ms = 0;
        let forged = Signed::sign(forged, &grantee.account_keys().unwrap().sig);
        assert!(
            grantee
                .open_emergency_access(
                    &forged.encoded(),
                    &forged.encoded_signature(),
                    &upload.sealed_keys
                )
                .is_err()
        );
        // Another account cannot open it.
        let mut stranger = account();
        let mut server = server;
        server.publish(&mut stranger);
        stranger
            .verify_directory_lookup(
                grantor.account_id(),
                &server.lookup(grantor.account_id(), 0),
            )
            .unwrap();
        assert!(
            stranger
                .open_emergency_access(&upload.grant, &upload.grant_signature, &upload.sealed_keys)
                .is_err()
        );
        // Waiting periods are bounded.
        assert!(
            grantor
                .seal_emergency_access("g2", grantee.account_id(), 0, &ids, 1, 5)
                .is_err()
        );
        assert!(
            grantor
                .seal_emergency_access("g2", grantee.account_id(), 31, &ids, 1, 5)
                .is_err()
        );
    }
}
