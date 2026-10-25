//! Builders for sharing requests. Each builder checks the account's
//! verified authority, seals keys to verified recipients, signs the
//! objects and returns the request body for the server. Keys it creates
//! (organization, vault and group keys) are added to the keyring right
//! away.

use serde::{Deserialize, Serialize};

use super::objects::{
    GroupBundle, GroupKeyGrant, ManifestEntry, MemberAttestation, OrgGenesis, OrgKeyGrant, OrgKind,
    OrgRole, PrincipalType, Signed, VaultGrant, VaultManifest, VaultRole, seal_context,
    short_fingerprint,
};
use super::verify::{Roster, VerifiedManifest};
use crate::aead::SymmetricKey;
use crate::identity::{self, EncryptionKey, HASH_LEN, sealed_hash};
use crate::keyring::{Keyring, ensure_json};
use crate::{Error, Result, encoding, id};

fn denied(message: impl Into<String>) -> Error {
    Error::InvalidData(message.into())
}

/// An organization key sealed for one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgKeyUpload {
    pub account_id: String,
    pub epoch: u32,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
}

/// A vault key sealed for one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultKeyUpload {
    pub principal_type: String,
    pub principal_id: String,
    pub key_epoch: u32,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
    /// The uploader's own wrapped copy (only for its own key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<String>,
}

/// A group key sealed for one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupKeyUpload {
    pub account_id: String,
    pub key_version: u32,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
}

/// `POST /api/v1/orgs/{org_id}/vaults` (and part of `POST /api/v1/orgs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSharedVault {
    pub id: String,
    pub key_epoch: u32,
    pub encrypted_meta: String,
    pub keys: Vec<VaultKeyUpload>,
    pub manifest: String,
    pub manifest_signature: String,
}

/// `POST /api/v1/orgs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrg {
    pub id: String,
    pub kind: String,
    pub genesis: String,
    pub genesis_signature: String,
    pub encrypted_meta: String,
    pub meta_epoch: u32,
    pub org_key: OrgKeyUpload,
    /// The family vault, created together with a family organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<NewSharedVault>,
}

/// `POST /api/v1/orgs/{org_id}/members/{account_id}/confirm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmMember {
    pub role: String,
    pub attestation: String,
    pub attestation_signature: String,
    pub org_key: OrgKeyUpload,
    /// The fingerprint of the key that was attested, for showing.
    pub fingerprint: String,
}

/// `PUT /api/v1/orgs/{org_id}/members/{account_id}` (role change or
/// re-attestation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberAttestationUpload {
    pub account_id: String,
    pub role: String,
    pub attestation: String,
    pub attestation_signature: String,
}

/// `POST /api/v1/vaults/{vault_id}/members` (add a member or change a role).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMemberChange {
    pub principal_type: String,
    pub principal_id: String,
    pub role: String,
    pub key: VaultKeyUpload,
    pub manifest: String,
    pub manifest_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalRef {
    pub principal_type: String,
    pub principal_id: String,
}

/// `POST /api/v1/vaults/{vault_id}/rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateVault {
    pub key_epoch: u32,
    pub encrypted_meta: String,
    pub removed: Vec<PrincipalRef>,
    pub keys: Vec<VaultKeyUpload>,
    pub manifest: String,
    pub manifest_signature: String,
}

/// `POST /api/v1/orgs/{org_id}/groups`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewGroup {
    pub id: String,
    pub key_version: u32,
    pub bundle: String,
    pub bundle_signature: String,
    pub encrypted_meta: String,
    pub meta_epoch: u32,
    pub members: Vec<GroupKeyUpload>,
}

/// `POST /api/v1/orgs/{org_id}/groups/{group_id}/rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateGroup {
    pub key_version: u32,
    pub bundle: String,
    pub bundle_signature: String,
    pub removed: Vec<String>,
    pub members: Vec<GroupKeyUpload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMetaUpload {
    pub group_id: String,
    pub encrypted_meta: String,
}

/// `POST /api/v1/orgs/{org_id}/rotate-key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateOrgKey {
    pub epoch: u32,
    pub encrypted_meta: String,
    pub groups: Vec<GroupMetaUpload>,
    pub keys: Vec<OrgKeyUpload>,
}

struct Recipient {
    key_hash: [u8; HASH_LEN],
    enc_pk: Vec<u8>,
}

impl Keyring {
    fn admin_roster(&self, org_id: &str) -> Result<&Roster> {
        let roster = self
            .sharing
            .rosters
            .get(org_id)
            .ok_or_else(|| denied("the organization is unknown or could not be verified"))?;
        if roster.admin(&self.account_id).is_none() {
            return Err(denied(
                "only owners and admins of the organization can do this",
            ));
        }
        Ok(roster)
    }

    fn org_epoch(&self, org_id: &str) -> Result<u32> {
        self.sharing
            .data
            .orgs
            .get(org_id)
            .map(|o| o.meta_epoch)
            .ok_or_else(|| denied("unknown organization"))
    }

    /// Resolves a principal to its verified encryption key. With `strict`,
    /// accounts whose key differs from the pinned one are refused.
    fn recipient(
        &self,
        roster: &Roster,
        principal_type: PrincipalType,
        principal_id: &str,
        strict: bool,
    ) -> Result<Recipient> {
        match principal_type {
            PrincipalType::Account => {
                let member = roster.active(principal_id).ok_or_else(|| {
                    denied(format!(
                        "{principal_id} is not a confirmed, verified member of the organization"
                    ))
                })?;
                if strict
                    && let Some(pin) = self.sharing.trust.pins.get(principal_id)
                    && pin.bundle_hash != encoding::encode(&member.bundle.hash())
                {
                    return Err(Error::KeyChanged(principal_id.to_owned()));
                }
                Ok(Recipient {
                    key_hash: member.bundle.hash(),
                    enc_pk: member.bundle.bundle.enc_pk.clone(),
                })
            }
            PrincipalType::Group => {
                let group = self
                    .sharing
                    .groups
                    .get(principal_id)
                    .filter(|g| g.org_id == roster.org_id)
                    .ok_or_else(|| denied(format!("unknown or unverified group {principal_id}")))?;
                Ok(Recipient {
                    key_hash: group.bundle.hash(),
                    enc_pk: group.bundle.value.enc_pk.clone(),
                })
            }
        }
    }

    fn sealed_org_key(
        &self,
        org_id: &str,
        epoch: u32,
        account_id: &str,
        recipient: &Recipient,
        key: &SymmetricKey,
        now: i64,
    ) -> Result<OrgKeyUpload> {
        let sealed = identity::seal(
            &recipient.enc_pk,
            &recipient.key_hash,
            seal_context::ORG_KEY,
            &seal_context::org_key(org_id, epoch, account_id),
            key.as_bytes(),
        )?;
        let grant = Signed::sign(
            OrgKeyGrant {
                org_id: org_id.to_owned(),
                epoch,
                account_id: account_id.to_owned(),
                account_bundle_hash: recipient.key_hash,
                sealed_hash: sealed_hash(&sealed),
                granter_id: self.account_id.clone(),
                granted_at: now,
            },
            &self.account_keys()?.sig,
        );
        Ok(OrgKeyUpload {
            account_id: account_id.to_owned(),
            epoch,
            sealed_key: encoding::encode(&sealed),
            grant: grant.encoded(),
            grant_signature: grant.encoded_signature(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn sealed_vault_key(
        &self,
        manifest: &VaultManifest,
        principal_type: PrincipalType,
        principal_id: &str,
        role: VaultRole,
        recipient: &Recipient,
        key: &SymmetricKey,
        now: i64,
    ) -> Result<VaultKeyUpload> {
        let epoch = manifest.key_epoch;
        let sealed = identity::seal(
            &recipient.enc_pk,
            &recipient.key_hash,
            seal_context::VAULT_KEY,
            &seal_context::vault_key(&manifest.vault_id, epoch, principal_type, principal_id),
            key.as_bytes(),
        )?;
        let grant = Signed::sign(
            VaultGrant {
                vault_id: manifest.vault_id.clone(),
                org_id: manifest.org_id.clone(),
                key_epoch: epoch,
                manifest_version: manifest.version,
                principal_type,
                principal_id: principal_id.to_owned(),
                principal_key_hash: recipient.key_hash,
                role,
                sealed_hash: sealed_hash(&sealed),
                granter_id: self.account_id.clone(),
                granted_at: now,
            },
            &self.account_keys()?.sig,
        );
        let own = principal_type == PrincipalType::Account && principal_id == self.account_id;
        Ok(VaultKeyUpload {
            principal_type: principal_type.as_str().to_owned(),
            principal_id: principal_id.to_owned(),
            key_epoch: epoch,
            sealed_key: encoding::encode(&sealed),
            grant: grant.encoded(),
            grant_signature: grant.encoded_signature(),
            wrapped_key: if own {
                Some(self.wrap_vault_key(&manifest.vault_id, epoch)?)
            } else {
                None
            },
        })
    }

    fn sign_manifest(&self, mut manifest: VaultManifest) -> Result<Signed<VaultManifest>> {
        manifest.members.sort_by(|a, b| {
            (a.principal_type, &a.principal_id).cmp(&(b.principal_type, &b.principal_id))
        });
        manifest.members.dedup_by(|a, b| {
            a.principal_type == b.principal_type && a.principal_id == b.principal_id
        });
        Ok(Signed::sign(manifest, &self.account_keys()?.sig))
    }

    fn own_recipient(&self) -> Result<Recipient> {
        let own = &self.account_keys()?.bundle;
        Ok(Recipient {
            key_hash: own.hash(),
            enc_pk: own.bundle.enc_pk.clone(),
        })
    }

    // --- Organizations ------------------------------------------------------------

    /// Creates an organization owned by this account. `meta_json` holds the
    /// name (`{"name": ...}`), encrypted with a new organization key. With
    /// `vault_meta_json` a shared vault is created with it (the family vault
    /// of a family organization).
    pub fn create_org(
        &mut self,
        kind: OrgKind,
        meta_json: &str,
        vault_meta_json: Option<&str>,
        now: i64,
    ) -> Result<NewOrg> {
        ensure_json(meta_json.as_bytes())?;
        let own = self.account_keys()?.bundle.clone();
        let org_id = id::new_id()?;
        let genesis = Signed::sign(
            OrgGenesis {
                org_id: org_id.clone(),
                kind,
                owner_id: self.account_id.clone(),
                owner_bundle_hash: own.hash(),
                created_at: now,
            },
            &self.account_keys()?.sig,
        );
        let org_key = SymmetricKey::generate()?;
        let org_key_upload = self.sealed_org_key(
            &org_id,
            1,
            &self.account_id.clone(),
            &self.own_recipient()?,
            &org_key,
            now,
        )?;
        self.org_keys.insert((org_id.clone(), 1), org_key);
        let encrypted_meta = self.encrypt_org_meta(&org_id, 1, meta_json)?;
        self.sharing
            .trust
            .org_roots
            .insert(org_id.clone(), encoding::encode(&genesis.hash()));
        let vault = match vault_meta_json {
            Some(meta) => Some(self.new_shared_vault(&org_id, meta, now)?),
            None => None,
        };
        Ok(NewOrg {
            id: org_id,
            kind: kind.as_str().to_owned(),
            genesis: genesis.encoded(),
            genesis_signature: genesis.encoded_signature(),
            encrypted_meta,
            meta_epoch: 1,
            org_key: org_key_upload,
            vault,
        })
    }

    /// The organization fingerprint for invitation links:
    /// `(root hash, human-readable fingerprint)`.
    pub fn org_fingerprint(&self, org_id: &str) -> Result<(String, String)> {
        let root = self
            .sharing
            .trust
            .org_roots
            .get(org_id)
            .ok_or_else(|| denied("unknown organization"))?;
        let hash: [u8; HASH_LEN] = encoding::decode(root)?
            .try_into()
            .map_err(|_| denied("invalid organization root"))?;
        Ok((root.clone(), short_fingerprint(&hash)))
    }

    /// Confirms a member who accepted an invitation: attests the member's
    /// key with this admin's signature and seals the organization key.
    ///
    /// The member's key must have been looked up in the key directory first
    /// ([`Keyring::verify_directory_lookup`]) and must equal the key the
    /// member published; compare the returned fingerprint out of band for
    /// full protection against a malicious server.
    pub fn confirm_member(
        &mut self,
        org_id: &str,
        account_id: &str,
        now: i64,
    ) -> Result<ConfirmMember> {
        let roster = self.admin_roster(org_id)?;
        let member = roster
            .unverified
            .get(account_id)
            .filter(|m| m.status == "accepted")
            .ok_or_else(|| denied("the member has not accepted an invitation"))?;
        let bundle = member
            .bundle
            .clone()
            .ok_or_else(|| denied("the member has not published keys"))?;
        let role = OrgRole::parse(&member.role)?;
        if role == OrgRole::Owner {
            return Err(denied("an organization has exactly one owner"));
        }
        if role == OrgRole::Admin
            && roster.admin(&self.account_id).map(|m| m.role) != Some(OrgRole::Owner)
        {
            return Err(denied("only the owner can confirm admins"));
        }
        match self.sharing.trust.pins.get(account_id) {
            None => {
                return Err(denied(
                    "look up the member's key in the key directory before confirming",
                ));
            }
            Some(pin) if pin.bundle_hash != encoding::encode(&bundle.hash()) => {
                return Err(Error::KeyChanged(account_id.to_owned()));
            }
            Some(_) => {}
        }
        let attestation = Signed::sign(
            MemberAttestation {
                org_id: org_id.to_owned(),
                account_id: account_id.to_owned(),
                key_version: bundle.bundle.key_version,
                bundle_hash: bundle.hash(),
                role,
                attester_id: self.account_id.clone(),
                created_at: now,
            },
            &self.account_keys()?.sig,
        );
        let epoch = self.org_epoch(org_id)?;
        let org_key = self.org_key(org_id, epoch)?.clone();
        let recipient = Recipient {
            key_hash: bundle.hash(),
            enc_pk: bundle.bundle.enc_pk.clone(),
        };
        let org_key = self.sealed_org_key(org_id, epoch, account_id, &recipient, &org_key, now)?;
        Ok(ConfirmMember {
            role: role.as_str().to_owned(),
            attestation: attestation.encoded(),
            attestation_signature: attestation.encoded_signature(),
            org_key,
            fingerprint: bundle.fingerprint(),
        })
    }

    /// Attests a confirmed member with a new role.
    pub fn set_member_role(
        &self,
        org_id: &str,
        account_id: &str,
        role: OrgRole,
        now: i64,
    ) -> Result<MemberAttestationUpload> {
        let roster = self.admin_roster(org_id)?;
        if role == OrgRole::Owner || account_id == roster.owner_id {
            return Err(denied("the owner's role cannot be changed"));
        }
        let my_role = roster.admin(&self.account_id).map(|m| m.role);
        let member = roster
            .members
            .get(account_id)
            .ok_or_else(|| denied("the member is not verified"))?;
        if (role == OrgRole::Admin || member.role == OrgRole::Admin)
            && my_role != Some(OrgRole::Owner)
        {
            return Err(denied("only the owner can grant or revoke admin rights"));
        }
        self.attest(
            org_id,
            member.account_id.as_str(),
            &member.bundle,
            role,
            now,
        )
    }

    fn attest(
        &self,
        org_id: &str,
        account_id: &str,
        bundle: &identity::SignedBundle,
        role: OrgRole,
        now: i64,
    ) -> Result<MemberAttestationUpload> {
        let attestation = Signed::sign(
            MemberAttestation {
                org_id: org_id.to_owned(),
                account_id: account_id.to_owned(),
                key_version: bundle.bundle.key_version,
                bundle_hash: bundle.hash(),
                role,
                attester_id: self.account_id.clone(),
                created_at: now,
            },
            &self.account_keys()?.sig,
        );
        Ok(MemberAttestationUpload {
            account_id: account_id.to_owned(),
            role: role.as_str().to_owned(),
            attestation: attestation.encoded(),
            attestation_signature: attestation.encoded_signature(),
        })
    }

    /// Re-attests every member whose attestation was signed by `attester_id`
    /// (call after removing or demoting that admin, so their members stay
    /// verifiable).
    pub fn reattest_members(
        &self,
        org_id: &str,
        attester_id: &str,
        now: i64,
    ) -> Result<Vec<MemberAttestationUpload>> {
        let roster = self.admin_roster(org_id)?;
        let mut uploads = Vec::new();
        for member in roster.members.values() {
            if member.attested_by.as_deref() == Some(attester_id)
                && member.account_id != attester_id
            {
                uploads.push(self.attest(
                    org_id,
                    &member.account_id,
                    &member.bundle,
                    member.role,
                    now,
                )?);
            }
        }
        // Members whose attester is gone show up as unverified; re-attest
        // them too when their key is pinned on this device.
        for member in roster.unverified.values() {
            let Some(bundle) = &member.bundle else {
                continue;
            };
            let pinned = self
                .sharing
                .trust
                .pins
                .get(&member.account_id)
                .is_some_and(|p| p.bundle_hash == encoding::encode(&bundle.hash()));
            if member.status == "confirmed" && pinned {
                let role = OrgRole::parse(&member.role)?;
                if role != OrgRole::Owner {
                    uploads.push(self.attest(org_id, &member.account_id, bundle, role, now)?);
                }
            }
        }
        Ok(uploads)
    }

    /// Rotates the organization key: a new key sealed for every confirmed
    /// member, with the organization and group metadata re-encrypted.
    /// Call after removing a member.
    pub fn rotate_org_key(&mut self, org_id: &str, now: i64) -> Result<RotateOrgKey> {
        let roster = self.admin_roster(org_id)?.clone();
        let epoch = self.org_epoch(org_id)?;
        let org = self.sharing.data.orgs[org_id].clone();
        let meta = self.decrypt_org_meta(org_id, epoch, &org.encrypted_meta)?;
        let new_epoch = epoch + 1;
        let key = SymmetricKey::generate()?;
        let mut keys = Vec::new();
        for member in roster.members.values().filter(|m| m.status == "confirmed") {
            let recipient = Recipient {
                key_hash: member.bundle.hash(),
                enc_pk: member.bundle.bundle.enc_pk.clone(),
            };
            keys.push(self.sealed_org_key(
                org_id,
                new_epoch,
                &member.account_id,
                &recipient,
                &key,
                now,
            )?);
        }
        let groups_meta: Vec<(String, String)> = self
            .sharing
            .data
            .groups
            .values()
            .filter(|g| g.org_id == org_id)
            .map(|g| {
                Ok((
                    g.id.clone(),
                    self.decrypt_group_meta(org_id, &g.id, g.meta_epoch, &g.encrypted_meta)?,
                ))
            })
            .collect::<Result<_>>()?;
        self.org_keys.insert((org_id.to_owned(), new_epoch), key);
        let groups = groups_meta
            .into_iter()
            .map(|(group_id, meta)| {
                Ok(GroupMetaUpload {
                    encrypted_meta: self.encrypt_group_meta(org_id, &group_id, new_epoch, &meta)?,
                    group_id,
                })
            })
            .collect::<Result<_>>()?;
        Ok(RotateOrgKey {
            epoch: new_epoch,
            encrypted_meta: self.encrypt_org_meta(org_id, new_epoch, &meta)?,
            groups,
            keys,
        })
    }

    // --- Shared vaults ---------------------------------------------------------------

    fn new_shared_vault(
        &mut self,
        org_id: &str,
        meta_json: &str,
        now: i64,
    ) -> Result<NewSharedVault> {
        ensure_json(meta_json.as_bytes())?;
        let vault_id = id::new_id()?;
        let key = SymmetricKey::generate()?;
        self.insert_vault_key(&vault_id, 1, key.clone());
        let own = self.own_recipient()?;
        let manifest = self.sign_manifest(VaultManifest {
            vault_id: vault_id.clone(),
            org_id: org_id.to_owned(),
            version: 1,
            key_epoch: 1,
            members: vec![ManifestEntry {
                principal_type: PrincipalType::Account,
                principal_id: self.account_id.clone(),
                role: VaultRole::Manage,
                key_hash: own.key_hash,
            }],
            prev_hash: [0; HASH_LEN],
            signer_id: self.account_id.clone(),
            created_at: now,
        })?;
        let own_key = self.sealed_vault_key(
            &manifest.value,
            PrincipalType::Account,
            &self.account_id.clone(),
            VaultRole::Manage,
            &own,
            &key,
            now,
        )?;
        Ok(NewSharedVault {
            encrypted_meta: self.encrypt_vault_meta_at(&vault_id, 1, meta_json)?,
            id: vault_id,
            key_epoch: 1,
            keys: vec![own_key],
            manifest: manifest.encoded(),
            manifest_signature: manifest.encoded_signature(),
        })
    }

    /// Creates a shared vault in an organization (owners and admins).
    pub fn create_shared_vault(
        &mut self,
        org_id: &str,
        meta_json: &str,
        now: i64,
    ) -> Result<NewSharedVault> {
        self.admin_roster(org_id)?;
        self.new_shared_vault(org_id, meta_json, now)
    }

    /// The latest verified manifest of a vault this account may manage, and
    /// its organization's roster.
    fn managed_vault(&self, vault_id: &str) -> Result<(VerifiedManifest, Roster)> {
        let chain = self
            .sharing
            .chains
            .get(vault_id)
            .ok_or_else(|| denied("the vault's member list could not be verified"))?;
        let latest = chain.latest().clone();
        let roster = self
            .sharing
            .rosters
            .get(&latest.manifest.org_id)
            .ok_or_else(|| denied("the vault's organization could not be verified"))?
            .clone();
        let direct_manager = latest
            .manifest
            .entry(PrincipalType::Account, &self.account_id)
            .is_some_and(|e| e.role == VaultRole::Manage);
        let admin_member = roster.admin(&self.account_id).is_some()
            && latest
                .manifest
                .entry(PrincipalType::Account, &self.account_id)
                .is_some();
        if !(direct_manager || admin_member) {
            return Err(denied(
                "only managers (and organization admins who are members) can change this vault",
            ));
        }
        if !self.has_vault_key(vault_id, latest.manifest.key_epoch) {
            return Err(Error::MissingKey(format!("vault {vault_id}")));
        }
        Ok((latest, roster))
    }

    /// Shares a vault with an account or group, or changes its role. The
    /// recipient must be a verified member (or group) of the vault's
    /// organization whose key did not change.
    pub fn share_vault(
        &self,
        vault_id: &str,
        principal_type: PrincipalType,
        principal_id: &str,
        role: VaultRole,
        now: i64,
    ) -> Result<VaultMemberChange> {
        let (latest, roster) = self.managed_vault(vault_id)?;
        let recipient = self.recipient(&roster, principal_type, principal_id, true)?;
        if principal_type == PrincipalType::Account
            && roster
                .active(principal_id)
                .is_some_and(|member| role > member.role.max_vault_role())
        {
            return Err(denied("guests can only view shared vaults"));
        }
        let m = &latest.manifest;
        let mut members: Vec<ManifestEntry> = m
            .members
            .iter()
            .filter(|e| !(e.principal_type == principal_type && e.principal_id == principal_id))
            .cloned()
            .collect();
        members.push(ManifestEntry {
            principal_type,
            principal_id: principal_id.to_owned(),
            role,
            key_hash: recipient.key_hash,
        });
        if !members
            .iter()
            .any(|e| e.principal_type == PrincipalType::Account && e.role == VaultRole::Manage)
        {
            return Err(denied("a vault needs at least one manager"));
        }
        let manifest = self.sign_manifest(VaultManifest {
            vault_id: vault_id.to_owned(),
            org_id: m.org_id.clone(),
            version: m.version + 1,
            key_epoch: m.key_epoch,
            members,
            prev_hash: latest.hash,
            signer_id: self.account_id.clone(),
            created_at: now,
        })?;
        let key = self.vault_key(vault_id, m.key_epoch)?.clone();
        let upload = self.sealed_vault_key(
            &manifest.value,
            principal_type,
            principal_id,
            role,
            &recipient,
            &key,
            now,
        )?;
        Ok(VaultMemberChange {
            principal_type: principal_type.as_str().to_owned(),
            principal_id: principal_id.to_owned(),
            role: role.as_str().to_owned(),
            key: upload,
            manifest: manifest.encoded(),
            manifest_signature: manifest.encoded_signature(),
        })
    }

    /// Rotates a vault's key, removing `removed` from its members: a new key
    /// epoch, sealed for every remaining member (members that are no longer
    /// active in the organization are dropped too), the metadata re-encrypted
    /// with `meta_json`. Items must then be re-encrypted with
    /// [`Keyring::encrypt_item_at`] for the new epoch.
    pub fn rotate_vault(
        &mut self,
        vault_id: &str,
        removed: &[(PrincipalType, String)],
        meta_json: &str,
        now: i64,
    ) -> Result<RotateVault> {
        ensure_json(meta_json.as_bytes())?;
        let (latest, roster) = self.managed_vault(vault_id)?;
        let m = &latest.manifest;
        let current_epoch = self
            .sharing
            .data
            .vault_access
            .get(vault_id)
            .map_or(m.key_epoch, |a| a.key_epoch.max(m.key_epoch));
        let epoch = current_epoch + 1;
        let mut removed_refs: Vec<PrincipalRef> = removed
            .iter()
            .map(|(t, id)| PrincipalRef {
                principal_type: t.as_str().to_owned(),
                principal_id: id.clone(),
            })
            .collect();
        let mut members = Vec::new();
        let mut recipients = Vec::new();
        for entry in &m.members {
            if removed
                .iter()
                .any(|(t, id)| *t == entry.principal_type && *id == entry.principal_id)
            {
                continue;
            }
            match self.recipient(&roster, entry.principal_type, &entry.principal_id, false) {
                Ok(recipient) => {
                    members.push(ManifestEntry {
                        key_hash: recipient.key_hash,
                        ..entry.clone()
                    });
                    recipients.push((
                        entry.principal_type,
                        entry.principal_id.clone(),
                        entry.role,
                        recipient,
                    ));
                }
                Err(_) => removed_refs.push(PrincipalRef {
                    principal_type: entry.principal_type.as_str().to_owned(),
                    principal_id: entry.principal_id.clone(),
                }),
            }
        }
        if !members.iter().any(|e| {
            e.principal_type == PrincipalType::Account && e.principal_id == self.account_id
        }) {
            return Err(denied("the rotating manager must stay a member"));
        }
        let key = SymmetricKey::generate()?;
        self.insert_vault_key(vault_id, epoch, key.clone());
        let manifest = self.sign_manifest(VaultManifest {
            vault_id: vault_id.to_owned(),
            org_id: m.org_id.clone(),
            version: m.version + 1,
            key_epoch: epoch,
            members,
            prev_hash: latest.hash,
            signer_id: self.account_id.clone(),
            created_at: now,
        })?;
        let keys = recipients
            .iter()
            .map(|(t, id, role, recipient)| {
                self.sealed_vault_key(&manifest.value, *t, id, *role, recipient, &key, now)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RotateVault {
            key_epoch: epoch,
            encrypted_meta: self.encrypt_vault_meta_at(vault_id, epoch, meta_json)?,
            removed: removed_refs,
            keys,
            manifest: manifest.encoded(),
            manifest_signature: manifest.encoded_signature(),
        })
    }

    // --- Groups -------------------------------------------------------------------------

    fn group_key_upload(
        &self,
        bundle: &Signed<GroupBundle>,
        seed: &[u8; 32],
        account_id: &str,
        recipient: &Recipient,
        now: i64,
    ) -> Result<GroupKeyUpload> {
        let b = &bundle.value;
        let sealed = identity::seal(
            &recipient.enc_pk,
            &recipient.key_hash,
            seal_context::GROUP_KEY,
            &seal_context::group_key(&b.group_id, b.key_version, account_id),
            seed,
        )?;
        let grant = Signed::sign(
            GroupKeyGrant {
                group_id: b.group_id.clone(),
                org_id: b.org_id.clone(),
                key_version: b.key_version,
                account_id: account_id.to_owned(),
                account_bundle_hash: recipient.key_hash,
                sealed_hash: sealed_hash(&sealed),
                granter_id: self.account_id.clone(),
                granted_at: now,
            },
            &self.account_keys()?.sig,
        );
        Ok(GroupKeyUpload {
            account_id: account_id.to_owned(),
            key_version: b.key_version,
            sealed_key: encoding::encode(&sealed),
            grant: grant.encoded(),
            grant_signature: grant.encoded_signature(),
        })
    }

    fn new_group_key(
        &mut self,
        org_id: &str,
        group_id: &str,
        key_version: u32,
        members: &[String],
        roster: &Roster,
        now: i64,
    ) -> Result<(Signed<GroupBundle>, Vec<GroupKeyUpload>)> {
        let enc = EncryptionKey::generate()?;
        let bundle = Signed::sign(
            GroupBundle {
                group_id: group_id.to_owned(),
                org_id: org_id.to_owned(),
                key_version,
                enc_pk: enc.public_key(),
                creator_id: self.account_id.clone(),
                created_at: now,
            },
            &self.account_keys()?.sig,
        );
        let mut ids: Vec<String> = members.to_vec();
        ids.push(self.account_id.clone());
        ids.sort();
        ids.dedup();
        let uploads = ids
            .iter()
            .map(|account_id| {
                let recipient = self.recipient(roster, PrincipalType::Account, account_id, true)?;
                self.group_key_upload(&bundle, enc.seed(), account_id, &recipient, now)
            })
            .collect::<Result<Vec<_>>>()?;
        self.group_keys
            .insert((group_id.to_owned(), key_version), enc);
        Ok((bundle, uploads))
    }

    /// Creates a group with its own key pair. The creating admin is always a
    /// member (only members can add others, because adding means sealing the
    /// group key).
    pub fn create_group(
        &mut self,
        org_id: &str,
        meta_json: &str,
        members: &[String],
        now: i64,
    ) -> Result<NewGroup> {
        ensure_json(meta_json.as_bytes())?;
        let roster = self.admin_roster(org_id)?.clone();
        let group_id = id::new_id()?;
        let (bundle, uploads) = self.new_group_key(org_id, &group_id, 1, members, &roster, now)?;
        let epoch = self.org_epoch(org_id)?;
        Ok(NewGroup {
            encrypted_meta: self.encrypt_group_meta(org_id, &group_id, epoch, meta_json)?,
            id: group_id,
            key_version: 1,
            bundle: bundle.encoded(),
            bundle_signature: bundle.encoded_signature(),
            meta_epoch: epoch,
            members: uploads,
        })
    }

    /// Adds a member to a group: one sealing of the group key, no matter how
    /// many vaults are shared with the group.
    pub fn add_group_member(
        &self,
        group_id: &str,
        account_id: &str,
        now: i64,
    ) -> Result<GroupKeyUpload> {
        let group = self
            .sharing
            .groups
            .get(group_id)
            .ok_or_else(|| denied("unknown or unverified group"))?;
        let roster = self.admin_roster(&group.org_id)?;
        let enc = self
            .group_keys
            .get(&(group_id.to_owned(), group.key_version))
            .ok_or_else(|| denied("only admins who are members of the group can add members"))?;
        let recipient = self.recipient(roster, PrincipalType::Account, account_id, true)?;
        self.group_key_upload(&group.bundle, enc.seed(), account_id, &recipient, now)
    }

    /// Rotates a group's key without `removed`. Afterwards every vault shared
    /// with the group must be rotated too ([`Keyring::rotate_vault`]).
    pub fn rotate_group(
        &mut self,
        group_id: &str,
        removed: &[String],
        now: i64,
    ) -> Result<RotateGroup> {
        let group = self
            .sharing
            .groups
            .get(group_id)
            .ok_or_else(|| denied("unknown or unverified group"))?
            .clone();
        let roster = self.admin_roster(&group.org_id)?.clone();
        if !group.members_verified {
            return Err(denied(
                "only admins who are members of the group can rotate it",
            ));
        }
        let remaining: Vec<String> = group
            .members
            .iter()
            .filter(|m| !removed.contains(m) && roster.active(m).is_some())
            .cloned()
            .collect();
        let version = group.key_version + 1;
        let (bundle, uploads) =
            self.new_group_key(&group.org_id, group_id, version, &remaining, &roster, now)?;
        Ok(RotateGroup {
            key_version: version,
            bundle: bundle.encoded(),
            bundle_signature: bundle.encoded_signature(),
            removed: removed.to_vec(),
            members: uploads,
        })
    }
}
