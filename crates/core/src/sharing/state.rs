//! The client's verified view of organizations, groups and shared vaults.
//!
//! [`Keyring::apply_sharing`] merges a sync delta, verifies everything
//! against the trust store (pinned organization roots, member keys,
//! manifest versions, key directory state), opens the keys the account is
//! entitled to and returns a [`SharingView`] plus actions for the client
//! (own vault key copies to upload). Problems never abort the evaluation;
//! they become [`Warning`]s and the affected object is shown as unverified
//! (and its keys are not opened).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::data::{SharingData, SharingDelta};
use super::objects::{
    GroupBundle, GroupKeyGrant, OrgGenesis, OrgKeyGrant, OrgRole, PrincipalType, Signed,
    VaultGrant, VaultManifest, VaultRole, seal_context, short_fingerprint,
};
use super::verify::{
    Roster, VerifiedChain, verify_group_bundle, verify_group_grant, verify_manifest_chain,
    verify_org_key_grant, verify_roster, verify_vault_grant,
};
use crate::directory::{DirectoryState, LookupResponse, LookupStatus, Pin, Pins};
use crate::identity::{HASH_LEN, SignedBundle};
use crate::keyring::{Keyring, key_from_plaintext};
use crate::{Error, Result, encoding};

/// What a client persists between sessions to detect changes (trust on
/// first use). Contains only public data; store it next to the account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TrustStore {
    pub directory: DirectoryState,
    /// Account keys seen before (from the directory or attestations).
    pub pins: Pins,
    /// Organization genesis hashes (Base64url), pinned on first contact or
    /// from the invitation link.
    pub org_roots: BTreeMap<String, String>,
    /// Latest verified manifest version and hash per vault.
    pub manifests: BTreeMap<String, ManifestPin>,
    /// Newest verified policy per organization (D2).
    pub policies: BTreeMap<String, crate::policy::PolicyPin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestPin {
    pub version: u64,
    pub hash: String,
}

/// A problem found while verifying sharing data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    /// `key_changed`, `org_root_changed`, `org_unverified`,
    /// `member_unverified`, `manifest_invalid`, `grant_invalid`,
    /// `role_mismatch`, `membership_mismatch`, `group_unverified`,
    /// `own_key_changed`, or for policies `policy_invalid`,
    /// `policy_rollback`, `policy_conflict`, `policy_missing` and
    /// `policy_needs_resign`.
    pub kind: String,
    /// The account, organization, group or vault concerned.
    pub subject_id: String,
    #[serde(default)]
    pub org_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub account_id: String,
    #[serde(default)]
    pub email: Option<String>,
    /// Attested role (server role while unverified).
    pub role: String,
    /// `accepted`, `confirmed` or `suspended`.
    pub status: String,
    /// Fingerprint of the member's current key, if published.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// The key is attested by the owner or an admin.
    pub verified: bool,
    /// The key differs from the one pinned on this device.
    pub key_changed: bool,
    #[serde(default)]
    pub attested_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub id: String,
    pub org_id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub key_version: u32,
    /// Members with a verified grant of the current key version (only known
    /// to group members), otherwise the server's list.
    pub members: Vec<String>,
    pub members_verified: bool,
    pub verified: bool,
    /// Whether this account holds the group's current key.
    pub is_member: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgView {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    /// This account's role and status.
    pub role: String,
    pub status: String,
    #[serde(default)]
    pub default_vault_id: Option<String>,
    /// Organization fingerprint (hash of the genesis), as in invitation links.
    pub fingerprint: String,
    pub root_hash: String,
    pub verified: bool,
    pub members: Vec<MemberView>,
    pub groups: Vec<GroupView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMemberView {
    pub principal_type: String,
    pub principal_id: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedVaultView {
    pub vault_id: String,
    pub org_id: String,
    /// The role from the verified manifest; `None` if unverified.
    #[serde(default)]
    pub role: Option<String>,
    /// The role the server enforces.
    pub server_role: String,
    pub key_epoch: u32,
    pub manifest_version: u64,
    pub members: Vec<VaultMemberView>,
    pub verified: bool,
    /// Whether the current key epoch can be opened.
    pub has_key: bool,
    /// A member was removed and the key must be rotated by a manager.
    pub rotation_pending: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharingView {
    pub orgs: Vec<OrgView>,
    pub vaults: Vec<SharedVaultView>,
    pub warnings: Vec<Warning>,
    /// Policies in force per organization (D2).
    #[serde(default)]
    pub policies: Vec<crate::policy::OrgPolicyView>,
    /// The combination of the policies this account is bound by.
    #[serde(default)]
    pub effective_policy: crate::policy::EffectivePolicy,
}

/// An own copy of a vault key to store on the server
/// (`PUT /api/v1/vaults/{id}/keys/{epoch}/wrapped`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKeyUpload {
    pub vault_id: String,
    pub key_epoch: u32,
    pub wrapped_key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharingReport {
    pub view: SharingView,
    pub wrapped_keys: Vec<WrappedKeyUpload>,
}

/// A verified group (its current key version).
#[derive(Debug, Clone)]
pub(crate) struct VerifiedGroup {
    pub org_id: String,
    pub key_version: u32,
    pub bundle: Signed<GroupBundle>,
    pub members: Vec<String>,
    pub members_verified: bool,
}

/// Sharing state held by the keyring. Public data only.
#[derive(Debug, Default)]
pub struct SharingState {
    pub(crate) data: SharingData,
    pub(crate) trust: TrustStore,
    pub(crate) rosters: BTreeMap<String, Roster>,
    pub(crate) chains: BTreeMap<String, VerifiedChain>,
    pub(crate) groups: BTreeMap<String, VerifiedGroup>,
    /// Bundle hash per (group, key version) for group keys this account holds.
    pub(crate) group_key_hashes: HashMap<(String, u32), [u8; HASH_LEN]>,
    /// Bundles from recent directory lookups, for accepting key changes.
    pub(crate) lookups: BTreeMap<String, SignedBundle>,
    pub(crate) view: SharingView,
}

fn warning(kind: &str, subject: &str, org: Option<&str>, message: impl Into<String>) -> Warning {
    Warning {
        kind: kind.to_owned(),
        subject_id: subject.to_owned(),
        org_id: org.map(str::to_owned),
        message: message.into(),
    }
}

fn pin_for(bundle: &SignedBundle, seq: Option<u64>) -> Pin {
    Pin {
        key_version: bundle.bundle.key_version,
        bundle_hash: encoding::encode(&bundle.hash()),
        fingerprint: bundle.fingerprint(),
        seq,
    }
}

/// Result of a directory lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryLookup {
    pub account_id: String,
    pub fingerprint: String,
    pub bundle_hash: String,
    /// `new`, `unchanged` or `changed`.
    pub status: String,
    /// The previously pinned fingerprint when the key changed.
    #[serde(default)]
    pub previous_fingerprint: Option<String>,
}

impl Keyring {
    /// The trust store, for persisting.
    pub fn trust_store(&self) -> &TrustStore {
        &self.sharing.trust
    }

    /// Restores a persisted trust store. Call before the first sync.
    pub fn set_trust_store(&mut self, trust: TrustStore) {
        self.sharing.trust = trust;
    }

    /// The last evaluated view.
    pub fn sharing_view(&self) -> &SharingView {
        &self.sharing.view
    }

    /// The merged (unverified) sharing data, for the native clients' cache.
    pub fn sharing_data(&self) -> &SharingData {
        &self.sharing.data
    }

    /// Replaces the sharing data (from a cache) without a server delta and
    /// re-evaluates.
    pub fn restore_sharing_data(&mut self, data: SharingData) -> SharingReport {
        self.sharing.data = data;
        self.evaluate_sharing()
    }

    /// Pins the organization fingerprint from an invitation link before the
    /// organization is first synced. Fails if a different root is pinned.
    pub fn pin_org_root(&mut self, org_id: &str, root_hash: &str) -> Result<()> {
        match self.sharing.trust.org_roots.get(org_id) {
            Some(existing) if existing != root_hash => Err(Error::InvalidData(
                "the organization fingerprint does not match the one seen before".into(),
            )),
            _ => {
                self.sharing
                    .trust
                    .org_roots
                    .insert(org_id.to_owned(), root_hash.to_owned());
                Ok(())
            }
        }
    }

    /// Verifies a key directory lookup (see [`crate::directory`]). New keys
    /// are pinned; a changed key is reported and stays unpinned until
    /// [`Keyring::accept_key_change`].
    pub fn verify_directory_lookup(
        &mut self,
        account_id: &str,
        response: &LookupResponse,
    ) -> Result<DirectoryLookup> {
        let state = &mut self.sharing;
        let pin = state.trust.pins.get(account_id).cloned();
        let mut directory = state.trust.directory.clone();
        let verified = directory.verify_lookup(account_id, response, pin.as_ref())?;
        state.trust.directory = directory;
        let bundle_hash = encoding::encode(&verified.bundle.hash());
        let (status, previous) = match &verified.status {
            LookupStatus::New => {
                state.trust.pins.insert(
                    account_id.to_owned(),
                    pin_for(&verified.bundle, Some(verified.seq)),
                );
                ("new", None)
            }
            LookupStatus::Unchanged => ("unchanged", None),
            LookupStatus::Changed { previous } => ("changed", Some(previous.fingerprint.clone())),
        };
        if account_id == self.account_id
            && let Some(own) = self.account.as_ref()
            && own.bundle.hash() != verified.bundle.hash()
        {
            return Err(Error::InvalidData(
                "the key directory lists a different key for this account".into(),
            ));
        }
        state
            .lookups
            .insert(account_id.to_owned(), verified.bundle.clone());
        Ok(DirectoryLookup {
            account_id: account_id.to_owned(),
            fingerprint: verified.bundle.fingerprint(),
            bundle_hash,
            status: status.to_owned(),
            previous_fingerprint: previous,
        })
    }

    /// Accepts the current key of `account_id` (from the last directory
    /// lookup or a verified roster) as the new pin. Call only after the user
    /// decided to trust it, for example after comparing fingerprints.
    pub fn accept_key_change(&mut self, account_id: &str) -> Result<String> {
        let state = &mut self.sharing;
        let bundle = state
            .rosters
            .values()
            .find_map(|r| r.members.get(account_id).map(|m| m.bundle.clone()))
            .or_else(|| state.lookups.get(account_id).cloned())
            .ok_or_else(|| Error::MissingKey(format!("key of {account_id}")))?;
        state
            .trust
            .pins
            .insert(account_id.to_owned(), pin_for(&bundle, None));
        let _ = self.evaluate_sharing();
        Ok(bundle.fingerprint())
    }

    /// Merges a sync delta and re-evaluates.
    pub fn apply_sharing(&mut self, delta: SharingDelta) -> SharingReport {
        self.sharing.data.merge(delta);
        self.evaluate_sharing()
    }

    /// Verifies the merged sharing data and opens keys.
    pub fn evaluate_sharing(&mut self) -> SharingReport {
        let mut warnings = Vec::new();
        let mut wrapped_keys = Vec::new();
        let data = self.sharing.data.clone();
        let Some(me) = self.account.as_ref().map(|a| a.bundle.clone()) else {
            if !data.orgs.is_empty() || !data.vault_access.is_empty() {
                warnings.push(warning(
                    "org_unverified",
                    &self.account_id,
                    None,
                    "this account has no key pairs yet",
                ));
            }
            self.sharing.view = SharingView {
                warnings,
                ..SharingView::default()
            };
            return SharingReport {
                view: self.sharing.view.clone(),
                wrapped_keys,
            };
        };
        let my_id = self.account_id.clone();

        // --- Organizations and rosters -----------------------------------------
        let mut rosters = BTreeMap::new();
        let mut org_views = Vec::new();
        for org in data.orgs.values() {
            let mut view = OrgView {
                id: org.id.clone(),
                kind: org.kind.clone(),
                name: None,
                role: org.role.clone(),
                status: org.status.clone(),
                default_vault_id: org.default_vault_id.clone(),
                fingerprint: String::new(),
                root_hash: String::new(),
                verified: false,
                members: Vec::new(),
                groups: Vec::new(),
            };
            let roster = (|| -> core::result::Result<Roster, Warning> {
                let genesis = Signed::<OrgGenesis>::parse(&org.genesis, &org.genesis_signature)
                    .map_err(|e| {
                        warning("org_unverified", &org.id, Some(&org.id), e.to_string())
                    })?;
                let root = encoding::encode(&genesis.hash());
                view.root_hash = root.clone();
                view.fingerprint = short_fingerprint(&genesis.hash());
                match self.sharing.trust.org_roots.get(&org.id) {
                    Some(pinned) if *pinned != root => {
                        return Err(warning(
                            "org_root_changed",
                            &org.id,
                            Some(&org.id),
                            "the organization's identity changed since it was first seen",
                        ));
                    }
                    Some(_) => {}
                    None => {
                        self.sharing
                            .trust
                            .org_roots
                            .insert(org.id.clone(), root.clone());
                    }
                }
                let members = data
                    .rosters
                    .get(&org.id)
                    .map(|r| r.members.as_slice())
                    .unwrap_or_default();
                verify_roster(&org.id, &genesis, members)
                    .map_err(|e| warning("org_unverified", &org.id, Some(&org.id), e.to_string()))
            })();
            let roster = match roster {
                Ok(roster) => roster,
                Err(w) => {
                    warnings.push(w);
                    org_views.push(view);
                    continue;
                }
            };
            view.verified = true;

            for member in roster.members.values() {
                let hash = encoding::encode(&member.bundle.hash());
                let key_changed = match self.sharing.trust.pins.get(&member.account_id) {
                    Some(pin) if pin.bundle_hash != hash => {
                        warnings.push(warning(
                            if member.account_id == my_id {
                                "own_key_changed"
                            } else {
                                "key_changed"
                            },
                            &member.account_id,
                            Some(&org.id),
                            format!(
                                "the key of {} changed (was {}, now {})",
                                member.email.as_deref().unwrap_or(&member.account_id),
                                pin.fingerprint,
                                member.bundle.fingerprint()
                            ),
                        ));
                        true
                    }
                    Some(_) => false,
                    None => {
                        self.sharing
                            .trust
                            .pins
                            .insert(member.account_id.clone(), pin_for(&member.bundle, None));
                        false
                    }
                };
                if member.account_id == my_id && member.bundle.hash() != me.hash() {
                    warnings.push(warning(
                        "own_key_changed",
                        &my_id,
                        Some(&org.id),
                        "the organization lists a different key for this account",
                    ));
                }
                view.members.push(MemberView {
                    account_id: member.account_id.clone(),
                    email: member.email.clone(),
                    role: member.role.as_str().to_owned(),
                    status: member.status.clone(),
                    fingerprint: Some(member.bundle.fingerprint()),
                    verified: true,
                    key_changed,
                    attested_by: member.attested_by.clone(),
                });
            }
            for member in roster.unverified.values() {
                if member.status == "confirmed" {
                    warnings.push(warning(
                        "member_unverified",
                        &member.account_id,
                        Some(&org.id),
                        member.reason.clone(),
                    ));
                }
                view.members.push(MemberView {
                    account_id: member.account_id.clone(),
                    email: member.email.clone(),
                    role: member.role.clone(),
                    status: member.status.clone(),
                    fingerprint: member.bundle.as_ref().map(SignedBundle::fingerprint),
                    verified: false,
                    key_changed: false,
                    attested_by: None,
                });
            }
            if let Some(member) = roster.members.get(&my_id)
                && member.role.as_str() != org.role
                && org.status == "confirmed"
            {
                warnings.push(warning(
                    "role_mismatch",
                    &org.id,
                    Some(&org.id),
                    format!(
                        "the server reports role {} but the attested role is {}",
                        org.role, member.role
                    ),
                ));
            }

            // Organization keys sealed for this account.
            for key in data.org_keys.values().filter(|k| k.org_id == org.id) {
                if self.org_keys.contains_key(&(org.id.clone(), key.epoch)) {
                    continue;
                }
                let opened = (|| -> Result<()> {
                    let grant = Signed::<OrgKeyGrant>::parse(&key.grant, &key.grant_signature)?;
                    let sealed = encoding::decode(&key.sealed_key)?;
                    verify_org_key_grant(&roster, &grant, &me, &sealed)?;
                    if grant.value.epoch != key.epoch {
                        return Err(Error::InvalidData("organization key epoch mismatch".into()));
                    }
                    let plaintext = self.account_keys()?.enc.open(
                        &me.hash(),
                        seal_context::ORG_KEY,
                        &seal_context::org_key(&org.id, key.epoch, &my_id),
                        &sealed,
                    )?;
                    self.org_keys.insert(
                        (org.id.clone(), key.epoch),
                        key_from_plaintext(plaintext.to_vec())?,
                    );
                    Ok(())
                })();
                if let Err(e) = opened {
                    warnings.push(warning(
                        "grant_invalid",
                        &org.id,
                        Some(&org.id),
                        e.to_string(),
                    ));
                }
            }
            view.name = self
                .decrypt_org_meta(&org.id, org.meta_epoch, &org.encrypted_meta)
                .ok()
                .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
                .and_then(|v| v["name"].as_str().map(str::to_owned));
            rosters.insert(org.id.clone(), roster);
            org_views.push(view);
        }

        // --- Groups -------------------------------------------------------------
        let mut groups = BTreeMap::new();
        let mut group_key_hashes = HashMap::new();
        for group in data.groups.values() {
            let Some(roster) = rosters.get(&group.org_id) else {
                continue;
            };
            let mut gview = GroupView {
                id: group.id.clone(),
                org_id: group.org_id.clone(),
                name: None,
                key_version: group.key_version,
                members: group.members.clone(),
                members_verified: false,
                verified: false,
                is_member: false,
            };
            let verified = Signed::<GroupBundle>::parse(&group.bundle, &group.bundle_signature)
                .and_then(|bundle| {
                    verify_group_bundle(roster, &bundle)?;
                    if bundle.value.group_id != group.id
                        || bundle.value.key_version != group.key_version
                    {
                        return Err(Error::InvalidData("group bundle does not match".into()));
                    }
                    Ok(bundle)
                });
            match verified {
                Ok(bundle) => {
                    gview.verified = true;
                    // Group keys sealed for this account (any version).
                    for key in data.group_keys.values().filter(|k| k.group_id == group.id) {
                        let opened = (|| -> Result<[u8; HASH_LEN]> {
                            let version_bundle =
                                Signed::<GroupBundle>::parse(&key.bundle, &key.bundle_signature)?;
                            verify_group_bundle(roster, &version_bundle)?;
                            let grant =
                                Signed::<GroupKeyGrant>::parse(&key.grant, &key.grant_signature)?;
                            let sealed = encoding::decode(&key.sealed_key)?;
                            verify_group_grant(roster, &version_bundle, &grant, Some(&sealed))?;
                            if grant.value.account_id != my_id
                                || version_bundle.value.group_id != group.id
                                || version_bundle.value.key_version != key.key_version
                            {
                                return Err(Error::InvalidData("group key does not match".into()));
                            }
                            let id = (group.id.clone(), key.key_version);
                            if !self.group_keys.contains_key(&id) {
                                let seed = self.account_keys()?.enc.open(
                                    &me.hash(),
                                    seal_context::GROUP_KEY,
                                    &seal_context::group_key(&group.id, key.key_version, &my_id),
                                    &sealed,
                                )?;
                                let enc = crate::identity::EncryptionKey::from_seed(
                                    &seed[..].try_into().map_err(|_| {
                                        Error::InvalidData("group key has the wrong length".into())
                                    })?,
                                );
                                if enc.public_key() != version_bundle.value.enc_pk {
                                    return Err(Error::InvalidData(
                                        "group key does not match its public key".into(),
                                    ));
                                }
                                self.group_keys.insert(id, enc);
                            }
                            Ok(version_bundle.hash())
                        })();
                        match opened {
                            Ok(hash) => {
                                group_key_hashes.insert((group.id.clone(), key.key_version), hash);
                            }
                            Err(e) => warnings.push(warning(
                                "grant_invalid",
                                &group.id,
                                Some(&group.org_id),
                                e.to_string(),
                            )),
                        }
                    }
                    gview.is_member =
                        group_key_hashes.contains_key(&(group.id.clone(), group.key_version));
                    if gview.is_member {
                        let mut members = Vec::new();
                        let mut all_valid = true;
                        for record in &group.member_grants {
                            match Signed::<GroupKeyGrant>::parse(
                                &record.grant,
                                &record.grant_signature,
                            )
                            .and_then(|g| verify_group_grant(roster, &bundle, &g, None).map(|()| g))
                            {
                                Ok(g) => members.push(g.value.account_id),
                                Err(_) => all_valid = false,
                            }
                        }
                        members.sort();
                        members.dedup();
                        let mut listed = group.members.clone();
                        listed.sort();
                        if !all_valid || listed != members {
                            warnings.push(warning(
                                "membership_mismatch",
                                &group.id,
                                Some(&group.org_id),
                                "the group's member list does not match its signed grants",
                            ));
                        }
                        gview.members = members.clone();
                        gview.members_verified = true;
                        groups.insert(
                            group.id.clone(),
                            VerifiedGroup {
                                org_id: group.org_id.clone(),
                                key_version: group.key_version,
                                bundle,
                                members,
                                members_verified: true,
                            },
                        );
                    } else {
                        groups.insert(
                            group.id.clone(),
                            VerifiedGroup {
                                org_id: group.org_id.clone(),
                                key_version: group.key_version,
                                bundle,
                                members: group.members.clone(),
                                members_verified: false,
                            },
                        );
                    }
                }
                Err(e) => warnings.push(warning(
                    "group_unverified",
                    &group.id,
                    Some(&group.org_id),
                    e.to_string(),
                )),
            }
            gview.name = self
                .decrypt_group_meta(
                    &group.org_id,
                    &group.id,
                    group.meta_epoch,
                    &group.encrypted_meta,
                )
                .ok()
                .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
                .and_then(|v| v["name"].as_str().map(str::to_owned));
            if let Some(view) = org_views.iter_mut().find(|o| o.id == group.org_id) {
                view.groups.push(gview);
            }
        }

        // --- Shared vaults --------------------------------------------------------
        let mut chains = BTreeMap::new();
        let mut vault_views = Vec::new();
        for access in data.vault_access.values() {
            let mut vview = SharedVaultView {
                vault_id: access.vault_id.clone(),
                org_id: access.org_id.clone(),
                role: None,
                server_role: access.role.clone(),
                key_epoch: access.key_epoch,
                manifest_version: 0,
                members: Vec::new(),
                verified: false,
                has_key: false,
                rotation_pending: access.rotation_pending,
            };
            let Some(roster) = rosters.get(&access.org_id) else {
                warnings.push(warning(
                    "manifest_invalid",
                    &access.vault_id,
                    Some(&access.org_id),
                    "the vault's organization could not be verified",
                ));
                vault_views.push(vview);
                continue;
            };
            let chain_records = data
                .manifests
                .get(&access.vault_id)
                .cloned()
                .unwrap_or_default();
            let pinned = self
                .sharing
                .trust
                .manifests
                .get(&access.vault_id)
                .and_then(|p| Some((p.version, encoding::decode(&p.hash).ok()?.try_into().ok()?)));
            let chain = chain_records
                .iter()
                .map(|r| Signed::<VaultManifest>::parse(&r.manifest, &r.signature))
                .collect::<Result<Vec<_>>>()
                .and_then(|chain| {
                    let signers: Vec<_> = data.signers.values().cloned().collect();
                    verify_manifest_chain(&access.vault_id, roster, &chain, &signers, pinned)
                });
            let chain = match chain {
                Ok(chain) => chain,
                Err(e) => {
                    warnings.push(warning(
                        "manifest_invalid",
                        &access.vault_id,
                        Some(&access.org_id),
                        e.to_string(),
                    ));
                    vault_views.push(vview);
                    continue;
                }
            };
            let latest = chain.latest().clone();
            self.sharing.trust.manifests.insert(
                access.vault_id.clone(),
                ManifestPin {
                    version: latest.manifest.version,
                    hash: encoding::encode(&latest.hash),
                },
            );
            vview.verified = true;
            vview.manifest_version = latest.manifest.version;
            vview.members = latest
                .manifest
                .members
                .iter()
                .map(|e| VaultMemberView {
                    principal_type: e.principal_type.as_str().to_owned(),
                    principal_id: e.principal_id.clone(),
                    role: e.role.as_str().to_owned(),
                })
                .collect();
            // Role: direct entry or via groups this account holds the key of.
            let mut role: Option<VaultRole> = latest
                .manifest
                .entry(PrincipalType::Account, &my_id)
                .filter(|e| e.key_hash == me.hash())
                .map(|e| e.role);
            for entry in latest
                .manifest
                .members
                .iter()
                .filter(|e| e.principal_type == PrincipalType::Group)
            {
                let holds = groups.get(&entry.principal_id).is_some_and(|g| {
                    group_key_hashes.get(&(entry.principal_id.clone(), g.key_version))
                        == Some(&entry.key_hash)
                });
                if holds {
                    role = role.max(Some(entry.role));
                }
            }
            // Guests are view-only whatever the manifest grants (B8).
            if let Some(own) = roster.active(&my_id) {
                role = role.map(|r| r.min(own.role.max_vault_role()));
            }
            vview.role = role.map(|r| r.as_str().to_owned());
            let server_role = VaultRole::parse(&access.role).ok();
            if server_role != role {
                warnings.push(warning(
                    "role_mismatch",
                    &access.vault_id,
                    Some(&access.org_id),
                    format!(
                        "the server grants {} but the signed member list grants {}",
                        access.role,
                        role.map_or("no access", VaultRole::as_str)
                    ),
                ));
            }
            if latest.manifest.key_epoch != access.key_epoch {
                warnings.push(warning(
                    "manifest_invalid",
                    &access.vault_id,
                    Some(&access.org_id),
                    "the vault's key epoch does not match its member list",
                ));
            }

            // Vault keys for this account or its groups.
            for key in data
                .vault_keys
                .values()
                .filter(|k| k.vault_id == access.vault_id)
            {
                if self.has_vault_key(&key.vault_id, key.key_epoch) {
                    continue;
                }
                let is_me = key.principal_type == "account" && key.principal_id == my_id;
                if is_me
                    && let Some(wrapped) = &key.wrapped_key
                    && self
                        .add_wrapped_vault_key(&key.vault_id, key.key_epoch, wrapped)
                        .is_ok()
                {
                    continue;
                }
                let opened = (|| -> Result<()> {
                    let grant = Signed::<VaultGrant>::parse(&key.grant, &key.grant_signature)?;
                    let g = &grant.value;
                    if g.vault_id != key.vault_id
                        || g.key_epoch != key.key_epoch
                        || g.principal_type.as_str() != key.principal_type
                        || g.principal_id != key.principal_id
                    {
                        return Err(Error::InvalidData(
                            "vault key does not match its grant".into(),
                        ));
                    }
                    let sealed = encoding::decode(&key.sealed_key)?;
                    let context = seal_context::vault_key(
                        &key.vault_id,
                        key.key_epoch,
                        g.principal_type,
                        &g.principal_id,
                    );
                    let plaintext = match g.principal_type {
                        PrincipalType::Account if is_me => {
                            verify_vault_grant(&chain, &grant, &me.hash(), &sealed)?;
                            self.account_keys()?.enc.open(
                                &me.hash(),
                                seal_context::VAULT_KEY,
                                &context,
                                &sealed,
                            )?
                        }
                        PrincipalType::Group => {
                            let (version, hash) = group_key_hashes
                                .iter()
                                .find(|((gid, _), h)| {
                                    *gid == g.principal_id && **h == g.principal_key_hash
                                })
                                .map(|((_, v), h)| (*v, *h))
                                .ok_or_else(|| {
                                    Error::MissingKey(format!("group {}", g.principal_id))
                                })?;
                            verify_vault_grant(&chain, &grant, &hash, &sealed)?;
                            self.group_keys[&(g.principal_id.clone(), version)].open(
                                &hash,
                                seal_context::VAULT_KEY,
                                &context,
                                &sealed,
                            )?
                        }
                        PrincipalType::Account => {
                            return Err(Error::InvalidData("vault key for another account".into()));
                        }
                    };
                    let vault_key = key_from_plaintext(plaintext.to_vec())?;
                    self.insert_vault_key(&key.vault_id, key.key_epoch, vault_key);
                    if is_me && key.wrapped_key.is_none() {
                        wrapped_keys.push(WrappedKeyUpload {
                            vault_id: key.vault_id.clone(),
                            key_epoch: key.key_epoch,
                            wrapped_key: self.wrap_vault_key(&key.vault_id, key.key_epoch)?,
                        });
                    }
                    Ok(())
                })();
                if let Err(e) = opened {
                    warnings.push(warning(
                        "grant_invalid",
                        &access.vault_id,
                        Some(&access.org_id),
                        e.to_string(),
                    ));
                }
            }
            vview.has_key = self.has_vault_key(&access.vault_id, access.key_epoch);
            chains.insert(access.vault_id.clone(), chain);
            vault_views.push(vview);
        }

        let state = &mut self.sharing;
        let (policies, effective_policy) =
            crate::policy::evaluate(&mut state.trust, &rosters, &data, &mut warnings);
        state.rosters = rosters;
        state.groups = groups;
        state.chains = chains;
        state.group_key_hashes = group_key_hashes;
        state.view = SharingView {
            orgs: org_views,
            vaults: vault_views,
            warnings,
            policies,
            effective_policy,
        };
        SharingReport {
            view: state.view.clone(),
            wrapped_keys,
        }
    }

    /// The account's verified role in an organization (`None` if not a
    /// confirmed, verified member).
    pub fn org_role(&self, org_id: &str) -> Option<OrgRole> {
        self.sharing
            .rosters
            .get(org_id)
            .and_then(|r| r.active(&self.account_id))
            .map(|m| m.role)
    }
}
