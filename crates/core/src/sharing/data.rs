//! The sharing data the server delivers in `GET /api/v1/sync?sharing=1`,
//! and how clients merge incremental deltas into their local copy.
//!
//! Everything here is untrusted input: [`super::state`] verifies it before
//! anything is shown or used.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The `sharing` object of a sync response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SharingDelta {
    /// Every organization the account belongs to (full list).
    pub orgs: Vec<OrgRecord>,
    /// Member lists of organizations that changed (full list per org).
    pub rosters: Vec<RosterRecord>,
    /// Organization keys sealed for this account (new or changed rows).
    pub org_keys: Vec<OrgKeyRecord>,
    /// Groups of these organizations (full list).
    pub groups: Vec<GroupRecord>,
    /// Group keys sealed for this account (new or changed rows).
    pub group_keys: Vec<GroupKeyRecord>,
    /// Every shared vault the account can open, with the server's view of
    /// its role (full list).
    pub vault_access: Vec<VaultAccessRecord>,
    /// Vault keys sealed for this account or its groups (new or changed rows).
    pub vault_keys: Vec<VaultKeyRecord>,
    /// Full manifest chains of vaults whose members changed.
    pub manifests: Vec<ManifestRecord>,
    /// Public bundles of manifest signers, including former members.
    pub signers: Vec<BundleRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgRecord {
    pub id: String,
    pub kind: String,
    /// This account's role and status according to the server.
    pub role: String,
    pub status: String,
    pub genesis: String,
    pub genesis_signature: String,
    pub encrypted_meta: String,
    pub meta_epoch: u32,
    pub revision: u64,
    #[serde(default)]
    pub default_vault_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RosterRecord {
    pub org_id: String,
    pub members: Vec<RosterMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RosterMember {
    pub account_id: String,
    pub role: String,
    /// `accepted`, `confirmed` or `suspended`.
    pub status: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub bundle: Option<String>,
    #[serde(default)]
    pub bundle_signature: Option<String>,
    #[serde(default)]
    pub attestation: Option<String>,
    #[serde(default)]
    pub attestation_signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgKeyRecord {
    pub org_id: String,
    pub epoch: u32,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupRecord {
    pub id: String,
    pub org_id: String,
    pub key_version: u32,
    pub bundle: String,
    pub bundle_signature: String,
    pub encrypted_meta: String,
    pub meta_epoch: u32,
    /// Signed grants of the current key version, one per member (without
    /// the sealed keys). Only delivered to members of the group.
    #[serde(default)]
    pub member_grants: Vec<GrantRecord>,
    /// Member account IDs according to the server.
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRecord {
    pub grant: String,
    pub grant_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupKeyRecord {
    pub group_id: String,
    pub key_version: u32,
    /// The group bundle of this key version.
    pub bundle: String,
    pub bundle_signature: String,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultAccessRecord {
    pub vault_id: String,
    pub org_id: String,
    pub role: String,
    pub key_epoch: u32,
    #[serde(default)]
    pub rotation_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultKeyRecord {
    pub vault_id: String,
    pub key_epoch: u32,
    pub principal_type: String,
    pub principal_id: String,
    pub sealed_key: String,
    /// The member's own copy, wrapped with its account key.
    #[serde(default)]
    pub wrapped_key: Option<String>,
    pub grant: String,
    pub grant_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestRecord {
    pub vault_id: String,
    pub version: u64,
    pub manifest: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleRecord {
    pub bundle: String,
    pub bundle_signature: String,
}

/// The merged sharing data a client keeps (in memory, and in the native
/// clients' offline cache).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SharingData {
    pub orgs: BTreeMap<String, OrgRecord>,
    pub rosters: BTreeMap<String, RosterRecord>,
    pub org_keys: BTreeMap<String, OrgKeyRecord>,
    pub groups: BTreeMap<String, GroupRecord>,
    pub group_keys: BTreeMap<String, GroupKeyRecord>,
    pub vault_access: BTreeMap<String, VaultAccessRecord>,
    pub vault_keys: BTreeMap<String, VaultKeyRecord>,
    /// Manifest chains by vault ID, sorted by version.
    pub manifests: BTreeMap<String, Vec<ManifestRecord>>,
    /// Signer bundles by their Base64url canonical encoding.
    pub signers: BTreeMap<String, BundleRecord>,
}

impl SharingData {
    /// Merges a sync delta. Full lists replace what was there; changed rows
    /// are upserted; data of organizations, groups and vaults the account
    /// lost access to is dropped.
    pub fn merge(&mut self, delta: SharingDelta) {
        self.orgs = delta.orgs.into_iter().map(|o| (o.id.clone(), o)).collect();
        self.groups = delta
            .groups
            .into_iter()
            .map(|g| (g.id.clone(), g))
            .collect();
        self.vault_access = delta
            .vault_access
            .into_iter()
            .map(|v| (v.vault_id.clone(), v))
            .collect();
        for roster in delta.rosters {
            self.rosters.insert(roster.org_id.clone(), roster);
        }
        for key in delta.org_keys {
            self.org_keys
                .insert(format!("{}#{}", key.org_id, key.epoch), key);
        }
        for key in delta.group_keys {
            self.group_keys
                .insert(format!("{}#{}", key.group_id, key.key_version), key);
        }
        for key in delta.vault_keys {
            self.vault_keys.insert(
                format!(
                    "{}#{}#{}#{}",
                    key.vault_id, key.key_epoch, key.principal_type, key.principal_id
                ),
                key,
            );
        }
        let mut chains: BTreeMap<String, Vec<ManifestRecord>> = BTreeMap::new();
        for manifest in delta.manifests {
            chains
                .entry(manifest.vault_id.clone())
                .or_default()
                .push(manifest);
        }
        for (vault_id, mut chain) in chains {
            chain.sort_by_key(|m| m.version);
            chain.dedup_by_key(|m| m.version);
            self.manifests.insert(vault_id, chain);
        }
        for signer in delta.signers {
            self.signers.insert(signer.bundle.clone(), signer);
        }

        let orgs = &self.orgs;
        let groups = &self.groups;
        let vaults = &self.vault_access;
        self.rosters.retain(|id, _| orgs.contains_key(id));
        self.org_keys.retain(|_, k| orgs.contains_key(&k.org_id));
        self.group_keys
            .retain(|_, k| groups.contains_key(&k.group_id));
        self.vault_keys
            .retain(|_, k| vaults.contains_key(&k.vault_id));
        self.manifests.retain(|id, _| vaults.contains_key(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(id: &str) -> VaultAccessRecord {
        VaultAccessRecord {
            vault_id: id.into(),
            org_id: "o".into(),
            role: "view".into(),
            key_epoch: 1,
            rotation_pending: false,
        }
    }

    fn manifest(vault: &str, version: u64) -> ManifestRecord {
        ManifestRecord {
            vault_id: vault.into(),
            version,
            manifest: format!("m{version}"),
            signature: String::new(),
        }
    }

    #[test]
    fn merge_replaces_lists_and_prunes_lost_access() {
        let mut data = SharingData::default();
        data.merge(SharingDelta {
            vault_access: vec![access("a"), access("b")],
            manifests: vec![manifest("a", 2), manifest("a", 1), manifest("b", 1)],
            ..SharingDelta::default()
        });
        assert_eq!(data.manifests["a"].len(), 2);
        assert_eq!(data.manifests["a"][0].version, 1);
        data.merge(SharingDelta {
            vault_access: vec![access("a")],
            ..SharingDelta::default()
        });
        assert!(data.manifests.contains_key("a"));
        assert!(!data.manifests.contains_key("b"));
        assert_eq!(data.vault_access.len(), 1);
    }
}
