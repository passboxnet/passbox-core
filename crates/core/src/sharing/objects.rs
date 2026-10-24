//! Signed objects of organizations and shared vaults, with their canonical
//! encodings ([`crate::canon`]). Each type has its own tag, so signatures
//! cannot be moved between object types.

use serde::{Deserialize, Serialize};

use crate::canon::{Reader, Writer};
use crate::identity::{self, HASH_LEN, SIG_PK_LEN, SIGNATURE_LEN, SignatureKey};
use crate::{Error, Result, encoding};

macro_rules! string_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum $name { $($variant),+ }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }

            pub fn parse(value: &str) -> Result<Self> {
                match value {
                    $($text => Ok(Self::$variant),)+
                    _ => Err(Error::InvalidData(format!(
                        concat!("unknown ", stringify!($name), " {:?}"), value
                    ))),
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

string_enum!(
    /// Kind of organization.
    OrgKind { Family => "family", Team => "team" }
);
string_enum!(
    /// Role in an organization. Owners and admins manage members.
    OrgRole { Owner => "owner", Admin => "admin", Member => "member", Guest => "guest" }
);
string_enum!(
    /// Role in a shared vault: `view` reads, `edit` also writes items,
    /// `manage` also changes members and rotates keys.
    VaultRole { View => "view", Edit => "edit", Manage => "manage" }
);
string_enum!(
    /// Who a vault is shared with.
    PrincipalType { Account => "account", Group => "group" }
);

impl OrgRole {
    /// Owners and admins confirm members, attest keys and manage groups.
    pub fn is_admin(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

impl VaultRole {
    pub fn can_write(self) -> bool {
        matches!(self, Self::Edit | Self::Manage)
    }

    pub fn can_manage(self) -> bool {
        self == Self::Manage
    }
}

/// Types with a canonical encoding.
pub trait Canonical: Sized {
    const TAG: &'static str;
    fn encode(&self, w: &mut Writer);
    fn decode(r: &mut Reader<'_>) -> Result<Self>;

    fn to_canonical(&self) -> Vec<u8> {
        let mut w = Writer::new(Self::TAG);
        self.encode(&mut w);
        w.finish()
    }

    fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, Self::TAG)?;
        let value = Self::decode(&mut r)?;
        r.finish()?;
        Ok(value)
    }
}

/// A canonical object with its signature. Parsing does not verify the
/// signature; callers verify against the key of the signer they expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<T> {
    pub value: T,
    canonical: Vec<u8>,
    signature: [u8; SIGNATURE_LEN],
}

impl<T: Canonical> Signed<T> {
    pub fn sign(value: T, key: &SignatureKey) -> Self {
        let canonical = value.to_canonical();
        let signature = key.sign(&canonical);
        Self {
            value,
            canonical,
            signature,
        }
    }

    /// Parses Base64url object and signature.
    pub fn parse(object: &str, signature: &str) -> Result<Self> {
        let canonical = encoding::decode(object)?;
        let signature: [u8; SIGNATURE_LEN] = encoding::decode(signature)?
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;
        Ok(Self {
            value: T::from_canonical(&canonical)?,
            canonical,
            signature,
        })
    }

    pub fn verify(&self, sig_pk: &[u8; SIG_PK_LEN]) -> Result<()> {
        identity::verify(sig_pk, &self.canonical, &self.signature)
    }

    pub fn hash(&self) -> [u8; HASH_LEN] {
        identity::object_hash(&self.canonical)
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    pub fn encoded(&self) -> String {
        encoding::encode(&self.canonical)
    }

    pub fn encoded_signature(&self) -> String {
        encoding::encode(&self.signature)
    }
}

/// The root of an organization: who created it, with which key. Its hash
/// is the organization fingerprint that invitation links carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgGenesis {
    pub org_id: String,
    pub kind: OrgKind,
    pub owner_id: String,
    pub owner_bundle_hash: [u8; HASH_LEN],
    pub created_at: i64,
}

impl Canonical for OrgGenesis {
    const TAG: &'static str = "passbox/v1/org-genesis";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.org_id)
            .str(self.kind.as_str())
            .str(&self.owner_id)
            .bytes(&self.owner_bundle_hash)
            .i64(self.created_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            org_id: r.string()?,
            kind: OrgKind::parse(r.str()?)?,
            owner_id: r.string()?,
            owner_bundle_hash: r.array()?,
            created_at: r.i64()?,
        })
    }
}

/// An admin's statement "this is the key of member X, with role R".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberAttestation {
    pub org_id: String,
    pub account_id: String,
    pub key_version: u32,
    pub bundle_hash: [u8; HASH_LEN],
    pub role: OrgRole,
    pub attester_id: String,
    pub created_at: i64,
}

impl Canonical for MemberAttestation {
    const TAG: &'static str = "passbox/v1/member-attestation";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.org_id)
            .str(&self.account_id)
            .u64(u64::from(self.key_version))
            .bytes(&self.bundle_hash)
            .str(self.role.as_str())
            .str(&self.attester_id)
            .i64(self.created_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            org_id: r.string()?,
            account_id: r.string()?,
            key_version: r.u32()?,
            bundle_hash: r.array()?,
            role: OrgRole::parse(r.str()?)?,
            attester_id: r.string()?,
            created_at: r.i64()?,
        })
    }
}

/// The organization key (encrypts the organization's name and group names)
/// sealed for one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgKeyGrant {
    pub org_id: String,
    pub epoch: u32,
    pub account_id: String,
    pub account_bundle_hash: [u8; HASH_LEN],
    pub sealed_hash: [u8; HASH_LEN],
    pub granter_id: String,
    pub granted_at: i64,
}

impl Canonical for OrgKeyGrant {
    const TAG: &'static str = "passbox/v1/org-key-grant";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.org_id)
            .u64(u64::from(self.epoch))
            .str(&self.account_id)
            .bytes(&self.account_bundle_hash)
            .bytes(&self.sealed_hash)
            .str(&self.granter_id)
            .i64(self.granted_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            org_id: r.string()?,
            epoch: r.u32()?,
            account_id: r.string()?,
            account_bundle_hash: r.array()?,
            sealed_hash: r.array()?,
            granter_id: r.string()?,
            granted_at: r.i64()?,
        })
    }
}

/// The public encryption key of a group, signed by the admin who created
/// (or rotated) it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBundle {
    pub group_id: String,
    pub org_id: String,
    pub key_version: u32,
    pub enc_pk: Vec<u8>,
    pub creator_id: String,
    pub created_at: i64,
}

impl Canonical for GroupBundle {
    const TAG: &'static str = "passbox/v1/group-bundle";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.group_id)
            .str(&self.org_id)
            .u64(u64::from(self.key_version))
            .bytes(&self.enc_pk)
            .str(&self.creator_id)
            .i64(self.created_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let bundle = Self {
            group_id: r.string()?,
            org_id: r.string()?,
            key_version: r.u32()?,
            enc_pk: r.bytes()?.to_vec(),
            creator_id: r.string()?,
            created_at: r.i64()?,
        };
        if bundle.enc_pk.len() != identity::ENC_PK_LEN {
            return Err(Error::InvalidData("invalid group public key".into()));
        }
        Ok(bundle)
    }
}

/// A group's private key sealed for one group member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKeyGrant {
    pub group_id: String,
    pub org_id: String,
    pub key_version: u32,
    pub account_id: String,
    pub account_bundle_hash: [u8; HASH_LEN],
    pub sealed_hash: [u8; HASH_LEN],
    pub granter_id: String,
    pub granted_at: i64,
}

impl Canonical for GroupKeyGrant {
    const TAG: &'static str = "passbox/v1/group-key-grant";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.group_id)
            .str(&self.org_id)
            .u64(u64::from(self.key_version))
            .str(&self.account_id)
            .bytes(&self.account_bundle_hash)
            .bytes(&self.sealed_hash)
            .str(&self.granter_id)
            .i64(self.granted_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            group_id: r.string()?,
            org_id: r.string()?,
            key_version: r.u32()?,
            account_id: r.string()?,
            account_bundle_hash: r.array()?,
            sealed_hash: r.array()?,
            granter_id: r.string()?,
            granted_at: r.i64()?,
        })
    }
}

/// One member of a vault in its manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManifestEntry {
    pub principal_type: PrincipalType,
    pub principal_id: String,
    pub role: VaultRole,
    /// Hash of the member's account bundle or group bundle.
    pub key_hash: [u8; HASH_LEN],
}

/// The signed member list of a shared vault. Versions form a hash chain;
/// a new version is signed by a manager of the previous version (or an
/// organization admin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultManifest {
    pub vault_id: String,
    pub org_id: String,
    pub version: u64,
    pub key_epoch: u32,
    /// Sorted by principal type and ID, without duplicates.
    pub members: Vec<ManifestEntry>,
    pub prev_hash: [u8; HASH_LEN],
    pub signer_id: String,
    pub created_at: i64,
}

impl VaultManifest {
    pub fn entry(
        &self,
        principal_type: PrincipalType,
        principal_id: &str,
    ) -> Option<&ManifestEntry> {
        self.members
            .iter()
            .find(|e| e.principal_type == principal_type && e.principal_id == principal_id)
    }
}

impl Canonical for VaultManifest {
    const TAG: &'static str = "passbox/v1/vault-manifest";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.vault_id)
            .str(&self.org_id)
            .u64(self.version)
            .u64(u64::from(self.key_epoch))
            .count(self.members.len());
        for entry in &self.members {
            w.str(entry.principal_type.as_str())
                .str(&entry.principal_id)
                .str(entry.role.as_str())
                .bytes(&entry.key_hash);
        }
        w.bytes(&self.prev_hash)
            .str(&self.signer_id)
            .i64(self.created_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let vault_id = r.string()?;
        let org_id = r.string()?;
        let version = r.u64()?;
        let key_epoch = r.u32()?;
        let count = r.count()?;
        let mut members = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            members.push(ManifestEntry {
                principal_type: PrincipalType::parse(r.str()?)?,
                principal_id: r.string()?,
                role: VaultRole::parse(r.str()?)?,
                key_hash: r.array()?,
            });
        }
        if members.windows(2).any(|w| {
            (w[0].principal_type, &w[0].principal_id) >= (w[1].principal_type, &w[1].principal_id)
        }) {
            return Err(Error::InvalidData(
                "manifest members are not sorted or not unique".into(),
            ));
        }
        Ok(Self {
            vault_id,
            org_id,
            version,
            key_epoch,
            members,
            prev_hash: r.array()?,
            signer_id: r.string()?,
            created_at: r.i64()?,
        })
    }
}

/// A vault key (of one epoch) sealed for one member, with the role the
/// member has. Issued together with the manifest version it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultGrant {
    pub vault_id: String,
    pub org_id: String,
    pub key_epoch: u32,
    pub manifest_version: u64,
    pub principal_type: PrincipalType,
    pub principal_id: String,
    pub principal_key_hash: [u8; HASH_LEN],
    pub role: VaultRole,
    pub sealed_hash: [u8; HASH_LEN],
    pub granter_id: String,
    pub granted_at: i64,
}

impl Canonical for VaultGrant {
    const TAG: &'static str = "passbox/v1/vault-grant";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.vault_id)
            .str(&self.org_id)
            .u64(u64::from(self.key_epoch))
            .u64(self.manifest_version)
            .str(self.principal_type.as_str())
            .str(&self.principal_id)
            .bytes(&self.principal_key_hash)
            .str(self.role.as_str())
            .bytes(&self.sealed_hash)
            .str(&self.granter_id)
            .i64(self.granted_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            vault_id: r.string()?,
            org_id: r.string()?,
            key_epoch: r.u32()?,
            manifest_version: r.u64()?,
            principal_type: PrincipalType::parse(r.str()?)?,
            principal_id: r.string()?,
            principal_key_hash: r.array()?,
            role: VaultRole::parse(r.str()?)?,
            sealed_hash: r.array()?,
            granter_id: r.string()?,
            granted_at: r.i64()?,
        })
    }
}

/// Seal purposes and contexts. The context binds a sealed key to exactly
/// one use.
pub mod seal_context {
    use super::PrincipalType;
    use crate::canon::Writer;

    pub const VAULT_KEY: &str = "vault-key";
    pub const GROUP_KEY: &str = "group-key";
    pub const ORG_KEY: &str = "org-key";

    pub fn vault_key(
        vault_id: &str,
        epoch: u32,
        principal_type: PrincipalType,
        principal_id: &str,
    ) -> Vec<u8> {
        Writer::new("passbox/v1/seal-context/vault-key")
            .str(vault_id)
            .u64(u64::from(epoch))
            .str(principal_type.as_str())
            .str(principal_id)
            .finish()
    }

    pub fn group_key(group_id: &str, key_version: u32, account_id: &str) -> Vec<u8> {
        Writer::new("passbox/v1/seal-context/group-key")
            .str(group_id)
            .u64(u64::from(key_version))
            .str(account_id)
            .finish()
    }

    pub fn org_key(org_id: &str, epoch: u32, account_id: &str) -> Vec<u8> {
        Writer::new("passbox/v1/seal-context/org-key")
            .str(org_id)
            .u64(u64::from(epoch))
            .str(account_id)
            .finish()
    }
}

/// Formats a 32-byte hash as a human-comparable fingerprint (8 groups of
/// five digits), for example the organization fingerprint.
pub fn short_fingerprint(hash: &[u8; HASH_LEN]) -> String {
    (0..8)
        .map(|i| {
            let chunk = &hash[i * 4..i * 4 + 4];
            let value = u32::from_be_bytes(chunk.try_into().expect("4 bytes"));
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_round_trip() {
        let manifest = VaultManifest {
            vault_id: "v".into(),
            org_id: "o".into(),
            version: 2,
            key_epoch: 1,
            members: vec![
                ManifestEntry {
                    principal_type: PrincipalType::Account,
                    principal_id: "a".into(),
                    role: VaultRole::Manage,
                    key_hash: [1; 32],
                },
                ManifestEntry {
                    principal_type: PrincipalType::Group,
                    principal_id: "g".into(),
                    role: VaultRole::View,
                    key_hash: [2; 32],
                },
            ],
            prev_hash: [3; 32],
            signer_id: "a".into(),
            created_at: 5,
        };
        assert_eq!(
            VaultManifest::from_canonical(&manifest.to_canonical()).unwrap(),
            manifest
        );
        let mut unsorted = manifest.clone();
        unsorted.members.reverse();
        assert!(VaultManifest::from_canonical(&unsorted.to_canonical()).is_err());
        // Types do not parse as each other.
        let genesis = OrgGenesis {
            org_id: "o".into(),
            kind: OrgKind::Family,
            owner_id: "a".into(),
            owner_bundle_hash: [0; 32],
            created_at: 1,
        };
        assert!(MemberAttestation::from_canonical(&genesis.to_canonical()).is_err());
    }

    #[test]
    fn signed_objects_verify_only_with_the_signer_key() {
        let key = SignatureKey::generate().unwrap();
        let other = SignatureKey::generate().unwrap();
        let genesis = OrgGenesis {
            org_id: "o".into(),
            kind: OrgKind::Team,
            owner_id: "a".into(),
            owner_bundle_hash: [0; 32],
            created_at: 1,
        };
        let signed = Signed::sign(genesis, &key);
        let parsed =
            Signed::<OrgGenesis>::parse(&signed.encoded(), &signed.encoded_signature()).unwrap();
        parsed.verify(&key.public_key()).unwrap();
        assert!(parsed.verify(&other.public_key()).is_err());
    }

    #[test]
    fn roles() {
        assert!(OrgRole::Admin.is_admin() && !OrgRole::Member.is_admin());
        assert!(VaultRole::Edit.can_write() && !VaultRole::View.can_write());
        assert!(VaultRole::View < VaultRole::Edit && VaultRole::Edit < VaultRole::Manage);
        assert_eq!(VaultRole::parse("manage").unwrap(), VaultRole::Manage);
        assert!(VaultRole::parse("owner").is_err());
    }
}
