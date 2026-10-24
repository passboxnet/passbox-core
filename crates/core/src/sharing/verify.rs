//! Verification of organization rosters, vault manifest chains and grants.
//!
//! Trust flows from an organization's genesis (signed by its owner, pinned
//! by every member on first contact or checked against the fingerprint in
//! the invitation link) through admin attestations of member keys, to
//! manifests and grants signed by admins and vault managers. Nothing the
//! server says about members, roles or keys is believed without such a
//! chain.

use std::collections::{BTreeMap, HashMap};

use super::data::{BundleRecord, RosterMember};
use super::objects::{
    GroupBundle, GroupKeyGrant, MemberAttestation, OrgGenesis, OrgKeyGrant, OrgKind, OrgRole,
    PrincipalType, Signed, VaultGrant, VaultManifest, VaultRole,
};
use crate::identity::{HASH_LEN, SignedBundle, sealed_hash};
use crate::{Error, Result};

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidData(message.into())
}

/// A member whose key is vouched for by the owner or an admin.
#[derive(Debug, Clone)]
pub struct VerifiedMember {
    pub account_id: String,
    /// The role from the attestation (or owner, from the genesis).
    pub role: OrgRole,
    /// The server's status: `confirmed` or `suspended`.
    pub status: String,
    pub email: Option<String>,
    pub bundle: SignedBundle,
    /// Who attested the key; `None` for the owner.
    pub attested_by: Option<String>,
}

/// A member the client cannot verify (not confirmed yet, or a broken chain).
#[derive(Debug, Clone)]
pub struct UnverifiedMember {
    pub account_id: String,
    pub role: String,
    pub status: String,
    pub email: Option<String>,
    pub bundle: Option<SignedBundle>,
    pub reason: String,
}

/// The verified member list of an organization.
#[derive(Debug, Clone)]
pub struct Roster {
    pub org_id: String,
    pub kind: OrgKind,
    pub owner_id: String,
    /// Hash of the genesis: the organization fingerprint.
    pub root_hash: [u8; HASH_LEN],
    pub members: BTreeMap<String, VerifiedMember>,
    pub unverified: BTreeMap<String, UnverifiedMember>,
}

impl Roster {
    /// The member's bundle if it is verified and an active admin.
    pub fn admin(&self, account_id: &str) -> Option<&VerifiedMember> {
        self.members
            .get(account_id)
            .filter(|m| m.role.is_admin() && m.status == "confirmed")
    }

    pub fn active(&self, account_id: &str) -> Option<&VerifiedMember> {
        self.members
            .get(account_id)
            .filter(|m| m.status == "confirmed")
    }
}

/// Verifies a roster against its genesis. Fails if the genesis itself is
/// not valid (wrong organization, or not signed by the owner's key).
pub fn verify_roster(
    org_id: &str,
    genesis: &Signed<OrgGenesis>,
    members: &[RosterMember],
) -> Result<Roster> {
    let root = &genesis.value;
    if root.org_id != org_id {
        return Err(invalid(
            "organization genesis belongs to another organization",
        ));
    }
    let bundles: HashMap<&str, Result<SignedBundle>> = members
        .iter()
        .map(|m| {
            let bundle = match (&m.bundle, &m.bundle_signature) {
                (Some(b), Some(s)) => SignedBundle::parse(b, s),
                _ => Err(invalid("no published keys")),
            };
            (m.account_id.as_str(), bundle)
        })
        .collect();

    let owner_bundle = match bundles.get(root.owner_id.as_str()) {
        Some(Ok(bundle)) if bundle.hash() == root.owner_bundle_hash => bundle.clone(),
        _ => {
            return Err(invalid(
                "the owner's key does not match the organization genesis",
            ));
        }
    };
    genesis
        .verify(&owner_bundle.bundle.sig_pk)
        .map_err(|_| invalid("the organization genesis is not signed by its owner"))?;

    let owner_record = members.iter().find(|m| m.account_id == root.owner_id);
    let mut verified = BTreeMap::new();
    verified.insert(
        root.owner_id.clone(),
        VerifiedMember {
            account_id: root.owner_id.clone(),
            role: OrgRole::Owner,
            status: owner_record.map_or_else(|| "confirmed".to_owned(), |m| m.status.clone()),
            email: owner_record.and_then(|m| m.email.clone()),
            bundle: owner_bundle,
            attested_by: None,
        },
    );

    // Attestations chain from the owner through admins; iterate until no
    // more members can be verified.
    let mut reasons: HashMap<String, String> = HashMap::new();
    loop {
        let mut progress = false;
        for member in members {
            if verified.contains_key(&member.account_id) {
                continue;
            }
            match verify_member(org_id, member, &bundles, &verified) {
                Ok(v) => {
                    reasons.remove(&member.account_id);
                    verified.insert(member.account_id.clone(), v);
                    progress = true;
                }
                Err(reason) => {
                    reasons.insert(member.account_id.clone(), reason);
                }
            }
        }
        if !progress {
            break;
        }
    }

    let unverified = members
        .iter()
        .filter(|m| !verified.contains_key(&m.account_id))
        .map(|m| {
            (
                m.account_id.clone(),
                UnverifiedMember {
                    account_id: m.account_id.clone(),
                    role: m.role.clone(),
                    status: m.status.clone(),
                    email: m.email.clone(),
                    bundle: bundles
                        .get(m.account_id.as_str())
                        .and_then(|b| b.as_ref().ok().cloned()),
                    reason: reasons
                        .get(&m.account_id)
                        .cloned()
                        .unwrap_or_else(|| "not verified".into()),
                },
            )
        })
        .collect();

    Ok(Roster {
        org_id: org_id.to_owned(),
        kind: root.kind,
        owner_id: root.owner_id.clone(),
        root_hash: genesis.hash(),
        members: verified,
        unverified,
    })
}

fn verify_member(
    org_id: &str,
    member: &RosterMember,
    bundles: &HashMap<&str, Result<SignedBundle>>,
    verified: &BTreeMap<String, VerifiedMember>,
) -> core::result::Result<VerifiedMember, String> {
    let bundle = match bundles.get(member.account_id.as_str()) {
        Some(Ok(bundle)) => bundle.clone(),
        Some(Err(e)) => return Err(format!("invalid keys: {e}")),
        None => return Err("no published keys".into()),
    };
    let (Some(attestation), Some(signature)) = (&member.attestation, &member.attestation_signature)
    else {
        return Err("not confirmed by an admin yet".into());
    };
    let attestation = Signed::<MemberAttestation>::parse(attestation, signature)
        .map_err(|e| format!("invalid attestation: {e}"))?;
    let a = &attestation.value;
    let Some(attester) = verified
        .get(&a.attester_id)
        .filter(|m| m.role.is_admin() && m.status == "confirmed")
    else {
        return Err("attested by someone who is not a verified admin".into());
    };
    if a.org_id != org_id
        || a.account_id != member.account_id
        || a.key_version != bundle.bundle.key_version
        || a.bundle_hash != bundle.hash()
    {
        return Err("the attestation does not match the member's key".into());
    }
    if a.role == OrgRole::Owner {
        return Err("only the creator of an organization is its owner".into());
    }
    attestation
        .verify(&attester.bundle.bundle.sig_pk)
        .map_err(|_| "the attestation signature is invalid".to_owned())?;
    Ok(VerifiedMember {
        account_id: member.account_id.clone(),
        role: a.role,
        status: member.status.clone(),
        email: member.email.clone(),
        bundle,
        attested_by: Some(a.attester_id.clone()),
    })
}

/// Verifies an organization key grant for `account`.
pub fn verify_org_key_grant(
    roster: &Roster,
    grant: &Signed<OrgKeyGrant>,
    account: &SignedBundle,
    sealed: &[u8],
) -> Result<()> {
    let g = &grant.value;
    let granter = roster
        .admin(&g.granter_id)
        .ok_or_else(|| invalid("organization key granted by someone who is not an admin"))?;
    grant.verify(&granter.bundle.bundle.sig_pk)?;
    if g.org_id != roster.org_id
        || g.account_id != account.bundle.account_id
        || g.account_bundle_hash != account.hash()
        || g.sealed_hash != sealed_hash(sealed)
    {
        return Err(invalid("organization key grant does not match"));
    }
    Ok(())
}

/// Verifies a group bundle: created or rotated by an admin of its
/// organization.
pub fn verify_group_bundle(roster: &Roster, bundle: &Signed<GroupBundle>) -> Result<()> {
    let b = &bundle.value;
    if b.org_id != roster.org_id {
        return Err(invalid("group belongs to another organization"));
    }
    let creator = roster
        .admin(&b.creator_id)
        .ok_or_else(|| invalid("group key created by someone who is not an admin"))?;
    bundle.verify(&creator.bundle.bundle.sig_pk)
}

/// Verifies a group key grant (without the sealed key when `sealed` is
/// `None`, for checking another member's grant).
pub fn verify_group_grant(
    roster: &Roster,
    group: &Signed<GroupBundle>,
    grant: &Signed<GroupKeyGrant>,
    sealed: Option<&[u8]>,
) -> Result<()> {
    let g = &grant.value;
    let granter = roster
        .admin(&g.granter_id)
        .ok_or_else(|| invalid("group key granted by someone who is not an admin"))?;
    grant.verify(&granter.bundle.bundle.sig_pk)?;
    let member = roster
        .members
        .get(&g.account_id)
        .ok_or_else(|| invalid("group member is not a verified organization member"))?;
    if g.group_id != group.value.group_id
        || g.org_id != roster.org_id
        || g.key_version != group.value.key_version
        || g.account_bundle_hash != member.bundle.hash()
        || sealed.is_some_and(|s| g.sealed_hash != sealed_hash(s))
    {
        return Err(invalid("group key grant does not match"));
    }
    Ok(())
}

/// One verified manifest version.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    pub manifest: VaultManifest,
    pub hash: [u8; HASH_LEN],
    pub signer: SignedBundle,
}

/// The result of verifying a vault's manifest chain.
#[derive(Debug, Clone)]
pub struct VerifiedChain {
    /// The verified versions by version number. The latest version is
    /// always among them.
    pub verified: BTreeMap<u64, VerifiedManifest>,
    pub latest_version: u64,
}

impl VerifiedChain {
    pub fn latest(&self) -> &VerifiedManifest {
        &self.verified[&self.latest_version]
    }
}

/// Verifies the full manifest chain of a vault.
///
/// - Versions are consecutive from 1, each `prev_hash` is the hash of its
///   predecessor, and the pinned version (if any) is in the chain with the
///   pinned hash (no rollback, no fork).
/// - A version is verified if it is signed by an active admin of the
///   organization (an anchor), or by a `manage` member of the verified
///   previous version whose key matches that version's entry.
/// - The latest version must be verified.
pub fn verify_manifest_chain(
    vault_id: &str,
    roster: &Roster,
    chain: &[Signed<VaultManifest>],
    signers: &[BundleRecord],
    pinned: Option<(u64, [u8; HASH_LEN])>,
) -> Result<VerifiedChain> {
    if chain.is_empty() {
        return Err(invalid("the vault has no manifest"));
    }
    let signer_bundles: HashMap<[u8; HASH_LEN], SignedBundle> = signers
        .iter()
        .filter_map(|s| SignedBundle::parse(&s.bundle, &s.bundle_signature).ok())
        .map(|b| (b.hash(), b))
        .collect();

    let mut prev_hash = [0u8; HASH_LEN];
    for (i, signed) in chain.iter().enumerate() {
        let m = &signed.value;
        if m.version != i as u64 + 1 {
            return Err(invalid("manifest versions are not consecutive"));
        }
        if m.vault_id != vault_id || m.org_id != roster.org_id {
            return Err(invalid("manifest belongs to another vault"));
        }
        if m.prev_hash != prev_hash {
            return Err(invalid("manifest chain is broken"));
        }
        if i > 0 && m.key_epoch < chain[i - 1].value.key_epoch {
            return Err(invalid("manifest key epoch went backwards"));
        }
        prev_hash = signed.hash();
    }
    let latest_version = chain.len() as u64;
    if let Some((version, hash)) = pinned {
        if version > latest_version {
            return Err(invalid(
                "the server shows an older member list than before (rollback)",
            ));
        }
        if chain[version as usize - 1].hash() != hash {
            return Err(invalid("the vault's member list history was rewritten"));
        }
    }

    let mut verified: BTreeMap<u64, VerifiedManifest> = BTreeMap::new();
    for (i, signed) in chain.iter().enumerate() {
        let m = &signed.value;
        let anchored = roster
            .admin(&m.signer_id)
            .filter(|admin| signed.verify(&admin.bundle.bundle.sig_pk).is_ok())
            .map(|admin| admin.bundle.clone());
        let chained = || -> Option<SignedBundle> {
            let previous = verified.get(&(i as u64))?;
            let entry = previous
                .manifest
                .entry(PrincipalType::Account, &m.signer_id)
                .filter(|e| e.role == VaultRole::Manage)?;
            let bundle = roster
                .members
                .get(&m.signer_id)
                .map(|member| &member.bundle)
                .filter(|b| b.hash() == entry.key_hash)
                .or_else(|| signer_bundles.get(&entry.key_hash))?;
            (bundle.bundle.account_id == m.signer_id
                && signed.verify(&bundle.bundle.sig_pk).is_ok())
            .then(|| bundle.clone())
        };
        if let Some(signer) = anchored.or_else(chained) {
            verified.insert(
                m.version,
                VerifiedManifest {
                    manifest: m.clone(),
                    hash: signed.hash(),
                    signer,
                },
            );
        }
    }
    if !verified.contains_key(&latest_version) {
        return Err(invalid(
            "the vault's member list is not signed by a manager or admin",
        ));
    }
    Ok(VerifiedChain {
        verified,
        latest_version,
    })
}

/// Verifies a vault key grant against the verified manifest chain:
/// the grant names a verified manifest version with the same key epoch,
/// is signed by that version's signer, matches that version's entry for
/// the principal, covers exactly these sealed bytes and is addressed to
/// `principal_key_hash`.
pub fn verify_vault_grant(
    chain: &VerifiedChain,
    grant: &Signed<VaultGrant>,
    principal_key_hash: &[u8; HASH_LEN],
    sealed: &[u8],
) -> Result<()> {
    let g = &grant.value;
    let version = chain
        .verified
        .get(&g.manifest_version)
        .ok_or_else(|| invalid("vault grant refers to an unverified member list"))?;
    let m = &version.manifest;
    if g.granter_id != m.signer_id {
        return Err(invalid(
            "vault grant was not issued by the member list's signer",
        ));
    }
    grant.verify(&version.signer.bundle.sig_pk)?;
    let entry = m
        .entry(g.principal_type, &g.principal_id)
        .ok_or_else(|| invalid("vault grant is not backed by the member list"))?;
    if g.vault_id != m.vault_id
        || g.org_id != m.org_id
        || g.key_epoch != m.key_epoch
        || entry.role != g.role
        || entry.key_hash != g.principal_key_hash
        || g.principal_key_hash != *principal_key_hash
        || g.sealed_hash != sealed_hash(sealed)
    {
        return Err(invalid("vault grant does not match"));
    }
    Ok(())
}
