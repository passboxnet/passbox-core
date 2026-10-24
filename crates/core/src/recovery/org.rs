//! Recovery through an organization or family (wave C1).
//!
//! ```text
//! recovery bundle = { org_id, key_version, enc_pk, creator_id, created_at }   signed by an admin
//! recovery grant  = { org_id, key_version, account_id, account_bundle_hash,
//!                     sealed_hash, granter_id, granted_at }                    signed by an admin
//!   sealed: recovery private seed, purpose "org-recovery-key"
//! escrow          = { org_id, account_id, account_bundle_hash, key_version,
//!                     recovery_bundle_hash, sealed_hash, created_at }          signed by the member
//!   sealed: the member's account key, purpose "recovery-escrow"
//! approval        = { request_id, org_id, account_id, ephemeral_key_hash,
//!                     sealed_hash, approver_id, approved_at }                  signed by the approving admin
//!   sealed: the account key for the requesting device's ephemeral key, purpose "recovery-transfer"
//! ```
//!
//! Members verify the recovery bundle against the organization's verified
//! roster (signed by a verified admin) before they escrow their account
//! key. Admins verify escrows against the member's verified key. The
//! requesting device shows a [`request_code`] derived from its ephemeral
//! key, which the admin compares out of band before approving: otherwise a
//! malicious server could swap in its own ephemeral key.
//!
//! The approving admin's client holds the member's account key in memory
//! while it re-seals it. That is inherent to admin recovery and documented.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::ephemeral_key_hash;
use crate::canon::{Reader, Writer};
use crate::identity::{self, EncryptionKey, HASH_LEN, SignedBundle, sealed_hash};
use crate::keyring::{Keyring, key_from_plaintext};
use crate::sharing::objects::{Canonical, Signed, short_fingerprint};
use crate::sharing::verify::Roster;
use crate::{Error, Result, encoding};

pub const PURPOSE_RECOVERY_KEY: &str = "org-recovery-key";
pub const PURPOSE_ESCROW: &str = "recovery-escrow";
pub const PURPOSE_TRANSFER: &str = "recovery-transfer";

fn denied(message: impl Into<String>) -> Error {
    Error::InvalidData(message.into())
}

fn recovery_key_context(org_id: &str, key_version: u32, account_id: &str) -> Vec<u8> {
    Writer::new("passbox/v1/seal-context/org-recovery-key")
        .str(org_id)
        .u64(u64::from(key_version))
        .str(account_id)
        .finish()
}

fn escrow_context(org_id: &str, account_id: &str, key_version: u32) -> Vec<u8> {
    Writer::new("passbox/v1/seal-context/recovery-escrow")
        .str(org_id)
        .str(account_id)
        .u64(u64::from(key_version))
        .finish()
}

fn transfer_context(request_id: &str, account_id: &str) -> Vec<u8> {
    Writer::new("passbox/v1/seal-context/recovery-transfer")
        .str(request_id)
        .str(account_id)
        .finish()
}

// --- Objects ----------------------------------------------------------------------

/// The organization's recovery public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryKeyBundle {
    pub org_id: String,
    pub key_version: u32,
    pub enc_pk: Vec<u8>,
    pub creator_id: String,
    pub created_at: i64,
}

impl Canonical for RecoveryKeyBundle {
    const TAG: &'static str = "passbox/v1/org-recovery-bundle";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.org_id)
            .u64(u64::from(self.key_version))
            .bytes(&self.enc_pk)
            .str(&self.creator_id)
            .i64(self.created_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let bundle = Self {
            org_id: r.string()?,
            key_version: r.u32()?,
            enc_pk: r.bytes()?.to_vec(),
            creator_id: r.string()?,
            created_at: r.i64()?,
        };
        if bundle.enc_pk.len() != identity::ENC_PK_LEN || bundle.key_version == 0 {
            return Err(Error::InvalidData("invalid recovery public key".into()));
        }
        Ok(bundle)
    }
}

/// The recovery private key sealed for one admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryKeyGrant {
    pub org_id: String,
    pub key_version: u32,
    pub account_id: String,
    pub account_bundle_hash: [u8; HASH_LEN],
    pub sealed_hash: [u8; HASH_LEN],
    pub granter_id: String,
    pub granted_at: i64,
}

impl Canonical for RecoveryKeyGrant {
    const TAG: &'static str = "passbox/v1/org-recovery-grant";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.org_id)
            .u64(u64::from(self.key_version))
            .str(&self.account_id)
            .bytes(&self.account_bundle_hash)
            .bytes(&self.sealed_hash)
            .str(&self.granter_id)
            .i64(self.granted_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
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

/// A member's account key sealed to the organization's recovery key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEscrow {
    pub org_id: String,
    pub account_id: String,
    pub account_bundle_hash: [u8; HASH_LEN],
    pub key_version: u32,
    pub recovery_bundle_hash: [u8; HASH_LEN],
    pub sealed_hash: [u8; HASH_LEN],
    pub created_at: i64,
}

impl Canonical for RecoveryEscrow {
    const TAG: &'static str = "passbox/v1/recovery-escrow";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.org_id)
            .str(&self.account_id)
            .bytes(&self.account_bundle_hash)
            .u64(u64::from(self.key_version))
            .bytes(&self.recovery_bundle_hash)
            .bytes(&self.sealed_hash)
            .i64(self.created_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            org_id: r.string()?,
            account_id: r.string()?,
            account_bundle_hash: r.array()?,
            key_version: r.u32()?,
            recovery_bundle_hash: r.array()?,
            sealed_hash: r.array()?,
            created_at: r.i64()?,
        })
    }
}

/// An admin's approval of a recovery request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryApproval {
    pub request_id: String,
    pub org_id: String,
    pub account_id: String,
    pub ephemeral_key_hash: [u8; HASH_LEN],
    pub sealed_hash: [u8; HASH_LEN],
    pub approver_id: String,
    pub approved_at: i64,
}

impl Canonical for RecoveryApproval {
    const TAG: &'static str = "passbox/v1/recovery-approval";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.request_id)
            .str(&self.org_id)
            .str(&self.account_id)
            .bytes(&self.ephemeral_key_hash)
            .bytes(&self.sealed_hash)
            .str(&self.approver_id)
            .i64(self.approved_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            request_id: r.string()?,
            org_id: r.string()?,
            account_id: r.string()?,
            ephemeral_key_hash: r.array()?,
            sealed_hash: r.array()?,
            approver_id: r.string()?,
            approved_at: r.i64()?,
        })
    }
}

// --- Server data and uploads --------------------------------------------------------

/// `GET /api/v1/orgs/{id}/recovery`: the current recovery key and its grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgRecoveryRecord {
    pub key_version: u32,
    pub bundle: String,
    pub bundle_signature: String,
    #[serde(default)]
    pub grants: Vec<RecoveryGrantRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryGrantRecord {
    pub account_id: String,
    pub key_version: u32,
    pub grant: String,
    pub grant_signature: String,
    /// Only delivered to the admin the grant is for.
    #[serde(default)]
    pub sealed_key: Option<String>,
}

/// A pending request as an admin sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRequestRecord {
    pub id: String,
    pub org_id: String,
    pub account_id: String,
    /// The requesting device's ephemeral X-Wing public key (Base64url).
    pub ephemeral_key: String,
    pub key_version: u32,
    pub escrow: String,
    pub escrow_signature: String,
    pub sealed_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryGrantUpload {
    pub account_id: String,
    pub key_version: u32,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
}

/// `POST /api/v1/orgs/{id}/recovery/keys` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgRecoveryKeyUpload {
    pub key_version: u32,
    pub bundle: String,
    pub bundle_signature: String,
    pub grant: RecoveryGrantUpload,
}

/// `PUT /api/v1/orgs/{id}/recovery/escrow` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryEscrowUpload {
    pub key_version: u32,
    pub escrow: String,
    pub escrow_signature: String,
    pub sealed_key: String,
}

/// `POST /api/v1/orgs/{id}/recovery/requests/{rid}/approve` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryApprovalUpload {
    pub approval: String,
    pub approval_signature: String,
    pub sealed_key: String,
    /// The code the admin compared with the member (for the audit log).
    pub request_code: String,
}

/// The verified state of an organization's recovery key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgRecoveryInfo {
    pub org_id: String,
    pub key_version: u32,
    /// Fingerprint of the recovery key (8 groups of five digits).
    pub fingerprint: String,
    /// The account that created the key.
    pub creator_id: String,
    /// Verified admins who hold the recovery key.
    pub admins: Vec<String>,
    /// This account holds the key and can approve requests.
    pub can_approve: bool,
}

// --- Verification -------------------------------------------------------------------

struct VerifiedRecovery {
    bundle: Signed<RecoveryKeyBundle>,
    admins: Vec<String>,
    own_grant: Option<(Signed<RecoveryKeyGrant>, Vec<u8>)>,
}

fn verify_record(
    roster: &Roster,
    org_id: &str,
    record: &OrgRecoveryRecord,
    own_id: &str,
) -> Result<VerifiedRecovery> {
    let bundle = Signed::<RecoveryKeyBundle>::parse(&record.bundle, &record.bundle_signature)?;
    if bundle.value.org_id != org_id || bundle.value.key_version != record.key_version {
        return Err(denied(
            "the recovery key belongs to another organization or version",
        ));
    }
    let creator = roster
        .admin(&bundle.value.creator_id)
        .ok_or_else(|| denied("the recovery key was not created by a verified owner or admin"))?;
    bundle.verify(&creator.bundle.bundle.sig_pk)?;
    let mut admins = Vec::new();
    let mut own_grant = None;
    for record_grant in &record.grants {
        let Ok(grant) =
            Signed::<RecoveryKeyGrant>::parse(&record_grant.grant, &record_grant.grant_signature)
        else {
            continue;
        };
        let g = &grant.value;
        let Some(holder) = roster.admin(&g.account_id) else {
            continue;
        };
        let Some(granter) = roster.admin(&g.granter_id) else {
            continue;
        };
        if g.org_id != org_id
            || g.key_version != record.key_version
            || g.account_id != record_grant.account_id
            || holder.bundle.hash() != g.account_bundle_hash
            || grant.verify(&granter.bundle.bundle.sig_pk).is_err()
        {
            continue;
        }
        if g.account_id == own_id
            && let Some(sealed) = &record_grant.sealed_key
            && let Ok(sealed) = encoding::decode(sealed)
            && sealed_hash(&sealed) == g.sealed_hash
        {
            own_grant = Some((grant.clone(), sealed));
        }
        if !admins.contains(&g.account_id) {
            admins.push(g.account_id.clone());
        }
    }
    admins.sort();
    Ok(VerifiedRecovery {
        bundle,
        admins,
        own_grant,
    })
}

/// The short code a requesting device shows and the approving admin
/// compares: 4 groups of five digits (about 66 bits) derived from the
/// ephemeral key alone, so a server cannot cheaply find another key with
/// the same code.
pub fn request_code(ephemeral_pk: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"passbox/v1/recovery-request-code\0");
    hasher.update(ephemeral_pk);
    let hash = hasher.finalize();
    (0..4)
        .map(|i| {
            let chunk = &hash[i * 5..i * 5 + 5];
            let value = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl Keyring {
    fn recovery_roster(&self, org_id: &str) -> Result<&Roster> {
        self.sharing
            .rosters
            .get(org_id)
            .ok_or_else(|| denied("the organization is unknown or could not be verified"))
    }

    fn open_recovery_key(
        &self,
        org_id: &str,
        verified: &VerifiedRecovery,
    ) -> Result<EncryptionKey> {
        let (grant, sealed) = verified
            .own_grant
            .as_ref()
            .ok_or_else(|| denied("this account does not hold the recovery key"))?;
        let own = self.account_keys()?;
        if own.bundle.hash() != grant.value.account_bundle_hash {
            return Err(denied("the recovery key was sealed for an older key"));
        }
        let seed = own.enc.open(
            &own.bundle.hash(),
            PURPOSE_RECOVERY_KEY,
            &recovery_key_context(org_id, grant.value.key_version, &self.account_id),
            sealed,
        )?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| denied("recovery key has the wrong length"))?,
        );
        let key = EncryptionKey::from_seed(&seed);
        if key.public_key() != verified.bundle.value.enc_pk {
            return Err(denied(
                "the sealed recovery key does not match its public key",
            ));
        }
        Ok(key)
    }

    fn seal_recovery_grant(
        &self,
        org_id: &str,
        key_version: u32,
        recovery_seed: &[u8; 32],
        account_id: &str,
        now: i64,
    ) -> Result<RecoveryGrantUpload> {
        let roster = self.recovery_roster(org_id)?;
        let holder = roster.admin(account_id).ok_or_else(|| {
            denied(format!(
                "{account_id} is not a confirmed, verified owner or admin"
            ))
        })?;
        if let Some(pin) = self.sharing.trust.pins.get(account_id)
            && pin.bundle_hash != encoding::encode(&holder.bundle.hash())
        {
            return Err(Error::KeyChanged(account_id.to_owned()));
        }
        let sealed = holder.bundle.seal(
            PURPOSE_RECOVERY_KEY,
            &recovery_key_context(org_id, key_version, account_id),
            recovery_seed,
        )?;
        let grant = Signed::sign(
            RecoveryKeyGrant {
                org_id: org_id.to_owned(),
                key_version,
                account_id: account_id.to_owned(),
                account_bundle_hash: holder.bundle.hash(),
                sealed_hash: sealed_hash(&sealed),
                granter_id: self.account_id.clone(),
                granted_at: now,
            },
            &self.account_keys()?.sig,
        );
        Ok(RecoveryGrantUpload {
            account_id: account_id.to_owned(),
            key_version,
            sealed_key: encoding::encode(&sealed),
            grant: grant.encoded(),
            grant_signature: grant.encoded_signature(),
        })
    }

    /// Creates the organization's recovery key pair (owner or admin) with
    /// `key_version` (1 for the first key) and seals it for this account.
    pub fn create_org_recovery_key(
        &self,
        org_id: &str,
        key_version: u32,
        now: i64,
    ) -> Result<OrgRecoveryKeyUpload> {
        let roster = self.recovery_roster(org_id)?;
        if roster.admin(&self.account_id).is_none() {
            return Err(denied(
                "only owners and admins can set up organization recovery",
            ));
        }
        if key_version == 0 {
            return Err(denied("key versions start at 1"));
        }
        let key = EncryptionKey::generate()?;
        let bundle = Signed::sign(
            RecoveryKeyBundle {
                org_id: org_id.to_owned(),
                key_version,
                enc_pk: key.public_key(),
                creator_id: self.account_id.clone(),
                created_at: now,
            },
            &self.account_keys()?.sig,
        );
        let grant =
            self.seal_recovery_grant(org_id, key_version, key.seed(), &self.account_id, now)?;
        Ok(OrgRecoveryKeyUpload {
            key_version,
            bundle: bundle.encoded(),
            bundle_signature: bundle.encoded_signature(),
            grant,
        })
    }

    /// Verifies an organization's recovery key against the verified roster.
    pub fn verify_org_recovery(
        &self,
        org_id: &str,
        record: &OrgRecoveryRecord,
    ) -> Result<OrgRecoveryInfo> {
        let roster = self.recovery_roster(org_id)?;
        let verified = verify_record(roster, org_id, record, &self.account_id)?;
        let can_approve = self.open_recovery_key(org_id, &verified).is_ok();
        Ok(OrgRecoveryInfo {
            org_id: org_id.to_owned(),
            key_version: record.key_version,
            fingerprint: short_fingerprint(&verified.bundle.hash()),
            creator_id: verified.bundle.value.creator_id.clone(),
            admins: verified.admins,
            can_approve,
        })
    }

    /// Lets another verified admin approve recovery requests: seals the
    /// recovery key (which this account holds) for them.
    pub fn grant_org_recovery(
        &self,
        org_id: &str,
        record: &OrgRecoveryRecord,
        admin_id: &str,
        now: i64,
    ) -> Result<RecoveryGrantUpload> {
        let roster = self.recovery_roster(org_id)?;
        let verified = verify_record(roster, org_id, record, &self.account_id)?;
        let key = self.open_recovery_key(org_id, &verified)?;
        self.seal_recovery_grant(org_id, record.key_version, key.seed(), admin_id, now)
    }

    /// Escrows this account's key with the organization (opt-in): seals it
    /// to the verified recovery key and signs the escrow.
    pub fn enroll_org_recovery(
        &self,
        org_id: &str,
        record: &OrgRecoveryRecord,
        now: i64,
    ) -> Result<RecoveryEscrowUpload> {
        let roster = self.recovery_roster(org_id)?;
        if roster.active(&self.account_id).is_none() {
            return Err(denied("only confirmed members can turn on recovery"));
        }
        let verified = verify_record(roster, org_id, record, &self.account_id)?;
        let own = self.account_keys()?;
        let bundle_hash = verified.bundle.hash();
        let sealed = identity::seal(
            &verified.bundle.value.enc_pk,
            &bundle_hash,
            PURPOSE_ESCROW,
            &escrow_context(org_id, &self.account_id, record.key_version),
            self.account_key().as_bytes(),
        )?;
        let escrow = Signed::sign(
            RecoveryEscrow {
                org_id: org_id.to_owned(),
                account_id: self.account_id.clone(),
                account_bundle_hash: own.bundle.hash(),
                key_version: record.key_version,
                recovery_bundle_hash: bundle_hash,
                sealed_hash: sealed_hash(&sealed),
                created_at: now,
            },
            &own.sig,
        );
        Ok(RecoveryEscrowUpload {
            key_version: record.key_version,
            escrow: escrow.encoded(),
            escrow_signature: escrow.encoded_signature(),
            sealed_key: encoding::encode(&sealed),
        })
    }

    /// Approves a recovery request: verifies the member's escrow, opens it
    /// with the recovery key and re-seals the account key for the requesting
    /// device's ephemeral key. Call only after verifying the member's
    /// identity out of band and comparing [`request_code`] with them.
    ///
    /// The member's account key is in this process's memory until the
    /// function returns.
    pub fn approve_org_recovery(
        &self,
        record: &OrgRecoveryRecord,
        request: &RecoveryRequestRecord,
        now: i64,
    ) -> Result<RecoveryApprovalUpload> {
        let org_id = request.org_id.as_str();
        let roster = self.recovery_roster(org_id)?;
        if roster.admin(&self.account_id).is_none() {
            return Err(denied("only owners and admins approve recovery requests"));
        }
        let verified = verify_record(roster, org_id, record, &self.account_id)?;
        let recovery_key = self.open_recovery_key(org_id, &verified)?;

        let escrow = Signed::<RecoveryEscrow>::parse(&request.escrow, &request.escrow_signature)?;
        let member = roster
            .members
            .get(&request.account_id)
            .ok_or_else(|| denied("the member's key is not verified in this organization"))?;
        let e = &escrow.value;
        let sealed_escrow = encoding::decode(&request.sealed_key)?;
        if e.org_id != org_id
            || e.account_id != request.account_id
            || e.key_version != record.key_version
            || request.key_version != record.key_version
            || e.recovery_bundle_hash != verified.bundle.hash()
            || e.account_bundle_hash != member.bundle.hash()
            || e.sealed_hash != sealed_hash(&sealed_escrow)
        {
            return Err(denied("the escrow does not match the request"));
        }
        escrow.verify(&member.bundle.bundle.sig_pk)?;
        let account_key = recovery_key.open(
            &verified.bundle.hash(),
            PURPOSE_ESCROW,
            &escrow_context(org_id, &request.account_id, record.key_version),
            &sealed_escrow,
        )?;
        if account_key.len() != 32 {
            return Err(denied("the escrowed key has the wrong length"));
        }

        let ephemeral = encoding::decode(&request.ephemeral_key)?;
        let ephemeral_hash = ephemeral_key_hash(&ephemeral);
        let sealed = identity::seal(
            &ephemeral,
            &ephemeral_hash,
            PURPOSE_TRANSFER,
            &transfer_context(&request.id, &request.account_id),
            &account_key,
        )?;
        drop(account_key);
        let approval = Signed::sign(
            RecoveryApproval {
                request_id: request.id.clone(),
                org_id: org_id.to_owned(),
                account_id: request.account_id.clone(),
                ephemeral_key_hash: ephemeral_hash,
                sealed_hash: sealed_hash(&sealed),
                approver_id: self.account_id.clone(),
                approved_at: now,
            },
            &self.account_keys()?.sig,
        );
        Ok(RecoveryApprovalUpload {
            approval: approval.encoded(),
            approval_signature: approval.encoded_signature(),
            sealed_key: encoding::encode(&sealed),
            request_code: request_code(&ephemeral),
        })
    }
}

// --- The requesting device ------------------------------------------------------------

/// The ephemeral key pair of a device that requested recovery. Keep it
/// until the request is approved (its seed can be persisted on the device
/// with [`RecoveryRequestKey::seed`]); it is useless after the request
/// expires.
pub struct RecoveryRequestKey {
    key: EncryptionKey,
}

impl core::fmt::Debug for RecoveryRequestKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryRequestKey(<redacted>)")
    }
}

/// What the server returns for an approved request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedRecovery {
    pub request_id: String,
    pub account_id: String,
    pub approval: String,
    pub approval_signature: String,
    pub sealed_key: String,
    /// The approving admin's public bundle.
    pub approver_bundle: String,
    pub approver_bundle_signature: String,
}

impl RecoveryRequestKey {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            key: EncryptionKey::generate()?,
        })
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: EncryptionKey::from_seed(seed),
        }
    }

    pub fn seed(&self) -> &[u8; 32] {
        self.key.seed()
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    /// The code to read to the approving admin.
    pub fn request_code(&self) -> String {
        request_code(&self.public_key())
    }

    /// Opens the account key from an approval. Checks that the approval
    /// names this request, account and key, covers the sealed bytes and is
    /// signed by the approver's (self-signed) bundle. Callers must then
    /// check that the account key opens the account's own key pairs
    /// ([`Keyring::load_account_keys`]), which proves it is the real key.
    pub fn open(&self, approved: &ApprovedRecovery) -> Result<Keyring> {
        let approval =
            Signed::<RecoveryApproval>::parse(&approved.approval, &approved.approval_signature)?;
        let approver = SignedBundle::parse(
            &approved.approver_bundle,
            &approved.approver_bundle_signature,
        )?;
        let sealed = encoding::decode(&approved.sealed_key)?;
        let public_key = self.public_key();
        let a = &approval.value;
        if a.request_id != approved.request_id
            || a.account_id != approved.account_id
            || a.ephemeral_key_hash != ephemeral_key_hash(&public_key)
            || a.sealed_hash != sealed_hash(&sealed)
            || approver.bundle.account_id != a.approver_id
        {
            return Err(denied("the approval does not match this request"));
        }
        approval.verify(&approver.bundle.sig_pk)?;
        let plaintext = self.key.open(
            &ephemeral_key_hash(&public_key),
            PURPOSE_TRANSFER,
            &transfer_context(&approved.request_id, &approved.account_id),
            &sealed,
        )?;
        let key = key_from_plaintext(plaintext.to_vec())?;
        Ok(Keyring::from_account_key(&approved.account_id, key))
    }
}

#[cfg(test)]
mod tests;
