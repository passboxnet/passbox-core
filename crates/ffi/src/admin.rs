//! Organization policies and the audit log (additive API, wave D). See
//! `docs/architecture/administration.md`.
//!
//! Policies are signed by an owner or admin and verified by the Rust core
//! during `sync`; apps read the result with `effective_policy` and enforce
//! it (two-factor sign-in, master password strength when it is entered,
//! auto-lock limit, export, sharing outside the organization, personal
//! vaults, share links). `verify_audit_chain` checks an exported audit log.

use passbox_core::audit;
use passbox_core::policy::{self, ShareLinkRule};

use crate::{PassboxClient, Result};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PolicyRules {
    pub require_two_factor: bool,
    /// 0–4, 0 = no requirement.
    pub min_password_score: u8,
    /// 0 = no limit.
    pub max_auto_lock_minutes: u32,
    pub forbid_export: bool,
    pub forbid_external_sharing: bool,
    /// `allowed`, `restricted` or `forbidden`.
    pub share_links: String,
    pub share_link_max_days: u32,
    pub share_link_max_views: u32,
    pub require_recovery_enrollment: bool,
    pub allow_personal_vault: bool,
    pub report_item_usage: bool,
}

impl From<policy::PolicyRules> for PolicyRules {
    fn from(r: policy::PolicyRules) -> Self {
        Self {
            require_two_factor: r.require_two_factor,
            min_password_score: r.min_password_score,
            max_auto_lock_minutes: r.max_auto_lock_minutes,
            forbid_export: r.forbid_export,
            forbid_external_sharing: r.forbid_external_sharing,
            share_links: r.share_links.as_str().to_owned(),
            share_link_max_days: r.share_link_max_days,
            share_link_max_views: r.share_link_max_views,
            require_recovery_enrollment: r.require_recovery_enrollment,
            allow_personal_vault: r.allow_personal_vault,
            report_item_usage: r.report_item_usage,
        }
    }
}

impl TryFrom<PolicyRules> for policy::PolicyRules {
    type Error = passbox_core::Error;
    fn try_from(r: PolicyRules) -> passbox_core::Result<Self> {
        Ok(Self {
            require_two_factor: r.require_two_factor,
            min_password_score: r.min_password_score,
            max_auto_lock_minutes: r.max_auto_lock_minutes,
            forbid_export: r.forbid_export,
            forbid_external_sharing: r.forbid_external_sharing,
            share_links: ShareLinkRule::parse(&r.share_links)?,
            share_link_max_days: r.share_link_max_days,
            share_link_max_views: r.share_link_max_views,
            require_recovery_enrollment: r.require_recovery_enrollment,
            allow_personal_vault: r.allow_personal_vault,
            report_item_usage: r.report_item_usage,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgPolicy {
    pub org_id: String,
    pub version: u64,
    pub rules: PolicyRules,
    /// Rules this app does not know yet (ask the user to update).
    pub unknown_rules: Vec<String>,
    pub signer_id: String,
    pub signed_at: i64,
    /// `verified` or `pinned` (the server's copy was missing, older or invalid).
    pub source: String,
    /// The signer is no longer an admin; an admin should sign it again.
    pub needs_resign: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EffectivePolicy {
    pub require_two_factor: bool,
    pub min_password_score: u8,
    /// `None` without a limit.
    pub max_auto_lock_minutes: Option<u32>,
    pub allow_personal_vault: bool,
    pub recovery_enrollment_orgs: Vec<String>,
    pub export_blocked_orgs: Vec<String>,
    pub external_sharing_blocked_orgs: Vec<String>,
    pub item_usage_orgs: Vec<String>,
    pub has_unknown_rules: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditChainCheck {
    pub valid: bool,
    pub length: u64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub head_hash: Option<String>,
    pub broken_at: Option<u64>,
    pub problem: Option<String>,
}

#[uniffi::export]
impl PassboxClient {
    /// The policies in force per organization (after the last sync).
    pub fn org_policies(&self) -> Result<Vec<OrgPolicy>> {
        Ok(self
            .inner
            .org_policies()?
            .into_iter()
            .map(|p| OrgPolicy {
                org_id: p.org_id,
                version: p.version,
                rules: p.rules.into(),
                unknown_rules: p.unknown_rules,
                signer_id: p.signer_id,
                signed_at: p.signed_at,
                source: p.source,
                needs_resign: p.needs_resign,
            })
            .collect())
    }

    /// The combination of every policy this account is bound by.
    pub fn effective_policy(&self) -> Result<EffectivePolicy> {
        let e = self.inner.effective_policy()?;
        Ok(EffectivePolicy {
            require_two_factor: e.require_two_factor,
            min_password_score: e.min_password_score,
            max_auto_lock_minutes: e.max_auto_lock_minutes,
            allow_personal_vault: e.allow_personal_vault,
            recovery_enrollment_orgs: e.recovery_enrollment_orgs,
            export_blocked_orgs: e.export_blocked_orgs,
            external_sharing_blocked_orgs: e.external_sharing_blocked_orgs,
            item_usage_orgs: e.item_usage_orgs,
            has_unknown_rules: e.has_unknown_rules,
        })
    }

    /// Signs and uploads the next policy version (owners and admins).
    pub fn set_org_policy(&self, org_id: String, rules: PolicyRules) -> Result<()> {
        let rules = policy::PolicyRules::try_from(rules).map_err(passbox_client::Error::from)?;
        Ok(self.inner.set_org_policy(&org_id, &rules)?)
    }
}

/// Checks an exported audit log: `records_json` is the `events` array of a
/// JSON export (oldest first), `anchor` the hash the first entry links to
/// (`""` for a log that starts at entry 1, `head.prunedHash` otherwise).
#[uniffi::export]
pub fn verify_audit_chain(records_json: String, anchor: Option<String>) -> AuditChainCheck {
    let check = match serde_json::from_str::<Vec<audit::AuditRecord>>(&records_json) {
        Ok(records) => audit::verify_chain(&records, anchor.as_deref()),
        Err(err) => audit::ChainCheck {
            valid: false,
            length: 0,
            first_seq: None,
            last_seq: None,
            head_hash: None,
            broken_at: None,
            problem: Some(format!("invalid export: {err}")),
        },
    };
    AuditChainCheck {
        valid: check.valid,
        length: check.length,
        first_seq: check.first_seq,
        last_seq: check.last_seq,
        head_hash: check.head_hash,
        broken_at: check.broken_at,
        problem: check.problem,
    }
}
