//! Organization policies.
//!
//! ```text
//! policy = { org_id, version, prev_hash, rules: [(name, value)] sorted, signer_id, created_at }
//!          signed by an owner or admin of the organization (Ed25519, tag passbox/v1/org-policy)
//! ```
//!
//! Policies are signed by an admin's account key, so a server cannot
//! loosen them: it can only deliver a policy some verified owner or admin
//! signed. Clients verify the signer against the organization's verified
//! roster and pin the newest verified version (with its rules) in the
//! [`TrustStore`]. A server that later shows an older version (rollback),
//! a different policy with the same version (fork) or no policy at all
//! cannot make a client forget what it pinned: the pinned rules stay in
//! force and a warning is shown.
//!
//! Policies are a feature of team organizations (Business). A family's
//! policy only carries whether members must enroll in recovery through the
//! organization (set up with every new family, see
//! [`PolicyRules::new_org_defaults`]); its other rules are not in force
//! ([`PolicyRules::for_family`]), also for versions a family signed
//! before. The kind comes from the organization's signed genesis, so a
//! server cannot turn a team's policy off by calling it a family.
//!
//! Rules travel as sorted `(name, value)` string pairs. A client that does
//! not know a rule still verifies the signature and reports the rule as
//! unknown (the web app asks to update), so new rules can be added without
//! a new object format.
//!
//! Known limits (documented in `docs/architecture/administration.md`): a
//! server can withhold a newer policy from a device that has not seen it
//! yet, and the first policy a new device sees is trusted on first use like
//! the roster it is checked against. Enforcement happens in the clients
//! (and in the server where it can); a modified client can ignore a policy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canon::{Reader, Writer};
use crate::identity::HASH_LEN;
use crate::keyring::Keyring;
use crate::sharing::data::SharingData;
use crate::sharing::objects::{Canonical, OrgKind, OrgRole, Signed};
use crate::sharing::state::{TrustStore, Warning};
use crate::sharing::verify::Roster;
use crate::{Error, Result, encoding};

/// Upper bound for the number of rules in one policy.
pub const MAX_RULES: usize = 64;
const MAX_RULE_NAME_LEN: usize = 64;
const MAX_RULE_VALUE_LEN: usize = 256;
/// Upper bound for auto-lock limits: one day.
pub const MAX_AUTO_LOCK_MINUTES: u32 = 24 * 60;
/// Upper bound for the lifetime of share links under a policy.
pub const MAX_SHARE_LINK_DAYS: u32 = 365;

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidData(message.into())
}

// --- Rules ---------------------------------------------------------------------------

/// What share links may do with this organization's items.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareLinkRule {
    #[default]
    Allowed,
    /// Allowed within `share_link_max_days` and `share_link_max_views`.
    Restricted,
    Forbidden,
}

impl ShareLinkRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Restricted => "restricted",
            Self::Forbidden => "forbidden",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "allowed" => Ok(Self::Allowed),
            "restricted" => Ok(Self::Restricted),
            "forbidden" => Ok(Self::Forbidden),
            other => Err(invalid(format!("unknown share link rule {other:?}"))),
        }
    }
}

/// The rules of an organization policy. The default value restricts
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyRules {
    /// Members must turn on two-factor sign-in.
    pub require_two_factor: bool,
    /// Minimum strength score (0–4, 0 = no requirement) of the master
    /// password, checked on the device when it is entered.
    pub min_password_score: u8,
    /// Highest auto-lock time members may choose, in minutes (0 = no limit).
    pub max_auto_lock_minutes: u32,
    /// Items of this organization's vaults cannot be exported.
    pub forbid_export: bool,
    /// Items of this organization's vaults cannot be moved or copied to
    /// vaults outside the organization (personal vaults, other organizations).
    pub forbid_external_sharing: bool,
    /// Share links for items of this organization's vaults.
    pub share_links: ShareLinkRule,
    /// With `share_links = restricted`: longest lifetime in days (1–365).
    pub share_link_max_days: u32,
    /// With `share_links = restricted`: most views per link (0 = no limit).
    pub share_link_max_views: u32,
    /// Members must enroll in recovery through the organization.
    pub require_recovery_enrollment: bool,
    /// Members may keep personal vaults. When off, clients do not create
    /// personal vaults or new items in them (existing items can be moved).
    pub allow_personal_vault: bool,
    /// Members' apps report viewing, revealing, copying and filling items
    /// of this organization's vaults to its audit log (signed events, no
    /// contents). Off by default; members see that it is on.
    pub report_item_usage: bool,
    /// Members may let AI agents see values of this organization's items
    /// (`passbox_reveal`, each time with an explicit tick in the approval
    /// dialog). Off by default: without a policy that turns it on, agents
    /// can only use these secrets, never see them (ADR 0006).
    pub allow_agent_reveal: bool,
}

impl Default for PolicyRules {
    fn default() -> Self {
        Self {
            require_two_factor: false,
            min_password_score: 0,
            max_auto_lock_minutes: 0,
            forbid_export: false,
            forbid_external_sharing: false,
            share_links: ShareLinkRule::Allowed,
            share_link_max_days: 0,
            share_link_max_views: 0,
            require_recovery_enrollment: false,
            allow_personal_vault: true,
            report_item_usage: false,
            allow_agent_reveal: false,
        }
    }
}

impl PolicyRules {
    /// The first policy of a new organization: recovery through the
    /// organization is required (on by default), everything else as
    /// [`PolicyRules::default`]. Admins can
    /// turn it off like any rule.
    pub fn new_org_defaults() -> Self {
        Self {
            require_recovery_enrollment: true,
            ..Self::default()
        }
    }

    /// The rules in force for a family: recovery enrollment as signed,
    /// everything else as [`PolicyRules::default`] (policies are for
    /// teams).
    pub fn for_family(&self) -> Self {
        Self {
            require_recovery_enrollment: self.require_recovery_enrollment,
            ..Self::default()
        }
    }
}

const RULE_NAMES: [&str; 12] = [
    "allow_agent_reveal",
    "allow_personal_vault",
    "forbid_export",
    "forbid_external_sharing",
    "max_auto_lock_minutes",
    "min_password_score",
    "report_item_usage",
    "require_recovery_enrollment",
    "require_two_factor",
    "share_link_max_days",
    "share_link_max_views",
    "share_links",
];

fn parse_bool(name: &str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid(format!("{name} must be true or false"))),
    }
}

fn parse_number(name: &str, value: &str, max: u32) -> Result<u32> {
    // Canonical decimal only: no sign, no leading zeros.
    if value.is_empty()
        || value.len() > 10
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid(format!("{name} must be a number")));
    }
    let number: u32 = value
        .parse()
        .map_err(|_| invalid(format!("{name} must be a number")))?;
    if number > max {
        return Err(invalid(format!("{name} must be at most {max}")));
    }
    Ok(number)
}

impl PolicyRules {
    /// Checks value ranges and combinations.
    pub fn validate(&self) -> Result<()> {
        if self.min_password_score > 4 {
            return Err(invalid("min_password_score must be between 0 and 4"));
        }
        if self.max_auto_lock_minutes > MAX_AUTO_LOCK_MINUTES {
            return Err(invalid(format!(
                "max_auto_lock_minutes must be at most {MAX_AUTO_LOCK_MINUTES}"
            )));
        }
        match self.share_links {
            ShareLinkRule::Restricted => {
                if self.share_link_max_days == 0 || self.share_link_max_days > MAX_SHARE_LINK_DAYS {
                    return Err(invalid(format!(
                        "share_link_max_days must be between 1 and {MAX_SHARE_LINK_DAYS}"
                    )));
                }
            }
            _ => {
                if self.share_link_max_days != 0 || self.share_link_max_views != 0 {
                    return Err(invalid(
                        "share link limits only apply to restricted share links",
                    ));
                }
            }
        }
        Ok(())
    }

    /// The rules as sorted `(name, value)` pairs, every known rule included.
    pub fn to_pairs(&self) -> Vec<(String, String)> {
        let pairs = [
            ("allow_agent_reveal", self.allow_agent_reveal.to_string()),
            (
                "allow_personal_vault",
                self.allow_personal_vault.to_string(),
            ),
            ("forbid_export", self.forbid_export.to_string()),
            (
                "forbid_external_sharing",
                self.forbid_external_sharing.to_string(),
            ),
            (
                "max_auto_lock_minutes",
                self.max_auto_lock_minutes.to_string(),
            ),
            ("min_password_score", self.min_password_score.to_string()),
            ("report_item_usage", self.report_item_usage.to_string()),
            (
                "require_recovery_enrollment",
                self.require_recovery_enrollment.to_string(),
            ),
            ("require_two_factor", self.require_two_factor.to_string()),
            ("share_link_max_days", self.share_link_max_days.to_string()),
            (
                "share_link_max_views",
                self.share_link_max_views.to_string(),
            ),
            ("share_links", self.share_links.as_str().to_owned()),
        ];
        pairs
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect()
    }

    /// Reads rules from pairs. Known rules must have valid values; missing
    /// ones keep their default. Returns the names of unknown rules.
    pub fn from_pairs(pairs: &[(String, String)]) -> Result<(Self, Vec<String>)> {
        let mut rules = Self::default();
        let mut unknown = Vec::new();
        for (name, value) in pairs {
            match name.as_str() {
                "allow_agent_reveal" => rules.allow_agent_reveal = parse_bool(name, value)?,
                "allow_personal_vault" => rules.allow_personal_vault = parse_bool(name, value)?,
                "forbid_export" => rules.forbid_export = parse_bool(name, value)?,
                "forbid_external_sharing" => {
                    rules.forbid_external_sharing = parse_bool(name, value)?;
                }
                "max_auto_lock_minutes" => {
                    rules.max_auto_lock_minutes = parse_number(name, value, MAX_AUTO_LOCK_MINUTES)?;
                }
                "min_password_score" => {
                    rules.min_password_score = u8::try_from(parse_number(name, value, 4)?)
                        .map_err(|_| invalid("min_password_score is out of range"))?;
                }
                "report_item_usage" => rules.report_item_usage = parse_bool(name, value)?,
                "require_recovery_enrollment" => {
                    rules.require_recovery_enrollment = parse_bool(name, value)?;
                }
                "require_two_factor" => rules.require_two_factor = parse_bool(name, value)?,
                "share_link_max_days" => {
                    rules.share_link_max_days = parse_number(name, value, MAX_SHARE_LINK_DAYS)?;
                }
                "share_link_max_views" => {
                    rules.share_link_max_views = parse_number(name, value, u32::MAX)?;
                }
                "share_links" => rules.share_links = ShareLinkRule::parse(value)?,
                _ => unknown.push(name.clone()),
            }
        }
        debug_assert!(RULE_NAMES.windows(2).all(|w| w[0] < w[1]));
        rules.validate()?;
        Ok((rules, unknown))
    }

    /// Whether a share link with this lifetime (days) and view limit
    /// (0 = unlimited) is allowed. The error says why not.
    pub fn check_share_link(&self, days: u32, max_views: u32) -> Result<()> {
        match self.share_links {
            ShareLinkRule::Allowed => Ok(()),
            ShareLinkRule::Forbidden => Err(Error::PolicyViolation(
                "share links are turned off for this organization".into(),
            )),
            ShareLinkRule::Restricted => {
                if days == 0 || days > self.share_link_max_days {
                    return Err(Error::PolicyViolation(format!(
                        "share links may last at most {} days",
                        self.share_link_max_days
                    )));
                }
                if self.share_link_max_views > 0
                    && (max_views == 0 || max_views > self.share_link_max_views)
                {
                    return Err(Error::PolicyViolation(format!(
                        "share links may be opened at most {} times",
                        self.share_link_max_views
                    )));
                }
                Ok(())
            }
        }
    }
}

// --- Signed object --------------------------------------------------------------------

/// A signed organization policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgPolicy {
    pub org_id: String,
    /// 1 for the first policy, then +1 per change.
    pub version: u64,
    /// Hash of the previous version (zero for version 1).
    pub prev_hash: [u8; HASH_LEN],
    /// Sorted by name, names unique.
    pub rules: Vec<(String, String)>,
    pub signer_id: String,
    pub created_at: i64,
}

fn valid_rule_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_RULE_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl Canonical for OrgPolicy {
    const TAG: &'static str = "passbox/v1/org-policy";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.org_id)
            .u64(self.version)
            .bytes(&self.prev_hash)
            .count(self.rules.len());
        for (name, value) in &self.rules {
            w.str(name).str(value);
        }
        w.str(&self.signer_id).i64(self.created_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let org_id = r.string()?;
        let version = r.u64()?;
        let prev_hash: [u8; HASH_LEN] = r.array()?;
        let count = r.count()?;
        if count > MAX_RULES {
            return Err(invalid("the policy has too many rules"));
        }
        let mut rules: Vec<(String, String)> = Vec::with_capacity(count);
        for _ in 0..count {
            let name = r.string()?;
            let value = r.string()?;
            if !valid_rule_name(&name) || value.len() > MAX_RULE_VALUE_LEN {
                return Err(invalid("the policy has an invalid rule"));
            }
            if rules.last().is_some_and(|(last, _)| *last >= name) {
                return Err(invalid("policy rules must be sorted and unique"));
            }
            rules.push((name, value));
        }
        let policy = Self {
            org_id,
            version,
            prev_hash,
            rules,
            signer_id: r.string()?,
            created_at: r.i64()?,
        };
        if policy.version == 0 || (policy.version == 1 && policy.prev_hash != [0; HASH_LEN]) {
            return Err(invalid("invalid policy version"));
        }
        Ok(policy)
    }
}

// --- Server data and uploads ------------------------------------------------------------

/// A policy as the server stores and delivers it (`sharing.policies` in
/// sync, `GET /api/v1/orgs/{id}/policy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRecord {
    pub org_id: String,
    pub version: u64,
    /// Base64url canonical [`OrgPolicy`].
    pub policy: String,
    pub signature: String,
}

/// `PUT /api/v1/orgs/{id}/policy` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyUpload {
    pub version: u64,
    pub policy: String,
    pub signature: String,
}

/// What a client remembers about the newest verified policy of an
/// organization. Public data, part of the [`TrustStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyPin {
    pub version: u64,
    /// Base64url hash of the signed policy.
    pub hash: String,
    pub rules: PolicyRules,
    #[serde(default)]
    pub unknown_rules: Vec<String>,
    pub signer_id: String,
    pub signed_at: i64,
}

/// The policy a client enforces for one organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgPolicyView {
    pub org_id: String,
    pub version: u64,
    pub hash: String,
    pub rules: PolicyRules,
    /// Rules this client does not know (update the app to enforce them).
    pub unknown_rules: Vec<String>,
    pub signer_id: String,
    pub signed_at: i64,
    /// `verified`: the server's policy verified now. `pinned`: the server's
    /// policy is missing, older or invalid; the pinned one stays in force.
    pub source: String,
    /// The signer is no longer an active owner or admin; an admin should
    /// sign the policy again (same rules, next version).
    pub needs_resign: bool,
}

/// The combination of every policy of the organizations this account is a
/// confirmed member of: account-wide rules take the strictest value; rules
/// about an organization's own vaults stay per organization (see
/// `orgs_*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectivePolicy {
    pub require_two_factor: bool,
    /// Organizations that require two-factor sign-in.
    pub two_factor_orgs: Vec<String>,
    /// Highest required master password score (0 = none).
    pub min_password_score: u8,
    /// Lowest auto-lock limit in minutes; `None` without a limit.
    #[serde(default)]
    pub max_auto_lock_minutes: Option<u32>,
    pub allow_personal_vault: bool,
    /// Organizations that do not allow personal vaults.
    pub personal_vault_orgs: Vec<String>,
    /// Organizations whose recovery the account must enroll in.
    pub recovery_enrollment_orgs: Vec<String>,
    /// Organizations whose vaults cannot be exported.
    pub export_blocked_orgs: Vec<String>,
    /// Organizations whose items must stay in the organization.
    pub external_sharing_blocked_orgs: Vec<String>,
    /// Organizations whose audit log receives item usage from this device.
    pub item_usage_orgs: Vec<String>,
    /// Organizations whose policy lets members reveal values of the
    /// organization's items to AI agents (`allow_agent_reveal`). Vaults of
    /// any other organization never reveal values to agents.
    #[serde(default)]
    pub agent_reveal_orgs: Vec<String>,
    /// Some policy has rules this client does not know.
    pub has_unknown_rules: bool,
}

impl Default for EffectivePolicy {
    fn default() -> Self {
        Self::combine(&[])
    }
}

impl EffectivePolicy {
    /// Combines the policies of organizations the account is bound by.
    pub fn combine(policies: &[&OrgPolicyView]) -> Self {
        let mut effective = Self {
            require_two_factor: false,
            two_factor_orgs: Vec::new(),
            min_password_score: 0,
            max_auto_lock_minutes: None,
            allow_personal_vault: true,
            personal_vault_orgs: Vec::new(),
            recovery_enrollment_orgs: Vec::new(),
            export_blocked_orgs: Vec::new(),
            external_sharing_blocked_orgs: Vec::new(),
            item_usage_orgs: Vec::new(),
            agent_reveal_orgs: Vec::new(),
            has_unknown_rules: false,
        };
        for policy in policies {
            let r = &policy.rules;
            let org = || policy.org_id.clone();
            if r.require_two_factor {
                effective.require_two_factor = true;
                effective.two_factor_orgs.push(org());
            }
            effective.min_password_score = effective.min_password_score.max(r.min_password_score);
            if r.max_auto_lock_minutes > 0 {
                effective.max_auto_lock_minutes = Some(
                    effective
                        .max_auto_lock_minutes
                        .map_or(r.max_auto_lock_minutes, |m| m.min(r.max_auto_lock_minutes)),
                );
            }
            if !r.allow_personal_vault {
                effective.allow_personal_vault = false;
                effective.personal_vault_orgs.push(org());
            }
            if r.require_recovery_enrollment {
                effective.recovery_enrollment_orgs.push(org());
            }
            if r.forbid_export {
                effective.export_blocked_orgs.push(org());
            }
            if r.forbid_external_sharing {
                effective.external_sharing_blocked_orgs.push(org());
            }
            if r.report_item_usage {
                effective.item_usage_orgs.push(org());
            }
            if r.allow_agent_reveal {
                effective.agent_reveal_orgs.push(org());
            }
            effective.has_unknown_rules |= !policy.unknown_rules.is_empty();
        }
        effective
    }

    /// Clamps an auto-lock time (minutes, 0 = never) to the policy limit.
    pub fn clamp_auto_lock(&self, minutes: u32) -> u32 {
        match self.max_auto_lock_minutes {
            Some(limit) if minutes == 0 || minutes > limit => limit,
            _ => minutes,
        }
    }
}

// --- Verification -----------------------------------------------------------------------

/// A policy whose signature and signer checked out.
#[derive(Debug, Clone)]
pub struct VerifiedPolicy {
    pub signed: Signed<OrgPolicy>,
    pub rules: PolicyRules,
    pub unknown_rules: Vec<String>,
}

impl VerifiedPolicy {
    fn pin(&self) -> PolicyPin {
        PolicyPin {
            version: self.signed.value.version,
            hash: encoding::encode(&self.signed.hash()),
            rules: self.rules.clone(),
            unknown_rules: self.unknown_rules.clone(),
            signer_id: self.signed.value.signer_id.clone(),
            signed_at: self.signed.value.created_at,
        }
    }
}

/// Why a policy did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyProblem {
    /// Malformed, wrong organization, bad signature or invalid rules.
    Invalid(String),
    /// Signed by someone who is not (or no longer) an active owner or admin.
    SignerInactive,
}

impl PolicyProblem {
    fn message(&self) -> String {
        match self {
            Self::Invalid(message) => message.clone(),
            Self::SignerInactive => {
                "the policy is not signed by an active owner or admin of the organization".into()
            }
        }
    }
}

/// Parses a policy and checks its rules (not its signer).
pub fn parse_policy(
    org_id: &str,
    policy: &str,
    signature: &str,
) -> Result<(Signed<OrgPolicy>, PolicyRules, Vec<String>)> {
    let signed = Signed::<OrgPolicy>::parse(policy, signature)?;
    if signed.value.org_id != org_id {
        return Err(invalid("the policy belongs to another organization"));
    }
    let (rules, unknown) = PolicyRules::from_pairs(&signed.value.rules)?;
    Ok((signed, rules, unknown))
}

/// Verifies a policy against an organization's verified roster: it must be
/// signed by an active, verified owner or admin.
pub fn verify_policy(
    roster: &Roster,
    record: &PolicyRecord,
) -> core::result::Result<VerifiedPolicy, PolicyProblem> {
    let (signed, rules, unknown_rules) =
        parse_policy(&roster.org_id, &record.policy, &record.signature)
            .map_err(|e| PolicyProblem::Invalid(e.to_string()))?;
    if signed.value.version != record.version {
        return Err(PolicyProblem::Invalid(
            "the policy version does not match".into(),
        ));
    }
    let signer = roster
        .admin(&signed.value.signer_id)
        .ok_or(PolicyProblem::SignerInactive)?;
    signed
        .verify(&signer.bundle.bundle.sig_pk)
        .map_err(|_| PolicyProblem::Invalid("the policy signature is invalid".into()))?;
    Ok(VerifiedPolicy {
        signed,
        rules,
        unknown_rules,
    })
}

fn view_from_pin(org_id: &str, pin: &PolicyPin, source: &str, needs_resign: bool) -> OrgPolicyView {
    OrgPolicyView {
        org_id: org_id.to_owned(),
        version: pin.version,
        hash: pin.hash.clone(),
        rules: pin.rules.clone(),
        unknown_rules: pin.unknown_rules.clone(),
        signer_id: pin.signer_id.clone(),
        signed_at: pin.signed_at,
        source: source.to_owned(),
        needs_resign,
    }
}

fn policy_warning(kind: &str, org_id: &str, message: impl Into<String>) -> Warning {
    Warning {
        kind: kind.to_owned(),
        subject_id: org_id.to_owned(),
        org_id: Some(org_id.to_owned()),
        message: message.into(),
    }
}

/// Verifies the delivered policies, updates the pins and returns the
/// policies in force plus their combination. Called by
/// [`Keyring::evaluate_sharing`].
pub(crate) fn evaluate(
    trust: &mut TrustStore,
    rosters: &BTreeMap<String, Roster>,
    data: &SharingData,
    warnings: &mut Vec<Warning>,
) -> (Vec<OrgPolicyView>, EffectivePolicy) {
    // Pins of organizations the account left are dropped with them.
    trust
        .policies
        .retain(|org_id, _| data.orgs.contains_key(org_id));
    let mut views = Vec::new();
    for org_id in data.orgs.keys() {
        let pin = trust.policies.get(org_id).cloned();
        let record = data.policies.get(org_id);
        let verified = match (record, rosters.get(org_id)) {
            (Some(record), Some(roster)) => Some(verify_policy(roster, record)),
            (Some(_), None) => Some(Err(PolicyProblem::Invalid(
                "the organization could not be verified".into(),
            ))),
            (None, _) => None,
        };
        let view = match (verified, pin) {
            (Some(Ok(policy)), pin) => {
                let new_pin = policy.pin();
                match pin {
                    Some(pin) if pin.version > new_pin.version => {
                        warnings.push(policy_warning(
                            "policy_rollback",
                            org_id,
                            format!(
                                "the server shows policy version {} after version {} was seen; the newer policy stays in force",
                                new_pin.version, pin.version
                            ),
                        ));
                        Some(view_from_pin(org_id, &pin, "pinned", false))
                    }
                    Some(pin) if pin.version == new_pin.version && pin.hash != new_pin.hash => {
                        warnings.push(policy_warning(
                            "policy_conflict",
                            org_id,
                            "the server shows a different policy with the same version; the policy seen first stays in force",
                        ));
                        Some(view_from_pin(org_id, &pin, "pinned", false))
                    }
                    _ => {
                        trust.policies.insert(org_id.clone(), new_pin.clone());
                        Some(view_from_pin(org_id, &new_pin, "verified", false))
                    }
                }
            }
            (Some(Err(PolicyProblem::SignerInactive)), Some(pin))
                if record.is_some_and(|r| {
                    r.version == pin.version
                        && Signed::<OrgPolicy>::parse(&r.policy, &r.signature)
                            .is_ok_and(|s| encoding::encode(&s.hash()) == pin.hash)
                }) =>
            {
                // Verified before; the signer has left or lost admin rights.
                warnings.push(policy_warning(
                    "policy_needs_resign",
                    org_id,
                    PolicyProblem::SignerInactive.message(),
                ));
                Some(view_from_pin(org_id, &pin, "pinned", true))
            }
            (Some(Err(problem)), pin) => {
                warnings.push(policy_warning("policy_invalid", org_id, problem.message()));
                pin.map(|pin| view_from_pin(org_id, &pin, "pinned", false))
            }
            (None, Some(pin)) => {
                warnings.push(policy_warning(
                    "policy_missing",
                    org_id,
                    "the server no longer shows the organization's policy; the last verified policy stays in force",
                ));
                Some(view_from_pin(org_id, &pin, "pinned", false))
            }
            (None, None) => None,
        };
        if let Some(mut view) = view {
            // Families keep the recovery rule only; the pin keeps what was
            // signed.
            if rosters
                .get(org_id)
                .is_some_and(|roster| roster.kind == OrgKind::Family)
            {
                view.rules = view.rules.for_family();
                view.unknown_rules.clear();
            }
            views.push(view);
        }
    }
    let binding: Vec<&OrgPolicyView> = views
        .iter()
        .filter(|v| {
            data.orgs
                .get(&v.org_id)
                .is_some_and(|o| o.status == "confirmed" || o.status == "suspended")
        })
        .collect();
    let mut effective = EffectivePolicy::combine(&binding);
    // Guests are external people with their own account: an
    // organization never gets to recover a guest's account, so a policy
    // that requires recovery does not apply to them.
    effective.recovery_enrollment_orgs.retain(|org_id| {
        data.orgs
            .get(org_id)
            .is_none_or(|o| o.role != OrgRole::Guest.as_str())
    });
    (views, effective)
}

impl Keyring {
    /// The policy in force for an organization (after the last sync).
    pub fn org_policy(&self, org_id: &str) -> Option<&OrgPolicyView> {
        self.sharing
            .view
            .policies
            .iter()
            .find(|p| p.org_id == org_id)
    }

    /// The combination of every policy this account is bound by.
    pub fn effective_policy(&self) -> &EffectivePolicy {
        &self.sharing.view.effective_policy
    }

    /// Signs a new policy version for an organization (owners and admins):
    /// the version after the one in force, linked to it by hash.
    pub fn sign_org_policy(
        &self,
        org_id: &str,
        rules: &PolicyRules,
        now: i64,
    ) -> Result<PolicyUpload> {
        rules.validate()?;
        let roster = self
            .sharing
            .rosters
            .get(org_id)
            .ok_or_else(|| invalid("the organization is unknown or could not be verified"))?;
        if roster.admin(&self.account_id).is_none() {
            return Err(invalid("only owners and admins can change the policy"));
        }
        let current = self.sharing.trust.policies.get(org_id);
        let (version, prev_hash) = match current {
            Some(pin) => {
                let hash: [u8; HASH_LEN] = encoding::decode(&pin.hash)?
                    .try_into()
                    .map_err(|_| invalid("invalid pinned policy hash"))?;
                (pin.version + 1, hash)
            }
            None => (1, [0; HASH_LEN]),
        };
        let signed = Signed::sign(
            OrgPolicy {
                org_id: org_id.to_owned(),
                version,
                prev_hash,
                rules: rules.to_pairs(),
                signer_id: self.account_id.clone(),
                created_at: now,
            },
            &self.account_keys()?.sig,
        );
        Ok(PolicyUpload {
            version,
            policy: signed.encoded(),
            signature: signed.encoded_signature(),
        })
    }

    /// Verifies a policy record against the organization's verified roster
    /// without changing any pin (for showing history or a single record).
    pub fn verify_org_policy(&self, org_id: &str, record: &PolicyRecord) -> Result<OrgPolicyView> {
        let roster = self
            .sharing
            .rosters
            .get(org_id)
            .ok_or_else(|| invalid("the organization is unknown or could not be verified"))?;
        let verified = verify_policy(roster, record).map_err(|p| invalid(p.message()))?;
        Ok(view_from_pin(org_id, &verified.pin(), "verified", false))
    }
}

/// Checks that a policy history (ascending versions) is one unbroken hash
/// chain. Signatures are not checked here (signers may have left); use
/// [`Keyring::verify_org_policy`] per version.
pub fn verify_policy_chain(org_id: &str, records: &[PolicyRecord]) -> Result<()> {
    let mut prev = [0u8; HASH_LEN];
    for (i, record) in records.iter().enumerate() {
        let (signed, _, _) = parse_policy(org_id, &record.policy, &record.signature)?;
        if signed.value.version != i as u64 + 1 || record.version != signed.value.version {
            return Err(invalid("policy versions are not consecutive"));
        }
        if signed.value.prev_hash != prev {
            return Err(invalid("the policy history is broken"));
        }
        prev = signed.hash();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing::objects::OrgRole;
    use crate::sharing::tests::{account, family, team};

    fn strict() -> PolicyRules {
        PolicyRules {
            require_two_factor: true,
            min_password_score: 3,
            max_auto_lock_minutes: 10,
            forbid_export: true,
            forbid_external_sharing: true,
            share_links: ShareLinkRule::Restricted,
            share_link_max_days: 7,
            share_link_max_views: 5,
            require_recovery_enrollment: true,
            allow_personal_vault: false,
            report_item_usage: true,
            allow_agent_reveal: false,
        }
    }

    #[test]
    fn new_organizations_require_recovery_and_forbid_agent_reveals() {
        let rules = PolicyRules::new_org_defaults();
        assert!(rules.require_recovery_enrollment);
        assert!(!rules.allow_agent_reveal);
        assert_eq!(
            PolicyRules {
                require_recovery_enrollment: false,
                ..rules.clone()
            },
            PolicyRules::default()
        );
        // A policy signed before the rule existed keeps agent reveals off.
        let (old, unknown) =
            PolicyRules::from_pairs(&[("require_two_factor".to_owned(), "true".to_owned())])
                .unwrap();
        assert!(!old.allow_agent_reveal && unknown.is_empty());
        let (on, _) =
            PolicyRules::from_pairs(&[("allow_agent_reveal".to_owned(), "true".to_owned())])
                .unwrap();
        assert!(on.allow_agent_reveal);
    }

    fn record(org_id: &str, upload: &PolicyUpload) -> PolicyRecord {
        PolicyRecord {
            org_id: org_id.to_owned(),
            version: upload.version,
            policy: upload.policy.clone(),
            signature: upload.signature.clone(),
        }
    }

    #[test]
    fn rules_round_trip_through_pairs() {
        let rules = strict();
        let pairs = rules.to_pairs();
        assert!(pairs.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(
            pairs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            RULE_NAMES
        );
        let (parsed, unknown) = PolicyRules::from_pairs(&pairs).unwrap();
        assert_eq!(parsed, rules);
        assert!(unknown.is_empty());
        assert_eq!(
            PolicyRules::from_pairs(&PolicyRules::default().to_pairs())
                .unwrap()
                .0,
            PolicyRules::default()
        );
    }

    #[test]
    fn rules_reject_invalid_values() {
        let bad = |name: &str, value: &str| {
            PolicyRules::from_pairs(&[(name.to_owned(), value.to_owned())]).is_err()
        };
        assert!(bad("require_two_factor", "yes"));
        assert!(bad("min_password_score", "5"));
        assert!(bad("min_password_score", "03"));
        assert!(bad("min_password_score", "-1"));
        assert!(bad("max_auto_lock_minutes", "1441"));
        assert!(bad("share_links", "sometimes"));
        // Limits without restricted links.
        assert!(bad("share_link_max_days", "3"));
        let (_, unknown) =
            PolicyRules::from_pairs(&[("future_rule".to_owned(), "on".to_owned())]).unwrap();
        assert_eq!(unknown, vec!["future_rule".to_owned()]);
    }

    #[test]
    fn share_link_limits() {
        let rules = strict();
        assert!(rules.check_share_link(7, 5).is_ok());
        assert!(rules.check_share_link(8, 5).is_err());
        assert!(rules.check_share_link(7, 0).is_err());
        assert!(rules.check_share_link(7, 6).is_err());
        assert!(PolicyRules::default().check_share_link(365, 0).is_ok());
        let forbidden = PolicyRules {
            share_links: ShareLinkRule::Forbidden,
            ..PolicyRules::default()
        };
        assert!(forbidden.check_share_link(1, 1).is_err());
    }

    #[test]
    fn canonical_encoding_rejects_unsorted_rules() {
        let policy = OrgPolicy {
            org_id: "o".into(),
            version: 1,
            prev_hash: [0; HASH_LEN],
            rules: vec![("b".into(), "1".into()), ("a".into(), "1".into())],
            signer_id: "s".into(),
            created_at: 1,
        };
        assert!(OrgPolicy::from_canonical(&policy.to_canonical()).is_err());
        let duplicate = OrgPolicy {
            rules: vec![("a".into(), "1".into()), ("a".into(), "2".into())],
            ..policy.clone()
        };
        assert!(OrgPolicy::from_canonical(&duplicate.to_canonical()).is_err());
        let first_with_prev = OrgPolicy {
            rules: vec![],
            prev_hash: [1; HASH_LEN],
            ..policy
        };
        assert!(OrgPolicy::from_canonical(&first_with_prev.to_canonical()).is_err());
    }

    #[test]
    fn combine_takes_the_strictest_values() {
        let a = OrgPolicyView {
            org_id: "a".into(),
            version: 1,
            hash: String::new(),
            rules: PolicyRules {
                max_auto_lock_minutes: 30,
                min_password_score: 2,
                ..PolicyRules::default()
            },
            unknown_rules: vec![],
            signer_id: String::new(),
            signed_at: 0,
            source: "verified".into(),
            needs_resign: false,
        };
        let b = OrgPolicyView {
            org_id: "b".into(),
            rules: strict(),
            unknown_rules: vec!["x".into()],
            ..a.clone()
        };
        let c = OrgPolicyView {
            org_id: "c".into(),
            rules: PolicyRules {
                allow_agent_reveal: true,
                ..PolicyRules::default()
            },
            ..a.clone()
        };
        assert_eq!(
            EffectivePolicy::combine(&[&a, &b, &c]).agent_reveal_orgs,
            vec!["c".to_owned()]
        );
        let effective = EffectivePolicy::combine(&[&a, &b]);
        assert!(effective.agent_reveal_orgs.is_empty());
        assert!(effective.require_two_factor);
        assert_eq!(effective.two_factor_orgs, vec!["b".to_owned()]);
        assert_eq!(effective.min_password_score, 3);
        assert_eq!(effective.max_auto_lock_minutes, Some(10));
        assert!(!effective.allow_personal_vault);
        assert_eq!(effective.export_blocked_orgs, vec!["b".to_owned()]);
        assert!(effective.has_unknown_rules);
        assert_eq!(effective.clamp_auto_lock(0), 10);
        assert_eq!(effective.clamp_auto_lock(60), 10);
        assert_eq!(effective.clamp_auto_lock(5), 5);
        assert_eq!(EffectivePolicy::default().clamp_auto_lock(0), 0);
    }

    #[test]
    fn members_verify_and_pin_admin_signed_policies() {
        let (mut server, mut alice, mut bob, org, _) = team();
        let upload = alice.sign_org_policy(&org, &strict(), 10).unwrap();
        assert_eq!(upload.version, 1);
        server.policies.insert(org.clone(), record(&org, &upload));

        let report = bob.apply_sharing(server.delta(bob.account_id()));
        let policy = report
            .view
            .policies
            .iter()
            .find(|p| p.org_id == org)
            .unwrap();
        assert_eq!(policy.source, "verified");
        assert_eq!(policy.rules, strict());
        assert!(report.view.effective_policy.require_two_factor);
        assert_eq!(bob.trust_store().policies[&org].version, 1);

        // A member cannot sign a policy.
        assert!(
            bob.sign_org_policy(&org, &PolicyRules::default(), 11)
                .is_err()
        );

        // Version 2 loosens the rules and links to version 1.
        alice.apply_sharing(server.delta(alice.account_id()));
        let loose = alice
            .sign_org_policy(&org, &PolicyRules::default(), 20)
            .unwrap();
        assert_eq!(loose.version, 2);
        server.policies.insert(org.clone(), record(&org, &loose));
        verify_policy_chain(&org, &[record(&org, &upload), record(&org, &loose)]).unwrap();
        let report = bob.apply_sharing(server.delta(bob.account_id()));
        assert!(!report.view.effective_policy.require_two_factor);
    }

    #[test]
    fn a_server_cannot_roll_back_forge_or_drop_a_policy() {
        let (mut server, mut alice, mut bob, org, _) = team();
        let v1 = alice
            .sign_org_policy(&org, &PolicyRules::default(), 10)
            .unwrap();
        server.policies.insert(org.clone(), record(&org, &v1));
        alice.apply_sharing(server.delta(alice.account_id()));
        let v2 = alice.sign_org_policy(&org, &strict(), 20).unwrap();
        server.policies.insert(org.clone(), record(&org, &v2));
        bob.apply_sharing(server.delta(bob.account_id()));

        // Rollback to the looser version 1.
        server.policies.insert(org.clone(), record(&org, &v1));
        let report = bob.apply_sharing(server.delta(bob.account_id()));
        let policy = &report.view.policies[0];
        assert_eq!((policy.version, policy.source.as_str()), (2, "pinned"));
        assert!(report.view.effective_policy.require_two_factor);
        assert!(
            report
                .view
                .warnings
                .iter()
                .any(|w| w.kind == "policy_rollback")
        );

        // A policy signed by someone who is not an admin (the server's own key).
        let mallory = {
            let mut m = account();
            m.create_account_keys(1).unwrap();
            m
        };
        let forged = Signed::sign(
            OrgPolicy {
                org_id: org.clone(),
                version: 3,
                prev_hash: [0; HASH_LEN],
                rules: PolicyRules::default().to_pairs(),
                signer_id: alice.account_id().to_owned(),
                created_at: 30,
            },
            &mallory.account_keys().unwrap().sig,
        );
        server.policies.insert(
            org.clone(),
            PolicyRecord {
                org_id: org.clone(),
                version: 3,
                policy: forged.encoded(),
                signature: forged.encoded_signature(),
            },
        );
        let report = bob.apply_sharing(server.delta(bob.account_id()));
        assert_eq!(report.view.policies[0].version, 2);
        assert!(
            report
                .view
                .warnings
                .iter()
                .any(|w| w.kind == "policy_invalid")
        );

        // No policy at all.
        server.policies.remove(&org);
        let report = bob.apply_sharing(server.delta(bob.account_id()));
        assert_eq!(report.view.policies[0].version, 2);
        assert!(report.view.effective_policy.require_two_factor);
        assert!(
            report
                .view
                .warnings
                .iter()
                .any(|w| w.kind == "policy_missing")
        );
    }

    #[test]
    fn a_family_keeps_only_the_recovery_rule() {
        let (mut server, mut alice, mut bob, org, _) = family();
        // A strict policy a family signed before policies became a team
        // feature.
        let rules = PolicyRules {
            require_recovery_enrollment: true,
            ..strict()
        };
        let upload = alice.sign_org_policy(&org, &rules, 10).unwrap();
        server.policies.insert(org.clone(), record(&org, &upload));
        let report = bob.apply_sharing(server.delta(bob.account_id()));
        let policy = report
            .view
            .policies
            .iter()
            .find(|p| p.org_id == org)
            .unwrap();
        assert_eq!(policy.source, "verified");
        assert_eq!(policy.rules, PolicyRules::new_org_defaults());
        assert!(policy.unknown_rules.is_empty());
        let effective = &report.view.effective_policy;
        assert!(!effective.require_two_factor);
        assert!(effective.allow_personal_vault);
        assert_eq!(effective.max_auto_lock_minutes, None);
        assert!(effective.export_blocked_orgs.is_empty());
        assert_eq!(effective.recovery_enrollment_orgs, vec![org.clone()]);
        // The pin keeps what was signed, so a server cannot roll it back.
        assert_eq!(bob.trust_store().policies[&org].version, 1);
        server.policies.remove(&org);
        let report = bob.apply_sharing(server.delta(bob.account_id()));
        assert_eq!(
            report.view.effective_policy.recovery_enrollment_orgs,
            vec![org.clone()]
        );
        assert!(!report.view.effective_policy.require_two_factor);

        // The organizer can still turn the recovery rule off.
        alice.apply_sharing(server.delta(alice.account_id()));
        server.policies.insert(org.clone(), record(&org, &upload));
        alice.apply_sharing(server.delta(alice.account_id()));
        let off = alice
            .sign_org_policy(&org, &PolicyRules::default(), 20)
            .unwrap();
        assert_eq!(off.version, 2);
        server.policies.insert(org.clone(), record(&org, &off));
        let report = bob.apply_sharing(server.delta(bob.account_id()));
        assert!(
            report
                .view
                .effective_policy
                .recovery_enrollment_orgs
                .is_empty()
        );
    }

    #[test]
    fn verify_org_policy_checks_the_signer_role() {
        let (mut server, alice, mut bob, org, _) = team();
        let upload = alice.sign_org_policy(&org, &strict(), 10).unwrap();
        server.policies.insert(org.clone(), record(&org, &upload));
        bob.apply_sharing(server.delta(bob.account_id()));
        let view = bob.verify_org_policy(&org, &record(&org, &upload)).unwrap();
        assert_eq!(view.signer_id, alice.account_id());
        assert_eq!(bob.org_role(&org), Some(OrgRole::Member));
        // Wrong organization.
        assert!(
            bob.verify_org_policy("other", &record(&org, &upload))
                .is_err()
        );
    }
}
