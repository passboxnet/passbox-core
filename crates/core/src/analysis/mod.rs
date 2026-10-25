//! The vault security analysis ("Sicherheits-Check"): an overall score with
//! its explanation, findings per item with severity and a concrete fix,
//! and a prioritized "fix these first" list.
//!
//! Pure logic over decrypted items, shared by every client: natively by
//! `passbox-client` (CLI, desktop, iOS and Android through FFI) and through
//! WebAssembly by the web vault and the extension. Nothing here talks to
//! the network: breach counts (Have I Been Pwned, k-anonymity), email
//! exposures (server-side monitoring) and the public breach catalogue are
//! passed in by the caller; the 2FA/passkey site lists and a snapshot of the
//! breach catalogue are bundled ([`sites`], [`breaches`]).
//!
//! Dismissals are stored in the item itself (`securityIgnore`, a list of
//! finding codes), so they are encrypted and synced like the item.

pub mod breaches;
pub mod domain;
pub mod expiry;
pub mod lookalike;
pub mod similar;
pub mod sites;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::strength;
use lookalike::LookalikeReason;

/// The item key that holds dismissed finding codes.
pub const IGNORE_KEY: &str = "securityIgnore";
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Length of the "fix these first" list.
pub const FIX_FIRST_LEN: usize = 10;

// --- Input --------------------------------------------------------------------------

/// A field of an item as stored (`{ id, label, type, value }`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FieldView {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub value: String,
}

/// An earlier password of an item.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HistoryView {
    pub value: String,
    pub replaced_at: i64,
}

/// The parts of the item format (`ItemData`, v1) the analysis reads.
/// Unknown keys are ignored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ItemView {
    pub category: String,
    pub title: String,
    pub fields: Vec<FieldView>,
    pub passkeys: Vec<serde_json::Value>,
    pub trashed_at: Option<i64>,
    pub password_history: Vec<HistoryView>,
    /// Dismissed finding codes ([`FindingKind::as_str`]).
    pub security_ignore: Vec<String>,
}

impl ItemView {
    fn field(&self, id: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.value.trim())
            .filter(|v| !v.is_empty())
    }
}

/// An item to analyze.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AnalysisItem {
    pub id: String,
    /// Unix ms; 0 when unknown.
    pub created_at: i64,
    pub data: ItemView,
}

/// A breach an email address appeared in (from the server's monitoring).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BreachInfo {
    /// Have I Been Pwned's stable name of the breach (`Adobe`).
    pub name: String,
    pub title: String,
    /// Domain of the breached site; may be empty.
    pub domain: String,
    /// `YYYY-MM-DD`.
    pub breach_date: String,
    /// Kinds of data exposed (`Passwords`, `Email addresses`, …).
    pub data_classes: Vec<String>,
}

/// A monitored email address and the breaches it was found in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ExposedEmail {
    pub email: String,
    pub breaches: Vec<BreachInfo>,
}

/// Settings and external results for one analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AnalysisOptions {
    /// Current time, Unix ms.
    pub now: i64,
    /// Words an attacker would try first (account email, name).
    pub user_inputs: Vec<String>,
    /// Passwords older than this many days count as old; 0 turns it off.
    pub old_after_days: u32,
    /// Cards and documents expiring within this many days are flagged.
    pub expiring_within_days: u32,
    /// Finding kinds the user turned off entirely.
    pub disabled: Vec<FindingKind>,
    /// Breach counts by item ID from a breach check in this session;
    /// `None` when no check ran (breaches are then unknown, not absent).
    pub breach_counts: Option<BTreeMap<String, u64>>,
    /// Results of server-side email monitoring.
    pub exposed_emails: Vec<ExposedEmail>,
    /// The public breach catalogue (from the server); `None` uses the
    /// bundled snapshot ([`breaches::bundled`]).
    pub site_breaches: Option<breaches::BreachCatalog>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            now: 0,
            user_inputs: Vec::new(),
            old_after_days: 365,
            expiring_within_days: 60,
            disabled: Vec::new(),
            breach_counts: None,
            exposed_emails: Vec::new(),
            site_breaches: None,
        }
    }
}

// --- Output -------------------------------------------------------------------------

/// How urgent a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Share of an item's score this severity costs (0–1).
    pub fn weight(self) -> f64 {
        match self {
            Self::Critical => 1.0,
            Self::High => 0.7,
            Self::Medium => 0.35,
            Self::Low => 0.1,
            Self::Info => 0.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

/// The kinds of findings, in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// The password appears in known data breaches.
    Breached,
    /// The login's site was breached and its email address was in it.
    ExposedEmail,
    /// The login's website had a data breach after its password was set.
    BreachedSite,
    /// The website address looks like another domain (phishing).
    Lookalike,
    /// Other logins use the same password.
    Reused,
    /// The password is easy to guess (strength ≤ 1 of 4).
    Weak,
    /// The password is a small variation of another one (or of an
    /// earlier password of the same item).
    Similar,
    /// The website uses `http://`.
    InsecureUrl,
    /// The site offers two-factor authentication and the login has none.
    MissingTwoFactor,
    /// The card or document has expired.
    Expired,
    /// The card or document expires soon.
    Expiring,
    /// The password was not changed for a long time.
    Old,
    /// The site supports passkeys and the login has none.
    PasskeyAvailable,
    /// Several items for the same account.
    Duplicate,
    /// A login without a website (no autofill, no phishing protection).
    MissingUrl,
    /// A login without a username.
    MissingUsername,
    /// Password and one-time code are stored in the same item.
    TotpInSameItem,
}

impl FindingKind {
    pub const ALL: [FindingKind; 17] = [
        Self::Breached,
        Self::ExposedEmail,
        Self::BreachedSite,
        Self::Lookalike,
        Self::Reused,
        Self::Weak,
        Self::Similar,
        Self::InsecureUrl,
        Self::MissingTwoFactor,
        Self::Expired,
        Self::Expiring,
        Self::Old,
        Self::PasskeyAvailable,
        Self::Duplicate,
        Self::MissingUrl,
        Self::MissingUsername,
        Self::TotpInSameItem,
    ];

    /// Stable code, used in `securityIgnore` and by the UIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Breached => "breached",
            Self::ExposedEmail => "exposed_email",
            Self::BreachedSite => "breached_site",
            Self::Lookalike => "lookalike",
            Self::Reused => "reused",
            Self::Weak => "weak",
            Self::Similar => "similar",
            Self::InsecureUrl => "insecure_url",
            Self::MissingTwoFactor => "missing_two_factor",
            Self::Expired => "expired",
            Self::Expiring => "expiring",
            Self::Old => "old",
            Self::PasskeyAvailable => "passkey_available",
            Self::Duplicate => "duplicate",
            Self::MissingUrl => "missing_url",
            Self::MissingUsername => "missing_username",
            Self::TotpInSameItem => "totp_in_same_item",
        }
    }

    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == code)
    }

    pub fn severity(self) -> Severity {
        match self {
            Self::Breached => Severity::Critical,
            Self::ExposedEmail
            | Self::BreachedSite
            | Self::Lookalike
            | Self::Reused
            | Self::Weak => Severity::High,
            Self::Similar | Self::InsecureUrl | Self::MissingTwoFactor | Self::Expired => {
                Severity::Medium
            }
            Self::Expiring | Self::Old | Self::PasskeyAvailable | Self::Duplicate => Severity::Low,
            Self::MissingUrl => Severity::Low,
            Self::MissingUsername | Self::TotpInSameItem => Severity::Info,
        }
    }

    pub fn fix(self) -> FixAction {
        match self {
            Self::Breached | Self::Reused | Self::Weak | Self::Similar | Self::Old => {
                FixAction::ChangePassword
            }
            Self::ExposedEmail | Self::BreachedSite => FixAction::ChangePassword,
            Self::Lookalike => FixAction::CheckWebsite,
            Self::InsecureUrl => FixAction::UseHttps,
            Self::MissingTwoFactor => FixAction::EnableTwoFactor,
            Self::Expired | Self::Expiring => FixAction::Renew,
            Self::PasskeyAvailable => FixAction::AddPasskey,
            Self::Duplicate => FixAction::ReviewDuplicates,
            Self::MissingUrl => FixAction::AddWebsite,
            Self::MissingUsername => FixAction::AddUsername,
            Self::TotpInSameItem => FixAction::SeparateTotp,
        }
    }
}

/// What the user should do about a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixAction {
    /// Change the password on the website, then save it (generator).
    ChangePassword,
    /// Turn on two-factor authentication on the website and store the
    /// one-time code (or a passkey) in the item.
    EnableTwoFactor,
    /// Create a passkey on the website and save it in Passbox.
    AddPasskey,
    /// Switch the saved address to `https://`.
    UseHttps,
    /// Make sure the saved address is the real website.
    CheckWebsite,
    /// Renew the card or document and update the expiry date.
    Renew,
    /// Compare the items and move extra ones to the trash.
    ReviewDuplicates,
    AddWebsite,
    AddUsername,
    /// Keep the one-time codes elsewhere (or accept the trade-off).
    SeparateTotp,
}

impl FixAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChangePassword => "change_password",
            Self::EnableTwoFactor => "enable_two_factor",
            Self::AddPasskey => "add_passkey",
            Self::UseHttps => "use_https",
            Self::CheckWebsite => "check_website",
            Self::Renew => "renew",
            Self::ReviewDuplicates => "review_duplicates",
            Self::AddWebsite => "add_website",
            Self::AddUsername => "add_username",
            Self::SeparateTotp => "separate_totp",
        }
    }
}

/// One problem of one item. Optional details depend on the kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub item_id: String,
    pub fix: FixAction,
    /// Other items of the same group (reused, similar, duplicate,
    /// lookalike target).
    pub related: Vec<String>,
    /// The user dismissed this finding for this item.
    pub dismissed: bool,
    /// Breached: how often the password appears in breaches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breach_count: Option<u64>,
    /// Weak: strength score 0–4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strength: Option<u8>,
    /// Old: days since the password was set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_days: Option<u32>,
    /// The item's registrable domain (Unicode), when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// MissingTwoFactor, PasskeyAvailable: how to turn it on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    /// Lookalike: the domain it imitates and why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookalike_of: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookalike_reason: Option<LookalikeReason>,
    /// Expired, Expiring: `YYYY-MM` or `YYYY-MM-DD`, and days left
    /// (negative when expired).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_left: Option<i64>,
    /// ExposedEmail: the address and the breaches of this site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub breaches: Vec<String>,
    /// Similar: the password resembles an earlier password of this item.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub similar_to_previous: bool,
    /// BreachedSite: Have I Been Pwned names of the breaches (details in
    /// [`SecurityReport::breached_sites`]); their titles are in `breaches`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub breach_names: Vec<String>,
    /// BreachedSite: date of the most recent of these breaches (`YYYY-MM-DD`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub breach_date: Option<String>,
    /// BreachedSite: kinds of data exposed (Have I Been Pwned's names).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub data_classes: Vec<String>,
    /// BreachedSite: it is unknown when the password was set, so the login
    /// is possibly affected.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub possibly: bool,
}

impl Finding {
    fn new(kind: FindingKind, item_id: &str) -> Self {
        Self {
            kind,
            severity: kind.severity(),
            item_id: item_id.to_owned(),
            fix: kind.fix(),
            related: Vec::new(),
            dismissed: false,
            breach_count: None,
            strength: None,
            age_days: None,
            domain: None,
            documentation_url: None,
            lookalike_of: None,
            lookalike_reason: None,
            expires: None,
            days_left: None,
            email: None,
            breaches: Vec::new(),
            similar_to_previous: false,
            breach_names: Vec::new(),
            breach_date: None,
            data_classes: Vec::new(),
            possibly: false,
        }
    }
}

/// Counts of one kind of finding, for the category cards.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategorySummary {
    pub kind: FindingKind,
    pub severity: Severity,
    /// Items with this finding that are not dismissed.
    pub count: u32,
    pub dismissed: u32,
    /// Score points this category costs (the explanation of the score).
    pub points: u32,
    /// False when the kind was turned off or its data is missing (breach
    /// check not run).
    pub checked: bool,
}

/// An item worth fixing first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Priority {
    pub item_id: String,
    /// Its open findings, most severe first.
    pub kinds: Vec<FindingKind>,
    pub severity: Severity,
    pub fix: FixAction,
    /// Score points gained by fixing everything on this item.
    pub points: u32,
}

/// How the score reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rating {
    Excellent,
    Good,
    Fair,
    Poor,
}

/// The result of [`analyze`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReport {
    /// 0–100, higher is better.
    pub score: u8,
    pub rating: Rating,
    /// Items outside the trash.
    pub items: u32,
    /// Logins with a password (the base of the score).
    pub logins: u32,
    /// Items that count for the score (logins with a password and items
    /// with scored findings).
    pub scored: u32,
    /// Whether breach counts were supplied.
    pub breach_checked: bool,
    /// One entry per kind, in priority order.
    pub categories: Vec<CategorySummary>,
    /// Every finding, dismissed ones included, most important first.
    pub findings: Vec<Finding>,
    /// Up to ten items to fix first.
    pub fix_first: Vec<Priority>,
    pub reused_groups: Vec<Vec<String>>,
    pub similar_groups: Vec<Vec<String>>,
    pub duplicate_groups: Vec<Vec<String>>,
    /// Snapshot dates of the bundled 2FA and passkey lists.
    pub directory_dates: (String, String),
    /// Breaches of sites with saved logins (affected, possibly affected or
    /// fixed), open ones first, newest first.
    pub breached_sites: Vec<breaches::BreachedSite>,
    /// The breach catalogue the report used.
    pub breach_catalog: CatalogInfo,
}

/// Which breach catalogue a report used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogInfo {
    pub version: String,
    /// Newest added or modified date of its entries (Unix ms).
    pub updated_at: i64,
    pub entries: u32,
    /// The snapshot bundled with the app (no catalogue from the server).
    pub bundled: bool,
    pub source: String,
    pub source_url: String,
    pub license: String,
}

// --- Analysis -----------------------------------------------------------------------

struct Login<'a> {
    item: &'a AnalysisItem,
    password: Option<&'a str>,
    url: Option<domain::ParsedUrl>,
    registrable: Option<String>,
}

fn is_expiry_field(field: &FieldView) -> bool {
    let id = field.id.to_lowercase();
    let label = field.label.to_lowercase();
    id.contains("expir")
        || id.contains("valid_until")
        || ["expir", "ablauf", "gültig bis", "valid until", "läuft ab"]
            .iter()
            .any(|word| label.contains(word))
}

/// Groups item IDs by key; only groups with more than one member, in the
/// order their first member appeared.
fn groups<K: Ord + Clone>(pairs: impl IntoIterator<Item = (K, String)>) -> Vec<Vec<String>> {
    let mut order = Vec::new();
    let mut by_key: BTreeMap<K, Vec<String>> = BTreeMap::new();
    for (key, id) in pairs {
        let ids = by_key.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Vec::new()
        });
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    order
        .into_iter()
        .filter_map(|key| by_key.remove(&key))
        .filter(|ids| ids.len() > 1)
        .collect()
}

/// Analyzes the vault. Items in the trash are skipped.
pub fn analyze(items: &[AnalysisItem], options: &AnalysisOptions) -> SecurityReport {
    let active: Vec<&AnalysisItem> = items
        .iter()
        .filter(|i| i.data.trashed_at.is_none())
        .collect();
    let enabled = |kind: FindingKind| !options.disabled.contains(&kind);
    let mut findings: Vec<Finding> = Vec::new();
    let logins: Vec<Login> = active
        .iter()
        .filter(|i| i.data.category == "login")
        .map(|item| {
            let url = item.data.field("url").and_then(domain::parse_url);
            let registrable = url
                .as_ref()
                .filter(|u| matches!(u.scheme.as_str(), "http" | "https"))
                .map(|u| domain::registrable_domain(&u.unicode_host));
            Login {
                item,
                password: item.data.field("password"),
                url,
                registrable,
            }
        })
        .collect();
    let user_inputs: Vec<&str> = options.user_inputs.iter().map(String::as_str).collect();

    // Strength, once per distinct password.
    let mut strengths: HashMap<&str, u8> = HashMap::new();
    for login in &logins {
        if let Some(password) = login.password {
            strengths
                .entry(password)
                .or_insert_with(|| strength::estimate(password, &user_inputs).score);
        }
    }

    // Groups.
    let reused_groups = groups(
        logins
            .iter()
            .filter_map(|l| Some((l.password?.to_owned(), l.item.id.clone()))),
    );
    let reused_ids: BTreeSet<&str> = reused_groups.iter().flatten().map(String::as_str).collect();
    let similar_groups: Vec<Vec<String>> = {
        // Distinct passwords sharing a base; identical ones are "reused".
        let mut by_base: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for login in &logins {
            if let Some(password) = login.password {
                if let Some(base) = similar::password_base(password) {
                    by_base.entry(base).or_default().insert(password);
                }
            }
        }
        groups(logins.iter().filter_map(|l| {
            let base = similar::password_base(l.password?)?;
            (by_base.get(&base)?.len() > 1).then(|| (base, l.item.id.clone()))
        }))
    };
    let duplicate_groups = {
        let mut pairs: Vec<((String, String), String)> = Vec::new();
        for login in &logins {
            if let (Some(site), Some(user)) =
                (&login.registrable, login.item.data.field("username"))
            {
                pairs.push(((site.clone(), user.to_lowercase()), login.item.id.clone()));
            }
        }
        for item in active.iter().filter(|i| i.data.category == "card") {
            if let Some(number) = item.data.field("card_number") {
                let digits: String = number.chars().filter(char::is_ascii_digit).collect();
                if digits.len() >= 8 {
                    pairs.push((("card".into(), digits), item.id.clone()));
                }
            }
        }
        groups(pairs)
    };
    let group_of = |groups: &[Vec<String>], id: &str| -> Vec<String> {
        groups
            .iter()
            .find(|g| g.iter().any(|m| m == id))
            .map(|g| g.iter().filter(|m| *m != id).cloned().collect())
            .unwrap_or_default()
    };

    // Lookalikes among the user's own domains and against well-known sites.
    let mut domain_use: BTreeMap<&str, usize> = BTreeMap::new();
    for login in &logins {
        if let Some(site) = &login.registrable {
            *domain_use.entry(site.as_str()).or_default() += 1;
        }
    }
    let lookalikes = own_lookalikes(&domain_use);

    let catalog = options
        .site_breaches
        .as_ref()
        .unwrap_or_else(|| breaches::bundled());
    let breach_index = breaches::BreachIndex::new(&catalog.breaches);
    let mut breached_sites: BTreeMap<String, breaches::BreachedSite> = BTreeMap::new();

    let exposures: Vec<(&str, &BreachInfo)> = options
        .exposed_emails
        .iter()
        .flat_map(|e| e.breaches.iter().map(move |b| (e.email.as_str(), b)))
        .collect();

    for login in &logins {
        let id = login.item.id.as_str();
        let data = &login.item.data;
        let site = login.registrable.clone();
        let support = login
            .url
            .as_ref()
            .filter(|u| matches!(u.scheme.as_str(), "http" | "https"))
            .and_then(|u| sites::lookup(&u.host));
        let has_totp = data.field("totp").is_some();
        let has_passkey = !data.passkeys.is_empty();
        let mut push = |finding: Finding| findings.push(finding);

        if let Some(password) = login.password {
            if let Some(count) = options
                .breach_counts
                .as_ref()
                .and_then(|c| c.get(id))
                .filter(|c| **c > 0)
            {
                let mut f = Finding::new(FindingKind::Breached, id);
                f.breach_count = Some(*count);
                push(f);
            }
            if reused_ids.contains(id) {
                let mut f = Finding::new(FindingKind::Reused, id);
                f.related = group_of(&reused_groups, id);
                push(f);
            }
            let score = strengths.get(password).copied().unwrap_or(0);
            if score <= 1 {
                let mut f = Finding::new(FindingKind::Weak, id);
                f.strength = Some(score);
                push(f);
            }
            let related = group_of(&similar_groups, id);
            let base = similar::password_base(password);
            let like_previous = base.is_some()
                && data
                    .password_history
                    .iter()
                    .any(|h| h.value != password && similar::password_base(&h.value) == base);
            if !related.is_empty() || like_previous {
                let mut f = Finding::new(FindingKind::Similar, id);
                f.related = related;
                f.similar_to_previous = like_previous;
                push(f);
            }
            if options.old_after_days > 0 {
                let set_at = data
                    .password_history
                    .iter()
                    .map(|h| h.replaced_at)
                    .max()
                    .filter(|t| *t > 0)
                    .or(Some(login.item.created_at).filter(|t| *t > 0));
                if let Some(set_at) = set_at {
                    let days = (options.now - set_at) / DAY_MS;
                    if days > i64::from(options.old_after_days) {
                        let mut f = Finding::new(FindingKind::Old, id);
                        f.age_days = Some(u32::try_from(days).unwrap_or(u32::MAX));
                        push(f);
                    }
                }
            }
            if has_totp {
                push(Finding::new(FindingKind::TotpInSameItem, id));
            }
            if data.field("username").is_none() {
                push(Finding::new(FindingKind::MissingUsername, id));
            }
            if login.url.is_none() {
                push(Finding::new(FindingKind::MissingUrl, id));
            }
        }
        if let Some(url) = &login.url {
            if url.scheme == "http" && !domain::is_ip_or_local(&url.host) {
                let mut f = Finding::new(FindingKind::InsecureUrl, id);
                f.domain = site.clone();
                push(f);
            }
        }
        if let Some(site_name) = &site {
            if let Some(found) = lookalikes.get(site_name) {
                let mut f = Finding::new(FindingKind::Lookalike, id);
                f.domain = Some(site_name.clone());
                f.lookalike_of = Some(found.looks_like.clone()).filter(|s| !s.is_empty());
                f.lookalike_reason = Some(found.reason);
                f.related = logins
                    .iter()
                    .filter(|o| o.registrable.as_deref() == Some(found.looks_like.as_str()))
                    .map(|o| o.item.id.clone())
                    .collect();
                push(f);
            }
        }
        if let Some(support) = &support {
            if login.password.is_some()
                && !has_totp
                && !has_passkey
                && (support.totp || support.security_key)
            {
                let mut f = Finding::new(FindingKind::MissingTwoFactor, id);
                f.domain = Some(support.domain.clone());
                f.documentation_url = support.two_factor_docs.clone();
                push(f);
            }
            if !has_passkey && support.passkey_sign_in {
                let mut f = Finding::new(FindingKind::PasskeyAvailable, id);
                f.domain = Some(support.domain.clone());
                f.documentation_url = support.passkey_docs.clone();
                push(f);
            }
        }
        if let Some(site_name) = &site {
            let emails: Vec<String> = data
                .fields
                .iter()
                .filter(|f| f.id == "username" || f.field_type == "email")
                .map(|f| f.value.trim().to_lowercase())
                .filter(|v| v.contains('@'))
                .collect();
            let mut matched: Vec<&BreachInfo> = Vec::new();
            let mut email = None;
            for (address, breach) in &exposures {
                let breach_site =
                    domain::idna_pair(&breach.domain).map(|(_, u)| domain::registrable_domain(&u));
                if breach_site.as_deref() == Some(site_name.as_str())
                    && emails.contains(&address.to_lowercase())
                {
                    email.get_or_insert_with(|| address.to_string());
                    matched.push(breach);
                }
            }
            if !matched.is_empty() {
                let mut f = Finding::new(FindingKind::ExposedEmail, id);
                f.email = email;
                f.domain = Some(site_name.clone());
                f.breaches = matched.iter().map(|b| b.title.clone()).collect();
                push(f);
            }
        }
        if let (Some(_), Some(url)) = (login.password, &login.url) {
            if matches!(url.scheme.as_str(), "http" | "https") {
                if let Some(f) = site_breach_finding(login, url, &breach_index, &mut breached_sites)
                {
                    push(f);
                }
            }
        }
        if duplicate_groups.iter().flatten().any(|m| m == id) {
            let mut f = Finding::new(FindingKind::Duplicate, id);
            f.related = group_of(&duplicate_groups, id);
            push(f);
        }
    }

    // Cards and documents.
    let today = options.now.div_euclid(DAY_MS);
    for item in active.iter().filter(|i| i.data.category != "login") {
        let id = item.id.as_str();
        let expiry = item
            .data
            .fields
            .iter()
            .filter(|f| is_expiry_field(f))
            .find_map(|f| expiry::parse(&f.value));
        if let Some(expiry) = expiry {
            let days_left = expiry.last_day() - today;
            let kind = if days_left < 0 {
                Some(FindingKind::Expired)
            } else if days_left <= i64::from(options.expiring_within_days) {
                Some(FindingKind::Expiring)
            } else {
                None
            };
            if let Some(kind) = kind {
                let mut f = Finding::new(kind, id);
                f.expires = Some(expiry.display());
                f.days_left = Some(days_left);
                findings.push(f);
            }
        }
        if item.data.category == "card" && duplicate_groups.iter().flatten().any(|m| m == id) {
            let mut f = Finding::new(FindingKind::Duplicate, id);
            f.related = group_of(&duplicate_groups, id);
            findings.push(f);
        }
    }

    findings.retain(|f| enabled(f.kind));
    let by_id: HashMap<&str, &AnalysisItem> = active.iter().map(|i| (i.id.as_str(), *i)).collect();
    for finding in &mut findings {
        if let Some(item) = by_id.get(finding.item_id.as_str()) {
            finding.dismissed = item
                .data
                .security_ignore
                .iter()
                .any(|code| code == finding.kind.as_str());
        }
    }
    // Order: severity, kind, then the bigger problem first.
    findings.sort_by(|a, b| {
        (a.dismissed, a.severity, a.kind)
            .cmp(&(b.dismissed, b.severity, b.kind))
            .then(b.breach_count.cmp(&a.breach_count))
            .then(b.related.len().cmp(&a.related.len()))
            .then(a.item_id.cmp(&b.item_id))
    });

    // Score: each scored item loses up to its full share, combining the
    // weights of its open findings (1 − Π(1 − w)).
    let login_count = logins.iter().filter(|l| l.password.is_some()).count();
    let mut scored_ids: BTreeSet<&str> = logins
        .iter()
        .filter(|l| l.password.is_some())
        .map(|l| l.item.id.as_str())
        .collect();
    for finding in findings
        .iter()
        .filter(|f| !f.dismissed && f.severity.weight() > 0.0)
    {
        scored_ids.insert(finding.item_id.as_str());
    }
    let scored = scored_ids.len();
    // Open, scored findings per item, most severe first (findings are sorted).
    let mut open_by_item: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in findings
        .iter()
        .filter(|f| !f.dismissed && f.severity.weight() > 0.0)
    {
        open_by_item
            .entry(finding.item_id.as_str())
            .or_default()
            .push(finding);
    }
    let mut item_penalty: BTreeMap<&str, f64> = BTreeMap::new();
    let mut kind_points: HashMap<FindingKind, f64> = HashMap::new();
    for (id, open) in &open_by_item {
        let penalty = 1.0
            - open
                .iter()
                .map(|f| 1.0 - f.severity.weight())
                .product::<f64>();
        let total_weight: f64 = open.iter().map(|f| f.severity.weight()).sum();
        for f in open.iter() {
            *kind_points.entry(f.kind).or_default() +=
                100.0 * penalty / scored as f64 * f.severity.weight() / total_weight;
        }
        item_penalty.insert(id, penalty);
    }
    let lost: f64 = item_penalty.values().sum();
    let score = if scored == 0 {
        100
    } else {
        (100.0 * (1.0 - lost / scored as f64))
            .round()
            .clamp(0.0, 100.0) as u8
    };
    let rating = match score {
        90.. => Rating::Excellent,
        75.. => Rating::Good,
        50.. => Rating::Fair,
        _ => Rating::Poor,
    };

    let categories = FindingKind::ALL
        .into_iter()
        .map(|kind| {
            let of_kind = findings.iter().filter(|f| f.kind == kind);
            CategorySummary {
                kind,
                severity: kind.severity(),
                count: of_kind.clone().filter(|f| !f.dismissed).count() as u32,
                dismissed: of_kind.filter(|f| f.dismissed).count() as u32,
                points: kind_points.get(&kind).copied().unwrap_or(0.0).round() as u32,
                checked: enabled(kind)
                    && (kind != FindingKind::Breached || options.breach_counts.is_some())
                    && (kind != FindingKind::ExposedEmail || !options.exposed_emails.is_empty())
                    && (kind != FindingKind::Old || options.old_after_days > 0),
            }
        })
        .collect();

    let mut fix_first: Vec<Priority> = item_penalty
        .iter()
        .map(|(id, penalty)| {
            let open = &open_by_item[id];
            let top = open[0];
            Priority {
                item_id: (*id).to_owned(),
                kinds: open.iter().map(|f| f.kind).collect(),
                severity: top.severity,
                fix: top.fix,
                points: (100.0 * penalty / scored as f64).round().max(1.0) as u32,
            }
        })
        .collect();
    fix_first.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.points.cmp(&a.points))
            .then(a.kinds[0].cmp(&b.kinds[0]))
            .then(b.kinds.len().cmp(&a.kinds.len()))
            .then(a.item_id.cmp(&b.item_id))
    });
    fix_first.truncate(FIX_FIRST_LEN);

    let (two_factor_date, passkey_date) = sites::snapshot_dates();
    let mut breached_sites: Vec<breaches::BreachedSite> = if enabled(FindingKind::BreachedSite) {
        breached_sites.into_values().collect()
    } else {
        Vec::new()
    };
    breached_sites.sort_by(|a, b| {
        b.is_open()
            .cmp(&a.is_open())
            .then(b.added_date.cmp(&a.added_date))
            .then(a.name.cmp(&b.name))
    });
    SecurityReport {
        score,
        rating,
        items: active.len() as u32,
        logins: login_count as u32,
        scored: scored as u32,
        breach_checked: options.breach_counts.is_some(),
        categories,
        findings,
        fix_first,
        reused_groups,
        similar_groups,
        duplicate_groups,
        directory_dates: (two_factor_date.to_owned(), passkey_date.to_owned()),
        breached_sites,
        breach_catalog: CatalogInfo {
            version: catalog.version.clone(),
            updated_at: catalog.updated_at,
            entries: catalog.breaches.len() as u32,
            bundled: options.site_breaches.is_none(),
            source: breaches::SOURCE_NAME.into(),
            source_url: breaches::SOURCE_URL.into(),
            license: breaches::SOURCE_LICENSE.into(),
        },
    }
}

/// When the login's current password was set: the newest password-history
/// entry, else when the item was created; 0 when unknown.
fn password_set_at(item: &AnalysisItem) -> i64 {
    item.data
        .password_history
        .iter()
        .map(|h| h.replaced_at)
        .max()
        .filter(|t| *t > 0)
        .unwrap_or(item.created_at.max(0))
}

/// The `breached_site` finding of a login with a password and a web
/// address, if a breach of its site concerns its current password. Records
/// every matching breach (also fixed ones) in `sites`.
fn site_breach_finding(
    login: &Login,
    url: &domain::ParsedUrl,
    index: &breaches::BreachIndex,
    sites: &mut BTreeMap<String, breaches::BreachedSite>,
) -> Option<Finding> {
    use breaches::Exposure;
    let id = login.item.id.as_str();
    let set_at = password_set_at(login.item);
    let mut open: Vec<(&breaches::SiteBreach, bool)> = Vec::new();
    for breach in index.for_host(&url.host) {
        let exposure = breaches::exposure(breach, set_at, login.item.created_at);
        if exposure == Exposure::NotAffected {
            continue;
        }
        let site = sites
            .entry(breach.name.clone())
            .or_insert_with(|| breaches::BreachedSite::new(breach));
        let list = match exposure {
            Exposure::Affected => &mut site.affected,
            Exposure::Possibly => &mut site.possibly,
            _ => &mut site.fixed,
        };
        list.push(id.to_owned());
        if matches!(exposure, Exposure::Affected | Exposure::Possibly) {
            open.push((breach, exposure == Exposure::Possibly));
        }
    }
    if open.is_empty() {
        return None;
    }
    let possibly = open.iter().all(|(_, possibly)| *possibly);
    let credentials = open.iter().any(|(b, _)| b.exposes_credentials());
    let mut f = Finding::new(FindingKind::BreachedSite, id);
    f.severity = match (credentials, possibly) {
        (true, false) => Severity::High,
        (true, true) => Severity::Medium,
        (false, false) => Severity::Low,
        (false, true) => Severity::Info,
    };
    f.possibly = possibly;
    f.domain = login.registrable.clone();
    f.documentation_url = Some(format!("https://{}/.well-known/change-password", url.host));
    // The index lists the newest breach first.
    f.breach_date = Some(open[0].0.breach_date.clone()).filter(|d| !d.is_empty());
    for (breach, _) in &open {
        f.breaches.push(breach.display_title().to_owned());
        f.breach_names.push(breach.name.clone());
        for class in &breach.data_classes {
            if !f.data_classes.contains(class) {
                f.data_classes.push(class.clone());
            }
        }
    }
    Some(f)
}

/// Lookalikes among the user's own login domains (registrable, Unicode,
/// with how many logins use each) and against well-known sites. Linear in
/// the number of domains except for typo checks, which only compare
/// domains with the same ending and similar length.
fn own_lookalikes(domain_use: &BTreeMap<&str, usize>) -> BTreeMap<String, lookalike::Lookalike> {
    use lookalike::{Lookalike, compare, has_mixed_script, skeleton};
    let mut found: BTreeMap<String, Lookalike> = BTreeMap::new();
    fn flag(
        found: &mut BTreeMap<String, Lookalike>,
        domain: &str,
        looks_like: &str,
        reason: LookalikeReason,
        saved: bool,
    ) {
        found.entry(domain.to_owned()).or_insert_with(|| Lookalike {
            domain: domain.to_owned(),
            looks_like: looks_like.to_owned(),
            reason,
            saved,
        });
    }
    let popular = |domain: &str| sites::known_by_skeleton(&skeleton(domain)) == Some(domain);
    // Same skeleton: everything but the most used (then ASCII, then
    // shortest) domain imitates it.
    let mut by_skeleton: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for domain in domain_use.keys() {
        by_skeleton
            .entry(skeleton(domain))
            .or_default()
            .push(domain);
    }
    for members in by_skeleton.values().filter(|m| m.len() > 1) {
        let target = members
            .iter()
            .copied()
            .max_by_key(|d| (domain_use[d], d.is_ascii(), std::cmp::Reverse(d.len())))
            .unwrap_or_default();
        for domain in members.iter().copied().filter(|d| *d != target) {
            if let Some(reason) = compare(domain, target) {
                flag(&mut found, domain, target, reason, true);
            }
        }
    }
    // Typos: the less used domain imitates the more used (or well-known) one.
    let mut by_suffix: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for domain in domain_use.keys().filter(|d| d.is_ascii()) {
        let (label, suffix) = domain::split_label(domain);
        if label.len() >= 5 {
            by_suffix.entry(suffix).or_default().push(domain);
        }
    }
    for members in by_suffix.values() {
        for (i, a) in members.iter().enumerate() {
            for b in &members[i + 1..] {
                let (la, lb) = (domain::split_label(a).0, domain::split_label(b).0);
                if la.len().abs_diff(lb.len()) > 1 || lookalike::edit_distance(la, lb, 1) != 1 {
                    continue;
                }
                let (ua, ub) = (domain_use[a], domain_use[b]);
                let (imitation, target) = if ua < ub || (ua == ub && popular(b) && !popular(a)) {
                    (*a, *b)
                } else if ub < ua || (ua == ub && popular(a) && !popular(b)) {
                    (*b, *a)
                } else {
                    continue;
                };
                flag(&mut found, imitation, target, LookalikeReason::Typo, true);
            }
        }
    }
    for domain in domain_use.keys() {
        if found.contains_key(*domain) {
            continue;
        }
        if let Some(known) = sites::known_by_skeleton(&skeleton(domain)) {
            let known = domain::idna_pair(known).map_or_else(|| known.to_owned(), |(_, u)| u);
            if let Some(reason) = compare(domain, &known) {
                flag(&mut found, domain, &known, reason, false);
                continue;
            }
        }
        if !domain.is_ascii() && has_mixed_script(domain::split_label(domain).0) {
            flag(&mut found, domain, "", LookalikeReason::MixedScript, false);
        }
    }
    found
}

/// Adds or removes a dismissal in an item's JSON object (`securityIgnore`).
/// Returns whether anything changed.
pub fn set_dismissed(
    item: &mut serde_json::Map<String, serde_json::Value>,
    kind: FindingKind,
    dismissed: bool,
) -> bool {
    let mut codes: Vec<String> = item
        .get(IGNORE_KEY)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let had = codes.iter().any(|c| c == kind.as_str());
    if had == dismissed {
        return false;
    }
    if dismissed {
        codes.push(kind.as_str().to_owned());
    } else {
        codes.retain(|c| c != kind.as_str());
    }
    if codes.is_empty() {
        item.remove(IGNORE_KEY);
    } else {
        item.insert(IGNORE_KEY.to_owned(), codes.into());
    }
    true
}

#[cfg(test)]
mod tests;
