//! The vault security analysis for iOS and Android (additive API): the
//! report with score, findings and "fix these first", dismissals, breach
//! check routing, email breach monitoring, lookalike checks and email
//! aliases. See `docs/architecture/security-analysis.md`.
//!
//! Kinds, severities and fixes are stable string codes (`breached`,
//! `critical`, `change_password`, …) so that newer cores can add kinds
//! without breaking older apps; apps map unknown codes to a generic text.

use passbox_client as client;

use crate::{PassboxClient, PassboxError, Result};

/// Settings for the report (device-local app preferences).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityReportOptions {
    /// Passwords older than this count as old; 0 turns it off. Default 365.
    pub old_after_days: u32,
    /// Cards and documents expiring within this many days are flagged. Default 60.
    pub expiring_within_days: u32,
    /// Finding kinds the user turned off.
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityFinding {
    /// `breached`, `exposed_email`, `breached_site`, `lookalike`, `reused`,
    /// `weak`, `similar`,
    /// `insecure_url`, `missing_two_factor`, `expired`, `expiring`, `old`,
    /// `passkey_available`, `duplicate`, `missing_url`, `missing_username`,
    /// `totp_in_same_item`.
    pub kind: String,
    /// `critical`, `high`, `medium`, `low` or `info`.
    pub severity: String,
    pub item_id: String,
    /// `change_password`, `enable_two_factor`, `add_passkey`, `use_https`,
    /// `check_website`, `renew`, `review_duplicates`, `add_website`,
    /// `add_username`, `separate_totp`.
    pub fix: String,
    pub related: Vec<String>,
    pub dismissed: bool,
    pub breach_count: Option<u64>,
    pub strength: Option<u8>,
    pub age_days: Option<u32>,
    pub domain: Option<String>,
    pub documentation_url: Option<String>,
    pub lookalike_of: Option<String>,
    /// `homograph`, `mixed_script`, `confusable` or `typo`.
    pub lookalike_reason: Option<String>,
    /// `YYYY-MM` or `YYYY-MM-DD`.
    pub expires: Option<String>,
    pub days_left: Option<i64>,
    pub email: Option<String>,
    pub breaches: Vec<String>,
    pub similar_to_previous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityCategorySummary {
    pub kind: String,
    pub severity: String,
    /// Items with this finding that are not dismissed.
    pub count: u32,
    pub dismissed: u32,
    /// Score points this category costs.
    pub points: u32,
    /// False when turned off or not checked yet (breaches before a check).
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityPriority {
    pub item_id: String,
    pub kinds: Vec<String>,
    pub severity: String,
    pub fix: String,
    /// Score points gained by fixing this item.
    pub points: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityReport {
    /// 0–100, higher is better.
    pub score: u8,
    /// `excellent`, `good`, `fair` or `poor`.
    pub rating: String,
    pub items: u32,
    pub logins: u32,
    pub breach_checked: bool,
    /// One per kind, in priority order.
    pub categories: Vec<SecurityCategorySummary>,
    /// All findings, dismissed ones included, most important first.
    pub findings: Vec<SecurityFinding>,
    /// Up to ten items to fix first.
    pub fix_first: Vec<SecurityPriority>,
    pub reused_groups: Vec<Vec<String>>,
    pub similar_groups: Vec<Vec<String>>,
    pub duplicate_groups: Vec<Vec<String>>,
    /// Snapshot dates of the bundled 2FA and passkey site lists.
    pub two_factor_list_date: String,
    pub passkey_list_date: String,
}

/// A website that looks like another one (phishing warning).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LookalikeMatch {
    pub domain: String,
    /// The domain it imitates; empty for `mixed_script`.
    pub looks_like: String,
    pub reason: String,
    /// `looks_like` is one of the user's saved domains.
    pub saved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmailBreach {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breach_date: String,
    pub data_classes: Vec<String>,
    pub first_seen_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MonitoredEmail {
    pub id: String,
    pub email: String,
    pub verified: bool,
    pub checked_at: i64,
    pub check_error: Option<String>,
    pub breaches: Vec<EmailBreach>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmailMonitoring {
    /// The server operator configured Have I Been Pwned.
    pub available: bool,
    pub check_interval_hours: u64,
    pub emails: Vec<MonitoredEmail>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AliasService {
    pub item_id: String,
    /// `simplelogin`, `addy`, `fastmail`, `duckduckgo`, `firefox_relay`.
    pub provider: String,
    pub provider_name: String,
    pub title: String,
}

/// The breach catalogue on this device ("compromised websites").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BreachCatalogStatus {
    /// The server offers the catalogue; otherwise the bundled snapshot is used.
    pub available: bool,
    /// A newer catalogue was downloaded by this call.
    pub changed: bool,
    pub version: String,
    /// Newest added or modified date of the entries (Unix ms).
    pub updated_at: i64,
    pub entries: u32,
    pub bundled: bool,
    /// Attribution to show with breach data: "Have I Been Pwned".
    pub source: String,
    pub source_url: String,
    pub license: String,
}

/// A breached website that concerns saved logins (`breached_site` findings).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BreachedSiteInfo {
    /// Have I Been Pwned's name (matches `SecurityFinding.breaches` titles).
    pub name: String,
    pub title: String,
    pub domain: String,
    /// `YYYY-MM-DD`.
    pub breach_date: String,
    /// ISO 8601: when the breach was published.
    pub added_date: String,
    pub pwn_count: u64,
    /// Have I Been Pwned's names (`Passwords`, `Email addresses`, …).
    pub data_classes: Vec<String>,
    pub verified: bool,
    /// Keep the name off the lock screen.
    pub sensitive: bool,
    /// Passwords or other sign-in secrets were exposed.
    pub exposes_credentials: bool,
    /// Item IDs: password older than the breach.
    pub affected: Vec<String>,
    /// Item IDs: unknown when the password was set.
    pub possibly: Vec<String>,
    /// Item IDs: password changed after the breach.
    pub fixed: Vec<String>,
}

fn site_info(site: client::BreachedSite) -> BreachedSiteInfo {
    BreachedSiteInfo {
        name: site.name,
        title: site.title,
        domain: site.domain,
        breach_date: site.breach_date,
        added_date: site.added_date,
        pwn_count: site.pwn_count,
        data_classes: site.data_classes,
        verified: site.verified,
        sensitive: site.sensitive,
        exposes_credentials: site.exposes_credentials,
        affected: site.affected,
        possibly: site.possibly,
        fixed: site.fixed,
    }
}

fn report_options(options: &SecurityReportOptions) -> client::ReportOptions {
    client::ReportOptions {
        old_after_days: options.old_after_days,
        expiring_within_days: options.expiring_within_days,
        disabled: options
            .disabled
            .iter()
            .filter_map(|c| client::FindingKind::parse(c))
            .collect(),
    }
}

fn rating(rating: client::Rating) -> String {
    match rating {
        client::Rating::Excellent => "excellent",
        client::Rating::Good => "good",
        client::Rating::Fair => "fair",
        client::Rating::Poor => "poor",
    }
    .to_owned()
}

fn invalid(message: &str) -> PassboxError {
    PassboxError::from(client::Error::InvalidData(message.to_owned()))
}

fn monitored(email: client::MonitoredEmail) -> MonitoredEmail {
    MonitoredEmail {
        id: email.id,
        email: email.email,
        verified: email.verified,
        checked_at: email.checked_at,
        check_error: email.check_error,
        breaches: email
            .breaches
            .into_iter()
            .map(|b| EmailBreach {
                name: b.name,
                title: b.title,
                domain: b.domain,
                breach_date: b.breach_date,
                data_classes: b.data_classes,
                first_seen_at: b.first_seen_at,
            })
            .collect(),
    }
}

/// Default report settings.
#[uniffi::export]
pub fn default_security_report_options() -> SecurityReportOptions {
    let defaults = client::ReportOptions::default();
    SecurityReportOptions {
        old_after_days: defaults.old_after_days,
        expiring_within_days: defaults.expiring_within_days,
        disabled: Vec::new(),
    }
}

#[uniffi::export]
impl PassboxClient {
    /// The vault security analysis ("Sicherheits-Check"), computed on the
    /// device. Breach findings appear after `breached_items()`, email
    /// exposures after `email_monitoring()`. Blocking.
    pub fn security_report(&self, options: SecurityReportOptions) -> Result<SecurityReport> {
        let report = self.inner.security_report(&client::ReportOptions {
            old_after_days: options.old_after_days,
            expiring_within_days: options.expiring_within_days,
            disabled: options
                .disabled
                .iter()
                .filter_map(|c| client::FindingKind::parse(c))
                .collect(),
        })?;
        Ok(SecurityReport {
            score: report.score,
            rating: rating(report.rating),
            items: report.items,
            logins: report.logins,
            breach_checked: report.breach_checked,
            categories: report
                .categories
                .iter()
                .map(|c| SecurityCategorySummary {
                    kind: c.kind.as_str().to_owned(),
                    severity: c.severity.as_str().to_owned(),
                    count: c.count,
                    dismissed: c.dismissed,
                    points: c.points,
                    checked: c.checked,
                })
                .collect(),
            findings: report
                .findings
                .into_iter()
                .map(|f| SecurityFinding {
                    kind: f.kind.as_str().to_owned(),
                    severity: f.severity.as_str().to_owned(),
                    item_id: f.item_id,
                    fix: f.fix.as_str().to_owned(),
                    related: f.related,
                    dismissed: f.dismissed,
                    breach_count: f.breach_count,
                    strength: f.strength,
                    age_days: f.age_days,
                    domain: f.domain,
                    documentation_url: f.documentation_url,
                    lookalike_of: f.lookalike_of,
                    lookalike_reason: f.lookalike_reason.map(|r| r.as_str().to_owned()),
                    expires: f.expires,
                    days_left: f.days_left,
                    email: f.email,
                    breaches: f.breaches,
                    similar_to_previous: f.similar_to_previous,
                })
                .collect(),
            fix_first: report
                .fix_first
                .into_iter()
                .map(|p| SecurityPriority {
                    item_id: p.item_id,
                    kinds: p.kinds.iter().map(|k| k.as_str().to_owned()).collect(),
                    severity: p.severity.as_str().to_owned(),
                    fix: p.fix.as_str().to_owned(),
                    points: p.points,
                })
                .collect(),
            reused_groups: report.reused_groups,
            similar_groups: report.similar_groups,
            duplicate_groups: report.duplicate_groups,
            two_factor_list_date: report.directory_dates.0,
            passkey_list_date: report.directory_dates.1,
        })
    }

    /// Checks the server's breach catalogue and downloads it when it is
    /// newer than the one on this device (one document for everyone; the
    /// server never learns which sites the user has). Works while locked.
    /// Blocking; call it at start, on refresh and from background refresh.
    pub fn refresh_breach_catalog(&self) -> Result<BreachCatalogStatus> {
        let status = self.inner.refresh_breach_catalog()?;
        Ok(BreachCatalogStatus {
            available: status.available,
            changed: status.changed,
            version: status.version,
            updated_at: status.updated_at,
            entries: status.entries,
            bundled: status.bundled,
            source: "Have I Been Pwned".into(),
            source_url: "https://haveibeenpwned.com/".into(),
            license: "CC BY 4.0".into(),
        })
    }

    /// Breached websites of saved logins (affected, possibly affected and
    /// fixed), open ones first. Needs an unlocked vault. Blocking.
    pub fn breached_sites(&self, options: SecurityReportOptions) -> Result<Vec<BreachedSiteInfo>> {
        let report = self.inner.security_report(&report_options(&options))?;
        Ok(report.breached_sites.into_iter().map(site_info).collect())
    }

    /// Breached websites with open findings that were published after the
    /// last `acknowledge_breach_alerts()`: show a local notification for
    /// them (only when the list is not empty), then acknowledge.
    pub fn breach_alerts(&self, options: SecurityReportOptions) -> Result<Vec<BreachedSiteInfo>> {
        Ok(self
            .inner
            .breach_alerts(&report_options(&options))?
            .into_iter()
            .map(site_info)
            .collect())
    }

    /// Marks the current catalogue as announced.
    pub fn acknowledge_breach_alerts(&self) -> Result<()> {
        Ok(self.inner.acknowledge_breach_alerts()?)
    }

    /// Dismisses or restores one finding of one item (stored encrypted in
    /// the item, synced).
    pub fn dismiss_finding(&self, item_id: String, kind: String, dismissed: bool) -> Result<()> {
        let kind = client::FindingKind::parse(&kind).ok_or_else(|| invalid("unknown finding"))?;
        Ok(self.inner.dismiss_finding(&item_id, kind, dismissed)?)
    }

    /// Whether `host` looks like a saved login domain or a well-known site.
    pub fn check_lookalike(&self, host: String) -> Result<Option<LookalikeMatch>> {
        Ok(self.inner.check_lookalike(&host)?.map(|l| LookalikeMatch {
            domain: l.domain,
            looks_like: l.looks_like,
            reason: l.reason.as_str().to_owned(),
            saved: l.saved,
        }))
    }

    /// How breach checks reach Have I Been Pwned: `auto` (through the
    /// Passbox server when it offers it), `server` or `direct`.
    pub fn set_breach_mode(&self, mode: String) -> Result<()> {
        let mode = match mode.as_str() {
            "auto" => client::BreachMode::Auto,
            "server" => client::BreachMode::Server,
            "direct" => client::BreachMode::Direct,
            _ => return Err(invalid("breach mode must be auto, server or direct")),
        };
        self.inner.set_breach_mode(mode);
        Ok(())
    }

    pub fn breach_mode(&self) -> String {
        match self.inner.breach_mode() {
            client::BreachMode::Auto => "auto",
            client::BreachMode::Server => "server",
            client::BreachMode::Direct => "direct",
        }
        .to_owned()
    }

    /// The server's email breach monitoring and its results.
    pub fn email_monitoring(&self) -> Result<EmailMonitoring> {
        let m = self.inner.email_monitoring()?;
        Ok(EmailMonitoring {
            available: m.available,
            check_interval_hours: m.check_interval_hours,
            emails: m.emails.into_iter().map(monitored).collect(),
        })
    }

    /// Starts monitoring an address; the server mails a confirmation code.
    /// The address is sent to Have I Been Pwned once confirmed.
    pub fn add_monitored_email(&self, email: String) -> Result<MonitoredEmail> {
        Ok(monitored(self.inner.add_monitored_email(&email)?))
    }

    pub fn verify_monitored_email(&self, id: String, code: String) -> Result<MonitoredEmail> {
        Ok(monitored(self.inner.verify_monitored_email(&id, &code)?))
    }

    pub fn check_monitored_email(&self, id: String) -> Result<MonitoredEmail> {
        Ok(monitored(self.inner.check_monitored_email(&id)?))
    }

    pub fn remove_monitored_email(&self, id: String) -> Result<()> {
        Ok(self.inner.remove_monitored_email(&id)?)
    }

    /// Alias services set up in the vault ("Alias erstellen").
    pub fn alias_services(&self) -> Result<Vec<AliasService>> {
        Ok(self
            .inner
            .alias_services()?
            .into_iter()
            .map(|s| AliasService {
                item_id: s.item_id,
                provider: s.provider.as_str().to_owned(),
                provider_name: s.provider.name().to_owned(),
                title: s.title,
            })
            .collect())
    }

    /// Saves an alias service's API key as a vault item; returns its ID.
    pub fn add_alias_service(
        &self,
        vault_id: String,
        provider: String,
        api_key: String,
        base_url: Option<String>,
        alias_domain: Option<String>,
    ) -> Result<String> {
        let provider = client::AliasProvider::parse(&provider)
            .ok_or_else(|| invalid("unknown alias service"))?;
        Ok(self.inner.add_alias_service(
            &vault_id,
            provider,
            &api_key,
            base_url.as_deref(),
            alias_domain.as_deref(),
        )?)
    }

    /// Creates an email alias for `for_domain`; the request goes directly
    /// to the provider. Blocking.
    pub fn create_alias(&self, service_item_id: String, for_domain: String) -> Result<String> {
        Ok(self.inner.create_alias(&service_item_id, &for_domain)?)
    }
}
