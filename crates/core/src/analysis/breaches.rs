//! Breached websites ("compromised websites"): which saved logins belong to
//! a site that had a data breach after their password was set.
//!
//! The catalogue of breaches is public data from Have I Been Pwned (CC BY
//! 4.0). Clients get it from their Passbox server
//! (`GET /api/v1/breaches/catalog`, the same list for everyone) or use the
//! snapshot bundled here, and match it against their decrypted items on the
//! device. Nobody learns which sites a user has an account with.
//!
//! A login matches a breach when its website belongs to the breached domain
//! (the registrable domain; for a breach of a subdomain such as
//! `forum.example.com`, that subdomain and its children) and its current
//! password was set before the breach became public (Have I Been Pwned's
//! `AddedDate`). Breach dates are often approximate and data is usually
//! exposed until the breach is discovered, so the publication date is the
//! safe cutoff. A password changed after it resolves the finding.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::domain::{idna_pair, registrable_domain};
use super::expiry::days_from_civil;

const SNAPSHOT: &str = include_str!("../../data/site-breaches.tsv");
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// Data classes that let an attacker sign in (or reset a password).
pub const CREDENTIAL_CLASSES: [&str; 6] = [
    "Passwords",
    "Password hints",
    "Historical passwords",
    "Auth tokens",
    "Security questions and answers",
    "PINs",
];

/// Where the catalogue data comes from (shown with every breach).
pub const SOURCE_NAME: &str = "Have I Been Pwned";
pub const SOURCE_URL: &str = "https://haveibeenpwned.com/";
pub const SOURCE_LICENSE: &str = "CC BY 4.0";

/// One breach of the catalogue (the fields clients need).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SiteBreach {
    /// Have I Been Pwned's stable name (`Adobe`).
    pub name: String,
    pub title: String,
    /// The breached site (`adobe.com`), lower case.
    pub domain: String,
    /// When the breach happened (`YYYY-MM-DD`, often approximate).
    pub breach_date: String,
    /// When it was published in Have I Been Pwned (ISO 8601).
    pub added_date: String,
    /// When the entry last changed (ISO 8601).
    pub modified_date: String,
    /// Accounts in the breach.
    pub pwn_count: u64,
    /// Kinds of data exposed (`Passwords`, `Email addresses`, …).
    pub data_classes: Vec<String>,
    /// Have I Been Pwned verified the breach.
    pub verified: bool,
    /// A sensitive breach (for example an adult site): apps keep its name
    /// off the lock screen.
    pub sensitive: bool,
}

impl SiteBreach {
    /// Passwords or other sign-in secrets were exposed.
    pub fn exposes_credentials(&self) -> bool {
        self.data_classes
            .iter()
            .any(|c| CREDENTIAL_CLASSES.contains(&c.as_str()))
    }

    /// Unix ms after which a newly set password is not in the breach: the
    /// publication date, else the end of the breach day. `None` if neither
    /// can be read.
    pub fn cutoff(&self) -> Option<i64> {
        parse_date_ms(&self.added_date)
            .or_else(|| parse_date_ms(&self.breach_date).map(|t| t + DAY_MS))
    }

    /// The newest date of the entry (added or modified), Unix ms.
    pub fn changed_at(&self) -> i64 {
        parse_date_ms(&self.added_date)
            .unwrap_or(0)
            .max(parse_date_ms(&self.modified_date).unwrap_or(0))
    }

    /// The title, or the name when the title is empty.
    pub fn display_title(&self) -> &str {
        if self.title.is_empty() {
            &self.name
        } else {
            &self.title
        }
    }
}

/// The catalogue document (`GET /api/v1/breaches/catalog`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BreachCatalog {
    /// Changes whenever the content changes.
    pub version: String,
    /// The newest added or modified date of its entries (Unix ms).
    pub updated_at: i64,
    pub source: String,
    pub source_url: String,
    pub license: String,
    pub breaches: Vec<SiteBreach>,
}

impl BreachCatalog {
    /// The newest added or modified date of the entries.
    pub fn newest_change(breaches: &[SiteBreach]) -> i64 {
        breaches
            .iter()
            .map(SiteBreach::changed_at)
            .max()
            .unwrap_or(0)
    }
}

/// Parses `YYYY-MM-DD` with an optional `THH:MM[:SS[.fff]]Z` to Unix ms.
pub fn parse_date_ms(value: &str) -> Option<i64> {
    let value = value.trim();
    let (date, time) = match value.split_once(['T', ' ']) {
        Some((date, time)) => (date, Some(time)),
        None => (value, None),
    };
    let mut parts = date.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some()
        || !(1900..=2200).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let mut ms = days_from_civil(year, month, day) * DAY_MS;
    if let Some(time) = time {
        let time = time.trim_end_matches('Z');
        let mut parts = time.split(':');
        let hours: i64 = parts.next()?.parse().ok()?;
        let minutes: i64 = parts.next().unwrap_or("0").parse().ok()?;
        let seconds: f64 = parts.next().unwrap_or("0").parse().ok()?;
        if !(0..24).contains(&hours)
            || !(0..60).contains(&minutes)
            || !(0.0..61.0).contains(&seconds)
        {
            return None;
        }
        ms += (hours * 3600 + minutes * 60) * 1000 + (seconds * 1000.0) as i64;
    }
    Some(ms)
}

/// `YYYY-MM-DD` of a Unix ms timestamp (UTC).
pub fn date_string(ms: i64) -> String {
    // Inverse of `days_from_civil` (Howard Hinnant's algorithm).
    let z = ms.div_euclid(DAY_MS) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// `YYYY-MM-DDTHH:MM:SSZ` of a Unix ms timestamp (UTC).
pub fn datetime_string(ms: i64) -> String {
    let seconds = ms.div_euclid(1000).rem_euclid(24 * 60 * 60);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date_string(ms),
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// Whether a catalogue entry belongs in the list clients match against.
/// The server and the snapshot script apply the same rule: a domain is
/// needed, fabricated entries and spam lists (not a security compromise)
/// and retired breaches are left out.
pub fn include_in_catalog(domain: &str, fabricated: bool, spam_list: bool, retired: bool) -> bool {
    !domain.trim().is_empty() && !fabricated && !spam_list && !retired
}

/// The bundled snapshot (`crates/core/data/site-breaches.tsv`, written by
/// `scripts/update-breach-catalog.py`).
pub fn bundled() -> &'static BreachCatalog {
    static CATALOG: OnceLock<BreachCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let date = SNAPSHOT
            .lines()
            .next()
            .and_then(|line| line.split(" snapshot of ").nth(1))
            .and_then(|rest| rest.get(..10))
            .unwrap_or_default();
        let breaches: Vec<SiteBreach> = SNAPSHOT
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .filter_map(|line| {
                let cols: Vec<&str> = line.split('\t').collect();
                if cols.len() < 9 {
                    return None;
                }
                Some(SiteBreach {
                    name: cols[0].to_owned(),
                    title: cols[1].to_owned(),
                    domain: cols[2].to_owned(),
                    breach_date: cols[3].to_owned(),
                    added_date: cols[4].to_owned(),
                    modified_date: cols[5].to_owned(),
                    pwn_count: cols[6].parse().unwrap_or(0),
                    verified: cols[7].contains('v'),
                    sensitive: cols[7].contains('s'),
                    data_classes: cols[8]
                        .split(';')
                        .filter(|c| !c.is_empty())
                        .map(str::to_owned)
                        .collect(),
                })
            })
            .collect();
        BreachCatalog {
            version: format!("bundled-{date}"),
            updated_at: BreachCatalog::newest_change(&breaches),
            source: SOURCE_NAME.into(),
            source_url: SOURCE_URL.into(),
            license: SOURCE_LICENSE.into(),
            breaches,
        }
    })
}

/// Date of the bundled snapshot (`YYYY-MM-DD`).
pub fn bundled_date() -> &'static str {
    bundled().version.trim_start_matches("bundled-")
}

/// How an item relates to one breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// The current password was set before the breach became public.
    Affected,
    /// When the password was set is unknown.
    Possibly,
    /// The item existed before the breach and its password was changed
    /// after it.
    Fixed,
    /// The password was set after the breach (the item is newer).
    NotAffected,
}

/// Classifies an item's exposure to `breach`. `password_set_at` is when the
/// current password was set (the newest password-history entry, else when
/// the item was created; 0 when unknown); `created_at` when the item was
/// created (0 when unknown).
pub fn exposure(breach: &SiteBreach, password_set_at: i64, created_at: i64) -> Exposure {
    let Some(cutoff) = breach.cutoff() else {
        return Exposure::Possibly;
    };
    if password_set_at <= 0 {
        return Exposure::Possibly;
    }
    if password_set_at < cutoff {
        Exposure::Affected
    } else if created_at > 0 && created_at < cutoff {
        Exposure::Fixed
    } else {
        Exposure::NotAffected
    }
}

/// Breaches indexed by registrable domain (ASCII).
pub struct BreachIndex<'a> {
    by_site: HashMap<String, Vec<(&'a SiteBreach, String)>>,
}

impl<'a> BreachIndex<'a> {
    pub fn new(breaches: &'a [SiteBreach]) -> Self {
        let mut by_site: HashMap<String, Vec<(&'a SiteBreach, String)>> = HashMap::new();
        for breach in breaches {
            let Some((ascii, _)) = idna_pair(&breach.domain) else {
                continue;
            };
            let host = ascii.strip_prefix("www.").unwrap_or(&ascii).to_owned();
            if !host.contains('.') {
                continue;
            }
            by_site
                .entry(registrable_domain(&host))
                .or_default()
                .push((breach, host));
        }
        for list in by_site.values_mut() {
            list.sort_by_key(|(breach, _)| std::cmp::Reverse(breach.changed_at()));
        }
        Self { by_site }
    }

    /// Breaches of the site of `host` (an ASCII, lower-case host name). A
    /// breach of the registrable domain matches every host under it; a
    /// breach of a subdomain only that subdomain and its children.
    pub fn for_host(&self, host: &str) -> Vec<&'a SiteBreach> {
        let host = host.trim_end_matches('.');
        let site = registrable_domain(host);
        self.by_site
            .get(&site)
            .map(|list| {
                list.iter()
                    .filter(|(_, breached)| {
                        breached == &site
                            || host == breached
                            || host.ends_with(&format!(".{breached}"))
                    })
                    .map(|(breach, _)| *breach)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A breach that concerns saved logins, with counts (for the detail view,
/// notifications and the organization aggregate). Item IDs stay on the
/// device; only the counts are reported to organizations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachedSite {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breach_date: String,
    pub added_date: String,
    pub pwn_count: u64,
    pub data_classes: Vec<String>,
    pub verified: bool,
    pub sensitive: bool,
    pub exposes_credentials: bool,
    /// Logins whose password is older than the breach.
    pub affected: Vec<String>,
    /// Logins where it is unknown when the password was set.
    pub possibly: Vec<String>,
    /// Logins whose password was changed after the breach.
    pub fixed: Vec<String>,
}

impl BreachedSite {
    /// Some login is still affected or possibly affected.
    pub fn is_open(&self) -> bool {
        !self.affected.is_empty() || !self.possibly.is_empty()
    }

    pub(crate) fn new(breach: &SiteBreach) -> Self {
        Self {
            name: breach.name.clone(),
            title: breach.display_title().to_owned(),
            domain: breach.domain.clone(),
            breach_date: breach.breach_date.clone(),
            added_date: breach.added_date.clone(),
            pwn_count: breach.pwn_count,
            data_classes: breach.data_classes.clone(),
            verified: breach.verified,
            sensitive: breach.sensitive,
            exposes_credentials: breach.exposes_credentials(),
            affected: Vec::new(),
            possibly: Vec::new(),
            fixed: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breach(domain: &str, added: &str, classes: &[&str]) -> SiteBreach {
        SiteBreach {
            name: domain.into(),
            title: domain.into(),
            domain: domain.into(),
            breach_date: added.get(..10).unwrap_or_default().into(),
            added_date: added.into(),
            data_classes: classes.iter().map(|c| (*c).to_owned()).collect(),
            ..SiteBreach::default()
        }
    }

    #[test]
    fn parses_dates() {
        assert_eq!(parse_date_ms("1970-01-02"), Some(DAY_MS));
        assert_eq!(parse_date_ms("1970-01-01T00:00:01Z"), Some(1000));
        assert_eq!(
            parse_date_ms("2013-12-04T00:00:00Z"),
            Some(1_386_115_200_000)
        );
        assert_eq!(
            parse_date_ms("2016-05-21T21:35:40Z"),
            Some(1_463_866_540_000)
        );
        assert_eq!(parse_date_ms(""), None);
        assert_eq!(parse_date_ms("2016-13-01"), None);
        assert_eq!(parse_date_ms("soon"), None);
        for date in ["1970-01-01", "2000-02-29", "2013-12-04", "2026-10-25"] {
            assert_eq!(date_string(parse_date_ms(date).unwrap()), date);
        }
        let added = "2016-05-21T21:35:40Z";
        assert_eq!(datetime_string(parse_date_ms(added).unwrap()), added);
    }

    #[test]
    fn bundled_snapshot_loads() {
        let catalog = bundled();
        assert!(catalog.breaches.len() > 500, "{}", catalog.breaches.len());
        assert_eq!(bundled_date().len(), 10);
        assert!(catalog.updated_at > 1_700_000_000_000);
        let adobe = catalog.breaches.iter().find(|b| b.name == "Adobe").unwrap();
        assert_eq!(adobe.domain, "adobe.com");
        assert!(adobe.exposes_credentials());
        assert!(adobe.verified);
        assert!(catalog.breaches.iter().all(|b| !b.domain.is_empty()));
    }

    #[test]
    fn classifies_exposure_by_dates() {
        let b = breach("example.com", "2020-06-01T00:00:00Z", &["Passwords"]);
        let cutoff = b.cutoff().unwrap();
        assert_eq!(exposure(&b, cutoff - 1, cutoff - 1), Exposure::Affected);
        assert_eq!(exposure(&b, cutoff + 1, cutoff - DAY_MS), Exposure::Fixed);
        assert_eq!(exposure(&b, cutoff + 1, cutoff + 1), Exposure::NotAffected);
        assert_eq!(exposure(&b, cutoff + 1, 0), Exposure::NotAffected);
        assert_eq!(exposure(&b, 0, 0), Exposure::Possibly);
        let undated = breach("example.com", "", &[]);
        assert_eq!(exposure(&undated, cutoff, cutoff), Exposure::Possibly);
        // Without an added date the end of the breach day counts.
        let mut by_breach_date = breach("example.com", "", &[]);
        by_breach_date.breach_date = "2020-06-01".into();
        assert_eq!(by_breach_date.cutoff(), Some(cutoff + DAY_MS));
    }

    #[test]
    fn matches_sites_and_subdomains() {
        let breaches = vec![
            breach("netflix.com", "2020-01-01", &["Passwords"]),
            breach("forum.example.com", "2020-01-01", &["Passwords"]),
            breach("www.shop.co.uk", "2020-01-01", &["Email addresses"]),
        ];
        let index = BreachIndex::new(&breaches);
        assert_eq!(index.for_host("www.netflix.com").len(), 1);
        assert_eq!(index.for_host("netflix.com").len(), 1);
        assert!(index.for_host("netflix.de").is_empty());
        assert!(index.for_host("notnetflix.com").is_empty());
        assert_eq!(index.for_host("forum.example.com").len(), 1);
        assert_eq!(index.for_host("eu.forum.example.com").len(), 1);
        assert!(index.for_host("example.com").is_empty());
        assert!(index.for_host("shop.example.com").is_empty());
        assert_eq!(index.for_host("login.shop.co.uk").len(), 1);
        assert!(!breaches[2].exposes_credentials());
    }

    #[test]
    fn catalog_filter() {
        assert!(include_in_catalog("adobe.com", false, false, false));
        assert!(!include_in_catalog("", false, false, false));
        assert!(!include_in_catalog("a.com", true, false, false));
        assert!(!include_in_catalog("a.com", false, true, false));
        assert!(!include_in_catalog("a.com", false, false, true));
    }
}
