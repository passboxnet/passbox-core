//! Bundled snapshots of public site directories: which sites support
//! two-factor authentication (2fa.directory, MIT) and passkeys (Passkeys
//! Directory, CC BY 4.0). Refreshed with `scripts/update-site-directories.py`;
//! sources, dates and licenses are in `THIRD_PARTY_NOTICES.md`.
//!
//! Lookups are local. Clients never ask these services about a site.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::domain::{idna_pair, registrable_domain};
use super::lookalike::skeleton;

const TWO_FACTOR: &str = include_str!("../../data/twofactor-sites.tsv");
const PASSKEYS: &str = include_str!("../../data/passkey-sites.tsv");

/// What the bundled directories know about a site.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSupport {
    /// The directory entry that matched (`google.com` for `accounts.google.com`).
    pub domain: String,
    /// One-time codes from an authenticator app (TOTP).
    pub totp: bool,
    /// Security keys (FIDO U2F/WebAuthn as a second factor).
    pub security_key: bool,
    /// Other second factors: SMS, email, call, the vendor's app or hardware.
    pub other_two_factor: bool,
    /// Passkeys for signing in (without a password).
    pub passkey_sign_in: bool,
    /// Passkeys as a second factor.
    pub passkey_two_factor: bool,
    /// How to turn on two-factor authentication.
    pub two_factor_docs: Option<String>,
    /// How to add a passkey.
    pub passkey_docs: Option<String>,
}

impl SiteSupport {
    /// Any form of two-factor authentication a password manager can help with.
    pub fn has_two_factor(&self) -> bool {
        self.totp || self.security_key || self.passkey_two_factor
    }

    pub fn has_passkeys(&self) -> bool {
        self.passkey_sign_in || self.passkey_two_factor
    }
}

struct Directory {
    sites: HashMap<&'static str, SiteSupport>,
    /// Entries merged by registrable domain (`google.com` from
    /// `mail.google.com`, `drive.google.com`, …).
    by_registrable: HashMap<String, SiteSupport>,
    /// Lookalike skeleton of each listed registrable domain.
    skeletons: HashMap<String, String>,
    /// Snapshot dates (`YYYY-MM-DD`) of the two lists.
    dates: (String, String),
}

fn snapshot_date(data: &str) -> String {
    data.lines()
        .next()
        .and_then(|line| line.split(" snapshot of ").nth(1))
        .and_then(|rest| rest.get(..10))
        .unwrap_or_default()
        .to_owned()
}

fn rows(data: &'static str) -> impl Iterator<Item = (&'static str, &'static str, &'static str)> {
    data.lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .filter_map(|line| {
            let mut parts = line.split('\t');
            Some((parts.next()?, parts.next()?, parts.next().unwrap_or("")))
        })
}

fn directory() -> &'static Directory {
    static DIRECTORY: OnceLock<Directory> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let mut sites: HashMap<&'static str, SiteSupport> = HashMap::new();
        let docs = |url: &str| Some(url.to_owned()).filter(|u| !u.is_empty());
        for (domain, methods, url) in rows(TWO_FACTOR) {
            let entry = sites.entry(domain).or_default();
            entry.domain = domain.to_owned();
            entry.totp = methods.contains('t');
            entry.security_key = methods.contains('u');
            entry.other_two_factor = methods.chars().any(|c| "secah".contains(c));
            entry.two_factor_docs = docs(url);
        }
        for (domain, flags, url) in rows(PASSKEYS) {
            let entry = sites.entry(domain).or_default();
            entry.domain = domain.to_owned();
            entry.passkey_sign_in = flags.contains('p');
            entry.passkey_two_factor = flags.contains('m');
            entry.passkey_docs = docs(url);
        }
        let mut by_registrable: HashMap<String, SiteSupport> = HashMap::new();
        let mut names: Vec<&&'static str> = sites.keys().collect();
        names.sort_by_key(|name| (name.len(), **name));
        for name in names {
            let site = &sites[*name];
            let registrable = registrable_domain(name);
            let merged = by_registrable.entry(registrable.clone()).or_default();
            merged.domain = registrable;
            merged.totp |= site.totp;
            merged.security_key |= site.security_key;
            merged.other_two_factor |= site.other_two_factor;
            merged.passkey_sign_in |= site.passkey_sign_in;
            merged.passkey_two_factor |= site.passkey_two_factor;
            if merged.two_factor_docs.is_none() {
                merged.two_factor_docs.clone_from(&site.two_factor_docs);
            }
            if merged.passkey_docs.is_none() {
                merged.passkey_docs.clone_from(&site.passkey_docs);
            }
        }
        let skeletons = by_registrable
            .keys()
            .filter_map(|domain| {
                let (_, unicode) = idna_pair(domain)?;
                Some((skeleton(&unicode), domain.clone()))
            })
            .collect();
        Directory {
            sites,
            by_registrable,
            skeletons,
            dates: (snapshot_date(TWO_FACTOR), snapshot_date(PASSKEYS)),
        }
    })
}

/// What the directories know about `host` (or one of its parent domains up
/// to the registrable domain). `None` when the site is not listed.
pub fn lookup(host: &str) -> Option<SiteSupport> {
    let (ascii, _) = idna_pair(host)?;
    let registrable = registrable_domain(&ascii);
    let sites = &directory().sites;
    let mut candidate = ascii.as_str();
    loop {
        if let Some(site) = sites.get(candidate) {
            return Some(site.clone());
        }
        if candidate == registrable {
            return directory().by_registrable.get(&registrable).cloned();
        }
        candidate = candidate.split_once('.')?.1;
    }
}

/// Every listed domain.
pub fn known_domains() -> impl Iterator<Item = &'static str> {
    directory().sites.keys().copied()
}

/// The listed (well-known) registrable domain whose lookalike skeleton is
/// `skeleton`, if any.
pub fn known_by_skeleton(skeleton: &str) -> Option<&'static str> {
    directory().skeletons.get(skeleton).map(String::as_str)
}

/// Snapshot dates of the 2FA and passkey lists (`YYYY-MM-DD`).
pub fn snapshot_dates() -> (&'static str, &'static str) {
    let dates = &directory().dates;
    (dates.0.as_str(), dates.1.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_sites_and_parent_domains() {
        let github = lookup("github.com").unwrap();
        assert!(github.totp && github.security_key);
        assert!(github.two_factor_docs.unwrap().starts_with("https://"));
        let google = lookup("accounts.google.com").unwrap();
        assert_eq!(google.domain, "google.com");
        assert_eq!(lookup("mail.google.com").unwrap().domain, "mail.google.com");
        assert_eq!(
            known_by_skeleton(&skeleton("paypa1.com")),
            Some("paypal.com")
        );
        assert!(google.has_two_factor());
        assert_eq!(lookup("passbox-unknown-site.example"), None);
        assert!(known_domains().count() > 2000);
        let (two_factor, passkeys) = snapshot_dates();
        assert_eq!(two_factor.len(), 10);
        assert_eq!(passkeys.len(), 10);
    }

    #[test]
    fn knows_passkey_sites() {
        assert!(rows(PASSKEYS).count() > 100);
        let (domain, _, _) = rows(PASSKEYS)
            .find(|(_, flags, _)| flags.contains('p'))
            .unwrap();
        assert!(lookup(domain).unwrap().passkey_sign_in);
    }
}
