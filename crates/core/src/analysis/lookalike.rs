//! Lookalike (phishing) domains: IDN homographs, confusable characters and
//! typos of domains the user has saved logins for. Fully local.
//!
//! - **Homograph:** a domain with non-Latin letters that reads like another
//!   domain (`аpple.com` with a Cyrillic `а`, shown as `xn--pple-43d.com`).
//! - **Mixed script:** a label mixes Latin with Cyrillic or Greek letters.
//! - **Confusable:** an ASCII domain that reads like another one once
//!   look-alike characters are folded (`paypa1.com`, `rnicrosoft.com`).
//! - **Typo:** one edit (insert, delete, replace, swap) away from a saved
//!   domain with a first label of at least five characters (`amazom.de`).

use serde::{Deserialize, Serialize};

use super::domain::{idna_pair, is_ip_or_local, registrable_domain, split_label};

/// Why a domain looks like another one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookalikeReason {
    Homograph,
    MixedScript,
    Confusable,
    Typo,
}

impl LookalikeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Homograph => "homograph",
            Self::MixedScript => "mixed_script",
            Self::Confusable => "confusable",
            Self::Typo => "typo",
        }
    }
}

/// A domain that looks like a known one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lookalike {
    /// The domain that was checked (registrable domain, Unicode form).
    pub domain: String,
    /// The domain it imitates (registrable domain); empty for
    /// [`LookalikeReason::MixedScript`] without a known target.
    pub looks_like: String,
    pub reason: LookalikeReason,
    /// Whether `looks_like` is one of the user's saved domains (otherwise
    /// it is a well-known site from the bundled list).
    pub saved: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

fn script(c: char) -> Option<Script> {
    match c {
        'a'..='z' | 'A'..='Z' => Some(Script::Latin),
        '\u{00C0}'..='\u{024F}' | '\u{1E00}'..='\u{1EFF}' => Some(Script::Latin),
        '\u{0370}'..='\u{03FF}' => Some(Script::Greek),
        '\u{0400}'..='\u{052F}' => Some(Script::Cyrillic),
        c if c.is_alphabetic() => Some(Script::Other),
        _ => None,
    }
}

/// True when a label mixes Latin letters with Cyrillic or Greek ones.
pub fn has_mixed_script(label: &str) -> bool {
    let mut latin = false;
    let mut confusable = false;
    for c in label.chars() {
        match script(c) {
            Some(Script::Latin) => latin = true,
            Some(Script::Cyrillic | Script::Greek) => confusable = true,
            _ => {}
        }
    }
    latin && confusable
}

/// Folds a character that looks like a Latin letter or digit.
fn fold(c: char) -> Option<&'static str> {
    Some(match c {
        // Cyrillic
        'а' => "a",
        'в' => "b",
        'е' | 'ё' | 'є' => "e",
        'һ' => "h",
        'і' | 'ї' | 'ӏ' => "i",
        'ј' => "j",
        'к' => "k",
        'м' => "m",
        'н' => "h",
        'о' => "o",
        'р' => "p",
        'с' => "c",
        'т' => "t",
        'у' => "y",
        'х' => "x",
        'ѕ' => "s",
        'ԁ' => "d",
        'ԛ' => "q",
        'ԝ' => "w",
        'ь' => "b",
        'п' => "n",
        // Greek
        'α' => "a",
        'β' => "b",
        'ε' => "e",
        'η' => "n",
        'ι' => "i",
        'κ' => "k",
        'ν' => "v",
        'ο' => "o",
        'ρ' => "p",
        'τ' => "t",
        'υ' => "u",
        'χ' => "x",
        'ω' => "w",
        // Latin look-alikes and accents
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' | 'ɑ' => "a",
        'ç' | 'ć' | 'č' | 'ĉ' | 'ċ' => "c",
        'ď' | 'đ' => "d",
        'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ė' | 'ę' | 'ě' => "e",
        'ĝ' | 'ğ' | 'ġ' | 'ģ' | 'ɡ' => "g",
        'ì' | 'í' | 'î' | 'ï' | 'ī' | 'į' | 'ı' => "i",
        'ķ' => "k",
        'ĺ' | 'ļ' | 'ľ' | 'ł' => "l",
        'ñ' | 'ń' | 'ņ' | 'ň' => "n",
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => "o",
        'ŕ' | 'ř' => "r",
        'ś' | 'ş' | 'š' | 'ș' => "s",
        'ţ' | 'ť' | 'ț' => "t",
        'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' | 'ų' => "u",
        'ý' | 'ÿ' => "y",
        'ź' | 'ż' | 'ž' => "z",
        // ASCII look-alikes
        '0' => "o",
        '1' | '|' => "l",
        _ => return None,
    })
}

/// The "skeleton" of a domain: look-alike characters folded to one form, so
/// that two domains that read the same get the same skeleton.
pub fn skeleton(domain: &str) -> String {
    let mut folded = String::with_capacity(domain.len());
    for c in domain.to_lowercase().chars() {
        match fold(c) {
            Some(s) => folded.push_str(s),
            None => folded.push(c),
        }
    }
    // Letter pairs that read like one letter.
    folded
        .replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .replace('i', "l")
}

/// Optimal string alignment distance, stopping early above `limit`.
pub fn edit_distance(a: &str, b: &str, limit: usize) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > limit {
        return limit + 1;
    }
    let width = b.len() + 1;
    let mut prev2 = vec![0usize; width];
    let mut prev: Vec<usize> = (0..width).collect();
    let mut row = vec![0usize; width];
    for i in 1..=a.len() {
        row[0] = i;
        let mut best = row[0];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut value = (prev[j] + 1).min(row[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                value = value.min(prev2[j - 2] + 1);
            }
            row[j] = value;
            best = best.min(value);
        }
        if best > limit {
            return limit + 1;
        }
        std::mem::swap(&mut prev2, &mut prev);
        std::mem::swap(&mut prev, &mut row);
    }
    prev[b.len()]
}

/// Compares the registrable domain `candidate` with a known domain. Both
/// must be lower-case Unicode registrable domains. Returns the reason when
/// `candidate` imitates `known`.
pub fn compare(candidate: &str, known: &str) -> Option<LookalikeReason> {
    if candidate == known || is_ip_or_local(candidate) || is_ip_or_local(known) {
        return None;
    }
    let (label, suffix) = split_label(candidate);
    let (known_label, known_suffix) = split_label(known);
    // The same name under another ending (amazon.de, amazon.com) is usually
    // the same company; not flagged.
    if label == known_label {
        return None;
    }
    let candidate_ascii = candidate.is_ascii();
    if skeleton(candidate) == skeleton(known) {
        return Some(if candidate_ascii {
            LookalikeReason::Confusable
        } else {
            LookalikeReason::Homograph
        });
    }
    if candidate_ascii
        && known.is_ascii()
        && suffix == known_suffix
        && label.chars().count() >= 5
        && known_label.chars().count() >= 5
        && edit_distance(label, known_label, 1) == 1
    {
        return Some(LookalikeReason::Typo);
    }
    None
}

/// Checks a host before filling or saving a login: `None` when it belongs
/// to one of `saved` (hosts or registrable domains of the user's logins,
/// ASCII or Unicode) or does not resemble any of them. With `popular`, it
/// is also compared with the well-known sites of the bundled directories
/// (exact lookalikes only, no typos).
pub fn check_host<'a>(
    host: &str,
    saved: impl IntoIterator<Item = &'a str>,
    popular: bool,
) -> Option<Lookalike> {
    let (ascii, unicode) = idna_pair(host)?;
    if is_ip_or_local(&ascii) {
        return None;
    }
    let candidate = registrable_domain(&unicode);
    let normalize = |h: &str| idna_pair(h).map(|(_, u)| registrable_domain(&u));
    let mut saved: Vec<String> = saved.into_iter().filter_map(normalize).collect();
    saved.sort();
    saved.dedup();
    if saved.contains(&candidate) {
        return None;
    }
    let mut best: Option<Lookalike> = None;
    for known in &saved {
        if let Some(reason) = compare(&candidate, known) {
            if best.as_ref().is_none_or(|b| reason < b.reason) {
                best = Some(Lookalike {
                    domain: candidate.clone(),
                    looks_like: known.clone(),
                    reason,
                    saved: true,
                });
            }
        }
    }
    if best.is_none() && popular {
        if let Some(known) = super::sites::known_by_skeleton(&skeleton(&candidate)) {
            let known_unicode = normalize(known).unwrap_or_else(|| known.to_owned());
            if let Some(reason) = compare(&candidate, &known_unicode) {
                best = Some(Lookalike {
                    domain: candidate.clone(),
                    looks_like: known_unicode,
                    reason,
                    saved: false,
                });
            }
        }
    }
    if best.is_none() && !candidate.is_ascii() && has_mixed_script(split_label(&candidate).0) {
        best = Some(Lookalike {
            domain: candidate.clone(),
            looks_like: String::new(),
            reason: LookalikeReason::MixedScript,
            saved: false,
        });
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeletons_fold_lookalikes() {
        assert_eq!(skeleton("paypa1.com"), skeleton("paypal.com"));
        assert_eq!(skeleton("rnicrosoft.com"), skeleton("microsoft.com"));
        assert_eq!(skeleton("аpple.com"), skeleton("apple.com"));
        assert_eq!(skeleton("gооgle.com"), skeleton("google.com"));
        assert_ne!(skeleton("github.com"), skeleton("gitlab.com"));
    }

    #[test]
    fn edit_distance_counts_swaps_as_one() {
        assert_eq!(edit_distance("amazon", "amazom", 2), 1);
        assert_eq!(edit_distance("amazon", "amaozn", 2), 1);
        assert_eq!(edit_distance("amazon", "amazonn", 2), 1);
        assert_eq!(edit_distance("amazon", "ebay", 2), 3);
        assert_eq!(edit_distance("", "abc", 5), 3);
    }

    #[test]
    fn checks_hosts_against_saved_and_popular_domains() {
        let saved = ["accounts.amazon.de", "www.sparkasse.de"];
        // Saved domains and their subdomains are fine.
        assert_eq!(check_host("login.amazon.de", saved, true), None);
        // Typos of saved domains.
        let typo = check_host("amazom.de", saved, true).unwrap();
        assert_eq!(typo.reason, LookalikeReason::Typo);
        assert_eq!(typo.looks_like, "amazon.de");
        assert!(typo.saved);
        // Homographs of popular sites, given as punycode ("pаypal.com"
        // with a Cyrillic а).
        let (ascii, _) = idna_pair("pаypal.com").unwrap();
        let homograph = check_host(&ascii, saved, true).unwrap();
        assert_eq!(homograph.reason, LookalikeReason::Homograph);
        assert_eq!(homograph.looks_like, "paypal.com");
        assert!(!homograph.saved);
        assert_eq!(homograph.domain, "pаypal.com");
        // ... and of saved ones.
        let saved_homograph = check_host("xn--pple-43d.com", ["apple.com"], false).unwrap();
        assert_eq!(saved_homograph.reason, LookalikeReason::Homograph);
        assert!(saved_homograph.saved);
        // ASCII confusables.
        let confusable = check_host("www.paypa1.com", saved, true).unwrap();
        assert_eq!(confusable.reason, LookalikeReason::Confusable);
        // The same name under another ending is not flagged.
        assert_eq!(check_host("amazon.com", saved, true), None);
        // Unrelated sites and local hosts are fine.
        assert_eq!(check_host("example.org", saved, true), None);
        assert_eq!(check_host("localhost", saved, true), None);
        // Mixed scripts without a known target.
        let (ascii, _) = idna_pair("bаnk-login.de").unwrap();
        assert_eq!(
            check_host(&ascii, saved, false).unwrap().reason,
            LookalikeReason::MixedScript
        );
        // Short labels are not compared for typos.
        assert_eq!(check_host("web.de", ["wen.de"], false), None);
    }
}
