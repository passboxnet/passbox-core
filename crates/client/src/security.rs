//! Password strength and vault health (Watchtower). Mirrors
//! `packages/client/src/security.ts`; both must give the same results.

use std::collections::BTreeMap;

use crate::model::{Item, ItemCategory, field};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strength {
    /// 0 (very weak) to 4 (very strong).
    pub score: u8,
    /// Rough entropy estimate in bits after pattern penalties.
    pub bits: u32,
}

impl Strength {
    pub fn label(&self) -> &'static str {
        ["Very weak", "Weak", "Fair", "Strong", "Very strong"][usize::from(self.score.min(4))]
    }
}

const COMMON: &[&str] = &[
    "123456",
    "123456789",
    "12345678",
    "password",
    "qwerty",
    "qwerty123",
    "1q2w3e4r",
    "111111",
    "123123",
    "abc123",
    "password1",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "letmein",
    "football",
    "sunshine",
    "princess",
    "passwort",
    "hallo123",
    "schatz",
    "master",
    "secret",
];

const SEQUENCES: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiopasdfghjklzxcvbnm",
    "qwertzuiopasdfghjklyxcvbnm",
];

fn charset_size(password: &str) -> u32 {
    let mut size = 0;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        size += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        size += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        size += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        size += 33;
    }
    size
}

fn pattern_chars(password: &str) -> usize {
    let lower: Vec<char> = password.to_lowercase().chars().collect();
    lower
        .windows(3)
        .filter(|w| {
            let run = w[0] == w[1] && w[1] == w[2];
            let forward: String = w.iter().collect();
            let backward: String = w.iter().rev().collect();
            run || SEQUENCES
                .iter()
                .any(|s| s.contains(&forward) || s.contains(&backward))
        })
        .count()
}

fn is_word_with_digits(password: &str) -> bool {
    let trimmed = password.trim_end_matches(['!', '.', '?']);
    if trimmed.len() + 1 < password.len() {
        return false;
    }
    let letters = trimmed.trim_end_matches(|c: char| c.is_ascii_digit());
    let digits = trimmed.len() - letters.len();
    !letters.is_empty()
        && letters.chars().all(|c| c.is_ascii_alphabetic())
        && (1..=4).contains(&digits)
}

/// Estimates password strength. A heuristic for user guidance, not a guarantee.
pub fn estimate_strength(password: &str) -> Strength {
    if password.is_empty() {
        return Strength { score: 0, bits: 0 };
    }
    let lower = password.to_lowercase();
    let normalized: String = lower.chars().filter(char::is_ascii_alphanumeric).collect();
    if COMMON.contains(&lower.as_str()) || COMMON.contains(&normalized.as_str()) {
        return Strength { score: 0, bits: 0 };
    }
    let length = password.chars().count();
    let effective = length.saturating_sub(pattern_chars(password)).max(1);
    let mut bits = effective as f64 * f64::from(charset_size(password).max(2)).log2();
    if password.chars().all(|c| c.is_ascii_alphabetic()) && length <= 10 {
        bits = bits.min(25.0);
    }
    if is_word_with_digits(password) {
        bits *= 0.6;
    }
    let score = match bits {
        b if b < 28.0 => 0,
        b if b < 40.0 => 1,
        b if b < 60.0 => 2,
        b if b < 80.0 => 3,
        _ => 4,
    };
    Strength {
        score,
        bits: bits.round() as u32,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultHealth {
    pub weak: Vec<String>,
    pub reused: Vec<Vec<String>>,
    pub insecure_urls: Vec<String>,
    pub without_totp: Vec<String>,
    /// 0–100, higher is better.
    pub score: u8,
    pub analyzed: usize,
}

/// Analyzes logins for weak, reused and insecure entries.
pub fn analyze_vault(items: &[Item]) -> VaultHealth {
    let mut health = VaultHealth::default();
    let mut by_password: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut order: Vec<&str> = Vec::new();
    for item in items
        .iter()
        .filter(|i| i.data.category == ItemCategory::Login)
    {
        if item
            .data
            .field(field::URL)
            .is_some_and(|url| url.trim().to_ascii_lowercase().starts_with("http://"))
        {
            health.insecure_urls.push(item.id.clone());
        }
        let Some(password) = item.data.field(field::PASSWORD) else {
            continue;
        };
        health.analyzed += 1;
        if estimate_strength(password).score <= 1 {
            health.weak.push(item.id.clone());
        }
        if item.data.field(field::TOTP).is_none() {
            health.without_totp.push(item.id.clone());
        }
        if !by_password.contains_key(password) {
            order.push(password);
        }
        by_password
            .entry(password)
            .or_default()
            .push(item.id.clone());
    }
    health.reused = order
        .into_iter()
        .filter_map(|p| by_password.remove(p))
        .filter(|ids| ids.len() > 1)
        .collect();
    let mut problems: Vec<&String> = health
        .weak
        .iter()
        .chain(health.reused.iter().flatten())
        .chain(health.insecure_urls.iter())
        .collect();
    problems.sort();
    problems.dedup();
    health.score = if health.analyzed == 0 {
        100
    } else {
        let denominator = health.analyzed.max(problems.len()) as f64;
        (100.0 * (1.0 - problems.len() as f64 / denominator)).round() as u8
    };
    health
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldType, ItemData};

    #[test]
    fn strength_matches_typescript_cases() {
        for (password, score) in [
            ("", 0),
            ("password", 0),
            ("Passwort!", 0),
            ("summer2024", 1),
            ("aaaaaaaaaaaa", 0),
            ("Tr0ub4dor&3x", 3),
            ("correct-horse-battery-staple", 4),
            ("9x$Lq!2vR#pW7zK@", 4),
        ] {
            assert_eq!(estimate_strength(password).score, score, "{password}");
        }
    }

    fn login(id: &str, password: &str, url: &str, totp: &str) -> Item {
        let mut data = ItemData::new(ItemCategory::Login, id);
        data.set_field(field::PASSWORD, "Password", FieldType::Concealed, password);
        data.set_field(field::URL, "Website", FieldType::Url, url);
        data.set_field(field::TOTP, "One-time password", FieldType::Totp, totp);
        Item {
            id: id.into(),
            vault_id: "v".into(),
            revision: 1,
            updated_at: 0,
            data,
        }
    }

    #[test]
    fn analysis_matches_typescript_case() {
        let health = analyze_vault(&[
            login("a", "123456", "https://example.com", ""),
            login("b", "x9$Lq!2vR#pW7zK@", "https://example.com", ""),
            login("c", "x9$Lq!2vR#pW7zK@", "http://intranet.local", ""),
            login(
                "d",
                "G7#kP2!mQ9$wX4&z",
                "https://bank.example",
                "JBSWY3DPEHPK3PXP",
            ),
        ]);
        assert_eq!(health.analyzed, 4);
        assert_eq!(health.weak, ["a"]);
        assert_eq!(health.reused, [vec!["b".to_string(), "c".to_string()]]);
        assert_eq!(health.insecure_urls, ["c"]);
        assert_eq!(health.without_totp, ["a", "b", "c"]);
        assert_eq!(health.score, 25);
        assert_eq!(analyze_vault(&[]).score, 100);
    }
}
