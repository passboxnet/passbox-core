//! Vault health (Watchtower). Mirrors `packages/client/src/security.ts`;
//! both must give the same results. Password strength comes from
//! `passbox_core::strength`, which every client shares.

use std::collections::BTreeMap;

use passbox_core::strength;
pub use passbox_core::strength::Strength;

use crate::model::{Item, ItemCategory, field};

/// Rates a password; see [`passbox_core::strength::estimate`].
pub fn estimate_strength(password: &str, user_inputs: &[&str]) -> Strength {
    strength::estimate(password, user_inputs)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultHealth {
    pub weak: Vec<String>,
    pub reused: Vec<Vec<String>>,
    pub insecure_urls: Vec<String>,
    pub without_totp: Vec<String>,
    /// Analyzed logins without any problem.
    pub secure: usize,
    /// 0–100, higher is better.
    pub score: u8,
    pub analyzed: usize,
}

/// Analyzes logins for weak, reused and insecure entries. Trashed items are
/// skipped. `user_inputs` are passed to the strength estimate (the account
/// email, for example).
pub fn analyze_vault(items: &[Item], user_inputs: &[&str]) -> VaultHealth {
    let mut health = VaultHealth::default();
    let mut by_password: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut order: Vec<&str> = Vec::new();
    for item in items
        .iter()
        .filter(|i| i.data.category == ItemCategory::Login && i.data.trashed_at().is_none())
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
        if estimate_strength(password, user_inputs).score <= 1 {
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
    let analyzed_problems = items
        .iter()
        .filter(|i| problems.contains(&&i.id) && i.data.field(field::PASSWORD).is_some())
        .count();
    health.secure = health.analyzed.saturating_sub(analyzed_problems);
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
            ("Sommer2024!", 1),
            ("aaaaaaaaaaaa", 0),
            ("Tr0ub4dor&3", 2),
            ("correct-horse-battery-staple", 4),
            ("9x$Lq!2vR#pW7zK@", 4),
        ] {
            assert_eq!(estimate_strength(password, &[]).score, score, "{password}");
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
            key_epoch: 0,
            updated_at: 0,
            data,
        }
    }

    fn trashed(mut item: Item) -> Item {
        item.data.set_trashed_at(Some(1));
        item
    }

    #[test]
    fn analysis_matches_typescript_case() {
        let health = analyze_vault(
            &[
                login("a", "123456", "https://example.com", ""),
                login("b", "x9$Lq!2vR#pW7zK@", "https://example.com", ""),
                login("c", "x9$Lq!2vR#pW7zK@", "http://intranet.local", ""),
                login(
                    "d",
                    "G7#kP2!mQ9$wX4&z",
                    "https://bank.example",
                    "JBSWY3DPEHPK3PXP",
                ),
                trashed(login("e", "123456", "http://x", "")),
            ],
            &[],
        );
        assert_eq!(health.analyzed, 4);
        assert_eq!(health.weak, ["a"]);
        assert_eq!(health.reused, [vec!["b".to_string(), "c".to_string()]]);
        assert_eq!(health.insecure_urls, ["c"]);
        assert_eq!(health.without_totp, ["a", "b", "c"]);
        assert_eq!(health.secure, 1);
        assert_eq!(health.score, 25);
        assert_eq!(analyze_vault(&[], &[]).score, 100);
    }
}
