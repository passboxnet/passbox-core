//! The redaction layer: the only code that can build model input.
//!
//! [`Redacted`] has no public constructor. Features build it through the
//! functions of this crate's feature modules ([`crate::import_mapping`],
//! [`crate::security_copilot`]), which take raw data and keep only what
//! the declared data classes allow. Providers accept nothing else.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// What kind of data a model input contains. D4, secrets
/// (passwords, TOTP seeds, card numbers, private keys, hidden fields), is
/// deliberately not representable: it never reaches a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DataClass {
    /// The user's own input (a search query, a question).
    D0,
    /// Structure: column headers, field types, value patterns, counts.
    D1,
    /// Metadata: titles, domains, usernames, tags, audit events.
    D2,
    /// Content: notes, custom fields, attachments.
    D3,
}

impl DataClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::D0 => "D0",
            Self::D1 => "D1",
            Self::D2 => "D2",
            Self::D3 => "D3",
        }
    }
}

/// Model input that went through the redaction layer.
///
/// Only this crate can create one (the constructor is `pub(crate)`), so a
/// caller cannot hand raw vault data to a provider by accident.
#[derive(Debug, Clone, PartialEq)]
pub struct Redacted<T> {
    value: T,
    classes: Vec<DataClass>,
    pseudonymized: bool,
}

impl<T> Redacted<T> {
    pub(crate) fn seal(value: T, classes: &[DataClass], pseudonymized: bool) -> Self {
        let mut classes = classes.to_vec();
        classes.sort();
        classes.dedup();
        Self {
            value,
            classes,
            pseudonymized,
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    /// The data classes the input contains.
    pub fn classes(&self) -> &[DataClass] {
        &self.classes
    }

    /// Whether names and domains were replaced by placeholders ("Site A").
    pub fn pseudonymized(&self) -> bool {
        self.pseudonymized
    }
}

impl<T: Serialize> Redacted<T> {
    /// The input as JSON text, as sent to a model.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.value).unwrap_or_else(|_| "null".into())
    }
}

/// Values that must never leave the device, checked against every string
/// a redaction function lets through. It lives in memory
/// for one request only. Values shorter than [`SecretGuard::MIN_LEN`]
/// characters are ignored, since short strings ("yes", "1") occur
/// everywhere.
#[derive(Default)]
pub struct SecretGuard {
    values: HashSet<String>,
}

impl SecretGuard {
    pub const MIN_LEN: usize = 4;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, value: &str) {
        let value = value.trim();
        if value.chars().count() >= Self::MIN_LEN {
            self.values.insert(value.to_owned());
        }
    }

    pub fn extend<'a>(&mut self, values: impl IntoIterator<Item = &'a str>) {
        for value in values {
            self.add(value);
        }
    }

    /// Whether `text` is or contains one of the values (case-insensitive
    /// for equality, exact for containment).
    pub fn leaks(&self, text: &str) -> bool {
        let text = text.trim();
        if text.is_empty() {
            return false;
        }
        self.values
            .iter()
            .any(|v| v.eq_ignore_ascii_case(text) || text.contains(v.as_str()))
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl std::fmt::Debug for SecretGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretGuard({} values)", self.values.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_matches_equal_and_contained_values() {
        let mut guard = SecretGuard::new();
        guard.extend(["hunter2-long", "no", ""]);
        assert_eq!(guard.len(), 1);
        assert!(guard.leaks("hunter2-long"));
        assert!(guard.leaks("HUNTER2-LONG"));
        assert!(guard.leaks("prefix hunter2-long suffix"));
        assert!(!guard.leaks("no"));
        assert!(!guard.leaks("Password"));
        assert!(!format!("{guard:?}").contains("hunter2"));
    }

    #[test]
    fn classes_are_sorted_and_unique() {
        let r = Redacted::seal(1, &[DataClass::D2, DataClass::D1, DataClass::D2], false);
        assert_eq!(r.classes(), &[DataClass::D1, DataClass::D2]);
    }
}
