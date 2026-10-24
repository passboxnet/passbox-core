//! Password and PIN generation.

use serde::{Deserialize, Serialize};

use crate::{Error, Result, random};

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &str = "Il1O0o";

/// Options for [`generate_password`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leave out characters that are easy to confuse, such as `l`, `1`, `O` and `0`.
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

/// Generates a random password. It contains at least one character from every
/// enabled character class.
pub fn generate_password(options: &PasswordOptions) -> Result<String> {
    let filter = |set: &str| -> Vec<char> {
        set.chars()
            .filter(|c| !options.avoid_ambiguous || !AMBIGUOUS.contains(*c))
            .collect()
    };
    let classes: Vec<Vec<char>> = [
        (options.lowercase, LOWERCASE),
        (options.uppercase, UPPERCASE),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, set)| filter(set))
    .collect();

    if classes.is_empty() {
        return Err(Error::InvalidGeneratorOptions(
            "enable at least one character class",
        ));
    }
    if options.length < classes.len() || options.length > 1024 {
        return Err(Error::InvalidGeneratorOptions(
            "length must cover every enabled class and be at most 1024",
        ));
    }

    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    let mut chars: Vec<char> = Vec::with_capacity(options.length);
    for class in &classes {
        chars.push(pick(class)?);
    }
    while chars.len() < options.length {
        chars.push(pick(&alphabet)?);
    }
    shuffle(&mut chars)?;
    Ok(chars.into_iter().collect())
}

/// Generates a numeric PIN of the given length.
pub fn generate_pin(length: usize) -> Result<String> {
    if !(4..=64).contains(&length) {
        return Err(Error::InvalidGeneratorOptions(
            "PIN length must be between 4 and 64",
        ));
    }
    let digits: Vec<char> = DIGITS.chars().collect();
    (0..length).map(|_| pick(&digits)).collect()
}

fn pick(set: &[char]) -> Result<char> {
    let bound = u32::try_from(set.len()).expect("character sets are small");
    Ok(set[random::below(bound)? as usize])
}

/// Fisher–Yates shuffle.
fn shuffle(chars: &mut [char]) -> Result<()> {
    for i in (1..chars.len()).rev() {
        let bound = u32::try_from(i + 1).expect("length is at most 1024");
        let j = random::below(bound)? as usize;
        chars.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_password_contains_every_class() {
        for _ in 0..50 {
            let pw = generate_password(&PasswordOptions::default()).unwrap();
            assert_eq!(pw.chars().count(), 20);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn respects_disabled_classes_and_ambiguity() {
        let options = PasswordOptions {
            length: 64,
            symbols: false,
            avoid_ambiguous: true,
            ..PasswordOptions::default()
        };
        let pw = generate_password(&options).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(pw.chars().all(|c| !AMBIGUOUS.contains(c)));
    }

    #[test]
    fn rejects_invalid_options() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert!(generate_password(&none).is_err());
        let too_short = PasswordOptions {
            length: 2,
            ..PasswordOptions::default()
        };
        assert!(generate_password(&too_short).is_err());
    }

    #[test]
    fn pin_is_numeric() {
        let pin = generate_pin(6).unwrap();
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
        assert!(generate_pin(3).is_err());
    }

    #[test]
    fn options_deserialize_with_defaults() {
        let options: PasswordOptions = serde_json::from_str(r#"{"length":32}"#).unwrap();
        assert_eq!(options.length, 32);
        assert!(options.symbols);
    }
}
