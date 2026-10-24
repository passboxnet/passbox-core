//! Similar passwords: the same base with small variations
//! (`Sommer2023!`, `Sommer2024!`, `sommer#1`). Computed locally from the
//! decrypted passwords; nothing leaves the device.

/// The base of a password: lower case, digits and symbols around it
/// removed, common substitutions (`@` → `a`, `3` → `e`, …) undone inside.
/// `None` when the base is too short to say anything (fewer than four
/// letters), which keeps random passwords and PINs out.
pub fn password_base(password: &str) -> Option<String> {
    let chars: Vec<char> = password.to_lowercase().chars().collect();
    let letter = |i: Option<usize>| {
        i.and_then(|i| chars.get(i))
            .is_some_and(|c| c.is_alphabetic())
    };
    let mut base = String::with_capacity(chars.len());
    for (i, &c) in chars.iter().enumerate() {
        if c.is_alphabetic() {
            base.push(c);
            continue;
        }
        // A substitution sits between letters (`p@ss`, `w0rd`); other
        // digits and symbols are the variation and are dropped.
        let substitute = match c {
            '@' | '4' => 'a',
            '3' => 'e',
            '1' | '!' => 'i',
            '0' => 'o',
            '$' | '5' => 's',
            '7' => 't',
            _ => continue,
        };
        if letter(i.checked_sub(1)) && letter(Some(i + 1)) {
            base.push(substitute);
        }
    }
    let letters = chars.iter().filter(|c| c.is_alphabetic()).count();
    (letters >= 4 && letters * 2 >= chars.len()).then_some(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bases_of_variations_match() {
        assert_eq!(password_base("Sommer2023!"), password_base("Sommer2024!"));
        assert_eq!(password_base("sommer#1").as_deref(), Some("sommer"));
        assert_eq!(password_base("P@ssw0rd"), password_base("Password1"));
        assert_eq!(
            password_base("correct-horse-battery-staple"),
            password_base("correct-horse-battery-staple2")
        );
        assert_ne!(password_base("Sommer2023!"), password_base("Winter2023!"));
    }

    #[test]
    fn random_passwords_have_no_base() {
        assert_eq!(password_base("123456"), None);
        assert_eq!(password_base("ab1!"), None);
        assert_eq!(password_base("1234ab5678"), None);
        // Random passwords have bases, but never the same one.
        assert_ne!(
            password_base("x9$Lq!2vR#pW7zK@"),
            password_base("G7#kP2!mQ9$wX4&z")
        );
    }
}
