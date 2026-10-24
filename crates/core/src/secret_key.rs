//! The Secret Key: a 128-bit, client-generated value that is combined with the
//! master password during key derivation.
//!
//! The server never sees the Secret Key. A stolen copy of the server database is
//! therefore useless for offline password guessing, even when the master
//! password is weak.
//!
//! Display format: `P1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX` (Crockford Base32, 26
//! characters after the version prefix). Parsing ignores case, dashes and
//! whitespace, and maps the ambiguous characters `I`/`L` to `1` and `O` to `0`.

use core::fmt;

use data_encoding::{Encoding, Specification};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, random};

/// Length of the Secret Key in bytes.
pub const SECRET_KEY_LEN: usize = 16;
const VERSION_PREFIX: &str = "P1";
const ENCODED_LEN: usize = 26;
const GROUPS: [usize; 5] = [5, 5, 5, 5, 6];

fn crockford() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    spec.translate.from.push_str("abcdefghjkmnpqrstvwxyzIiLlOo");
    spec.translate.to.push_str("ABCDEFGHJKMNPQRSTVWXYZ111100");
    spec.check_trailing_bits = false;
    spec.encoding()
        .expect("valid Crockford Base32 specification")
}

/// A Secret Key. The bytes are wiped from memory when the value is dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

impl SecretKey {
    /// Generates a new random Secret Key.
    pub fn generate() -> Result<Self> {
        Ok(Self(random::bytes()?))
    }

    /// Creates a Secret Key from raw bytes.
    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }

    /// Parses a Secret Key in display format.
    pub fn parse(input: &str) -> Result<Self> {
        let compact: String = input
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .collect();
        let body = compact
            .get(..VERSION_PREFIX.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(VERSION_PREFIX))
            .and_then(|_| compact.get(VERSION_PREFIX.len()..))
            .ok_or(Error::InvalidSecretKey)?;
        if body.len() != ENCODED_LEN {
            return Err(Error::InvalidSecretKey);
        }
        let mut decoded = crockford()
            .decode(body.as_bytes())
            .map_err(|_| Error::InvalidSecretKey)?;
        let bytes: [u8; SECRET_KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSecretKey)?;
        decoded.zeroize();
        Ok(Self(bytes))
    }

    /// Formats the Secret Key for display, for example in the Emergency Kit.
    pub fn to_display_string(&self) -> String {
        let mut encoded = crockford().encode(&self.0);
        let mut out = String::from(VERSION_PREFIX);
        let mut offset = 0;
        for group in GROUPS {
            out.push('-');
            out.push_str(&encoded[offset..offset + group]);
            offset += group;
        }
        encoded.zeroize();
        out
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_round_trip() {
        let key = SecretKey::generate().unwrap();
        let shown = key.to_display_string();
        assert_eq!(shown.len(), 2 + 5 + ENCODED_LEN);
        assert!(shown.starts_with("P1-"));
        assert_eq!(SecretKey::parse(&shown).unwrap(), key);
    }

    #[test]
    fn parsing_is_forgiving() {
        let key = SecretKey::from_bytes([0xAB; SECRET_KEY_LEN]);
        let shown = key.to_display_string();
        let sloppy = shown.to_lowercase().replace('-', " ");
        assert_eq!(SecretKey::parse(&sloppy).unwrap(), key);
    }

    #[test]
    fn ambiguous_characters_are_mapped() {
        let key = SecretKey::from_bytes([0; SECRET_KEY_LEN]);
        let shown = key.to_display_string().replace('0', "O");
        assert_eq!(SecretKey::parse(&shown).unwrap(), key);
    }

    #[test]
    fn rejects_invalid_input() {
        assert_eq!(SecretKey::parse("").unwrap_err(), Error::InvalidSecretKey);
        assert_eq!(
            SecretKey::parse("P1-ABC").unwrap_err(),
            Error::InvalidSecretKey
        );
        let wrong_prefix = SecretKey::generate()
            .unwrap()
            .to_display_string()
            .replacen("P1", "P2", 1);
        assert_eq!(
            SecretKey::parse(&wrong_prefix).unwrap_err(),
            Error::InvalidSecretKey
        );
    }

    #[test]
    fn debug_does_not_leak() {
        let key = SecretKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "SecretKey(<redacted>)");
    }
}
