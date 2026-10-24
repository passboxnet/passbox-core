//! Identifiers for accounts, vaults and items: 128 random bits as 26 lowercase
//! Crockford Base32 characters. Clients create IDs themselves, so encrypted
//! data can be bound to its ID before the server ever sees it.

use crate::{Result, random};

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
/// Length of an ID in characters.
pub const ID_LEN: usize = 26;

/// Creates a new random ID.
pub fn new_id() -> Result<String> {
    Ok(from_bytes(random::bytes()?))
}

/// Formats 16 bytes as an ID.
pub fn from_bytes(bytes: [u8; 16]) -> String {
    let value = u128::from_be_bytes(bytes);
    // 26 characters * 5 bits = 130 bits; the two leading bits are always zero.
    (0..ID_LEN)
        .rev()
        .map(|i| ALPHABET[((value >> (i * 5)) & 0x1f) as usize] as char)
        .collect()
}

/// Returns true if `id` has the format produced by [`new_id`].
pub fn is_valid_id(id: &str) -> bool {
    id.len() == ID_LEN && id.bytes().all(|b| ALPHABET.contains(&b)) && id.as_bytes()[0] <= b'7'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ids_are_valid_and_unique() {
        let a = new_id().unwrap();
        let b = new_id().unwrap();
        assert!(is_valid_id(&a), "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_invalid_ids() {
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("0123456789abcdefghjkmnpqrs0")); // too long
        assert!(!is_valid_id("0123456789abcdefghjkmnpqrU")); // invalid character
        assert!(!is_valid_id("z123456789abcdefghjkmnpqrs")); // overflows 128 bits
        assert!(!is_valid_id("../../etc/passwd/xxxxxxxxx"));
    }
}
