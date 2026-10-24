//! Login two-factor authentication: TOTP secrets for the account login,
//! one-time recovery codes and the server-side protection of both.
//!
//! The vault never depends on these values. They only protect the server
//! session: a second step after the OPAQUE login. WebAuthn security keys are
//! verified in [`crate::webauthn`].

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::aead::SymmetricKey;
use crate::totp::Totp;
use crate::{Error, Result, random};

/// Length of a login TOTP secret (160 bits, as recommended by RFC 4226).
pub const TOTP_SECRET_LEN: usize = 20;

/// Accepted clock drift for login codes: one 30-second step either way.
pub const TOTP_WINDOW: u64 = 1;

/// Number of recovery codes issued at a time.
pub const RECOVERY_CODE_COUNT: usize = 10;

/// Characters of a recovery code without separators (16 × 5 bits = 80 bits).
pub const RECOVERY_CODE_LEN: usize = 16;

/// Crockford Base32: no I, L, O or U, so codes are easy to read and type.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Creates a new login TOTP configuration (SHA-1, 6 digits, 30 seconds, the
/// settings every authenticator app supports) labelled for `account`.
pub fn new_login_totp(issuer: &str, account: &str) -> Result<Totp> {
    let secret = Zeroizing::new(random::bytes::<TOTP_SECRET_LEN>()?);
    let mut totp = Totp::new(secret.to_vec())?;
    totp.issuer = Some(issuer.to_owned()).filter(|s| !s.is_empty());
    totp.account = Some(account.to_owned()).filter(|s| !s.is_empty());
    Ok(totp)
}

/// Generates [`RECOVERY_CODE_COUNT`] recovery codes, formatted as
/// `XXXX-XXXX-XXXX-XXXX` (80 random bits each).
pub fn generate_recovery_codes() -> Result<Vec<String>> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let bytes = Zeroizing::new(random::bytes::<10>()?);
            Ok(format_recovery_code(&crockford_encode(&bytes)))
        })
        .collect()
}

fn crockford_encode(bytes: &[u8; 10]) -> String {
    let mut value = 0u128;
    for byte in bytes {
        value = (value << 8) | u128::from(*byte);
    }
    (0..RECOVERY_CODE_LEN)
        .rev()
        .map(|i| CROCKFORD[((value >> (i * 5)) & 0x1f) as usize] as char)
        .collect()
}

fn format_recovery_code(compact: &str) -> String {
    compact
        .as_bytes()
        .chunks(4)
        .map(|c| core::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

/// Normalizes what a user typed as a recovery code: case, spaces and dashes
/// are ignored, and the look-alikes O, I and L count as 0, 1 and 1. Returns
/// `None` if it cannot be a recovery code.
pub fn normalize_recovery_code(input: &str) -> Option<String> {
    let compact: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    (compact.len() == RECOVERY_CODE_LEN && compact.bytes().all(|b| CROCKFORD.contains(&b)))
        .then_some(compact)
}

/// Whether `input` looks like a recovery code rather than a 6-digit code,
/// so a single input field can accept both.
pub fn looks_like_recovery_code(input: &str) -> bool {
    normalize_recovery_code(input).is_some()
}

/// The value the server stores for a recovery code: SHA-256 over the
/// normalized code, bound to the account. With 80 random bits per code a
/// fast hash is enough; guessing a code from its hash is infeasible.
pub fn hash_recovery_code(account_id: &str, code: &str) -> Option<String> {
    let normalized = normalize_recovery_code(code)?;
    let mut hasher = Sha256::new();
    hasher.update(b"passbox/v1/recovery-code|");
    hasher.update(account_id.as_bytes());
    hasher.update(b"|");
    hasher.update(normalized.as_bytes());
    Some(HEXLOWER.encode(&hasher.finalize()))
}

fn totp_aad(account_id: &str) -> Vec<u8> {
    format!("passbox/v1/server/totp-secret|{account_id}").into_bytes()
}

/// Encrypts a login TOTP configuration with the server's two-factor key,
/// bound to the account, for storage in the database.
pub fn seal_totp(key: &SymmetricKey, account_id: &str, totp: &Totp) -> Result<Vec<u8>> {
    let json =
        Zeroizing::new(serde_json::to_vec(totp).map_err(|e| Error::InvalidData(e.to_string()))?);
    key.encrypt(&json, &totp_aad(account_id))
}

/// Decrypts a value from [`seal_totp`]. Fails if it was stored for another
/// account or modified.
pub fn open_totp(key: &SymmetricKey, account_id: &str, sealed: &[u8]) -> Result<Totp> {
    let json = Zeroizing::new(key.decrypt(sealed, &totp_aad(account_id))?);
    serde_json::from_slice(&json).map_err(|e| Error::InvalidData(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_totp_has_standard_settings() {
        let totp = new_login_totp("Passbox", "anna@example.com").unwrap();
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.period, 30);
        assert_eq!(totp.secret_base32().len(), 32);
        assert!(
            totp.to_uri()
                .starts_with("otpauth://totp/Passbox:anna@example.com?secret=")
        );
        assert_ne!(
            new_login_totp("Passbox", "a").unwrap().secret_base32(),
            totp.secret_base32()
        );
    }

    #[test]
    fn recovery_codes_are_unique_and_normalize() {
        let codes = generate_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        for code in &codes {
            assert_eq!(code.len(), 19, "{code}");
            assert_eq!(code.matches('-').count(), 3);
            assert!(looks_like_recovery_code(code));
            let compact = normalize_recovery_code(code).unwrap();
            assert_eq!(
                normalize_recovery_code(&code.to_lowercase()),
                Some(compact.clone())
            );
            assert_eq!(
                normalize_recovery_code(&format!(" {} ", compact)),
                Some(compact)
            );
        }
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn crockford_encoding_is_big_endian_5_bit_groups() {
        assert_eq!(crockford_encode(&[0; 10]), "0000000000000000");
        assert_eq!(crockford_encode(&[0xff; 10]), "ZZZZZZZZZZZZZZZZ");
        let mut one = [0u8; 10];
        one[9] = 1;
        assert_eq!(crockford_encode(&one), "0000000000000001");
    }

    #[test]
    fn look_alikes_and_invalid_input() {
        assert_eq!(
            normalize_recovery_code("oooo-iiii-llll-0000"),
            Some("0000111111110000".into())
        );
        assert_eq!(normalize_recovery_code("123456"), None);
        assert_eq!(normalize_recovery_code("UUUU-UUUU-UUUU-UUUU"), None);
        assert_eq!(normalize_recovery_code(""), None);
        assert!(!looks_like_recovery_code("123 456"));
    }

    #[test]
    fn recovery_code_hashes_are_bound_to_the_account() {
        let code = "ABCD-EFGH-JKMN-PQRS";
        let a = hash_recovery_code("account-a", code).unwrap();
        assert_eq!(
            a,
            hash_recovery_code("account-a", "abcdefghjkmnpqrs").unwrap()
        );
        assert_ne!(a, hash_recovery_code("account-b", code).unwrap());
        assert_eq!(a.len(), 64);
        assert_eq!(hash_recovery_code("account-a", "nope"), None);
    }

    #[test]
    fn sealed_totp_is_bound_to_the_account() {
        let key = SymmetricKey::generate().unwrap();
        let totp = new_login_totp("Passbox", "anna@example.com").unwrap();
        let sealed = seal_totp(&key, "account-a", &totp).unwrap();
        assert_eq!(open_totp(&key, "account-a", &sealed).unwrap(), totp);
        assert!(open_totp(&key, "account-b", &sealed).is_err());
        let other = SymmetricKey::generate().unwrap();
        assert!(open_totp(&other, "account-a", &sealed).is_err());
    }
}
