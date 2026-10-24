//! The personal recovery code (wave C2).
//!
//! A recovery code is 256 random bits, generated on the device and shown
//! once (in the Emergency Kit). It decrypts a second copy of the account key
//! and is the password of a second OPAQUE record, so the server hands the
//! wrapped copy only to someone who proves knowledge of the code:
//!
//! ```text
//! wrap_key    = HKDF-SHA256(ikm = R, info = "passbox/v1/recovery-code")
//! auth_secret = HKDF-SHA256(ikm = R, info = "passbox/v1/recovery-code/opaque")
//! wrapped     = XChaCha20-Poly1305(wrap_key, account_key,
//!                                  aad = "passbox/v1/recovery-wrap|{account_id}")
//! ```
//!
//! The code has full entropy, so no password hashing is needed and a copy of
//! the server database does not help guessing it.
//!
//! Display format: `R1-` followed by 11 groups of five Crockford Base32
//! characters (55 characters for 32 code bytes plus a 2-byte checksum).
//! Parsing ignores case, dashes and whitespace and maps `I`/`L` to `1` and
//! `O` to `0`, like the Secret Key; the checksum catches typos before
//! anything is sent.

use core::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::aead::SymmetricKey;
use crate::secret_key::crockford;
use crate::{Error, Result, random};

/// Length of a recovery code in bytes.
pub const RECOVERY_CODE_LEN: usize = 32;
const CHECKSUM_LEN: usize = 2;
const VERSION_PREFIX: &str = "R1";
const ENCODED_LEN: usize = 55;
const GROUP_LEN: usize = 5;
const WRAP_INFO: &[u8] = b"passbox/v1/recovery-code";
const AUTH_INFO: &[u8] = b"passbox/v1/recovery-code/opaque";
const CHECKSUM_PREFIX: &[u8] = b"passbox/v1/recovery-code-checksum\0";

/// A recovery code. Wiped from memory on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode([u8; RECOVERY_CODE_LEN]);

/// Keys derived from a recovery code.
pub struct RecoveryKeys {
    /// Wraps the second copy of the account key.
    pub wrap_key: SymmetricKey,
    /// The password of the recovery OPAQUE record.
    pub auth_secret: Zeroizing<[u8; 32]>,
}

fn checksum(bytes: &[u8; RECOVERY_CODE_LEN]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_PREFIX);
    hasher.update(bytes);
    let hash = hasher.finalize();
    [hash[0], hash[1]]
}

impl RecoveryCode {
    pub fn generate() -> Result<Self> {
        Ok(Self(random::bytes()?))
    }

    pub fn from_bytes(bytes: [u8; RECOVERY_CODE_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RECOVERY_CODE_LEN] {
        &self.0
    }

    /// Parses a code in display format. Fails with
    /// [`Error::InvalidRecoveryCode`] if it is incomplete, has a typo
    /// (checksum) or is not a recovery code.
    pub fn parse(input: &str) -> Result<Self> {
        let compact: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| *c != '-' && !c.is_whitespace())
                .collect(),
        );
        let body = compact
            .get(..VERSION_PREFIX.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(VERSION_PREFIX))
            .and_then(|_| compact.get(VERSION_PREFIX.len()..))
            .ok_or(Error::InvalidRecoveryCode)?;
        if body.len() != ENCODED_LEN {
            return Err(Error::InvalidRecoveryCode);
        }
        let decoded = Zeroizing::new(
            crockford()
                .decode(body.as_bytes())
                .map_err(|_| Error::InvalidRecoveryCode)?,
        );
        if decoded.len() != RECOVERY_CODE_LEN + CHECKSUM_LEN {
            return Err(Error::InvalidRecoveryCode);
        }
        let mut bytes = [0u8; RECOVERY_CODE_LEN];
        bytes.copy_from_slice(&decoded[..RECOVERY_CODE_LEN]);
        let code = Self(bytes);
        bytes.zeroize();
        if checksum(&code.0) != decoded[RECOVERY_CODE_LEN..] {
            return Err(Error::InvalidRecoveryCode);
        }
        Ok(code)
    }

    /// Whether `input` is a complete recovery code (format and checksum).
    pub fn is_valid(input: &str) -> bool {
        Self::parse(input).is_ok()
    }

    /// `R1-XXXXX-XXXXX-...` (11 groups of five).
    pub fn to_display_string(&self) -> String {
        let mut raw = Zeroizing::new(Vec::with_capacity(RECOVERY_CODE_LEN + CHECKSUM_LEN));
        raw.extend_from_slice(&self.0);
        raw.extend_from_slice(&checksum(&self.0));
        let encoded = Zeroizing::new(crockford().encode(&raw));
        let mut out = String::from(VERSION_PREFIX);
        for group in encoded.as_bytes().chunks(GROUP_LEN) {
            out.push('-');
            out.push_str(core::str::from_utf8(group).expect("Base32 is ASCII"));
        }
        out
    }

    /// Derives the wrapping key and the OPAQUE password.
    pub fn keys(&self) -> Result<RecoveryKeys> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        let mut wrap = Zeroizing::new([0u8; 32]);
        let mut auth_secret = Zeroizing::new([0u8; 32]);
        hkdf.expand(WRAP_INFO, wrap.as_mut())
            .and_then(|()| hkdf.expand(AUTH_INFO, auth_secret.as_mut()))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(RecoveryKeys {
            wrap_key: SymmetricKey::from_bytes(*wrap),
            auth_secret,
        })
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

pub(crate) fn wrap_aad(account_id: &str) -> Vec<u8> {
    format!("passbox/v1/recovery-wrap|{account_id}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::Keyring;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_answer() {
        let code = RecoveryCode::from_bytes([0x42; 32]);
        assert_eq!(
            code.to_display_string(),
            "R1-89144-GJ289-144GJ-28914-4GJ28-9144G-J2891-44GJ2-89144-GJ289-1BTT8"
        );
        let keys = code.keys().unwrap();
        assert_eq!(hex(keys.wrap_key.as_bytes()), KAT_WRAP);
        assert_eq!(hex(&*keys.auth_secret), KAT_AUTH);
    }

    // Computed independently with Python's hashlib and hmac (RFC 5869 HKDF).
    const KAT_WRAP: &str = "b412ee9cd8f7077f94421395691e2a4f4076efe80ce10774c617c121fae878f7";
    const KAT_AUTH: &str = "9500e0ea8a84475b7fa7e2cc6bf04cda61eed08787503cf19c7433c7e7c5eae4";

    #[test]
    fn display_round_trip_and_forgiving_parse() {
        let code = RecoveryCode::generate().unwrap();
        let shown = code.to_display_string();
        assert!(shown.starts_with("R1-"));
        assert_eq!(shown.split('-').count(), 12);
        assert_eq!(RecoveryCode::parse(&shown).unwrap(), code);
        let sloppy = shown.to_lowercase().replace('-', " ");
        assert_eq!(RecoveryCode::parse(&sloppy).unwrap(), code);
        assert!(RecoveryCode::is_valid(&shown));
    }

    #[test]
    fn typos_are_caught_by_the_checksum() {
        let code = RecoveryCode::from_bytes([7; 32]);
        let shown = code.to_display_string();
        let mut chars: Vec<char> = shown.chars().collect();
        // Change one character in the middle (skipping dashes).
        let index = 10;
        assert_ne!(chars[index], '-');
        chars[index] = if chars[index] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(
            RecoveryCode::parse(&typo).unwrap_err(),
            Error::InvalidRecoveryCode
        );
        assert_eq!(
            RecoveryCode::parse("R1-ABCDE").unwrap_err(),
            Error::InvalidRecoveryCode
        );
        // A Secret Key is not a recovery code.
        let secret_key = crate::secret_key::SecretKey::generate()
            .unwrap()
            .to_display_string();
        assert!(!RecoveryCode::is_valid(&secret_key));
    }

    #[test]
    fn wraps_and_unwraps_the_account_key() {
        let auk = SymmetricKey::generate().unwrap();
        let (keyring, encrypted) = Keyring::create(&auk, "acc_1").unwrap();
        let code = RecoveryCode::generate().unwrap();
        let wrapped = keyring
            .wrap_account_key_for_recovery(&code.keys().unwrap().wrap_key)
            .unwrap();
        let recovered =
            Keyring::unlock_with_recovery(&code.keys().unwrap().wrap_key, "acc_1", &wrapped)
                .unwrap();
        // Same account key: it opens the normal wrapped copy's vaults.
        assert_eq!(
            recovered.wrap_account_key(&auk).map(|_| ()),
            Ok(()),
            "keyring usable"
        );
        let original = Keyring::unlock(&auk, "acc_1", &encrypted).unwrap();
        let mut original = original;
        let vault = original.create_vault(r#"{"name":"V"}"#).unwrap();
        let mut recovered = recovered;
        recovered
            .add_vault(&vault.id, &vault.encrypted_key)
            .unwrap();

        // Wrong code, wrong account and tampering fail.
        let other = RecoveryCode::generate().unwrap();
        assert_eq!(
            Keyring::unlock_with_recovery(&other.keys().unwrap().wrap_key, "acc_1", &wrapped)
                .unwrap_err(),
            Error::InvalidCredentials
        );
        assert_eq!(
            Keyring::unlock_with_recovery(&code.keys().unwrap().wrap_key, "acc_2", &wrapped)
                .unwrap_err(),
            Error::InvalidCredentials
        );
        let mut bytes = crate::encoding::decode(&wrapped).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            Keyring::unlock_with_recovery(
                &code.keys().unwrap().wrap_key,
                "acc_1",
                &crate::encoding::encode(&bytes)
            )
            .unwrap_err(),
            Error::InvalidCredentials
        );
        // The recovery wrap is not the AUK wrap.
        assert!(Keyring::unlock(&code.keys().unwrap().wrap_key, "acc_1", &wrapped).is_err());
    }
}
