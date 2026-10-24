//! Derivation of the Account Unlock Key (AUK) from the master password and the
//! Secret Key ("two-secret key derivation").
//!
//! ```text
//! k_password = Argon2id(password, salt, params)            (32 bytes)
//! k_secret   = HKDF-SHA256(ikm = secret_key,
//!                          salt = account_id,
//!                          info = "passbox/v1/auk/secret-key")  (32 bytes)
//! AUK        = k_password XOR k_secret
//! ```
//!
//! Both halves are needed to recover the AUK. The Argon2 parameters travel with
//! the account, so the client enforces [`KdfParams::MINIMUM`] itself and never
//! trusts the server to choose safe values.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead::SymmetricKey;
use crate::secret_key::SecretKey;
use crate::{Error, Result, random};

/// Length of the per-account KDF salt in bytes.
pub const SALT_LEN: usize = 16;
const SECRET_KEY_INFO: &[u8] = b"passbox/v1/auk/secret-key";

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl KdfParams {
    /// The lowest parameters a client accepts (64 MiB, 3 passes).
    pub const MINIMUM: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Parameters used for new accounts.
    pub const DEFAULT: Self = Self {
        memory_kib: 128 * 1024,
        iterations: 3,
        parallelism: 4,
    };

    /// Returns an error if any parameter is below [`KdfParams::MINIMUM`].
    pub fn ensure_minimum(&self) -> Result<()> {
        let min = Self::MINIMUM;
        if self.memory_kib < min.memory_kib
            || self.iterations < min.iterations
            || self.parallelism < min.parallelism
        {
            return Err(Error::WeakKdfParams);
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Generates a new random KDF salt.
pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    random::bytes()
}

/// Derives the Account Unlock Key, enforcing the minimum KDF parameters.
pub fn derive_account_unlock_key(
    password: &str,
    secret_key: &SecretKey,
    account_id: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SymmetricKey> {
    params.ensure_minimum()?;
    derive_unchecked(password, secret_key, account_id, salt, params)
}

fn derive_unchecked(
    password: &str,
    secret_key: &SecretKey,
    account_id: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SymmetricKey> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;

    let mut k_secret = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(account_id.as_bytes()), secret_key.as_bytes())
        .expand(SECRET_KEY_INFO, k_secret.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;

    for (k, s) in key.iter_mut().zip(k_secret.iter()) {
        *k ^= s;
    }
    Ok(SymmetricKey::from_bytes(*key))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap parameters keep unit tests fast; production code goes through
    // `derive_account_unlock_key`, which rejects them.
    const TEST_PARAMS: KdfParams = KdfParams {
        memory_kib: 256,
        iterations: 1,
        parallelism: 1,
    };

    fn derive(password: &str, secret_key: &SecretKey, account_id: &str) -> SymmetricKey {
        derive_unchecked(
            password,
            secret_key,
            account_id,
            &[7; SALT_LEN],
            TEST_PARAMS,
        )
        .unwrap()
    }

    #[test]
    fn derivation_is_deterministic() {
        let sk = SecretKey::from_bytes([1; 16]);
        assert_eq!(
            derive("correct horse", &sk, "acc_1").as_bytes(),
            derive("correct horse", &sk, "acc_1").as_bytes()
        );
    }

    #[test]
    fn every_input_changes_the_key() {
        let sk = SecretKey::from_bytes([1; 16]);
        let base = derive("correct horse", &sk, "acc_1");
        assert_ne!(
            base.as_bytes(),
            derive("correct horsf", &sk, "acc_1").as_bytes()
        );
        assert_ne!(
            base.as_bytes(),
            derive("correct horse", &SecretKey::from_bytes([2; 16]), "acc_1").as_bytes()
        );
        assert_ne!(
            base.as_bytes(),
            derive("correct horse", &sk, "acc_2").as_bytes()
        );
    }

    #[test]
    fn weak_params_are_rejected() {
        let sk = SecretKey::from_bytes([1; 16]);
        let err =
            derive_account_unlock_key("pw", &sk, "acc", &[0; SALT_LEN], TEST_PARAMS).unwrap_err();
        assert_eq!(err, Error::WeakKdfParams);
    }

    #[test]
    fn default_params_meet_minimum() {
        KdfParams::DEFAULT.ensure_minimum().unwrap();
    }
}
