//! Derivation of the master keys from the master password and the Secret Key
//! ("two-secret key derivation").
//!
//! ```text
//! k_password  = Argon2id(password, salt, params)                    (32 bytes)
//! k_secret    = HKDF-SHA256(ikm = secret_key, salt = account_id,
//!                           info = "passbox/v1/auk/secret-key")       (32 bytes)
//! master      = k_password XOR k_secret
//! AUK         = HKDF-SHA256(ikm = master, info = "passbox/v1/auk")
//! auth_secret = HKDF-SHA256(ikm = master, info = "passbox/v1/opaque-password")
//! ```
//!
//! The Account Unlock Key (AUK) decrypts the account key. The auth secret is
//! the "password" for the OPAQUE login, so the server never learns anything
//! derived from the master password alone. Both secrets are needed for either
//! output. The Argon2 parameters travel with
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
const AUK_INFO: &[u8] = b"passbox/v1/auk";
const AUTH_INFO: &[u8] = b"passbox/v1/opaque-password";

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

/// Plain Argon2id (version 0x13) with a 32-byte output. Does not check the
/// parameters against [`KdfParams::MINIMUM`]; callers do.
pub(crate) fn argon2id(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
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
    Ok(key)
}

/// Keys derived from the master password and the Secret Key.
pub struct MasterKeys {
    /// Account Unlock Key: decrypts the account key.
    pub auk: SymmetricKey,
    /// Input to the OPAQUE login.
    pub auth_secret: Zeroizing<[u8; 32]>,
}

/// Derives the master keys, enforcing the minimum KDF parameters.
pub fn derive_master_keys(
    password: &str,
    secret_key: &SecretKey,
    account_id: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<MasterKeys> {
    params.ensure_minimum()?;
    derive_unchecked(password, secret_key, account_id, salt, params)
}

fn derive_unchecked(
    password: &str,
    secret_key: &SecretKey,
    account_id: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<MasterKeys> {
    let mut key = argon2id(password, salt, params)?;

    let mut k_secret = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(account_id.as_bytes()), secret_key.as_bytes())
        .expand(SECRET_KEY_INFO, k_secret.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;

    for (k, s) in key.iter_mut().zip(k_secret.iter()) {
        *k ^= s;
    }

    let master = Hkdf::<Sha256>::new(None, key.as_ref());
    let mut auk = Zeroizing::new([0u8; 32]);
    let mut auth_secret = Zeroizing::new([0u8; 32]);
    master
        .expand(AUK_INFO, auk.as_mut())
        .and_then(|()| master.expand(AUTH_INFO, auth_secret.as_mut()))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(MasterKeys {
        auk: SymmetricKey::from_bytes(*auk),
        auth_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap parameters keep unit tests fast; production code goes through
    // `derive_master_keys`, which rejects them.
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
        .auk
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
        let result = derive_master_keys("pw", &sk, "acc", &[0; SALT_LEN], TEST_PARAMS);
        assert_eq!(result.err(), Some(Error::WeakKdfParams));
    }

    #[test]
    fn auk_and_auth_secret_differ() {
        let sk = SecretKey::from_bytes([1; 16]);
        let keys = derive_unchecked("pw", &sk, "acc", &[0; SALT_LEN], TEST_PARAMS).unwrap();
        assert_ne!(keys.auk.as_bytes(), &*keys.auth_secret);
    }

    #[test]
    fn default_params_meet_minimum() {
        KdfParams::DEFAULT.ensure_minimum().unwrap();
    }
}
