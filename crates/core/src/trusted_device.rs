//! Unlocking with SSO on trusted devices (wave E2).
//!
//! A trusted device holds an X-Wing key pair. The account key is sealed to
//! the device's public key and the server stores the sealed copy. After an
//! SSO sign-in, the server hands the device its sealed copy and the device
//! opens it locally, so the user does not type the master password:
//!
//! ```text
//! sealed = Seal(device_pk, account_key, purpose "trusted-device",
//!               context (account_id, device_id))
//! grant  = { account_id, device_id, device_key_hash, sealed_hash,
//!            approved_by, approved_at }                     signed by the account (Ed25519)
//! code   = 4 groups of five digits from SHA-256("passbox/v1/trusted-device-code\0" || device_pk)
//! ```
//!
//! - **This device:** an unlocked device seals the account key to its own
//!   new key pair (`approved_by` is empty).
//! - **A new device:** it creates a key pair and shows the [`approval_code`]
//!   of its public key. An unlocked trusted device computes the same code
//!   from the public key the server relays; the user compares both, so a
//!   server that swaps in its own key is detected (it would have to find a
//!   key with the same 66-bit code). The approving device seals the
//!   account key and signs the grant (`approved_by` is its device ID).
//!
//! Opening checks the grant against the device, the account and the sealed
//! bytes, then that the account key opens the account's own key pairs
//! ([`Keyring::load_account_keys`]) and that the grant is signed by the
//! account's own signing key. A server therefore cannot hand a device some
//! other key, and cannot create a trusted device by itself.
//!
//! Without the master password, the protection of the account key is the
//! device key plus the identity provider: whoever controls a trusted
//! device's key storage *and* can sign in at the identity provider can
//! unlock. See `docs/architecture/sso.md`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canon::{Reader, Writer};
use crate::identity::{self, ENC_PK_LEN, EncryptionKey, HASH_LEN, object_hash, sealed_hash};
use crate::keyring::{Keyring, key_from_plaintext};
use crate::sharing::objects::{Canonical, Signed};
use crate::{Error, Result, encoding};

pub const PURPOSE: &str = "trusted-device";

fn denied(message: impl Into<String>) -> Error {
    Error::InvalidData(message.into())
}

fn context(account_id: &str, device_id: &str) -> Vec<u8> {
    Writer::new("passbox/v1/seal-context/trusted-device")
        .str(account_id)
        .str(device_id)
        .finish()
}

/// Hash of a device public key, the recipient key hash when sealing to it.
pub fn device_key_hash(device_pk: &[u8]) -> [u8; HASH_LEN] {
    object_hash(
        &Writer::new("passbox/v1/trusted-device-key")
            .bytes(device_pk)
            .finish(),
    )
}

/// The code a new device shows and the approving device compares: four
/// groups of five digits (about 66 bits) derived from the device's public
/// key alone.
pub fn approval_code(device_pk: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"passbox/v1/trusted-device-code\0");
    hasher.update(device_pk);
    let hash = hasher.finalize();
    (0..4)
        .map(|i| {
            let chunk = &hash[i * 5..i * 5 + 5];
            let value = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The account's signed statement that a device may open its account key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDeviceGrant {
    pub account_id: String,
    pub device_id: String,
    pub device_key_hash: [u8; HASH_LEN],
    pub sealed_hash: [u8; HASH_LEN],
    /// The device that approved this one; empty when the device trusted
    /// itself while unlocked.
    pub approved_by: String,
    pub approved_at: i64,
}

impl Canonical for TrustedDeviceGrant {
    const TAG: &'static str = "passbox/v1/trusted-device-grant";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.account_id)
            .str(&self.device_id)
            .bytes(&self.device_key_hash)
            .bytes(&self.sealed_hash)
            .str(&self.approved_by)
            .i64(self.approved_at);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            account_id: r.string()?,
            device_id: r.string()?,
            device_key_hash: r.array()?,
            sealed_hash: r.array()?,
            approved_by: r.string()?,
            approved_at: r.i64()?,
        })
    }
}

/// What a device uploads to become trusted (`POST /api/v1/account/trusted-devices`
/// or the approval of a request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDeviceUpload {
    pub device_id: String,
    /// The device's X-Wing public key (Base64url).
    pub public_key: String,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
}

/// What the server returns to a trusted device after an SSO sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDeviceUnlock {
    pub account_id: String,
    pub device_id: String,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
    /// The account's key pairs (`GET /api/v1/account/keys`).
    pub bundle: String,
    pub bundle_signature: String,
    pub encrypted_private: String,
}

impl Keyring {
    /// Seals the account key to a device's public key and signs the grant.
    /// `approved_by` is the approving device's ID, or empty when a device
    /// trusts itself. Call it for another device only after the user
    /// compared [`approval_code`] on both devices.
    pub fn trust_device(
        &self,
        device_id: &str,
        device_pk: &[u8],
        approved_by: &str,
        now: i64,
    ) -> Result<TrustedDeviceUpload> {
        if device_pk.len() != ENC_PK_LEN {
            return Err(denied("the device key has the wrong length"));
        }
        if device_id.is_empty() || device_id.len() > 64 {
            return Err(denied("invalid device ID"));
        }
        let keys = self.account_keys()?;
        let key_hash = device_key_hash(device_pk);
        let sealed = identity::seal(
            device_pk,
            &key_hash,
            PURPOSE,
            &context(self.account_id(), device_id),
            self.account_key().as_bytes(),
        )?;
        let grant = Signed::sign(
            TrustedDeviceGrant {
                account_id: self.account_id().to_owned(),
                device_id: device_id.to_owned(),
                device_key_hash: key_hash,
                sealed_hash: sealed_hash(&sealed),
                approved_by: approved_by.to_owned(),
                approved_at: now,
            },
            &keys.sig,
        );
        Ok(TrustedDeviceUpload {
            device_id: device_id.to_owned(),
            public_key: encoding::encode(device_pk),
            sealed_key: encoding::encode(&sealed),
            grant: grant.encoded(),
            grant_signature: grant.encoded_signature(),
        })
    }
}

/// A device's key pair. Its seed must be kept in the platform's protected
/// storage (Secure Enclave/Keychain, Android Keystore, TPM, or in the
/// browser wrapped with a non-extractable WebCrypto key).
pub struct TrustedDeviceKey {
    key: EncryptionKey,
}

impl core::fmt::Debug for TrustedDeviceKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TrustedDeviceKey(<redacted>)")
    }
}

impl TrustedDeviceKey {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            key: EncryptionKey::generate()?,
        })
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: EncryptionKey::from_seed(seed),
        }
    }

    pub fn seed(&self) -> &[u8; 32] {
        self.key.seed()
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    /// The code to compare with the approving device.
    pub fn approval_code(&self) -> String {
        approval_code(&self.public_key())
    }

    /// Opens the account key and verifies it (see the module docs). The
    /// returned keyring has the account's key pairs loaded.
    pub fn unlock(&self, unlock: &TrustedDeviceUnlock) -> Result<Keyring> {
        let grant = Signed::<TrustedDeviceGrant>::parse(&unlock.grant, &unlock.grant_signature)?;
        let sealed = encoding::decode(&unlock.sealed_key)?;
        let public_key = self.public_key();
        let key_hash = device_key_hash(&public_key);
        let g = &grant.value;
        if g.account_id != unlock.account_id
            || g.device_id != unlock.device_id
            || g.device_key_hash != key_hash
            || g.sealed_hash != sealed_hash(&sealed)
        {
            return Err(denied(
                "the trusted device grant does not match this device",
            ));
        }
        let plaintext = self.key.open(
            &key_hash,
            PURPOSE,
            &context(&unlock.account_id, &unlock.device_id),
            &sealed,
        )?;
        let account_key = key_from_plaintext(plaintext.to_vec())?;
        let mut keyring = Keyring::from_account_key(&unlock.account_id, account_key);
        keyring.load_account_keys(
            &unlock.bundle,
            &unlock.bundle_signature,
            &unlock.encrypted_private,
        )?;
        let sig_pk = keyring
            .own_bundle()
            .map(|b| b.bundle.sig_pk)
            .ok_or_else(|| Error::MissingKey("account key pairs".into()))?;
        grant.verify(&sig_pk)?;
        Ok(keyring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::SymmetricKey;
    use crate::keyring::AccountKeysUpload;

    fn account() -> (Keyring, AccountKeysUpload) {
        let auk = SymmetricKey::generate().unwrap();
        let (mut keyring, _) = Keyring::create(&auk, "acct-1").unwrap();
        let keys = keyring.create_account_keys(1).unwrap();
        (keyring, keys)
    }

    fn unlock_for(upload: &TrustedDeviceUpload, keys: &AccountKeysUpload) -> TrustedDeviceUnlock {
        TrustedDeviceUnlock {
            account_id: "acct-1".into(),
            device_id: upload.device_id.clone(),
            sealed_key: upload.sealed_key.clone(),
            grant: upload.grant.clone(),
            grant_signature: upload.grant_signature.clone(),
            bundle: keys.bundle.clone(),
            bundle_signature: keys.bundle_signature.clone(),
            encrypted_private: keys.encrypted_private.clone(),
        }
    }

    #[test]
    fn a_trusted_device_unlocks_the_account() {
        let (keyring, keys) = account();
        let device = TrustedDeviceKey::generate().unwrap();
        let upload = keyring
            .trust_device("dev-1", &device.public_key(), "", 10)
            .unwrap();
        // The seed survives a round trip through storage.
        let restored = TrustedDeviceKey::from_seed(device.seed());
        let opened = restored.unlock(&unlock_for(&upload, &keys)).unwrap();
        assert_eq!(opened.account_id(), "acct-1");
        assert!(opened.has_account_keys());
        assert_eq!(
            opened.account_key().as_bytes(),
            keyring.account_key().as_bytes()
        );
        assert_eq!(device.approval_code(), approval_code(&device.public_key()));
        assert_eq!(device.approval_code().len(), 23);
    }

    #[test]
    fn approval_by_another_device_and_tampering() {
        let (keyring, keys) = account();
        let new_device = TrustedDeviceKey::generate().unwrap();
        let upload = keyring
            .trust_device("dev-2", &new_device.public_key(), "dev-1", 10)
            .unwrap();
        let good = unlock_for(&upload, &keys);
        assert!(new_device.unlock(&good).is_ok());

        // Another device cannot open it.
        let other = TrustedDeviceKey::generate().unwrap();
        assert!(other.unlock(&good).is_err());
        // Wrong device ID or account in the record.
        let mut wrong = good.clone();
        wrong.device_id = "dev-3".into();
        assert!(new_device.unlock(&wrong).is_err());
        let mut wrong = good.clone();
        wrong.account_id = "acct-2".into();
        assert!(new_device.unlock(&wrong).is_err());

        // A server that seals some other key to the device, with a grant it
        // signs itself, is detected: the key does not open the key pairs,
        // and the grant is not signed by the account.
        let (attacker, attacker_keys) = account();
        let forged = attacker
            .trust_device("dev-2", &new_device.public_key(), "dev-1", 10)
            .unwrap();
        let mut mixed = unlock_for(&forged, &keys);
        assert!(new_device.unlock(&mixed).is_err(), "foreign account key");
        mixed = unlock_for(&upload, &attacker_keys);
        assert!(new_device.unlock(&mixed).is_err(), "foreign key pairs");
        let mut swapped = good.clone();
        swapped.grant = forged.grant.clone();
        swapped.grant_signature = forged.grant_signature.clone();
        assert!(new_device.unlock(&swapped).is_err(), "foreign grant");

        // A swapped key gives a different approval code.
        assert_ne!(new_device.approval_code(), other.approval_code());
        // Bad inputs.
        assert!(keyring.trust_device("dev", &[0; 10], "", 1).is_err());
        assert!(
            keyring
                .trust_device("", &new_device.public_key(), "", 1)
                .is_err()
        );
        let locked = Keyring::from_account_key("acct-1", SymmetricKey::generate().unwrap());
        assert!(
            locked
                .trust_device("dev", &new_device.public_key(), "", 1)
                .is_err()
        );
    }
}
