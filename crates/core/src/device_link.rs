//! Adding a device with a code from a signed-in device.
//!
//! The signed-in device asks the server for a link (the server picks a
//! 4-character `short_id`), adds a 12-character secret and shows
//! `XXXX-XXXX-XXXX-XXXX` (also as a QR code). The secret never reaches the
//! server. The new device types or scans the code, creates an ephemeral
//! X-Wing key pair and claims the link with
//!
//! ```text
//! mac = HMAC-SHA256(HKDF-SHA256(ikm = secret, salt = short_id, info = "passbox/v1/device-link"),
//!                   canonical("passbox/v1/device-link-claim", short_id, ephemeral_pk))
//! ```
//!
//! The signed-in device checks the MAC, so a server that swaps in its own
//! ephemeral key is detected (it would have to guess 60 secret bits within
//! the link's lifetime), shows the new device's name and, after the user
//! approves, seals the account's email, ID and Secret Key to the ephemeral
//! key (purpose `device-link`). The master password is never transferred:
//! the new device still asks for it.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canon::Writer;
use crate::identity::{self, EncryptionKey};
use crate::keyring::ensure_json;
use crate::recovery::ephemeral_key_hash;
use crate::{Error, Result, encoding, random};

pub const PURPOSE: &str = "device-link";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const SHORT_ID_LEN: usize = 4;
const SECRET_LEN: usize = 12;

fn normalize(input: &str) -> Zeroizing<String> {
    Zeroizing::new(
        input
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            })
            .collect(),
    )
}

/// Whether `value` is a valid short ID (4 Crockford Base32 characters).
pub fn is_short_id(value: &str) -> bool {
    value.len() == SHORT_ID_LEN && value.bytes().all(|b| ALPHABET.contains(&b))
}

/// A random short ID, for the server.
pub fn new_short_id() -> Result<String> {
    random_chars(SHORT_ID_LEN).map(|s| s.to_string())
}

fn random_chars(len: usize) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(len));
    for _ in 0..len {
        out.push(char::from(ALPHABET[random::below(32)? as usize]));
    }
    Ok(out)
}

fn mac_key(short_id: &str, secret: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(short_id.as_bytes()), secret.as_bytes())
        .expand(b"passbox/v1/device-link", key.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(key)
}

fn claim_mac(short_id: &str, secret: &str, ephemeral_pk: &[u8]) -> Result<Vec<u8>> {
    let key = mac_key(short_id, secret)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref())
        .expect("HMAC accepts any key length");
    mac.update(
        &Writer::new("passbox/v1/device-link-claim")
            .str(short_id)
            .bytes(ephemeral_pk)
            .finish(),
    );
    Ok(mac.finalize().into_bytes().to_vec())
}

fn context(short_id: &str) -> Vec<u8> {
    Writer::new("passbox/v1/seal-context/device-link")
        .str(short_id)
        .finish()
}

fn display(short_id: &str, secret: &str) -> String {
    let all = format!("{short_id}{secret}");
    all.as_bytes()
        .chunks(4)
        .map(|c| core::str::from_utf8(c).expect("ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// The signed-in device's side.
pub struct DeviceLinkOffer {
    short_id: String,
    secret: Zeroizing<String>,
}

impl core::fmt::Debug for DeviceLinkOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceLinkOffer")
            .field("short_id", &self.short_id)
            .finish_non_exhaustive()
    }
}

impl DeviceLinkOffer {
    /// Adds a fresh secret to the server's short ID.
    pub fn new(short_id: &str) -> Result<Self> {
        if !is_short_id(short_id) {
            return Err(Error::InvalidDeviceCode);
        }
        Ok(Self {
            short_id: short_id.to_owned(),
            secret: random_chars(SECRET_LEN)?,
        })
    }

    /// `XXXX-XXXX-XXXX-XXXX`, to show and to put into the QR code.
    pub fn code(&self) -> String {
        display(&self.short_id, &self.secret)
    }

    /// Checks that the claim comes from a device that knows the code.
    pub fn verify_claim(&self, ephemeral_pk: &[u8], mac: &[u8]) -> Result<()> {
        let key = mac_key(&self.short_id, &self.secret)?;
        let mut check = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref())
            .expect("HMAC accepts any key length");
        check.update(
            &Writer::new("passbox/v1/device-link-claim")
                .str(&self.short_id)
                .bytes(ephemeral_pk)
                .finish(),
        );
        check
            .verify_slice(mac)
            .map_err(|_| Error::InvalidDeviceCode)
    }

    /// Verifies the claim and seals `payload_json` (email, account ID and
    /// Secret Key) to the new device's ephemeral key.
    pub fn seal(&self, ephemeral_pk: &[u8], mac: &[u8], payload_json: &str) -> Result<String> {
        self.verify_claim(ephemeral_pk, mac)?;
        ensure_json(payload_json.as_bytes())?;
        let sealed = identity::seal(
            ephemeral_pk,
            &ephemeral_key_hash(ephemeral_pk),
            PURPOSE,
            &context(&self.short_id),
            payload_json.as_bytes(),
        )?;
        Ok(encoding::encode(&sealed))
    }
}

/// The new device's side.
pub struct DeviceLinkRequest {
    short_id: String,
    key: EncryptionKey,
    mac: Vec<u8>,
}

impl core::fmt::Debug for DeviceLinkRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceLinkRequest")
            .field("short_id", &self.short_id)
            .finish_non_exhaustive()
    }
}

impl DeviceLinkRequest {
    /// Parses the code shown on the signed-in device (typing mistakes
    /// such as `O`/`0` are forgiven) and creates an ephemeral key.
    pub fn new(code: &str) -> Result<Self> {
        let compact = normalize(code);
        if compact.len() != SHORT_ID_LEN + SECRET_LEN
            || !compact.bytes().all(|b| ALPHABET.contains(&b))
        {
            return Err(Error::InvalidDeviceCode);
        }
        let (short_id, secret) = compact.split_at(SHORT_ID_LEN);
        let key = EncryptionKey::generate()?;
        let mac = claim_mac(short_id, secret, &key.public_key())?;
        Ok(Self {
            short_id: short_id.to_owned(),
            key,
            mac,
        })
    }

    /// Whether `code` has the shape of a device code.
    pub fn is_valid_code(code: &str) -> bool {
        let compact = normalize(code);
        compact.len() == SHORT_ID_LEN + SECRET_LEN && compact.bytes().all(|b| ALPHABET.contains(&b))
    }

    pub fn short_id(&self) -> &str {
        &self.short_id
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    /// Opens the sealed payload (JSON).
    pub fn open(&self, sealed: &str) -> Result<String> {
        let public_key = self.key.public_key();
        let plaintext = self.key.open(
            &ephemeral_key_hash(&public_key),
            PURPOSE,
            &context(&self.short_id),
            &encoding::decode(sealed)?,
        )?;
        ensure_json(&plaintext)?;
        String::from_utf8(plaintext.to_vec())
            .map_err(|_| Error::InvalidData("payload is not UTF-8".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_device_receives_the_payload() {
        let short_id = new_short_id().unwrap();
        assert!(is_short_id(&short_id));
        let offer = DeviceLinkOffer::new(&short_id).unwrap();
        let code = offer.code();
        assert_eq!(code.len(), 19);
        assert!(code.starts_with(&short_id));
        // Typed in lower case with O instead of 0 still works.
        let typed = code.to_lowercase().replace('0', "o");
        assert!(DeviceLinkRequest::is_valid_code(&typed));
        let device = DeviceLinkRequest::new(&typed).unwrap();
        assert_eq!(device.short_id(), short_id);
        let payload = r#"{"email":"ada@example.com","accountId":"a","secretKey":"P1-X"}"#;
        let sealed = offer
            .seal(&device.public_key(), device.mac(), payload)
            .unwrap();
        assert_eq!(device.open(&sealed).unwrap(), payload);
    }

    #[test]
    fn a_swapped_key_or_wrong_code_is_detected() {
        let offer = DeviceLinkOffer::new("AB12").unwrap();
        let device = DeviceLinkRequest::new(&offer.code()).unwrap();
        // A server substituting its own ephemeral key cannot produce the MAC.
        let attacker = EncryptionKey::generate().unwrap();
        assert_eq!(
            offer.seal(&attacker.public_key(), device.mac(), "{}"),
            Err(Error::InvalidDeviceCode)
        );
        // A device that typed a different secret fails too.
        let mut wrong = offer.code();
        wrong.replace_range(18..19, if wrong.ends_with('A') { "B" } else { "A" });
        let other = DeviceLinkRequest::new(&wrong).unwrap();
        assert!(
            offer
                .verify_claim(&other.public_key(), other.mac())
                .is_err()
        );
        // Another device cannot open what was sealed for this one.
        let sealed = offer
            .seal(&device.public_key(), device.mac(), "{}")
            .unwrap();
        assert!(other.open(&sealed).is_err());
        // Malformed codes and IDs.
        assert!(DeviceLinkRequest::new("ABCD-EFGH").is_err());
        assert!(DeviceLinkOffer::new("ab1").is_err());
        assert!(!DeviceLinkRequest::is_valid_code("ABCD-EFGH-JKMN-PQR!"));
    }
}
