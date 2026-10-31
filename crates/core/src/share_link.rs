//! Share links for people without a Passbox account.
//!
//! A share link carries a snapshot (a copy of an item, or free text) that
//! is encrypted on the sender's device. The key travels only in the URL
//! fragment, which browsers never send to the server:
//!
//! ```text
//! k_link  = random(32)                                   (in the fragment: #{base64url(k_link)})
//! ikm     = k_link                                       (no passphrase)
//!         | k_link || Argon2id(passphrase, salt)          (with a passphrase; salt random(16))
//! enc_key = HKDF-SHA256(ikm, info = "passbox/v1/link-key|{link_id}")
//! auth    = HKDF-SHA256(ikm, info = "passbox/v1/link-auth|{link_id}")
//! blob    = XChaCha20-Poly1305(enc_key, snapshot, aad = "passbox/v1/link|{link_id}")
//! server stores blob, SHA-256("passbox/v1/link-auth-hash\0" || auth), expiry, view limit
//! ```
//!
//! The server hands out the blob (and counts a view) only to a caller that
//! presents `auth`. So a view is only consumed by someone who has the whole
//! link and, if set, the passphrase; somebody who only knows the link ID
//! (for example from a log) learns nothing and cannot use up views. A wrong
//! passphrase is rejected by the server without decrypting anything; the
//! server cannot try passphrases offline because it does not know `k_link`.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::aead::SymmetricKey;
use crate::kdf::{self, KdfParams};
use crate::{Error, Result, encoding, random};

const SALT_LEN: usize = 16;

/// Argon2id cost for link passphrases. The passphrase is combined with the
/// 256-bit link key, so it only has to resist online guessing by someone
/// who has the link; the cost stays low enough for phones.
pub const PASSPHRASE_KDF: KdfParams = KdfParams::MINIMUM;

/// What the sender's device produces for a new link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewShareLink {
    /// Base64url link key; goes into the URL fragment only.
    pub key: String,
    /// Base64url encrypted snapshot (an `aead` envelope), for the server.
    pub blob: String,
    /// Base64url hash of the access token, for the server.
    pub auth_hash: String,
    /// Base64url passphrase salt, for the server (`None` without a passphrase).
    pub salt: Option<String>,
}

struct LinkKeys {
    enc: SymmetricKey,
    auth: Zeroizing<[u8; 32]>,
}

fn check_link_id(link_id: &str) -> Result<()> {
    if !crate::id::is_valid_id(link_id) {
        return Err(Error::InvalidData("invalid link id".into()));
    }
    Ok(())
}

fn derive(
    link_id: &str,
    link_key: &[u8],
    passphrase: Option<&str>,
    salt: Option<&[u8]>,
) -> Result<LinkKeys> {
    if link_key.len() != 32 {
        return Err(Error::InvalidData("a link key has 32 bytes".into()));
    }
    let mut ikm = Zeroizing::new(link_key.to_vec());
    match (passphrase, salt) {
        (Some(passphrase), Some(salt)) => {
            if passphrase.is_empty() {
                return Err(Error::InvalidData("the passphrase is empty".into()));
            }
            if salt.len() != SALT_LEN {
                return Err(Error::InvalidData("invalid passphrase salt".into()));
            }
            let stretched = kdf::argon2id(passphrase, salt, PASSPHRASE_KDF)?;
            ikm.extend_from_slice(stretched.as_ref());
        }
        (None, None) => {}
        (None, Some(_)) => {
            return Err(Error::InvalidData("this link needs its passphrase".into()));
        }
        (Some(_), None) => {
            return Err(Error::InvalidData("this link has no passphrase".into()));
        }
    }
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut auth = Zeroizing::new([0u8; 32]);
    hkdf.expand(
        format!("passbox/v1/link-key|{link_id}").as_bytes(),
        enc.as_mut(),
    )
    .and_then(|()| {
        hkdf.expand(
            format!("passbox/v1/link-auth|{link_id}").as_bytes(),
            auth.as_mut(),
        )
    })
    .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(LinkKeys {
        enc: SymmetricKey::from_bytes(*enc),
        auth,
    })
}

fn aad(link_id: &str) -> Vec<u8> {
    format!("passbox/v1/link|{link_id}").into_bytes()
}

/// The hash the server stores for an access token (Base64url in and out).
pub fn auth_hash(auth_token: &str) -> Result<String> {
    let token = encoding::decode(auth_token)?;
    let mut hasher = Sha256::new();
    hasher.update(b"passbox/v1/link-auth-hash\0");
    hasher.update(&token);
    Ok(encoding::encode(&hasher.finalize()))
}

/// Encrypts `snapshot` for a new link with ID `link_id` (from `id::new_id`).
pub fn create(link_id: &str, snapshot: &str, passphrase: Option<&str>) -> Result<NewShareLink> {
    check_link_id(link_id)?;
    let link_key: Zeroizing<[u8; 32]> = Zeroizing::new(random::bytes()?);
    let salt: Option<[u8; SALT_LEN]> = passphrase.map(|_| random::bytes()).transpose()?;
    let keys = derive(
        link_id,
        link_key.as_ref(),
        passphrase,
        salt.as_ref().map(|s| &s[..]),
    )?;
    let blob = keys.enc.encrypt(snapshot.as_bytes(), &aad(link_id))?;
    Ok(NewShareLink {
        key: encoding::encode(link_key.as_ref()),
        blob: encoding::encode(&blob),
        auth_hash: auth_hash(&encoding::encode(keys.auth.as_ref()))?,
        salt: salt.map(|s| encoding::encode(&s)),
    })
}

/// The access token for opening a link (sent to the server).
pub fn auth_token(
    link_id: &str,
    key: &str,
    passphrase: Option<&str>,
    salt: Option<&str>,
) -> Result<String> {
    check_link_id(link_id)?;
    let link_key = Zeroizing::new(encoding::decode(key)?);
    let salt = salt.map(encoding::decode).transpose()?;
    let keys = derive(link_id, &link_key, passphrase, salt.as_deref())?;
    Ok(encoding::encode(keys.auth.as_ref()))
}

/// Decrypts the snapshot of a link.
pub fn open(
    link_id: &str,
    key: &str,
    passphrase: Option<&str>,
    salt: Option<&str>,
    blob: &str,
) -> Result<String> {
    check_link_id(link_id)?;
    let link_key = Zeroizing::new(encoding::decode(key)?);
    let salt = salt.map(encoding::decode).transpose()?;
    let keys = derive(link_id, &link_key, passphrase, salt.as_deref())?;
    let plaintext = Zeroizing::new(keys.enc.decrypt(&encoding::decode(blob)?, &aad(link_id))?);
    String::from_utf8(plaintext.to_vec()).map_err(|_| Error::InvalidData("not text".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "01hzy3m5k8q9w2e4r6t8y0a2a4";

    #[test]
    fn round_trip_without_passphrase() {
        let link = create(ID, r#"{"title":"Wi-Fi"}"#, None).unwrap();
        assert!(link.salt.is_none());
        let token = auth_token(ID, &link.key, None, None).unwrap();
        assert_eq!(auth_hash(&token).unwrap(), link.auth_hash);
        assert_eq!(
            open(ID, &link.key, None, None, &link.blob).unwrap(),
            r#"{"title":"Wi-Fi"}"#
        );
    }

    #[test]
    fn passphrase_is_needed_and_checked() {
        let link = create(ID, "secret", Some("correct horse")).unwrap();
        let salt = link.salt.as_deref();
        let good = auth_token(ID, &link.key, Some("correct horse"), salt).unwrap();
        assert_eq!(auth_hash(&good).unwrap(), link.auth_hash);
        let bad = auth_token(ID, &link.key, Some("wrong"), salt).unwrap();
        assert_ne!(auth_hash(&bad).unwrap(), link.auth_hash);
        assert!(open(ID, &link.key, Some("wrong"), salt, &link.blob).is_err());
        assert!(open(ID, &link.key, None, salt, &link.blob).is_err());
        assert!(open(ID, &link.key, None, None, &link.blob).is_err());
        assert_eq!(
            open(ID, &link.key, Some("correct horse"), salt, &link.blob).unwrap(),
            "secret"
        );
    }

    #[test]
    fn bound_to_link_id_and_key() {
        let link = create(ID, "x", None).unwrap();
        let other = "01hzy3m5k8q9w2e4r6t8y0a2a5";
        assert!(open(other, &link.key, None, None, &link.blob).is_err());
        let other_key = encoding::encode(&[1u8; 32]);
        assert!(open(ID, &other_key, None, None, &link.blob).is_err());
        assert!(create("not an id", "x", None).is_err());
        assert!(auth_token(ID, "AAAA", None, None).is_err());
    }
}
