//! Password-protected export files (`.pbx-export`).
//!
//! An export is a JSON envelope whose payload is encrypted with a key derived
//! from a password the user chooses for this file only. It does not depend on
//! the account, so it can be imported into any Passbox account (or kept as an
//! offline backup).
//!
//! ```text
//! {
//!   "format": "passbox-export",
//!   "version": 1,
//!   "kdf": { "algorithm": "argon2id", "salt": <16 bytes, Base64url>,
//!            "memoryKib": m, "iterations": t, "parallelism": p },
//!   "cipher": "xchacha20poly1305",
//!   "ciphertext": <aead envelope, Base64url>
//! }
//!
//! k   = Argon2id(password, salt, m, t, p)                        (32 bytes)
//! key = HKDF-SHA256(ikm = k, info = "passbox/v1/export")
//! aad = "passbox-export" 0x00 "1" 0x00 "argon2id" 0x00 m 0x00 t 0x00 p
//!       0x00 salt 0x00 "xchacha20poly1305"
//! ciphertext = XChaCha20-Poly1305(key, plaintext, aad)   (see `aead`)
//! ```
//!
//! The associated data is rebuilt from the parsed header, so changing any
//! header field (for example lowering the KDF cost) makes decryption fail.
//! Decryption enforces [`KdfParams::MINIMUM`] and an upper bound, so a crafted
//! file can neither downgrade the derivation nor exhaust memory.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead::SymmetricKey;
use crate::kdf::{self, KdfParams};
use crate::{Error, Result, encoding, random};

/// The `format` value of every export file.
pub const FORMAT: &str = "passbox-export";
/// The export format version this crate writes.
pub const VERSION: u32 = 1;
const KDF_ALGORITHM: &str = "argon2id";
const CIPHER: &str = "xchacha20poly1305";
const KEY_INFO: &[u8] = b"passbox/v1/export";
const SALT_LEN: usize = 16;

/// The highest KDF cost an export may ask for (1 GiB, 64 passes, 16 lanes).
pub const MAXIMUM: KdfParams = KdfParams {
    memory_kib: 1024 * 1024,
    iterations: 64,
    parallelism: 16,
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KdfHeader {
    algorithm: String,
    salt: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: String,
    version: u32,
    kdf: KdfHeader,
    cipher: String,
    ciphertext: String,
}

/// Encrypts `plaintext` with `password` and returns the JSON envelope.
pub fn encrypt(password: &str, plaintext: &[u8], params: KdfParams) -> Result<String> {
    check_params(params)?;
    let salt: [u8; SALT_LEN] = random::bytes()?;
    encrypt_with_salt(password, plaintext, params, &salt)
}

fn encrypt_with_salt(
    password: &str,
    plaintext: &[u8],
    params: KdfParams,
    salt: &[u8; SALT_LEN],
) -> Result<String> {
    if password.is_empty() {
        return Err(Error::InvalidData("the export password is empty".into()));
    }
    let salt_b64 = encoding::encode(salt);
    let aad = header_aad(VERSION, params, &salt_b64);
    let key = derive_key(password, salt, params)?;
    let ciphertext = key.encrypt(plaintext, &aad)?;
    let envelope = Envelope {
        format: FORMAT.into(),
        version: VERSION,
        kdf: KdfHeader {
            algorithm: KDF_ALGORITHM.into(),
            salt: salt_b64,
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
        },
        cipher: CIPHER.into(),
        ciphertext: encoding::encode(&ciphertext),
    };
    serde_json::to_string(&envelope).map_err(|e| Error::InvalidData(e.to_string()))
}

/// Decrypts an envelope produced by [`encrypt`]. A wrong password or a
/// modified file fails with [`Error::Decryption`].
pub fn decrypt(password: &str, envelope_json: &str) -> Result<Zeroizing<Vec<u8>>> {
    let envelope: Envelope = serde_json::from_str(envelope_json)
        .map_err(|_| Error::InvalidData("not a Passbox export file".into()))?;
    if envelope.format != FORMAT {
        return Err(Error::InvalidData("not a Passbox export file".into()));
    }
    if envelope.version != VERSION
        || envelope.kdf.algorithm != KDF_ALGORITHM
        || envelope.cipher != CIPHER
    {
        return Err(Error::UnsupportedEnvelope);
    }
    let params = KdfParams {
        memory_kib: envelope.kdf.memory_kib,
        iterations: envelope.kdf.iterations,
        parallelism: envelope.kdf.parallelism,
    };
    check_params(params)?;
    let salt = encoding::decode(&envelope.kdf.salt)?;
    if salt.len() != SALT_LEN {
        return Err(Error::MalformedEnvelope);
    }
    let ciphertext = encoding::decode(&envelope.ciphertext)?;
    let aad = header_aad(envelope.version, params, &envelope.kdf.salt);
    let key = derive_key(password, &salt, params)?;
    key.decrypt(&ciphertext, &aad).map(Zeroizing::new)
}

/// Returns `true` if `input` looks like an export envelope (without
/// decrypting it). Used to recognise export files during import.
pub fn is_export(input: &str) -> bool {
    #[derive(Deserialize)]
    struct Probe {
        format: String,
    }
    serde_json::from_str::<Probe>(input).is_ok_and(|p| p.format == FORMAT)
}

fn check_params(params: KdfParams) -> Result<()> {
    params.ensure_minimum()?;
    if params.memory_kib > MAXIMUM.memory_kib
        || params.iterations > MAXIMUM.iterations
        || params.parallelism > MAXIMUM.parallelism
    {
        return Err(Error::InvalidData(
            "key derivation parameters are too high".into(),
        ));
    }
    Ok(())
}

fn header_aad(version: u32, params: KdfParams, salt_b64: &str) -> Vec<u8> {
    let parts = [
        FORMAT.to_owned(),
        version.to_string(),
        KDF_ALGORITHM.to_owned(),
        params.memory_kib.to_string(),
        params.iterations.to_string(),
        params.parallelism.to_string(),
        salt_b64.to_owned(),
        CIPHER.to_owned(),
    ];
    parts.join("\0").into_bytes()
}

fn derive_key(password: &str, salt: &[u8], params: KdfParams) -> Result<SymmetricKey> {
    let k = kdf::argon2id(password, salt, params)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, k.as_ref())
        .expand(KEY_INFO, key.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(SymmetricKey::from_bytes(*key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const PARAMS: KdfParams = KdfParams::MINIMUM;

    fn tamper(envelope: &str, edit: impl FnOnce(&mut Value)) -> String {
        let mut value: Value = serde_json::from_str(envelope).unwrap();
        edit(&mut value);
        value.to_string()
    }

    #[test]
    fn round_trip() {
        let envelope = encrypt("export pass", b"{\"items\":[]}", PARAMS).unwrap();
        assert!(is_export(&envelope));
        let plaintext = decrypt("export pass", &envelope).unwrap();
        assert_eq!(plaintext.as_slice(), b"{\"items\":[]}");
    }

    #[test]
    fn header_is_readable_and_hides_the_plaintext() {
        let envelope = encrypt("pw", b"secret-password-123", PARAMS).unwrap();
        let value: Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(value["format"], "passbox-export");
        assert_eq!(value["version"], 1);
        assert_eq!(value["kdf"]["algorithm"], "argon2id");
        assert_eq!(value["kdf"]["memoryKib"], PARAMS.memory_kib);
        assert_eq!(value["cipher"], "xchacha20poly1305");
        assert!(!envelope.contains("secret-password-123"));
    }

    #[test]
    fn salts_differ() {
        let a = encrypt("pw", b"x", PARAMS).unwrap();
        let b = encrypt("pw", b"x", PARAMS).unwrap();
        let salt = |e: &str| serde_json::from_str::<Value>(e).unwrap()["kdf"]["salt"].clone();
        assert_ne!(salt(&a), salt(&b));
    }

    #[test]
    fn wrong_password_fails() {
        let envelope = encrypt("right", b"x", PARAMS).unwrap();
        assert_eq!(decrypt("wrong", &envelope).unwrap_err(), Error::Decryption);
    }

    #[test]
    fn header_is_authenticated() {
        let envelope = encrypt("pw", b"x", PARAMS).unwrap();
        // Raising the cost keeps the parameters valid but changes the AAD.
        let changed = tamper(&envelope, |v| v["kdf"]["iterations"] = 4.into());
        assert_eq!(decrypt("pw", &changed).unwrap_err(), Error::Decryption);
        let other_salt = encoding::encode(&[9u8; SALT_LEN]);
        let changed = tamper(&envelope, |v| v["kdf"]["salt"] = other_salt.into());
        assert_eq!(decrypt("pw", &changed).unwrap_err(), Error::Decryption);
    }

    #[test]
    fn aad_differs_per_header_field() {
        let salt = "c2FsdA";
        let base = header_aad(1, PARAMS, salt);
        assert_ne!(base, header_aad(2, PARAMS, salt));
        assert_ne!(base, header_aad(1, PARAMS, "b3RoZXI"));
        let more = KdfParams {
            parallelism: 2,
            ..PARAMS
        };
        assert_ne!(base, header_aad(1, more, salt));
    }

    #[test]
    fn ciphertext_tampering_fails() {
        let envelope = encrypt("pw", b"hello", PARAMS).unwrap();
        let value: Value = serde_json::from_str(&envelope).unwrap();
        let mut bytes = encoding::decode(value["ciphertext"].as_str().unwrap()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let changed = tamper(&envelope, |v| {
            v["ciphertext"] = encoding::encode(&bytes).into()
        });
        assert_eq!(decrypt("pw", &changed).unwrap_err(), Error::Decryption);
    }

    #[test]
    fn weak_and_excessive_params_are_rejected() {
        let weak = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert_eq!(encrypt("pw", b"x", weak).unwrap_err(), Error::WeakKdfParams);
        let envelope = encrypt("pw", b"x", PARAMS).unwrap();
        let downgraded = tamper(&envelope, |v| v["kdf"]["memoryKib"] = 1024.into());
        assert_eq!(
            decrypt("pw", &downgraded).unwrap_err(),
            Error::WeakKdfParams
        );
        let huge = tamper(&envelope, |v| v["kdf"]["memoryKib"] = (8u64 << 20).into());
        assert!(matches!(
            decrypt("pw", &huge).unwrap_err(),
            Error::InvalidData(_)
        ));
    }

    #[test]
    fn unknown_versions_and_other_files_are_rejected() {
        let envelope = encrypt("pw", b"x", PARAMS).unwrap();
        let v2 = tamper(&envelope, |v| v["version"] = 2.into());
        assert_eq!(decrypt("pw", &v2).unwrap_err(), Error::UnsupportedEnvelope);
        let cipher = tamper(&envelope, |v| v["cipher"] = "aes".into());
        assert_eq!(
            decrypt("pw", &cipher).unwrap_err(),
            Error::UnsupportedEnvelope
        );
        assert!(matches!(
            decrypt("pw", "{\"items\":[]}").unwrap_err(),
            Error::InvalidData(_)
        ));
        assert!(!is_export("name,url,username,password"));
        assert!(!is_export("{\"format\":\"other\"}"));
    }

    #[test]
    fn empty_password_is_rejected() {
        assert!(matches!(
            encrypt("", b"x", PARAMS).unwrap_err(),
            Error::InvalidData(_)
        ));
    }

    #[test]
    fn fixed_salt_is_deterministic_in_key_but_not_ciphertext() {
        let salt = [3u8; SALT_LEN];
        let a = encrypt_with_salt("pw", b"x", PARAMS, &salt).unwrap();
        let b = encrypt_with_salt("pw", b"x", PARAMS, &salt).unwrap();
        // Fresh nonces: same key, different ciphertexts, both decrypt.
        assert_ne!(a, b);
        assert_eq!(decrypt("pw", &a).unwrap().as_slice(), b"x");
        assert_eq!(decrypt("pw", &b).unwrap().as_slice(), b"x");
    }
}
