//! Passkeys (WebAuthn credentials) stored in the vault.
//!
//! Passbox acts as a WebAuthn authenticator for ES256 (ECDSA on P-256 with
//! SHA-256, COSE algorithm `-7`). This module creates credentials, encodes the
//! COSE public key, the authenticator data and a `"none"` attestation object,
//! and signs assertions over `authenticatorData || SHA-256(clientDataJSON)`.
//!
//! Private keys are exported as PKCS#8 DER so they can be stored in item data
//! (encrypted like every other field). Relying-party and origin checks are the
//! caller's job: this module trusts the `rp_id` it is given.
//!
//! References: W3C Web Authentication Level 3 (§6.1 authenticator data,
//! §6.5.4 attestation object), RFC 9052/9053 (COSE keys), RFC 8949 (CBOR).

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result, random};

/// COSE algorithm identifier for ES256.
pub const ALG_ES256: i64 = -7;

/// Authenticator Attestation GUID that identifies Passbox credentials.
/// Random value, fixed for all Passbox clients.
pub const AAGUID: [u8; 16] = [
    0x3c, 0x8e, 0x0b, 0x56, 0x1d, 0x4f, 0x4a, 0x5b, 0x9b, 0x2e, 0x6f, 0x0d, 0x7a, 0x41, 0xc2, 0x93,
];

/// Length of newly generated credential IDs in bytes.
pub const CREDENTIAL_ID_LEN: usize = 16;

/// Authenticator data flags (WebAuthn §6.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// UP: the user confirmed the operation.
    pub user_present: bool,
    /// UV: the user was verified, that is, they entered the master password
    /// (or used biometrics) right before this operation. Callers set it only
    /// after such a fresh check; an unlock hours ago does not count.
    pub user_verified: bool,
    /// BE: the credential can be synced to other devices.
    pub backup_eligible: bool,
    /// BS: the credential is currently synced.
    pub backup_state: bool,
}

impl Flags {
    /// Flags for a synced Passbox passkey after an explicit user confirmation.
    pub const SYNCED: Flags = Flags {
        user_present: true,
        user_verified: true,
        backup_eligible: true,
        backup_state: true,
    };

    /// Flags for a synced Passbox passkey after an explicit user confirmation,
    /// with UV set only when the user was verified for this operation.
    pub const fn synced(user_verified: bool) -> Flags {
        Flags {
            user_verified,
            ..Flags::SYNCED
        }
    }

    fn to_byte(self, attested: bool) -> u8 {
        let mut byte = 0;
        if self.user_present {
            byte |= 0x01;
        }
        if self.user_verified {
            byte |= 0x04;
        }
        if self.backup_eligible {
            byte |= 0x08;
        }
        if self.backup_state {
            byte |= 0x10;
        }
        if attested {
            byte |= 0x40;
        }
        byte
    }
}

/// A newly created passkey and the data the relying party receives.
pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    /// PKCS#8 DER private key. Wiped from memory on drop.
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
    /// COSE_Key encoding of the public key.
    pub public_key_cose: Vec<u8>,
    /// SubjectPublicKeyInfo DER encoding of the public key (`getPublicKey()`).
    pub public_key_spki: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// CBOR attestation object with format `"none"`.
    pub attestation_object: Vec<u8>,
}

impl core::fmt::Debug for NewPasskey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NewPasskey")
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

/// The result of signing an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    /// ASN.1 DER encoded ECDSA signature, as WebAuthn expects for ES256.
    pub signature: Vec<u8>,
}

/// SHA-256 of `clientDataJSON`, as signed by the authenticator.
pub fn client_data_hash(client_data_json: &[u8]) -> [u8; 32] {
    Sha256::digest(client_data_json).into()
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

fn generate_signing_key() -> Result<SigningKey> {
    // Rejection sampling: almost every 32-byte string is a valid scalar.
    for _ in 0..64 {
        let bytes = Zeroizing::new(random::bytes::<32>()?);
        if let Ok(key) = SigningKey::from_slice(bytes.as_slice()) {
            return Ok(key);
        }
    }
    Err(Error::Random)
}

fn signing_key_from_pkcs8(der: &[u8]) -> Result<SigningKey> {
    SigningKey::from_pkcs8_der(der)
        .map_err(|_| Error::InvalidData("invalid passkey private key".into()))
}

/// Encodes a P-256 public key as a COSE_Key (EC2, ES256), with the map keys in
/// CTAP2 canonical order.
fn cose_public_key(key: &SigningKey) -> Result<Vec<u8>> {
    let point = key.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    // Uncompressed SEC1: 0x04 || x (32) || y (32).
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(Error::InvalidData("unexpected public key encoding".into()));
    }
    let mut out = Vec::with_capacity(77);
    cbor::map_header(&mut out, 5);
    cbor::int(&mut out, 1); // kty
    cbor::int(&mut out, 2); // EC2
    cbor::int(&mut out, 3); // alg
    cbor::int(&mut out, ALG_ES256);
    cbor::int(&mut out, -1); // crv
    cbor::int(&mut out, 1); // P-256
    cbor::int(&mut out, -2); // x
    cbor::bytes(&mut out, &bytes[1..33]);
    cbor::int(&mut out, -3); // y
    cbor::bytes(&mut out, &bytes[33..65]);
    Ok(out)
}

/// Builds authenticator data. `attested` holds the credential ID and COSE key
/// for registrations.
fn authenticator_data(
    rp_id: &str,
    flags: Flags,
    sign_count: u32,
    attested: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>> {
    let mut out =
        Vec::with_capacity(37 + attested.map_or(0, |(id, key)| 18 + id.len() + key.len()));
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(flags.to_byte(attested.is_some()));
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((credential_id, cose_key)) = attested {
        let len = u16::try_from(credential_id.len())
            .map_err(|_| Error::InvalidData("credential ID is too long".into()))?;
        out.extend_from_slice(&AAGUID);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(cose_key);
    }
    Ok(out)
}

/// Encodes a `"none"` attestation object: `{"fmt": "none", "attStmt": {}, "authData": …}`.
fn none_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len() + 32);
    cbor::map_header(&mut out, 3);
    cbor::text(&mut out, "fmt");
    cbor::text(&mut out, "none");
    cbor::text(&mut out, "attStmt");
    cbor::map_header(&mut out, 0);
    cbor::text(&mut out, "authData");
    cbor::bytes(&mut out, auth_data);
    out
}

/// Creates a new ES256 passkey for `rp_id` with a random credential ID.
pub fn create(rp_id: &str, flags: Flags) -> Result<NewPasskey> {
    let credential_id = random::bytes::<CREDENTIAL_ID_LEN>()?.to_vec();
    let key = generate_signing_key()?;
    let private_key_pkcs8 = Zeroizing::new(
        key.to_pkcs8_der()
            .map_err(|_| Error::InvalidData("could not encode the private key".into()))?
            .as_bytes()
            .to_vec(),
    );
    let public_key_spki = key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| Error::InvalidData("could not encode the public key".into()))?
        .into_vec();
    let public_key_cose = cose_public_key(&key)?;
    let auth_data = authenticator_data(rp_id, flags, 0, Some((&credential_id, &public_key_cose)))?;
    let attestation_object = none_attestation_object(&auth_data);
    Ok(NewPasskey {
        credential_id,
        private_key_pkcs8,
        public_key_cose,
        public_key_spki,
        authenticator_data: auth_data,
        attestation_object,
    })
}

/// Signs an assertion for `rp_id` with a stored private key (PKCS#8 DER).
pub fn assert(
    private_key_pkcs8: &[u8],
    rp_id: &str,
    client_data_json: &[u8],
    sign_count: u32,
    flags: Flags,
) -> Result<Assertion> {
    let key = signing_key_from_pkcs8(private_key_pkcs8)?;
    let auth_data = authenticator_data(rp_id, flags, sign_count, None)?;
    let mut message = Vec::with_capacity(auth_data.len() + 32);
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&client_data_hash(client_data_json));
    let signature: Signature = key
        .try_sign(&message)
        .map_err(|_| Error::InvalidData("signing failed".into()))?;
    Ok(Assertion {
        authenticator_data: auth_data,
        signature: signature.to_der().as_bytes().to_vec(),
    })
}

/// Minimal deterministic CBOR encoder (RFC 8949) for the few structures
/// WebAuthn needs: unsigned and negative integers, byte and text strings and
/// maps.
mod cbor {
    fn header(out: &mut Vec<u8>, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..=23 => out.push(major | value as u8),
            24..=0xff => out.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(major | 26);
                out.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                out.push(major | 27);
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
    }

    pub fn int(out: &mut Vec<u8>, value: i64) {
        if value >= 0 {
            header(out, 0, value as u64);
        } else {
            // Major type 1 encodes -1 - n.
            header(out, 1, (-1 - value) as u64);
        }
    }

    pub fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        header(out, 2, value.len() as u64);
        out.extend_from_slice(value);
    }

    pub fn text(out: &mut Vec<u8>, value: &str) {
        header(out, 3, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
    }

    pub fn map_header(out: &mut Vec<u8>, len: u64) {
        header(out, 5, len);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn encoded(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
            let mut out = Vec::new();
            f(&mut out);
            out
        }

        #[test]
        fn matches_rfc_8949_examples() {
            assert_eq!(encoded(|o| int(o, 0)), [0x00]);
            assert_eq!(encoded(|o| int(o, 23)), [0x17]);
            assert_eq!(encoded(|o| int(o, 24)), [0x18, 0x18]);
            assert_eq!(encoded(|o| int(o, 1000)), [0x19, 0x03, 0xe8]);
            assert_eq!(
                encoded(|o| int(o, 1_000_000)),
                [0x1a, 0x00, 0x0f, 0x42, 0x40]
            );
            assert_eq!(
                encoded(|o| int(o, 1_000_000_000_000)),
                [0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]
            );
            assert_eq!(encoded(|o| int(o, -1)), [0x20]);
            assert_eq!(encoded(|o| int(o, -7)), [0x26]);
            assert_eq!(encoded(|o| int(o, -1000)), [0x39, 0x03, 0xe7]);
            assert_eq!(encoded(|o| text(o, "IETF")), [0x64, 0x49, 0x45, 0x54, 0x46]);
            assert_eq!(encoded(|o| bytes(o, &[1, 2, 3, 4])), [0x44, 1, 2, 3, 4]);
            assert_eq!(encoded(|o| map_header(o, 0)), [0xa0]);
            assert_eq!(encoded(|o| bytes(o, &[0; 300]))[..3], [0x59, 0x01, 0x2c]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    const RP: &str = "example.com";

    /// Reads the x and y coordinates out of our COSE key encoding.
    fn cose_coordinates(cose: &[u8]) -> ([u8; 32], [u8; 32]) {
        assert_eq!(
            &cose[..10],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        (
            cose[10..42].try_into().unwrap(),
            cose[45..77].try_into().unwrap(),
        )
    }

    fn verifying_key_from_cose(cose: &[u8]) -> VerifyingKey {
        let (x, y) = cose_coordinates(cose);
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&sec1).unwrap()
    }

    #[test]
    fn creates_a_credential_with_valid_encodings() {
        let passkey = create(RP, Flags::SYNCED).unwrap();
        assert_eq!(passkey.credential_id.len(), CREDENTIAL_ID_LEN);
        assert_eq!(passkey.public_key_cose.len(), 77);

        let auth = &passkey.authenticator_data;
        assert_eq!(&auth[..32], &rp_id_hash(RP));
        assert_eq!(auth[32], 0x01 | 0x04 | 0x08 | 0x10 | 0x40);
        assert_eq!(&auth[33..37], &[0, 0, 0, 0]);
        assert_eq!(&auth[37..53], &AAGUID);
        assert_eq!(&auth[53..55], &[0, CREDENTIAL_ID_LEN as u8]);
        assert_eq!(&auth[55..71], passkey.credential_id.as_slice());
        assert_eq!(&auth[71..], passkey.public_key_cose.as_slice());

        // The SPKI and COSE encodings describe the same key.
        let from_spki = VerifyingKey::from_public_key_der(&passkey.public_key_spki).unwrap();
        assert_eq!(from_spki, verifying_key_from_cose(&passkey.public_key_cose));
        // And the private key matches them.
        let private = signing_key_from_pkcs8(&passkey.private_key_pkcs8).unwrap();
        assert_eq!(*private.verifying_key(), from_spki);
    }

    #[test]
    fn attestation_object_is_none_format() {
        let passkey = create(RP, Flags::SYNCED).unwrap();
        let att = &passkey.attestation_object;
        let mut expected = vec![0xa3, 0x63];
        expected.extend_from_slice(b"fmt");
        expected.push(0x64);
        expected.extend_from_slice(b"none");
        expected.push(0x67);
        expected.extend_from_slice(b"attStmt");
        expected.push(0xa0);
        expected.push(0x68);
        expected.extend_from_slice(b"authData");
        // 37 + 18 + 16 + 77 = 148 bytes: one-byte length header.
        expected.extend_from_slice(&[0x58, 148]);
        expected.extend_from_slice(&passkey.authenticator_data);
        assert_eq!(att, &expected);
    }

    #[test]
    fn assertion_signature_verifies_with_the_public_key() {
        let passkey = create(RP, Flags::SYNCED).unwrap();
        let client_data = br#"{"type":"webauthn.get","challenge":"abc","origin":"https://example.com","crossOrigin":false}"#;
        let assertion = assert(
            &passkey.private_key_pkcs8,
            RP,
            client_data,
            7,
            Flags::SYNCED,
        )
        .unwrap();

        let auth = &assertion.authenticator_data;
        assert_eq!(auth.len(), 37);
        assert_eq!(&auth[..32], &rp_id_hash(RP));
        assert_eq!(auth[32], 0x1d);
        assert_eq!(&auth[33..37], &7u32.to_be_bytes());

        let mut message = auth.clone();
        message.extend_from_slice(&client_data_hash(client_data));
        let signature = Signature::from_der(&assertion.signature).unwrap();
        let public = verifying_key_from_cose(&passkey.public_key_cose);
        public.verify(&message, &signature).unwrap();

        // Any change to the signed data invalidates the signature.
        let mut other = message.clone();
        other[40] ^= 1;
        assert!(public.verify(&other, &signature).is_err());
        let other_passkey = create(RP, Flags::SYNCED).unwrap();
        assert!(
            verifying_key_from_cose(&other_passkey.public_key_cose)
                .verify(&message, &signature)
                .is_err()
        );
    }

    #[test]
    fn rp_id_is_bound_into_the_assertion() {
        let passkey = create(RP, Flags::SYNCED).unwrap();
        let a = assert(&passkey.private_key_pkcs8, RP, b"{}", 0, Flags::SYNCED).unwrap();
        let b = assert(
            &passkey.private_key_pkcs8,
            "evil.example",
            b"{}",
            0,
            Flags::SYNCED,
        )
        .unwrap();
        assert_ne!(a.authenticator_data[..32], b.authenticator_data[..32]);
    }

    #[test]
    fn flags_encode_individually() {
        let only_up = Flags {
            user_present: true,
            ..Flags::default()
        };
        assert_eq!(only_up.to_byte(false), 0x01);
        assert_eq!(Flags::default().to_byte(true), 0x40);
    }

    #[test]
    fn user_verification_is_reported_only_when_requested() {
        assert_eq!(Flags::synced(true), Flags::SYNCED);
        assert_eq!(Flags::synced(true).to_byte(false), 0x1d);
        assert_eq!(Flags::synced(false).to_byte(false), 0x19);
        let created = create(RP, Flags::synced(false)).unwrap();
        // Flags byte follows the 32-byte RP ID hash; AT (0x40) is set on creation.
        assert_eq!(created.authenticator_data[32], 0x59);
        let assertion = assert(
            &created.private_key_pkcs8,
            RP,
            b"{}",
            0,
            Flags::synced(false),
        )
        .unwrap();
        assert_eq!(assertion.authenticator_data[32] & 0x04, 0);
    }

    #[test]
    fn rejects_invalid_private_keys() {
        assert!(matches!(
            assert(b"not a key", RP, b"{}", 0, Flags::SYNCED),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn credentials_are_unique() {
        let a = create(RP, Flags::SYNCED).unwrap();
        let b = create(RP, Flags::SYNCED).unwrap();
        assert_ne!(a.credential_id, b.credential_id);
        assert_ne!(a.public_key_cose, b.public_key_cose);
    }
}
