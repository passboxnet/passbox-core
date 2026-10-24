//! WebAuthn relying-party verification for login two-factor authentication
//! (security keys and platform passkeys as a second factor).
//!
//! This is the server side of WebAuthn: it checks registrations
//! (`navigator.credentials.create`) and assertions
//! (`navigator.credentials.get`). Supported algorithms are ES256 (ECDSA P-256
//! with SHA-256, COSE `-7`) and EdDSA (Ed25519, COSE `-8`), which every
//! current security key and platform authenticator offers.
//!
//! Scope, deliberately small:
//!
//! - Attestation statements are not verified. Passbox requests
//!   `attestation: "none"` and does not restrict authenticator models, so the
//!   statement would not be used. The attested credential data (credential ID
//!   and public key) is taken from the signed-over authenticator data.
//! - The relying-party ID, origin, challenge, type, user presence and
//!   (optionally) user verification are checked, as are the signature and the
//!   signature counter (a counter that does not increase hints at a cloned
//!   authenticator; synced passkeys always report 0, which is accepted).
//!
//! References: W3C Web Authentication Level 3 §7.1 (registration) and §7.2
//! (authentication), RFC 9052/9053 (COSE), RFC 8949 (CBOR).

use p256::ecdsa::signature::Verifier as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{Error, Result, encoding};

/// COSE algorithm identifier for ES256.
pub const ALG_ES256: i64 = -7;
/// COSE algorithm identifier for EdDSA (Ed25519 only).
pub const ALG_EDDSA: i64 = -8;

/// Algorithms offered in `pubKeyCredParams`, in order of preference.
pub const SUPPORTED_ALGORITHMS: [i64; 2] = [ALG_ES256, ALG_EDDSA];

/// Longest credential ID accepted (WebAuthn §6.5.1).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

fn fail(reason: &'static str) -> Error {
    Error::WebAuthn(reason)
}

/// A registration response to verify.
pub struct RegistrationInput<'a> {
    pub client_data_json: &'a [u8],
    pub attestation_object: &'a [u8],
    /// The challenge the server issued for this registration.
    pub challenge: &'a [u8],
    pub rp_id: &'a str,
    pub require_user_verification: bool,
}

/// A credential that passed [`verify_registration`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCredential {
    pub credential_id: Vec<u8>,
    /// The COSE_Key exactly as the authenticator sent it. Store it and pass
    /// it to [`verify_assertion`].
    pub public_key: Vec<u8>,
    pub algorithm: i64,
    pub sign_count: u32,
    pub aaguid: [u8; 16],
    /// BE: a synced passkey rather than a hardware-bound key.
    pub backup_eligible: bool,
    pub user_verified: bool,
}

/// An assertion response to verify.
pub struct AssertionInput<'a> {
    pub client_data_json: &'a [u8],
    pub authenticator_data: &'a [u8],
    pub signature: &'a [u8],
    /// The challenge the server issued for this login.
    pub challenge: &'a [u8],
    /// The RP ID the credential was registered for.
    pub rp_id: &'a str,
    /// The stored COSE public key of the credential.
    pub public_key: &'a [u8],
    /// The last signature counter seen for the credential.
    pub stored_sign_count: u32,
    pub require_user_verification: bool,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

fn check_client_data(json: &[u8], kind: &str, challenge: &[u8], rp_id: &str) -> Result<()> {
    let data: ClientData =
        serde_json::from_slice(json).map_err(|_| fail("clientDataJSON is not valid JSON"))?;
    if data.kind != kind {
        return Err(fail("wrong clientData type"));
    }
    let received = encoding::decode(&data.challenge).map_err(|_| fail("malformed challenge"))?;
    if !crate::totp::constant_time_eq(&received, challenge) {
        return Err(fail("challenge does not match"));
    }
    if data.cross_origin {
        return Err(fail("cross-origin requests are not accepted"));
    }
    if !origin_matches_rp_id(&data.origin, rp_id) {
        return Err(fail("origin does not match the relying party"));
    }
    Ok(())
}

/// Whether a page at `origin` may use credentials of `rp_id`: the origin's
/// host must be the RP ID or a subdomain of it, over https. Plain http is
/// accepted for `localhost` only, as browsers do.
pub fn origin_matches_rp_id(origin: &str, rp_id: &str) -> bool {
    let rp_id = rp_id.to_ascii_lowercase();
    if rp_id.is_empty() || rp_id.starts_with('.') || rp_id.ends_with('.') {
        return false;
    }
    let (secure, rest) = if let Some(rest) = origin.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    if rest.contains(['/', '?', '#', '@']) {
        return false;
    }
    let host = match rest.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return false,
        None => rest,
    }
    .to_ascii_lowercase();
    let host_matches = host == rp_id || host.ends_with(&format!(".{rp_id}"));
    host_matches && (secure || rp_id == "localhost")
}

/// The RP ID a page at `origin` registers credentials for: its host, if
/// [`origin_matches_rp_id`] accepts it (so https, or http on `localhost`).
pub fn rp_id_from_origin(origin: &str) -> Option<String> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))?;
    let host = rest.rsplit_once(':').map_or(rest, |(host, _)| host);
    let host = host.to_ascii_lowercase();
    // IP addresses are not valid RP IDs.
    let is_ip = host.parse::<std::net::Ipv4Addr>().is_ok() || host.starts_with('[');
    (!is_ip && origin_matches_rp_id(origin, &host)).then_some(host)
}

/// Parsed authenticator data (WebAuthn §6.1).
struct AuthenticatorData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested: Option<AttestedCredential>,
}

struct AttestedCredential {
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
}

fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData> {
    if data.len() < 37 {
        return Err(fail("authenticator data is too short"));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[..32]);
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    let mut rest = &data[37..];
    let attested = if flags & FLAG_AT != 0 {
        if rest.len() < 18 {
            return Err(fail("attested credential data is too short"));
        }
        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&rest[..16]);
        let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        rest = &rest[18..];
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID_LEN || rest.len() < id_len {
            return Err(fail("invalid credential ID length"));
        }
        let credential_id = rest[..id_len].to_vec();
        rest = &rest[id_len..];
        let (_, used) = cbor::decode(rest)?;
        let public_key = rest[..used].to_vec();
        rest = &rest[used..];
        Some(AttestedCredential {
            aaguid,
            credential_id,
            public_key,
        })
    } else {
        None
    };
    if flags & FLAG_ED != 0 {
        let (extensions, used) = cbor::decode(rest)?;
        if !matches!(extensions, cbor::Value::Map(_)) {
            return Err(fail("extensions must be a map"));
        }
        rest = &rest[used..];
    }
    if !rest.is_empty() {
        return Err(fail("trailing bytes in authenticator data"));
    }
    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
    })
}

fn check_flags(data: &AuthenticatorData, rp_id: &str, require_uv: bool) -> Result<()> {
    let expected: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if !crate::totp::constant_time_eq(&data.rp_id_hash, &expected) {
        return Err(fail("RP ID hash does not match"));
    }
    if data.flags & FLAG_UP == 0 {
        return Err(fail("user presence flag is not set"));
    }
    if require_uv && data.flags & FLAG_UV == 0 {
        return Err(fail("user verification flag is not set"));
    }
    Ok(())
}

/// A public key from a COSE_Key.
enum PublicKey {
    Es256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    fn algorithm(&self) -> i64 {
        match self {
            Self::Es256(_) => ALG_ES256,
            Self::Ed25519(_) => ALG_EDDSA,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let ok = match self {
            Self::Es256(key) => p256::ecdsa::Signature::from_der(signature)
                .map(|sig| sig.normalize_s())
                .is_ok_and(|sig| key.verify(message, &sig).is_ok()),
            Self::Ed25519(key) => ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|sig| key.verify_strict(message, &sig).is_ok()),
        };
        if ok {
            Ok(())
        } else {
            Err(fail("signature is invalid"))
        }
    }
}

fn parse_public_key(cose: &[u8]) -> Result<PublicKey> {
    let (value, used) = cbor::decode(cose)?;
    if used != cose.len() {
        return Err(fail("trailing bytes after the public key"));
    }
    let cbor::Value::Map(entries) = value else {
        return Err(fail("public key is not a COSE_Key map"));
    };
    let get = |label: i64| {
        entries
            .iter()
            .find(|(k, _)| k.as_int() == Some(label))
            .map(|(_, v)| v)
    };
    let int = |label: i64| get(label).and_then(cbor::Value::as_int);
    let bytes = |label: i64| match get(label) {
        Some(cbor::Value::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    };
    match (int(1), int(3), int(-1)) {
        // kty EC2, alg ES256, crv P-256
        (Some(2), Some(ALG_ES256), Some(1)) => {
            let (Some(x), Some(y)) = (bytes(-2), bytes(-3)) else {
                return Err(fail("EC2 key without coordinates"));
            };
            if x.len() != 32 || y.len() != 32 {
                return Err(fail("invalid P-256 coordinates"));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map(PublicKey::Es256)
                .map_err(|_| fail("invalid P-256 public key"))
        }
        // kty OKP, alg EdDSA, crv Ed25519
        (Some(1), Some(ALG_EDDSA), Some(6)) => {
            let x: [u8; 32] = bytes(-2)
                .and_then(|x| x.try_into().ok())
                .ok_or(fail("invalid Ed25519 public key"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&x)
                .map(PublicKey::Ed25519)
                .map_err(|_| fail("invalid Ed25519 public key"))
        }
        _ => Err(fail("unsupported public key algorithm")),
    }
}

/// Verifies a registration (WebAuthn §7.1) and returns the new credential.
pub fn verify_registration(input: &RegistrationInput<'_>) -> Result<VerifiedCredential> {
    check_client_data(
        input.client_data_json,
        "webauthn.create",
        input.challenge,
        input.rp_id,
    )?;
    let (object, used) = cbor::decode(input.attestation_object)?;
    if used != input.attestation_object.len() {
        return Err(fail("trailing bytes after the attestation object"));
    }
    let cbor::Value::Map(entries) = object else {
        return Err(fail("attestation object is not a map"));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::Text(t) if t == name))
            .map(|(_, v)| v)
    };
    if !matches!(field("fmt"), Some(cbor::Value::Text(_))) {
        return Err(fail("attestation format is missing"));
    }
    let Some(cbor::Value::Bytes(auth_data)) = field("authData") else {
        return Err(fail("authenticator data is missing"));
    };
    let data = parse_authenticator_data(auth_data)?;
    check_flags(&data, input.rp_id, input.require_user_verification)?;
    let attested = data.attested.ok_or(fail("no attested credential data"))?;
    let key = parse_public_key(&attested.public_key)?;
    Ok(VerifiedCredential {
        credential_id: attested.credential_id,
        algorithm: key.algorithm(),
        public_key: attested.public_key,
        sign_count: data.sign_count,
        aaguid: attested.aaguid,
        backup_eligible: data.flags & FLAG_BE != 0,
        user_verified: data.flags & FLAG_UV != 0,
    })
}

/// Verifies an assertion (WebAuthn §7.2) and returns the new signature
/// counter to store.
pub fn verify_assertion(input: &AssertionInput<'_>) -> Result<u32> {
    check_client_data(
        input.client_data_json,
        "webauthn.get",
        input.challenge,
        input.rp_id,
    )?;
    let data = parse_authenticator_data(input.authenticator_data)?;
    check_flags(&data, input.rp_id, input.require_user_verification)?;
    let key = parse_public_key(input.public_key)?;
    let mut message = Vec::with_capacity(input.authenticator_data.len() + 32);
    message.extend_from_slice(input.authenticator_data);
    message.extend_from_slice(&Sha256::digest(input.client_data_json));
    key.verify(&message, input.signature)?;
    if (data.sign_count != 0 || input.stored_sign_count != 0)
        && data.sign_count <= input.stored_sign_count
    {
        return Err(fail("signature counter did not increase"));
    }
    Ok(data.sign_count)
}

/// Minimal CBOR decoder (RFC 8949) for WebAuthn structures: definite-length
/// integers, byte and text strings, arrays, maps, simple values and tags.
/// Nesting and lengths are bounded by the input, so hostile input cannot
/// cause deep recursion or large allocations.
mod cbor {
    use super::{Result, fail};

    const MAX_DEPTH: usize = 16;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Unsigned(u64),
        /// The value is `-1 - n`.
        Negative(u64),
        Bytes(Vec<u8>),
        Text(String),
        Array(Vec<Value>),
        Map(Vec<(Value, Value)>),
        Simple(u8),
        Float,
        Tag(u64, Box<Value>),
    }

    impl Value {
        pub fn as_int(&self) -> Option<i64> {
            match self {
                Self::Unsigned(n) => i64::try_from(*n).ok(),
                Self::Negative(n) => i64::try_from(*n).ok().map(|n| -1 - n),
                _ => None,
            }
        }
    }

    /// Decodes one value and returns it with the number of bytes it used.
    pub fn decode(input: &[u8]) -> Result<(Value, usize)> {
        let mut pos = 0;
        let value = item(input, &mut pos, 0)?;
        Ok((value, pos))
    }

    fn take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
        let end = pos
            .checked_add(len)
            .filter(|end| *end <= input.len())
            .ok_or(fail("truncated CBOR"))?;
        let slice = &input[*pos..end];
        *pos = end;
        Ok(slice)
    }

    fn argument(input: &[u8], pos: &mut usize, info: u8) -> Result<u64> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(take(input, pos, 1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                take(input, pos, 2)?.try_into().unwrap_or_default(),
            )),
            26 => u64::from(u32::from_be_bytes(
                take(input, pos, 4)?.try_into().unwrap_or_default(),
            )),
            27 => u64::from_be_bytes(take(input, pos, 8)?.try_into().unwrap_or_default()),
            _ => return Err(fail("unsupported CBOR length encoding")),
        })
    }

    fn length(input: &[u8], pos: usize, value: u64) -> Result<usize> {
        // Every element takes at least one byte, so a count beyond the
        // remaining input is malformed.
        usize::try_from(value)
            .ok()
            .filter(|len| *len <= input.len().saturating_sub(pos))
            .ok_or(fail("CBOR length exceeds the input"))
    }

    fn item(input: &[u8], pos: &mut usize, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(fail("CBOR is nested too deeply"));
        }
        let initial = take(input, pos, 1)?[0];
        let major = initial >> 5;
        let info = initial & 0x1f;
        if major == 7 {
            return match info {
                0..=23 => Ok(Value::Simple(info)),
                24 => Ok(Value::Simple(take(input, pos, 1)?[0])),
                25 => take(input, pos, 2).map(|_| Value::Float),
                26 => take(input, pos, 4).map(|_| Value::Float),
                27 => take(input, pos, 8).map(|_| Value::Float),
                _ => Err(fail("unsupported CBOR simple value")),
            };
        }
        let arg = argument(input, pos, info)?;
        Ok(match major {
            0 => Value::Unsigned(arg),
            1 => Value::Negative(arg),
            2 => Value::Bytes(take(input, pos, length(input, *pos, arg)?)?.to_vec()),
            3 => {
                let bytes = take(input, pos, length(input, *pos, arg)?)?;
                Value::Text(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|_| fail("CBOR text is not UTF-8"))?,
                )
            }
            4 => {
                let len = length(input, *pos, arg)?;
                let mut values = Vec::with_capacity(len);
                for _ in 0..len {
                    values.push(item(input, pos, depth + 1)?);
                }
                Value::Array(values)
            }
            5 => {
                let len = length(input, *pos, arg)?;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = item(input, pos, depth + 1)?;
                    let value = item(input, pos, depth + 1)?;
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(fail("duplicate CBOR map key"));
                    }
                    entries.push((key, value));
                }
                Value::Map(entries)
            }
            6 => Value::Tag(arg, Box::new(item(input, pos, depth + 1)?)),
            _ => return Err(fail("unsupported CBOR major type")),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn decodes_rfc_8949_examples() {
            let cases: [(&[u8], Value); 7] = [
                (&[0x00], Value::Unsigned(0)),
                (&[0x18, 0x64], Value::Unsigned(100)),
                (&[0x20], Value::Negative(0)),
                (&[0x38, 0x63], Value::Negative(99)),
                (&[0x44, 1, 2, 3, 4], Value::Bytes(vec![1, 2, 3, 4])),
                (&[0x62, 0x22, 0x5c], Value::Text("\"\\".into())),
                (
                    &[0x82, 0x01, 0x82, 0x02, 0x03],
                    Value::Array(vec![
                        Value::Unsigned(1),
                        Value::Array(vec![Value::Unsigned(2), Value::Unsigned(3)]),
                    ]),
                ),
            ];
            for (bytes, expected) in cases {
                assert_eq!(decode(bytes).unwrap(), (expected, bytes.len()));
            }
            assert_eq!(Value::Negative(99).as_int(), Some(-100));
        }

        #[test]
        fn rejects_hostile_input() {
            // Truncated, huge lengths, indefinite lengths, deep nesting.
            assert!(decode(&[]).is_err());
            assert!(decode(&[0x44, 1, 2]).is_err());
            assert!(decode(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
            assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
            assert!(decode(&[0x5f, 0x41, 0x00, 0xff]).is_err());
            assert!(decode(&[0x81; 64]).is_err());
            assert!(decode(&[0x62, 0xff, 0xfe]).is_err());
            // Duplicate map keys.
            assert!(decode(&[0xa2, 0x01, 0x00, 0x01, 0x00]).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::{self, Flags};
    use ed25519_dalek::Signer as _;

    const RP_ID: &str = "passbox.example";
    const ORIGIN: &str = "https://passbox.example";
    const CHALLENGE: [u8; 32] = [7; 32];

    fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
            encoding::encode(challenge)
        )
        .into_bytes()
    }

    fn register(flags: Flags) -> (passkey::NewPasskey, VerifiedCredential) {
        let created = passkey::create(RP_ID, flags).unwrap();
        let client_data = client_data("webauthn.create", &CHALLENGE, ORIGIN);
        let credential = verify_registration(&RegistrationInput {
            client_data_json: &client_data,
            attestation_object: &created.attestation_object,
            challenge: &CHALLENGE,
            rp_id: RP_ID,
            require_user_verification: false,
        })
        .unwrap();
        (created, credential)
    }

    struct Signed {
        client_data: Vec<u8>,
        auth_data: Vec<u8>,
        signature: Vec<u8>,
    }

    fn sign_es256(created: &passkey::NewPasskey, origin: &str, count: u32, flags: Flags) -> Signed {
        let client_data = client_data("webauthn.get", &CHALLENGE, origin);
        let assertion = passkey::assert(
            &created.private_key_pkcs8,
            RP_ID,
            &client_data,
            count,
            flags,
        )
        .unwrap();
        Signed {
            client_data,
            auth_data: assertion.authenticator_data,
            signature: assertion.signature,
        }
    }

    fn check(credential: &VerifiedCredential, signed: &Signed, stored: u32) -> Result<u32> {
        verify_assertion(&AssertionInput {
            client_data_json: &signed.client_data,
            authenticator_data: &signed.auth_data,
            signature: &signed.signature,
            challenge: &CHALLENGE,
            rp_id: RP_ID,
            public_key: &credential.public_key,
            stored_sign_count: stored,
            require_user_verification: false,
        })
    }

    #[test]
    fn registers_and_verifies_es256() {
        let (created, credential) = register(Flags::synced(false));
        assert_eq!(credential.credential_id, created.credential_id);
        assert_eq!(credential.public_key, created.public_key_cose);
        assert_eq!(credential.algorithm, ALG_ES256);
        assert_eq!(credential.aaguid, passkey::AAGUID);
        assert!(credential.backup_eligible);
        assert!(!credential.user_verified);

        let signed = sign_es256(&created, ORIGIN, 0, Flags::synced(false));
        assert_eq!(check(&credential, &signed, 0), Ok(0));
        // Subdomains of the RP ID may use it.
        let signed = sign_es256(
            &created,
            "https://vault.passbox.example:8443",
            0,
            Flags::synced(false),
        );
        assert_eq!(check(&credential, &signed, 0), Ok(0));
    }

    #[test]
    fn rejects_tampered_assertions() {
        let (created, credential) = register(Flags::synced(false));
        let good = sign_es256(&created, ORIGIN, 5, Flags::synced(false));
        assert_eq!(check(&credential, &good, 4), Ok(5));

        // Counter replay.
        assert!(check(&credential, &good, 5).is_err());
        // Signature over other data.
        let mut bad = sign_es256(&created, ORIGIN, 6, Flags::synced(false));
        bad.client_data = client_data("webauthn.get", &[8; 32], ORIGIN);
        assert!(check(&credential, &bad, 0).is_err());
        // Changed flags break the signature.
        let mut bad = sign_es256(&created, ORIGIN, 6, Flags::synced(false));
        bad.auth_data[32] ^= FLAG_UV;
        assert_eq!(
            check(&credential, &bad, 0),
            Err(fail("signature is invalid"))
        );
        // Another key.
        let (_, other) = register(Flags::synced(false));
        assert!(check(&other, &good, 0).is_err());
        // Phishing origin.
        let phished = sign_es256(
            &created,
            "https://passbox.example.evil.test",
            7,
            Flags::synced(false),
        );
        assert_eq!(
            check(&credential, &phished, 0),
            Err(fail("origin does not match the relying party"))
        );
        // No user presence.
        let absent = sign_es256(&created, ORIGIN, 8, Flags::default());
        assert_eq!(
            check(&credential, &absent, 0),
            Err(fail("user presence flag is not set"))
        );
        // A registration response is not an assertion.
        let mut wrong_type = sign_es256(&created, ORIGIN, 9, Flags::synced(false));
        wrong_type.client_data = client_data("webauthn.create", &CHALLENGE, ORIGIN);
        assert_eq!(
            check(&credential, &wrong_type, 0),
            Err(fail("wrong clientData type"))
        );
    }

    #[test]
    fn user_verification_can_be_required() {
        let created = passkey::create(RP_ID, Flags::synced(false)).unwrap();
        let client_data = client_data("webauthn.create", &CHALLENGE, ORIGIN);
        let input = RegistrationInput {
            client_data_json: &client_data,
            attestation_object: &created.attestation_object,
            challenge: &CHALLENGE,
            rp_id: RP_ID,
            require_user_verification: true,
        };
        assert_eq!(
            verify_registration(&input),
            Err(fail("user verification flag is not set"))
        );
    }

    #[test]
    fn registration_checks_challenge_rp_and_origin() {
        let created = passkey::create(RP_ID, Flags::synced(false)).unwrap();
        let verify = |client_data: &[u8], rp_id: &str| {
            verify_registration(&RegistrationInput {
                client_data_json: client_data,
                attestation_object: &created.attestation_object,
                challenge: &CHALLENGE,
                rp_id,
                require_user_verification: false,
            })
        };
        let wrong_challenge = client_data("webauthn.create", &[1; 32], ORIGIN);
        assert_eq!(
            verify(&wrong_challenge, RP_ID),
            Err(fail("challenge does not match"))
        );
        let other_origin = client_data("webauthn.create", &CHALLENGE, "https://other.example");
        assert!(verify(&other_origin, "other.example").is_err());
        let cross = br#"{"type":"webauthn.create","challenge":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","origin":"https://passbox.example","crossOrigin":true}"#;
        assert!(verify(cross, RP_ID).is_err());
        assert!(verify(b"not json", RP_ID).is_err());
        let good = client_data("webauthn.create", &CHALLENGE, ORIGIN);
        assert!(verify(&good, RP_ID).is_ok());
        // Truncated attestation object.
        let truncated = &created.attestation_object[..created.attestation_object.len() - 1];
        assert!(
            verify_registration(&RegistrationInput {
                client_data_json: &good,
                attestation_object: truncated,
                challenge: &CHALLENGE,
                rp_id: RP_ID,
                require_user_verification: false,
            })
            .is_err()
        );
    }

    fn ed25519_cose(key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
        let mut out = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        out.extend_from_slice(key.as_bytes());
        out
    }

    fn ed25519_attestation(cose: &[u8], credential_id: &[u8], flags: u8, count: u32) -> Vec<u8> {
        let mut auth = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth.push(flags | FLAG_AT);
        auth.extend_from_slice(&count.to_be_bytes());
        auth.extend_from_slice(&[0; 16]);
        auth.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth.extend_from_slice(credential_id);
        auth.extend_from_slice(cose);
        let mut object = vec![0xa3];
        object.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
        object.extend_from_slice(&[0x67]);
        object.extend_from_slice(b"attStmt");
        object.push(0xa0);
        object.extend_from_slice(&[0x68]);
        object.extend_from_slice(b"authData");
        object.extend_from_slice(&[0x58, auth.len() as u8]);
        object.extend_from_slice(&auth);
        object
    }

    #[test]
    fn registers_and_verifies_ed25519() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let cose = ed25519_cose(&signing.verifying_key());
        let object = ed25519_attestation(&cose, &[9; 32], FLAG_UP | FLAG_UV, 1);
        let create_data = client_data("webauthn.create", &CHALLENGE, ORIGIN);
        let credential = verify_registration(&RegistrationInput {
            client_data_json: &create_data,
            attestation_object: &object,
            challenge: &CHALLENGE,
            rp_id: RP_ID,
            require_user_verification: true,
        })
        .unwrap();
        assert_eq!(credential.algorithm, ALG_EDDSA);
        assert_eq!(credential.credential_id, vec![9; 32]);
        assert_eq!(credential.sign_count, 1);
        assert!(credential.user_verified);
        assert!(!credential.backup_eligible);

        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&2u32.to_be_bytes());
        let get_data = client_data("webauthn.get", &CHALLENGE, ORIGIN);
        let mut message = auth_data.clone();
        message.extend_from_slice(&Sha256::digest(&get_data));
        let signed = Signed {
            client_data: get_data,
            auth_data,
            signature: signing.sign(&message).to_bytes().to_vec(),
        };
        assert_eq!(check(&credential, &signed, 1), Ok(2));
        assert_eq!(
            check(&credential, &signed, 2),
            Err(fail("signature counter did not increase"))
        );
        let mut forged = Signed {
            signature: vec![0; 64],
            ..signed
        };
        assert!(check(&credential, &forged, 1).is_err());
        forged.signature = vec![0; 10];
        assert!(check(&credential, &forged, 1).is_err());
    }

    #[test]
    fn rejects_unsupported_keys_and_malformed_data() {
        // RS256 (kty RSA) is not supported.
        assert!(parse_public_key(&[0xa2, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00]).is_err());
        // EC2 with ES256 but wrong coordinate sizes.
        assert!(
            parse_public_key(&[
                0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x41, 0x00, 0x22, 0x41, 0x00
            ])
            .is_err()
        );
        assert!(parse_authenticator_data(&[0; 36]).is_err());
        // Trailing bytes.
        let mut data = vec![0; 37];
        data.push(0);
        assert!(parse_authenticator_data(&data).is_err());
        // AT flag with a zero-length credential ID.
        let mut data = vec![0; 37];
        data[32] = FLAG_AT;
        data.extend_from_slice(&[0; 18]);
        assert!(parse_authenticator_data(&data).is_err());
        // Extensions are skipped.
        let mut data = vec![0; 37];
        data[32] = FLAG_ED;
        data.push(0xa0);
        assert!(parse_authenticator_data(&data).is_ok());
    }

    #[test]
    fn origins() {
        assert!(origin_matches_rp_id(
            "https://passbox.example",
            "passbox.example"
        ));
        assert!(origin_matches_rp_id(
            "https://a.b.passbox.example:443",
            "passbox.example"
        ));
        assert!(origin_matches_rp_id(
            "https://Passbox.Example",
            "passbox.example"
        ));
        assert!(origin_matches_rp_id("http://localhost:5173", "localhost"));
        assert!(!origin_matches_rp_id(
            "http://passbox.example",
            "passbox.example"
        ));
        assert!(!origin_matches_rp_id(
            "https://xpassbox.example",
            "passbox.example"
        ));
        assert!(!origin_matches_rp_id(
            "https://passbox.example.evil",
            "passbox.example"
        ));
        assert!(!origin_matches_rp_id(
            "https://passbox.example/path",
            "passbox.example"
        ));
        assert!(!origin_matches_rp_id(
            "https://evil@passbox.example",
            "passbox.example"
        ));
        assert!(!origin_matches_rp_id(
            "https://passbox.example:x",
            "passbox.example"
        ));
        assert!(!origin_matches_rp_id("chrome-extension://abc", "abc"));
        assert!(!origin_matches_rp_id("https://example", ""));
        assert!(!origin_matches_rp_id("https://passbox.example", ".example"));
    }

    #[test]
    fn rp_ids_from_origins() {
        assert_eq!(
            rp_id_from_origin("https://Vault.Passbox.example:8443").as_deref(),
            Some("vault.passbox.example")
        );
        assert_eq!(
            rp_id_from_origin("http://localhost:8872").as_deref(),
            Some("localhost")
        );
        assert_eq!(rp_id_from_origin("http://passbox.example"), None);
        assert_eq!(rp_id_from_origin("https://127.0.0.1:8443"), None);
        assert_eq!(rp_id_from_origin("https://[::1]:8443"), None);
        assert_eq!(rp_id_from_origin("tauri://localhost"), None);
        assert_eq!(rp_id_from_origin(""), None);
    }
}
