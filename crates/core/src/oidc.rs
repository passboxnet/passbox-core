//! OpenID Connect primitives for single sign-on.
//!
//! The server is the OIDC relying party (a confidential client with
//! authorization code + PKCE). This module holds the cryptographic parts it
//! needs, so they live in the core like all other cryptography:
//!
//! - [`pkce_challenge`]: the S256 code challenge (RFC 7636).
//! - [`Jwks`]: the identity provider's signing keys (RFC 7517), RSA and
//!   P-256/P-384 only.
//! - [`verify_id_token`]: signature and claim checks of an ID token
//!   (OpenID Connect Core 1.0 §3.1.3.7): `iss`, `aud`, `azp`, `exp`,
//!   `iat`, `nbf` and `nonce`.
//!
//! Only asymmetric algorithms are accepted (`RS256/384/512`, `PS256/384/512`,
//! `ES256`, `ES384`). `none` and the HMAC algorithms are always rejected, so
//! a token cannot be "signed" with the client secret or not at all. RSA keys
//! need at least 2048 bits. Signatures are verified with `ring`.
//!
//! SSO only proves identity: nothing here decrypts vault data.

use std::collections::BTreeMap;

use ring::signature::{self, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{Error, Result, encoding};

/// Largest ID token accepted (bytes).
pub const MAX_TOKEN_LEN: usize = 16 * 1024;
/// Largest JWKS document accepted (bytes).
pub const MAX_JWKS_LEN: usize = 256 * 1024;
/// Clock skew allowed for `exp`, `iat` and `nbf` (seconds).
pub const LEEWAY_SECS: i64 = 120;
/// ID tokens issued further in the past are rejected (seconds).
pub const MAX_TOKEN_AGE_SECS: i64 = 15 * 60;

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidData(message.into())
}

/// The S256 PKCE code challenge for `verifier`:
/// `BASE64URL(SHA-256(ASCII(verifier)))`.
pub fn pkce_challenge(verifier: &str) -> String {
    encoding::encode(&Sha256::digest(verifier.as_bytes()))
}

/// A random PKCE code verifier (43 characters, 256 bits) or `state`/`nonce`
/// value.
pub fn random_token() -> Result<String> {
    Ok(encoding::encode(&crate::random::bytes::<32>()?))
}

/// The JWS algorithms Passbox accepts for ID tokens.
pub const SUPPORTED_ALGORITHMS: [&str; 8] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
];

fn supported(alg: &str) -> bool {
    SUPPORTED_ALGORITHMS.contains(&alg)
}

fn rsa_parameters(alg: &str) -> Option<&'static signature::RsaParameters> {
    Some(match alg {
        "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
        "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
        "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
        "PS256" => &signature::RSA_PSS_2048_8192_SHA256,
        "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
        "PS512" => &signature::RSA_PSS_2048_8192_SHA512,
        _ => return None,
    })
}

fn ec_algorithm(alg: &str) -> Option<&'static signature::EcdsaVerificationAlgorithm> {
    Some(match alg {
        "ES256" => &signature::ECDSA_P256_SHA256_FIXED,
        "ES384" => &signature::ECDSA_P384_SHA384_FIXED,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyMaterial {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// Uncompressed point `04 || x || y`.
    Ec {
        curve: &'static str,
        point: Vec<u8>,
    },
}

/// One verification key from a JWKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    pub kid: Option<String>,
    /// The `alg` the key is restricted to, if the JWK names one.
    pub alg: Option<String>,
    material: KeyMaterial,
}

impl Jwk {
    fn supports(&self, alg: &str) -> bool {
        if self.alg.as_deref().is_some_and(|a| a != alg) {
            return false;
        }
        match &self.material {
            KeyMaterial::Rsa { .. } => alg.starts_with("RS") || alg.starts_with("PS"),
            KeyMaterial::Ec { curve, .. } => {
                (alg == "ES256" && *curve == "P-256") || (alg == "ES384" && *curve == "P-384")
            }
        }
    }

    fn verify(&self, alg: &str, message: &[u8], sig: &[u8]) -> Result<()> {
        let ok = match &self.material {
            KeyMaterial::Rsa { n, e } => {
                let params = rsa_parameters(alg).ok_or_else(|| invalid("unsupported algorithm"))?;
                signature::RsaPublicKeyComponents {
                    n: n.as_slice(),
                    e: e.as_slice(),
                }
                .verify(params, message, sig)
                .is_ok()
            }
            KeyMaterial::Ec { point, .. } => {
                let algorithm =
                    ec_algorithm(alg).ok_or_else(|| invalid("unsupported algorithm"))?;
                UnparsedPublicKey::new(algorithm, point)
                    .verify(message, sig)
                    .is_ok()
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Deserialize)]
struct RawJwks {
    keys: Vec<Value>,
}

/// Base64url with or without padding (some providers pad JWK values).
fn b64(field: &str, value: Option<&str>) -> Result<Vec<u8>> {
    let value = value.ok_or_else(|| invalid(format!("JWK without {field}")))?;
    encoding::decode(value.trim_end_matches('='))
        .map_err(|_| invalid(format!("invalid JWK {field}")))
}

fn strip_leading_zeros(mut bytes: Vec<u8>) -> Vec<u8> {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    bytes.drain(..zeros.min(bytes.len().saturating_sub(1)));
    bytes
}

impl RawJwk {
    fn into_jwk(self) -> Result<Option<Jwk>> {
        // Encryption keys are not for us; keys without `use` are fine.
        if self.use_.as_deref().is_some_and(|u| u != "sig") {
            return Ok(None);
        }
        if let Some(alg) = &self.alg
            && !supported(alg)
        {
            return Ok(None);
        }
        let material = match self.kty.as_str() {
            "RSA" => {
                let n = strip_leading_zeros(b64("n", self.n.as_deref())?);
                let e = strip_leading_zeros(b64("e", self.e.as_deref())?);
                if n.len() < 256 {
                    return Err(invalid("RSA keys need at least 2048 bits"));
                }
                KeyMaterial::Rsa { n, e }
            }
            "EC" => {
                let (curve, len) = match self.crv.as_deref() {
                    Some("P-256") => ("P-256", 32),
                    Some("P-384") => ("P-384", 48),
                    _ => return Ok(None),
                };
                let x = b64("x", self.x.as_deref())?;
                let y = b64("y", self.y.as_deref())?;
                if x.len() != len || y.len() != len {
                    return Err(invalid("invalid EC key coordinates"));
                }
                let mut point = Vec::with_capacity(1 + 2 * len);
                point.push(4);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                KeyMaterial::Ec { curve, point }
            }
            // `oct` (symmetric) and OKP keys are never used for ID tokens.
            _ => return Ok(None),
        };
        Ok(Some(Jwk {
            kid: self.kid,
            alg: self.alg,
            material,
        }))
    }
}

/// The identity provider's published signing keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Parses a JWKS document. Keys of unsupported types are skipped;
    /// malformed supported keys are an error.
    pub fn parse(json: &str) -> Result<Self> {
        if json.len() > MAX_JWKS_LEN {
            return Err(invalid("the JWKS is too large"));
        }
        let raw: RawJwks = serde_json::from_str(json).map_err(|_| invalid("invalid JWKS"))?;
        let mut keys = Vec::new();
        for value in raw.keys {
            // Skip entries this module cannot use instead of failing the set.
            let Ok(key) = serde_json::from_value::<RawJwk>(value) else {
                continue;
            };
            if let Some(key) = key.into_jwk()? {
                keys.push(key);
            }
        }
        Ok(Self { keys })
    }

    /// Whether the set has a key for the token's `kid` (to decide whether to
    /// refetch the JWKS after a key rotation).
    pub fn has_kid(&self, kid: &str) -> bool {
        self.keys.iter().any(|k| k.kid.as_deref() == Some(kid))
    }

    fn candidates<'a>(
        &'a self,
        kid: Option<&'a str>,
        alg: &'a str,
    ) -> impl Iterator<Item = &'a Jwk> {
        self.keys.iter().filter(move |key| {
            key.supports(alg)
                && match (kid, &key.kid) {
                    (Some(kid), Some(key_kid)) => kid == key_kid,
                    (Some(_), None) => true,
                    (None, _) => true,
                }
        })
    }
}

/// What an ID token must say.
#[derive(Debug, Clone)]
pub struct Expectations<'a> {
    /// The configured issuer, compared exactly with `iss`.
    pub issuer: &'a str,
    /// Our client ID: must be in `aud` (and equal `azp` when present).
    pub client_id: &'a str,
    /// The nonce sent in the authorization request.
    pub nonce: &'a str,
    /// Current time (Unix seconds).
    pub now: i64,
}

/// The header fields of a JWS that matter for picking the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHeader {
    pub alg: String,
    pub kid: Option<String>,
}

/// Decodes the header of a compact JWS without verifying anything.
pub fn token_header(token: &str) -> Result<TokenHeader> {
    let (header, _, _) = split(token)?;
    Ok(header)
}

fn split(token: &str) -> Result<(TokenHeader, Map<String, Value>, Vec<u8>)> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(invalid("the ID token is too large"));
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("the ID token is not a compact JWS"));
    };
    let header: Map<String, Value> = serde_json::from_slice(
        &encoding::decode(header).map_err(|_| invalid("invalid JWS header"))?,
    )
    .map_err(|_| invalid("invalid JWS header"))?;
    // A critical extension we do not understand must be rejected (RFC 7515 §4.1.11).
    if header.contains_key("crit") {
        return Err(invalid("unsupported critical JWS header"));
    }
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("JWS header without alg"))?
        .to_owned();
    let kid = header.get("kid").and_then(Value::as_str).map(str::to_owned);
    let claims: Map<String, Value> = serde_json::from_slice(
        &encoding::decode(payload).map_err(|_| invalid("invalid ID token payload"))?,
    )
    .map_err(|_| invalid("invalid ID token payload"))?;
    let sig = encoding::decode(sig).map_err(|_| invalid("invalid JWS signature encoding"))?;
    Ok((TokenHeader { alg, kid }, claims, sig))
}

fn number(claims: &Map<String, Value>, name: &str) -> Result<Option<i64>> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_i64()
            .or_else(|| value.as_f64().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| invalid(format!("{name} is not a number"))),
    }
}

/// Verifies an ID token and returns its claims.
///
/// Checks, in this order: the algorithm is one of [`SUPPORTED_ALGORITHMS`];
/// the signature verifies with a matching key of `jwks`; `iss` equals the
/// configured issuer; `aud` contains the client ID and, with several
/// audiences, `azp` is the client ID; `exp` is in the future, `iat` is not
/// in the future and not older than [`MAX_TOKEN_AGE_SECS`], `nbf` has passed
/// (all with [`LEEWAY_SECS`]); `nonce` equals the one we sent; `sub` is a
/// non-empty string.
pub fn verify_id_token(
    token: &str,
    jwks: &Jwks,
    expect: &Expectations<'_>,
) -> Result<Map<String, Value>> {
    let (header, claims, sig) = split(token)?;
    if !supported(&header.alg) {
        return Err(invalid(format!(
            "the ID token algorithm {} is not allowed",
            header.alg
        )));
    }
    let signing_input = {
        let last_dot = token.rfind('.').expect("three parts");
        &token.as_bytes()[..last_dot]
    };
    let mut candidates = jwks
        .candidates(header.kid.as_deref(), &header.alg)
        .peekable();
    if candidates.peek().is_none() {
        return Err(invalid(
            "no signing key of the identity provider matches the ID token",
        ));
    }
    if !candidates.any(|key| key.verify(&header.alg, signing_input, &sig).is_ok()) {
        return Err(Error::InvalidSignature);
    }

    if claims.get("iss").and_then(Value::as_str) != Some(expect.issuer) {
        return Err(invalid("the ID token was issued by another issuer"));
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(aud)) => vec![aud.as_str()],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&expect.client_id) {
        return Err(invalid("the ID token is for another client"));
    }
    match claims.get("azp").and_then(Value::as_str) {
        Some(azp) if azp != expect.client_id => {
            return Err(invalid("the ID token was issued to another party"));
        }
        None if audiences.len() > 1 => {
            return Err(invalid("the ID token has several audiences but no azp"));
        }
        _ => {}
    }
    let exp = number(&claims, "exp")?.ok_or_else(|| invalid("the ID token has no exp"))?;
    if exp + LEEWAY_SECS <= expect.now {
        return Err(invalid("the ID token has expired"));
    }
    let iat = number(&claims, "iat")?.ok_or_else(|| invalid("the ID token has no iat"))?;
    if iat > expect.now + LEEWAY_SECS {
        return Err(invalid("the ID token was issued in the future"));
    }
    if iat + MAX_TOKEN_AGE_SECS + LEEWAY_SECS < expect.now {
        return Err(invalid("the ID token is too old"));
    }
    if let Some(nbf) = number(&claims, "nbf")?
        && nbf > expect.now + LEEWAY_SECS
    {
        return Err(invalid("the ID token is not valid yet"));
    }
    let nonce = claims.get("nonce").and_then(Value::as_str);
    if !nonce.is_some_and(|n| constant_time_eq(n.as_bytes(), expect.nonce.as_bytes())) {
        return Err(invalid("the ID token nonce does not match"));
    }
    if !claims
        .get("sub")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty() && s.len() <= 255)
    {
        return Err(invalid("the ID token has no valid sub"));
    }
    Ok(claims)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Reads a claim by name; `a.b` follows nested objects (Keycloak and
/// Zitadel nest roles). Strings and booleans (also `"true"`/`"false"`
/// strings, which some providers send) are returned as JSON values.
pub fn claim<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(value) = claims.get(path) {
        return Some(value);
    }
    let mut parts = path.split('.');
    let mut current = claims.get(parts.next()?)?;
    for part in parts {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

/// A claim as a boolean (`true`, or the strings `"true"`/`"True"`).
pub fn claim_bool(claims: &Map<String, Value>, path: &str) -> bool {
    match claim(claims, path) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// A claim as a list of strings (a string, or an array of strings).
pub fn claim_strings(claims: &Map<String, Value>, path: &str) -> Vec<String> {
    match claim(claims, path) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// The subset of claims shown in the "test connection" result, sorted.
pub fn summarize(claims: &Map<String, Value>) -> BTreeMap<String, String> {
    claims
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "nonce" | "at_hash" | "c_hash"))
        .map(|(name, value)| {
            let text = match value {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let text: String = text.chars().take(200).collect();
            (name.clone(), text)
        })
        .take(50)
        .collect()
}

/// A test-only identity provider that signs ID tokens: for the server's
/// integration tests and the e2e mock provider. Never use it for anything
/// else; its RSA key is public.
#[cfg(any(test, feature = "test-issuer"))]
pub mod test_issuer {
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
        RsaPublicKeyComponents,
    };
    use serde_json::{Value, json};

    use crate::encoding;

    /// A 2048-bit RSA key (PKCS#1 DER, Base64). Public test material.
    const RSA_KEY: &str = include_str!("oidc_test_rsa.b64");

    /// Signs ID tokens with RS256 (`kid` `rsa-1`) or ES256 (`kid` `ec-1`).
    pub struct TestIssuer {
        rsa: RsaKeyPair,
        ec: EcdsaKeyPair,
        rng: SystemRandom,
    }

    impl Default for TestIssuer {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestIssuer {
        pub fn new() -> Self {
            let der = data_encoding::BASE64
                .decode(RSA_KEY.trim().as_bytes())
                .expect("test key");
            let rsa = RsaKeyPair::from_der(&der).expect("test RSA key");
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("EC key");
            let ec =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("EC key");
            Self { rsa, ec, rng }
        }

        /// The JWKS document with both public keys.
        pub fn jwks(&self) -> Value {
            let components = RsaPublicKeyComponents::<Vec<u8>>::from(self.rsa.public());
            let (n, e) = (components.n, components.e);
            let point = self.ec.public_key().as_ref();
            json!({ "keys": [
                { "kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256", "n": encoding::encode(&n), "e": encoding::encode(&e) },
                { "kty": "EC", "kid": "ec-1", "use": "sig", "crv": "P-256", "x": encoding::encode(&point[1..33]), "y": encoding::encode(&point[33..65]) },
                { "kty": "oct", "kid": "hmac", "k": "c2VjcmV0" },
            ]})
        }

        /// A compact JWS over `claims`. `alg` is `RS256`, `ES256`, or
        /// anything else to produce a token with that header and an RS256
        /// signature (for negative tests).
        pub fn sign(&self, alg: &str, kid: &str, claims: &Value) -> String {
            let header = json!({ "alg": alg, "kid": kid, "typ": "JWT" });
            let input = format!(
                "{}.{}",
                encoding::encode(header.to_string().as_bytes()),
                encoding::encode(claims.to_string().as_bytes())
            );
            let sig = if alg == "ES256" {
                self.ec
                    .sign(&self.rng, input.as_bytes())
                    .expect("sign")
                    .as_ref()
                    .to_vec()
            } else {
                let mut sig = vec![0; self.rsa.public().modulus_len()];
                self.rsa
                    .sign(&RSA_PKCS1_SHA256, &self.rng, input.as_bytes(), &mut sig)
                    .expect("sign");
                sig
            };
            format!("{input}.{}", encoding::encode(&sig))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::test_issuer::TestIssuer;
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn claims() -> Value {
        json!({
            "iss": "https://idp.example.com/realms/acme",
            "aud": "passbox",
            "sub": "user-1",
            "email": "ada@acme.example",
            "email_verified": true,
            "nonce": "n-1",
            "iat": NOW - 5,
            "exp": NOW + 300,
            "realm_access": { "roles": ["staff"] },
        })
    }

    fn expect() -> Expectations<'static> {
        Expectations {
            issuer: "https://idp.example.com/realms/acme",
            client_id: "passbox",
            nonce: "n-1",
            now: NOW,
        }
    }

    fn jwks(issuer: &TestIssuer) -> Jwks {
        Jwks::parse(&issuer.jwks().to_string()).unwrap()
    }

    #[test]
    fn pkce_challenge_matches_rfc_7636() {
        // RFC 7636, Appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(random_token().unwrap().len(), 43);
    }

    #[test]
    fn accepts_rs256_and_es256_tokens() {
        let issuer = TestIssuer::new();
        let keys = jwks(&issuer);
        assert_eq!(keys.keys.len(), 2, "the oct key is skipped");
        for (alg, kid) in [("RS256", "rsa-1"), ("ES256", "ec-1")] {
            let token = issuer.sign(alg, kid, &claims());
            let verified = verify_id_token(&token, &keys, &expect()).unwrap();
            assert_eq!(verified["sub"], "user-1");
            assert!(claim_bool(&verified, "email_verified"));
            assert_eq!(
                claim_strings(&verified, "realm_access.roles"),
                vec!["staff"]
            );
        }
        // A token without kid is matched against every compatible key.
        let header = encoding::encode(br#"{"alg":"RS256"}"#);
        let token = issuer.sign("RS256", "rsa-1", &claims());
        let rest = token.split_once('.').unwrap().1;
        let without_kid = format!("{header}.{rest}");
        // The signature covers the original header, so this must fail.
        assert!(verify_id_token(&without_kid, &keys, &expect()).is_err());
    }

    #[test]
    fn rejects_forbidden_algorithms_and_bad_signatures() {
        let issuer = TestIssuer::new();
        let keys = jwks(&issuer);
        for alg in ["none", "HS256", "EdDSA"] {
            let token = issuer.sign(alg, "rsa-1", &claims());
            assert!(verify_id_token(&token, &keys, &expect()).is_err(), "{alg}");
        }
        // Wrong kid, key type mismatch, tampered payload.
        assert!(
            verify_id_token(
                &issuer.sign("RS256", "unknown", &claims()),
                &keys,
                &expect()
            )
            .is_err()
        );
        assert!(
            verify_id_token(&issuer.sign("ES256", "rsa-1", &claims()), &keys, &expect()).is_err()
        );
        let token = issuer.sign("RS256", "rsa-1", &claims());
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut forged = claims();
        forged["sub"] = json!("admin");
        parts[1] = encoding::encode(forged.to_string().as_bytes());
        assert_eq!(
            verify_id_token(&parts.join("."), &keys, &expect()),
            Err(Error::InvalidSignature)
        );
        // Another provider's keys.
        let other = jwks(&TestIssuer::new());
        let es = issuer.sign("ES256", "ec-1", &claims());
        assert!(verify_id_token(&es, &other, &expect()).is_err());
        // Malformed tokens.
        for bad in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert!(verify_id_token(bad, &keys, &expect()).is_err());
        }
    }

    #[test]
    fn checks_every_claim() {
        let issuer = TestIssuer::new();
        let keys = jwks(&issuer);
        let check = |change: &dyn Fn(&mut Value)| {
            let mut c = claims();
            change(&mut c);
            verify_id_token(&issuer.sign("RS256", "rsa-1", &c), &keys, &expect())
        };
        assert!(check(&|_| {}).is_ok());
        assert!(check(&|c| c["iss"] = json!("https://evil.example")).is_err());
        assert!(check(&|c| c["aud"] = json!("other")).is_err());
        assert!(
            check(&|c| c["aud"] = json!(["passbox", "other"])).is_err(),
            "several audiences need azp"
        );
        assert!(
            check(&|c| {
                c["aud"] = json!(["passbox", "other"]);
                c["azp"] = json!("passbox");
            })
            .is_ok()
        );
        assert!(check(&|c| c["azp"] = json!("other")).is_err());
        assert!(check(&|c| c["exp"] = json!(NOW - LEEWAY_SECS - 1)).is_err());
        assert!(check(&|c| c["iat"] = json!(NOW + LEEWAY_SECS + 10)).is_err());
        assert!(check(&|c| c["iat"] = json!(NOW - MAX_TOKEN_AGE_SECS - LEEWAY_SECS - 10)).is_err());
        assert!(check(&|c| c["nbf"] = json!(NOW + LEEWAY_SECS + 10)).is_err());
        assert!(check(&|c| c["nonce"] = json!("n-2")).is_err());
        assert!(
            check(&|c| {
                c.as_object_mut().unwrap().remove("nonce");
            })
            .is_err()
        );
        assert!(check(&|c| c["sub"] = json!("")).is_err());
        assert!(
            check(&|c| {
                c.as_object_mut().unwrap().remove("exp");
            })
            .is_err()
        );
    }

    #[test]
    fn parses_provider_jwks() {
        // Keys for encryption, unknown curves and malformed entries are skipped.
        let skipped = Jwks::parse(
            r#"{"keys":[{"kty":"RSA","use":"enc","n":"AQAB","e":"AQAB"},
                {"kty":"EC","crv":"secp256k1","x":"AA","y":"AA"},
                {"kty":"OKP","crv":"Ed25519","x":"AA"},{"no":"kty"}]}"#,
        )
        .unwrap();
        assert!(skipped.keys.is_empty());
        // Short RSA keys are refused.
        assert!(Jwks::parse(r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB"}]}"#).is_err());
        assert!(Jwks::parse("not json").is_err());
        let issuer = TestIssuer::new();
        let keys = jwks(&issuer);
        assert!(keys.has_kid("rsa-1"));
        assert!(!keys.has_kid("hmac"));
        assert_eq!(
            token_header(&issuer.sign("ES256", "ec-1", &claims()))
                .unwrap()
                .kid
                .as_deref(),
            Some("ec-1")
        );
        let summary = summarize(claims().as_object().unwrap());
        assert!(!summary.contains_key("nonce"));
        assert_eq!(summary["email"], "ada@acme.example");
    }
}
