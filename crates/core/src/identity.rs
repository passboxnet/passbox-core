//! Account key pairs (wave A1): public key bundles, sealing to a public key
//! and signatures.
//!
//! Every account has
//!
//! - an **encryption key pair** for X-Wing, the hybrid X25519 + ML-KEM-768
//!   KEM of draft-connolly-cfrg-xwing-kem (RustCrypto `x-wing`). The private
//!   key is a 32-byte seed from which both component keys are expanded.
//! - a **signing key pair** for Ed25519 (`ed25519-dalek`, strict
//!   verification). The private key is a 32-byte seed.
//!
//! The public halves form a [`PublicBundle`], encoded canonically
//! ([`crate::canon`]) and self-signed. The private seeds are encrypted with
//! the account key (see [`crate::keyring`]) and never leave the core.
//!
//! **Sealing** encrypts a small secret (a vault, group or organization key)
//! to a recipient's encryption key:
//!
//! ```text
//! (ct, ss)  = X-Wing.Encaps(recipient.enc_pk)
//! k         = HKDF-SHA256(ikm = ss, info = "passbox/v1/seal|" || purpose)
//! aad       = "passbox/v1/seal|" || purpose || 0x00 || recipient_key_hash || context
//! sealed    = 0x01 (version) | 0x01 (X-Wing) | ct (1120 B) | XChaCha20-Poly1305(k, plaintext, aad)
//! ```
//!
//! The `purpose` and `context` (for example vault ID, key epoch and member)
//! bind a sealed key to the one place it may be used; the recipient key hash
//! binds it to one recipient key. Sealing is anonymous: who sealed something
//! is established separately by a signed grant that covers the hash of the
//! sealed bytes (see [`crate::sharing`]).

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use x_wing::{DecapsulationKeyRejectNonContrib, EncapsulationKey, KeyExport, TryDecapsulate};
use zeroize::{Zeroize, Zeroizing};

use crate::aead::SymmetricKey;
use crate::canon::{Reader, Writer};
use crate::{Error, Result, encoding, random};

/// Length of an X-Wing encapsulation (public) key.
pub const ENC_PK_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
/// Length of an X-Wing ciphertext.
pub const KEM_CT_LEN: usize = x_wing::CIPHERTEXT_SIZE;
/// Length of an Ed25519 public key.
pub const SIG_PK_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of object hashes.
pub const HASH_LEN: usize = 32;

const SEALED_VERSION: u8 = 1;
const KEM_XWING: u8 = 1;
const BUNDLE_TAG: &str = "passbox/v1/public-bundle";
const SIGNATURE_PREFIX: &[u8] = b"passbox/v1/signature\0";
const OBJECT_HASH_PREFIX: &[u8] = b"passbox/v1/object-hash\0";
const SEALED_HASH_PREFIX: &[u8] = b"passbox/v1/sealed-hash\0";
const FINGERPRINT_PREFIX: &[u8] = b"passbox/v1/fingerprint\0";

/// SHA-256 of a canonical object encoding, domain separated.
pub fn object_hash(canonical: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(OBJECT_HASH_PREFIX);
    hasher.update(canonical);
    hasher.finalize().into()
}

/// SHA-256 of sealed bytes, as covered by grants.
pub fn sealed_hash(sealed: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(SEALED_HASH_PREFIX);
    hasher.update(sealed);
    hasher.finalize().into()
}

/// The message an Ed25519 signature covers: a fixed prefix plus the
/// canonical encoding, which itself starts with the object's type tag.
fn signed_message(canonical: &[u8]) -> Vec<u8> {
    [SIGNATURE_PREFIX, canonical].concat()
}

/// Verifies an Ed25519 signature over a canonical object (strict
/// verification: no malleable or small-order encodings).
pub fn verify(sig_pk: &[u8; SIG_PK_LEN], canonical: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(sig_pk).map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
    key.verify_strict(&signed_message(canonical), &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// An Ed25519 signing key. The seed is wiped on drop.
pub struct SignatureKey(SigningKey);

impl SignatureKey {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new(random::bytes::<32>()?);
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self(key))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public_key(&self) -> [u8; SIG_PK_LEN] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs a canonical object encoding.
    pub fn sign(&self, canonical: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(&signed_message(canonical)).to_bytes()
    }
}

impl fmt::Debug for SignatureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignatureKey(<redacted>)")
    }
}

/// An X-Wing decapsulation key, kept as its 32-byte seed. Wiped on drop.
pub struct EncryptionKey {
    seed: Zeroizing<[u8; 32]>,
}

impl EncryptionKey {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            seed: Zeroizing::new(random::bytes()?),
        })
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
        }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    fn decapsulation_key(&self) -> DecapsulationKeyRejectNonContrib {
        DecapsulationKeyRejectNonContrib::from(*self.seed)
    }

    /// The X-Wing encapsulation key (1216 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        use x_wing::Decapsulator;
        self.decapsulation_key()
            .encapsulation_key()
            .to_bytes()
            .to_vec()
    }

    /// Opens bytes produced by [`seal`] for this key. `recipient_key_hash`,
    /// `purpose` and `context` must match the values used for sealing.
    pub fn open(
        &self,
        recipient_key_hash: &[u8; HASH_LEN],
        purpose: &str,
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < 2 + KEM_CT_LEN {
            return Err(Error::MalformedEnvelope);
        }
        if sealed[0] != SEALED_VERSION || sealed[1] != KEM_XWING {
            return Err(Error::UnsupportedEnvelope);
        }
        let ct = x_wing::Ciphertext::try_from(&sealed[2..2 + KEM_CT_LEN])
            .map_err(|_| Error::MalformedEnvelope)?;
        let shared = self
            .decapsulation_key()
            .try_decapsulate(&ct)
            .map_err(|_| Error::Decryption)?;
        let key = seal_key(&shared, purpose)?;
        let aad = seal_aad(purpose, recipient_key_hash, context, &sealed[..2]);
        Ok(Zeroizing::new(
            key.decrypt(&sealed[2 + KEM_CT_LEN..], &aad)?,
        ))
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey(<redacted>)")
    }
}

fn seal_key(shared: &[u8], purpose: &str) -> Result<SymmetricKey> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(format!("passbox/v1/seal|{purpose}").as_bytes(), &mut *okm)
        .map_err(|_| Error::Kdf("HKDF expand failed".into()))?;
    Ok(SymmetricKey::from_bytes(*okm))
}

fn seal_aad(purpose: &str, recipient_key_hash: &[u8], context: &[u8], header: &[u8]) -> Vec<u8> {
    let mut aad = format!("passbox/v1/seal|{purpose}\0").into_bytes();
    aad.extend_from_slice(header);
    aad.extend_from_slice(recipient_key_hash);
    aad.extend_from_slice(context);
    aad
}

/// Seals `plaintext` to an X-Wing public key. See the module docs.
pub fn seal(
    enc_pk: &[u8],
    recipient_key_hash: &[u8; HASH_LEN],
    purpose: &str,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut randomness = Zeroizing::new(random::bytes::<64>()?);
    let nonce = random::bytes()?;
    let sealed = seal_with_randomness(
        enc_pk,
        recipient_key_hash,
        purpose,
        context,
        plaintext,
        &randomness,
        &nonce,
    );
    randomness.zeroize();
    sealed
}

fn seal_with_randomness(
    enc_pk: &[u8],
    recipient_key_hash: &[u8; HASH_LEN],
    purpose: &str,
    context: &[u8],
    plaintext: &[u8],
    randomness: &[u8; 64],
    nonce: &[u8; crate::aead::NONCE_LEN],
) -> Result<Vec<u8>> {
    let pk = EncapsulationKey::try_from(enc_pk)
        .map_err(|_| Error::InvalidData("invalid encryption public key".into()))?;
    let (ct, shared) = pk.encapsulate_deterministic(&(*randomness).into());
    let key = seal_key(&shared, purpose)?;
    let header = [SEALED_VERSION, KEM_XWING];
    let aad = seal_aad(purpose, recipient_key_hash, context, &header);
    let envelope = key.encrypt_with_nonce(plaintext, &aad, nonce)?;
    let mut out = Vec::with_capacity(2 + KEM_CT_LEN + envelope.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&envelope);
    Ok(out)
}

/// The public keys of an account. Self-signed with `sig_pk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBundle {
    pub account_id: String,
    pub key_version: u32,
    pub enc_pk: Vec<u8>,
    pub sig_pk: [u8; SIG_PK_LEN],
    /// Unix milliseconds.
    pub created_at: i64,
}

impl PublicBundle {
    pub fn to_canonical(&self) -> Vec<u8> {
        Writer::new(BUNDLE_TAG)
            .str(&self.account_id)
            .u64(u64::from(self.key_version))
            .bytes(&self.enc_pk)
            .bytes(&self.sig_pk)
            .i64(self.created_at)
            .finish()
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, BUNDLE_TAG)?;
        let bundle = Self {
            account_id: r.string()?,
            key_version: r.u32()?,
            enc_pk: r.bytes()?.to_vec(),
            sig_pk: r.array()?,
            created_at: r.i64()?,
        };
        r.finish()?;
        if bundle.enc_pk.len() != ENC_PK_LEN || EncapsulationKey::try_from(&*bundle.enc_pk).is_err()
        {
            return Err(Error::InvalidData("invalid encryption public key".into()));
        }
        if VerifyingKey::from_bytes(&bundle.sig_pk).is_err() || bundle.key_version == 0 {
            return Err(Error::InvalidData("invalid public bundle".into()));
        }
        Ok(bundle)
    }
}

/// A public bundle with its canonical bytes and a valid self-signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBundle {
    pub bundle: PublicBundle,
    canonical: Vec<u8>,
    signature: [u8; SIGNATURE_LEN],
}

impl SignedBundle {
    /// Parses Base64url bundle and signature and checks the self-signature.
    pub fn parse(bundle: &str, signature: &str) -> Result<Self> {
        Self::from_parts(&encoding::decode(bundle)?, &encoding::decode(signature)?)
    }

    pub fn from_parts(canonical: &[u8], signature: &[u8]) -> Result<Self> {
        let bundle = PublicBundle::from_canonical(canonical)?;
        verify(&bundle.sig_pk, canonical, signature)?;
        Ok(Self {
            bundle,
            canonical: canonical.to_vec(),
            signature: signature.try_into().map_err(|_| Error::InvalidSignature)?,
        })
    }

    /// Creates and self-signs a bundle.
    pub fn create(
        account_id: &str,
        key_version: u32,
        enc: &EncryptionKey,
        sig: &SignatureKey,
        created_at: i64,
    ) -> Self {
        let bundle = PublicBundle {
            account_id: account_id.to_owned(),
            key_version,
            enc_pk: enc.public_key(),
            sig_pk: sig.public_key(),
            created_at,
        };
        let canonical = bundle.to_canonical();
        let signature = sig.sign(&canonical);
        Self {
            bundle,
            canonical,
            signature,
        }
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Base64url of the canonical bundle.
    pub fn encoded(&self) -> String {
        encoding::encode(&self.canonical)
    }

    pub fn encoded_signature(&self) -> String {
        encoding::encode(&self.signature)
    }

    /// The bundle hash that attestations, grants and the key log refer to.
    pub fn hash(&self) -> [u8; HASH_LEN] {
        object_hash(&self.canonical)
    }

    /// The fingerprint people compare to verify each other's keys.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.bundle)
    }

    /// Seals `plaintext` to this bundle's encryption key.
    pub fn seal(&self, purpose: &str, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        seal(
            &self.bundle.enc_pk,
            &self.hash(),
            purpose,
            context,
            plaintext,
        )
    }
}

/// Fingerprint (safety number) of an account's keys: 60 decimal digits in
/// 12 groups of five, derived from the account ID and both public keys:
///
/// ```text
/// h = SHA-512("passbox/v1/fingerprint\0" || len(account_id) || account_id || sig_pk || enc_pk)
/// group i = big-endian u40 of h[5i .. 5i+5] mod 100000
/// ```
///
/// 60 digits carry about 199 bits, so finding another key with the same
/// fingerprint is infeasible even when people only compare part of it.
pub fn fingerprint(bundle: &PublicBundle) -> String {
    let mut hasher = Sha512::new();
    hasher.update(FINGERPRINT_PREFIX);
    hasher.update((bundle.account_id.len() as u32).to_be_bytes());
    hasher.update(bundle.account_id.as_bytes());
    hasher.update(bundle.sig_pk);
    hasher.update(&bundle.enc_pk);
    let hash = hasher.finalize();
    (0..12)
        .map(|i| {
            let chunk = &hash[i * 5..i * 5 + 5];
            let value = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (EncryptionKey, SignatureKey) {
        (
            EncryptionKey::generate().unwrap(),
            SignatureKey::generate().unwrap(),
        )
    }

    #[test]
    fn bundle_round_trips_and_verifies() {
        let (enc, sig) = keys();
        let signed = SignedBundle::create("acc", 1, &enc, &sig, 1_700_000_000_000);
        let parsed = SignedBundle::parse(&signed.encoded(), &signed.encoded_signature()).unwrap();
        assert_eq!(parsed, signed);
        assert_eq!(parsed.bundle.enc_pk.len(), ENC_PK_LEN);
        assert_eq!(parsed.hash(), signed.hash());
    }

    #[test]
    fn tampered_bundle_or_signature_is_rejected() {
        let (enc, sig) = keys();
        let signed = SignedBundle::create("acc", 1, &enc, &sig, 1);
        // Change the account ID: the self-signature no longer matches.
        let other = PublicBundle {
            account_id: "mallory".into(),
            ..signed.bundle.clone()
        };
        assert_eq!(
            SignedBundle::from_parts(&other.to_canonical(), signed.signature()).unwrap_err(),
            Error::InvalidSignature
        );
        let mut bad_sig = *signed.signature();
        bad_sig[0] ^= 1;
        assert!(SignedBundle::from_parts(signed.canonical(), &bad_sig).is_err());
        // A signature by another key over the same bundle fails too.
        let (_, other_sig) = keys();
        let forged = other_sig.sign(signed.canonical());
        assert!(SignedBundle::from_parts(signed.canonical(), &forged).is_err());
    }

    #[test]
    fn signatures_are_domain_separated() {
        let sig = SignatureKey::generate().unwrap();
        let a = Writer::new("passbox/v1/a").str("x").finish();
        let b = Writer::new("passbox/v1/b").str("x").finish();
        let signature = sig.sign(&a);
        verify(&sig.public_key(), &a, &signature).unwrap();
        assert!(verify(&sig.public_key(), &b, &signature).is_err());
    }

    #[test]
    fn seal_open_round_trip() {
        let (enc, sig) = keys();
        let bundle = SignedBundle::create("acc", 1, &enc, &sig, 1);
        let sealed = bundle.seal("vault-key", b"vault|1", b"secret").unwrap();
        assert_eq!(sealed.len(), 2 + KEM_CT_LEN + 2 + 24 + 6 + 16);
        let opened = enc
            .open(&bundle.hash(), "vault-key", b"vault|1", &sealed)
            .unwrap();
        assert_eq!(&*opened, b"secret");
    }

    #[test]
    fn sealed_data_is_bound_to_purpose_context_and_recipient() {
        let (enc, sig) = keys();
        let bundle = SignedBundle::create("acc", 1, &enc, &sig, 1);
        let sealed = bundle.seal("vault-key", b"ctx", b"secret").unwrap();
        let hash = bundle.hash();
        assert!(enc.open(&hash, "group-key", b"ctx", &sealed).is_err());
        assert!(enc.open(&hash, "vault-key", b"other", &sealed).is_err());
        assert!(enc.open(&[0; 32], "vault-key", b"ctx", &sealed).is_err());
        let (other, _) = keys();
        assert!(other.open(&hash, "vault-key", b"ctx", &sealed).is_err());
        for i in [0, 1, 5, 2 + KEM_CT_LEN + 10, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(
                enc.open(&hash, "vault-key", b"ctx", &tampered).is_err(),
                "byte {i}"
            );
        }
        assert!(
            enc.open(&hash, "vault-key", b"ctx", &sealed[..100])
                .is_err()
        );
    }

    #[test]
    fn sealing_is_randomized() {
        let (enc, sig) = keys();
        let bundle = SignedBundle::create("acc", 1, &enc, &sig, 1);
        assert_ne!(
            bundle.seal("p", b"", b"x").unwrap(),
            bundle.seal("p", b"", b"x").unwrap()
        );
    }

    /// Known-answer test: fixed seed, KEM randomness and nonce give fixed
    /// output, so any change to the construction (KDF label, AAD layout,
    /// header) is caught. The X-Wing KEM itself is checked against the
    /// draft's test vector in [`xwing_draft_vector`].
    #[test]
    fn seal_known_answer() {
        let enc = EncryptionKey::from_seed(&[7; 32]);
        let pk = enc.public_key();
        let sealed = seal_with_randomness(
            &pk,
            &[1; 32],
            "vault-key",
            b"ctx",
            b"secret",
            &[9; 64],
            &[3; 24],
        )
        .unwrap();
        assert_eq!(
            encoding::encode(&Sha256::digest(&sealed)),
            "Bu_Jc-HkzUhSaNZpYB9oetyEWtmHikD3hgoHTpy1iE0"
        );
        assert_eq!(
            &*enc.open(&[1; 32], "vault-key", b"ctx", &sealed).unwrap(),
            b"secret"
        );
    }

    /// Test vector from draft-connolly-cfrg-xwing-kem (first vector of the
    /// draft's test vectors): public key from the seed, ciphertext and
    /// shared secret for fixed encapsulation randomness, and decapsulation.
    #[test]
    fn xwing_draft_vector() {
        use x_wing::Decapsulate;
        let hex = |s: &str| data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap();
        let seed: [u8; 32] =
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
                .try_into()
                .unwrap();
        let eseed: [u8; 64] = hex(concat!(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
            "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
        ))
        .try_into()
        .unwrap();
        let enc = EncryptionKey::from_seed(&seed);
        let pk = enc.public_key();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&Sha256::digest(&pk)),
            "2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb"
        );
        let (ct, ss) = EncapsulationKey::try_from(&*pk)
            .unwrap()
            .encapsulate_deterministic(&eseed.into());
        assert_eq!(
            data_encoding::HEXLOWER.encode(&Sha256::digest(ct)),
            "17cd532d657e44c897ca6583e548a5424fc70bf54f99515a4d2bcf99e3469f33"
        );
        let expected = "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384";
        assert_eq!(data_encoding::HEXLOWER.encode(&ss), expected);
        let decapsulated = x_wing::DecapsulationKey::from(seed).decapsulate(&ct);
        assert_eq!(data_encoding::HEXLOWER.encode(&decapsulated), expected);
    }

    #[test]
    fn fingerprint_format() {
        let (enc, sig) = keys();
        let bundle = SignedBundle::create("acc", 1, &enc, &sig, 1);
        let fp = bundle.fingerprint();
        assert_eq!(fp.len(), 12 * 5 + 11);
        assert!(
            fp.split(' ')
                .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit()))
        );
        assert_eq!(fp, bundle.fingerprint());
        let other = SignedBundle::create("acc2", 1, &enc, &sig, 1);
        assert_ne!(fp, other.fingerprint());
    }
}
