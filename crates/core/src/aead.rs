//! Authenticated encryption of vault data.
//!
//! Every ciphertext is wrapped in a versioned envelope:
//!
//! ```text
//! +---------+-----------+----------------+---------------------------+
//! | version | algorithm | nonce (24 B)   | ciphertext + tag (16 B)   |
//! | 1 byte  | 1 byte    |                |                           |
//! +---------+-----------+----------------+---------------------------+
//! ```
//!
//! The version and algorithm bytes are part of the associated data, so they
//! cannot be swapped without failing authentication. Callers bind each
//! ciphertext to its context (for example item ID, vault ID and revision) by
//! passing that context as `aad`, which stops a server from swapping or
//! replaying ciphertexts between items.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, random};

/// Length of a symmetric key in bytes.
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 2;

/// Envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Supported AEAD algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    XChaCha20Poly1305 = 1,
}

/// A 256-bit symmetric key. The bytes are wiped from memory when the value is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    /// Generates a new random key.
    pub fn generate() -> Result<Self> {
        Ok(Self(random::bytes()?))
    }

    /// Creates a key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Encrypts `plaintext`, authenticating `aad`, and returns an envelope.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = random::bytes()?;
        self.encrypt_with_nonce(plaintext, aad, &nonce)
    }

    fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let header = [ENVELOPE_VERSION, Algorithm::XChaCha20Poly1305 as u8];
        let full_aad = bind_aad(&header, aad);
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: plaintext,
                    aad: &full_aad,
                },
            )
            .map_err(|_| Error::Decryption)?;

        let mut envelope = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Decrypts an envelope produced by [`SymmetricKey::encrypt`] with the same `aad`.
    pub fn decrypt(&self, envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if envelope.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
            return Err(Error::MalformedEnvelope);
        }
        let (header, rest) = envelope.split_at(HEADER_LEN);
        if header != [ENVELOPE_VERSION, Algorithm::XChaCha20Poly1305 as u8] {
            return Err(Error::UnsupportedEnvelope);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::MalformedEnvelope)?;
        let full_aad = bind_aad(header, aad);
        self.cipher()
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &full_aad,
                },
            )
            .map_err(|_| Error::Decryption)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

fn bind_aad(header: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + aad.len());
    out.extend_from_slice(header);
    out.extend_from_slice(aad);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SymmetricKey::generate().unwrap();
        let envelope = key.encrypt(b"hunter2", b"item:1").unwrap();
        assert_eq!(key.decrypt(&envelope, b"item:1").unwrap(), b"hunter2");
    }

    #[test]
    fn nonces_differ() {
        let key = SymmetricKey::generate().unwrap();
        assert_ne!(
            key.encrypt(b"x", b"").unwrap(),
            key.encrypt(b"x", b"").unwrap()
        );
    }

    #[test]
    fn wrong_aad_fails() {
        let key = SymmetricKey::generate().unwrap();
        let envelope = key.encrypt(b"hunter2", b"item:1").unwrap();
        assert_eq!(
            key.decrypt(&envelope, b"item:2").unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn wrong_key_fails() {
        let envelope = SymmetricKey::generate()
            .unwrap()
            .encrypt(b"x", b"")
            .unwrap();
        let other = SymmetricKey::generate().unwrap();
        assert_eq!(
            other.decrypt(&envelope, b"").unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn tampering_fails() {
        let key = SymmetricKey::generate().unwrap();
        let mut envelope = key.encrypt(b"hunter2", b"").unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        assert_eq!(key.decrypt(&envelope, b"").unwrap_err(), Error::Decryption);
    }

    #[test]
    fn unknown_version_is_rejected() {
        let key = SymmetricKey::generate().unwrap();
        let mut envelope = key.encrypt(b"x", b"").unwrap();
        envelope[0] = 99;
        assert_eq!(
            key.decrypt(&envelope, b"").unwrap_err(),
            Error::UnsupportedEnvelope
        );
    }

    #[test]
    fn short_input_is_rejected() {
        let key = SymmetricKey::generate().unwrap();
        assert_eq!(
            key.decrypt(&[1, 1, 0], b"").unwrap_err(),
            Error::MalformedEnvelope
        );
    }

    #[test]
    fn layout_is_stable() {
        let key = SymmetricKey::from_bytes([0x42; KEY_LEN]);
        let envelope = key
            .encrypt_with_nonce(b"abc", b"", &[9; NONCE_LEN])
            .unwrap();
        assert_eq!(envelope.len(), HEADER_LEN + NONCE_LEN + 3 + TAG_LEN);
        assert_eq!(&envelope[..2], &[1, 1]);
        assert_eq!(&envelope[2..26], &[9; NONCE_LEN]);
    }
}
