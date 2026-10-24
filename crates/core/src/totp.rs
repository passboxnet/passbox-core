//! One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238), including parsing
//! of `otpauth://` URIs as produced by QR codes.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// Hash function used by the one-time password.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OtpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

/// A TOTP configuration. The secret is wiped from memory when the value is dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Totp {
    #[serde(with = "base32_secret")]
    secret: Vec<u8>,
    #[zeroize(skip)]
    pub algorithm: OtpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl core::fmt::Debug for Totp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish()
    }
}

impl Totp {
    /// Creates a TOTP configuration with the common defaults (SHA-1, 6 digits, 30 seconds).
    pub fn new(secret: Vec<u8>) -> Result<Self> {
        Self::with_options(secret, OtpAlgorithm::Sha1, 6, 30)
    }

    /// Creates a TOTP configuration with explicit options.
    pub fn with_options(
        secret: Vec<u8>,
        algorithm: OtpAlgorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self> {
        if secret.is_empty() {
            return Err(Error::InvalidOtp("secret is empty"));
        }
        if !(6..=8).contains(&digits) {
            return Err(Error::InvalidOtp("digits must be between 6 and 8"));
        }
        if period == 0 {
            return Err(Error::InvalidOtp("period must be greater than zero"));
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
            issuer: None,
            account: None,
        })
    }

    /// Creates a TOTP configuration from a Base32 secret, as shown by most websites.
    ///
    /// Case, spaces, dashes and padding are ignored.
    pub fn from_base32(secret: &str) -> Result<Self> {
        Self::new(decode_base32(secret)?)
    }

    /// Parses an `otpauth://totp/...` URI.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("otpauth://")
            .ok_or(Error::InvalidOtp("not an otpauth URI"))?;
        let (kind, rest) = rest
            .split_once('/')
            .ok_or(Error::InvalidOtp("missing label"))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(Error::InvalidOtp("only TOTP URIs are supported"));
        }
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label)?;

        let mut secret = None;
        let mut issuer = None;
        let mut algorithm = OtpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value)?;
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_base32(&value)?),
                "issuer" => issuer = Some(value),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => OtpAlgorithm::Sha1,
                        "SHA256" => OtpAlgorithm::Sha256,
                        "SHA512" => OtpAlgorithm::Sha512,
                        _ => return Err(Error::InvalidOtp("unsupported algorithm")),
                    }
                }
                "digits" => {
                    digits = value
                        .parse()
                        .map_err(|_| Error::InvalidOtp("invalid digits"))?
                }
                "period" => {
                    period = value
                        .parse()
                        .map_err(|_| Error::InvalidOtp("invalid period"))?
                }
                _ => {}
            }
        }

        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
            None => (None, label.trim().to_owned()),
        };
        let mut totp = Self::with_options(
            secret.ok_or(Error::InvalidOtp("missing secret"))?,
            algorithm,
            digits,
            period,
        )?;
        totp.issuer = issuer.or(label_issuer).filter(|s| !s.is_empty());
        totp.account = Some(account).filter(|s| !s.is_empty());
        Ok(totp)
    }

    /// Returns the secret as unpadded Base32.
    pub fn secret_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.secret)
    }

    /// Generates the code valid at `unix_time` (seconds since the epoch).
    pub fn generate(&self, unix_time: u64) -> String {
        hotp(
            &self.secret,
            unix_time / self.period,
            self.digits,
            self.algorithm,
        )
    }

    /// Seconds until the code generated at `unix_time` expires.
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        self.period - (unix_time % self.period)
    }
}

/// Computes an HOTP value (RFC 4226).
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algorithm: OtpAlgorithm) -> String {
    let message = counter.to_be_bytes();
    let digest = match algorithm {
        OtpAlgorithm::Sha1 => mac::<Hmac<Sha1>>(secret, &message),
        OtpAlgorithm::Sha256 => mac::<Hmac<Sha256>>(secret, &message),
        OtpAlgorithm::Sha512 => mac::<Hmac<Sha512>>(secret, &message),
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    let code = binary % 10u32.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

fn mac<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| Error::InvalidOtp("secret is not valid Base32"))
}

fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| core::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or(Error::InvalidOtp("invalid percent encoding"))?;
                out.push(hex);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidOtp("label is not valid UTF-8"))
}

mod base32_secret {
    use data_encoding::BASE32_NOPAD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(secret: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE32_NOPAD.encode(secret))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        super::decode_base32(&encoded).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from RFC 6238, Appendix B.
    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";
    const VECTORS: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn rfc6238_vectors() {
        let sha1 = Totp::with_options(SEED_SHA1.to_vec(), OtpAlgorithm::Sha1, 8, 30).unwrap();
        let sha256 = Totp::with_options(SEED_SHA256.to_vec(), OtpAlgorithm::Sha256, 8, 30).unwrap();
        let sha512 = Totp::with_options(SEED_SHA512.to_vec(), OtpAlgorithm::Sha512, 8, 30).unwrap();
        for (time, c1, c256, c512) in VECTORS {
            assert_eq!(sha1.generate(time), c1, "SHA1 at {time}");
            assert_eq!(sha256.generate(time), c256, "SHA256 at {time}");
            assert_eq!(sha512.generate(time), c512, "SHA512 at {time}");
        }
    }

    #[test]
    fn rfc4226_hotp_vectors() {
        let expected = ["755224", "287082", "359152", "969429", "338314"];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(
                hotp(SEED_SHA1, counter as u64, 6, OtpAlgorithm::Sha1),
                *code
            );
        }
    }

    #[test]
    fn parses_uri() {
        let totp = Totp::from_uri(
            "otpauth://totp/ACME%20Co:john.doe@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(totp.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(totp.account.as_deref(), Some("john.doe@example.com"));
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.generate(59), "287082");
    }

    #[test]
    fn issuer_falls_back_to_label() {
        let totp = Totp::from_uri("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(totp.issuer.as_deref(), Some("GitHub"));
        assert_eq!(totp.account.as_deref(), Some("octocat"));
    }

    #[test]
    fn rejects_bad_uris() {
        assert!(Totp::from_uri("https://example.com").is_err());
        assert!(Totp::from_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Totp::from_uri("otpauth://totp/x").is_err());
        assert!(Totp::from_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12").is_err());
    }

    #[test]
    fn base32_input_is_forgiving() {
        let a = Totp::from_base32("jbsw y3dp ehpk 3pxp").unwrap();
        let b = Totp::from_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(a.generate(1_700_000_000), b.generate(1_700_000_000));
        assert_eq!(a.secret_base32(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn seconds_remaining_counts_down() {
        let totp = Totp::from_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(totp.seconds_remaining(0), 30);
        assert_eq!(totp.seconds_remaining(29), 1);
        assert_eq!(totp.seconds_remaining(30), 30);
    }

    #[test]
    fn serde_round_trip_and_debug_redacts() {
        let totp = Totp::from_base32("JBSWY3DPEHPK3PXP").unwrap();
        let json = serde_json::to_string(&totp).unwrap();
        let back: Totp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, totp);
        assert!(!format!("{totp:?}").contains("JBSWY3DPEHPK3PXP"));
    }
}
