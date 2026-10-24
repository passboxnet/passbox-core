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
    /// Steam Guard codes: 5 characters from Steam's alphabet instead of digits.
    #[serde(default)]
    pub steam: bool,
}

/// Characters of Steam Guard codes.
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

impl core::fmt::Debug for Totp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("steam", &self.steam)
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
            steam: false,
        })
    }

    /// Creates a TOTP configuration from a Base32 secret, as shown by most websites.
    ///
    /// Case, spaces, dashes and padding are ignored.
    ///
    /// A `steam://` prefix (as used by KeePassXC) marks a Steam Guard secret.
    pub fn from_base32(secret: &str) -> Result<Self> {
        let trimmed = secret.trim();
        match trimmed
            .get(..8)
            .filter(|p| p.eq_ignore_ascii_case("steam://"))
        {
            Some(_) => {
                let mut totp = Self::new(decode_base32(&trimmed[8..])?)?;
                totp.steam = true;
                totp.issuer = Some("Steam".into());
                Ok(totp)
            }
            None => Self::new(decode_base32(secret)?),
        }
    }

    /// Checks what a user typed into a one-time password field, so apps can
    /// explain mistakes before saving. Returns `None` for valid (or empty)
    /// input, `Some("one_time_code")` when it looks like a single 6 to 8
    /// digit code instead of the setup key, and `Some("invalid")` otherwise.
    pub fn input_problem(input: &str) -> Option<&'static str> {
        let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.is_empty() {
            None
        } else if (6..=8).contains(&compact.len()) && compact.chars().all(|c| c.is_ascii_digit()) {
            Some("one_time_code")
        } else if Self::parse(input).is_err() {
            Some("invalid")
        } else {
            None
        }
    }

    /// Parses an `otpauth://` URI or a Base32 secret (including `steam://`).
    pub fn parse(input: &str) -> Result<Self> {
        if input.trim_start().starts_with("otpauth://") {
            Self::from_uri(input.trim())
        } else {
            Self::from_base32(input)
        }
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
        let mut steam = false;
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
                "encoder" => steam = value.eq_ignore_ascii_case("steam"),
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
        // Steam Guard: marked by `encoder=steam` or the issuer "Steam".
        totp.steam = steam
            || totp
                .issuer
                .as_deref()
                .is_some_and(|i| i.eq_ignore_ascii_case("steam"));
        Ok(totp)
    }

    /// Returns the secret as unpadded Base32.
    pub fn secret_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.secret)
    }

    /// Generates the code valid at `unix_time` (seconds since the epoch).
    pub fn generate(&self, unix_time: u64) -> String {
        if self.steam {
            let mut value = hotp_binary(&self.secret, unix_time / self.period, OtpAlgorithm::Sha1);
            return (0..5)
                .map(|_| {
                    let c = STEAM_ALPHABET[(value % 26) as usize] as char;
                    value /= 26;
                    c
                })
                .collect();
        }
        hotp(
            &self.secret,
            unix_time / self.period,
            self.digits,
            self.algorithm,
        )
    }

    /// Checks a code typed by a user against the codes of the time steps
    /// from `unix_time / period - window` to `unix_time / period + window`
    /// and returns the matching time step, so callers can reject a step that
    /// was used before (replay protection). Spaces in `code` are ignored.
    /// Every candidate is compared in constant time.
    pub fn verify(&self, code: &str, unix_time: u64, window: u64) -> Option<u64> {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let current = unix_time / self.period;
        let mut matched = None;
        for step in current.saturating_sub(window)..=current.saturating_add(window) {
            let expected = self.generate(step.saturating_mul(self.period));
            if constant_time_eq(expected.as_bytes(), code.as_bytes()) && matched.is_none() {
                matched = Some(step);
            }
        }
        matched
    }

    /// Returns an `otpauth://totp/` URI for authenticator apps (QR codes),
    /// labelled `issuer:account`.
    pub fn to_uri(&self) -> String {
        let issuer = self.issuer.as_deref().unwrap_or_default();
        let account = self.account.as_deref().unwrap_or_default();
        let label = match (issuer.is_empty(), account.is_empty()) {
            (false, false) => format!("{}:{}", percent_encode(issuer), percent_encode(account)),
            (false, true) => percent_encode(issuer),
            _ => percent_encode(account),
        };
        let algorithm = match self.algorithm {
            OtpAlgorithm::Sha1 => "SHA1",
            OtpAlgorithm::Sha256 => "SHA256",
            OtpAlgorithm::Sha512 => "SHA512",
        };
        let mut uri = format!(
            "otpauth://totp/{label}?secret={}&algorithm={algorithm}&digits={}&period={}",
            self.secret_base32(),
            self.digits,
            self.period
        );
        if !issuer.is_empty() {
            uri.push_str("&issuer=");
            uri.push_str(&percent_encode(issuer));
        }
        uri
    }

    /// Seconds until the code generated at `unix_time` expires.
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        self.period - (unix_time % self.period)
    }
}

/// Computes an HOTP value (RFC 4226).
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algorithm: OtpAlgorithm) -> String {
    let code = hotp_binary(secret, counter, algorithm) % 10u32.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

/// The 31-bit dynamic truncation of the HMAC (RFC 4226, section 5.3).
fn hotp_binary(secret: &[u8], counter: u64, algorithm: OtpAlgorithm) -> u32 {
    let message = counter.to_be_bytes();
    let digest = match algorithm {
        OtpAlgorithm::Sha1 => mac::<Hmac<Sha1>>(secret, &message),
        OtpAlgorithm::Sha256 => mac::<Hmac<Sha256>>(secret, &message),
        OtpAlgorithm::Sha512 => mac::<Hmac<Sha512>>(secret, &message),
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ])
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

/// Compares two byte strings without an early exit on the first difference.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Percent-encodes everything except unreserved characters (RFC 3986).
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
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
    fn steam_guard_codes() {
        // Reference: the 31-bit truncation rendered base-26 in Steam's alphabet.
        let expected = {
            let mut value = hotp_binary(b"12345678901234567890", 59 / 30, OtpAlgorithm::Sha1);
            (0..5)
                .map(|_| {
                    let c = STEAM_ALPHABET[(value % 26) as usize] as char;
                    value /= 26;
                    c
                })
                .collect::<String>()
        };
        let secret = BASE32_NOPAD.encode(b"12345678901234567890");
        for input in [
            format!("otpauth://totp/Steam:gamer?secret={secret}&issuer=Steam"),
            format!("otpauth://totp/gamer?secret={secret}&encoder=steam"),
            format!("steam://{secret}"),
        ] {
            let totp = Totp::parse(&input).unwrap();
            assert!(totp.steam, "{input}");
            let code = totp.generate(59);
            assert_eq!(code, expected);
            assert_eq!(code.len(), 5);
            assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
        }
        // Ordinary TOTP stays numeric.
        let normal = Totp::parse(&format!("otpauth://totp/GitHub:me?secret={secret}")).unwrap();
        assert!(!normal.steam);
        assert_eq!(normal.generate(59), "287082");
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

    #[test]
    fn verifies_codes_within_the_window() {
        let totp = Totp::with_options(SEED_SHA1.to_vec(), OtpAlgorithm::Sha1, 8, 30).unwrap();
        // 1111111109 is in step 37037036; its code is 07081804 (RFC 6238).
        assert_eq!(totp.verify("07081804", 1111111109, 1), Some(37037036));
        assert_eq!(totp.verify("0708 1804", 1111111109 + 30, 1), Some(37037036));
        assert_eq!(totp.verify("07081804", 1111111109 - 30, 1), Some(37037036));
        assert_eq!(totp.verify("07081804", 1111111109 + 60, 1), None);
        assert_eq!(totp.verify("07081804", 1111111109 + 30, 0), None);
        assert_eq!(totp.verify("07081805", 1111111109, 1), None);
        assert_eq!(totp.verify("", 1111111109, 1), None);
        assert_eq!(totp.verify("0708180", 1111111109, 1), None);
        // Time zero does not underflow.
        let code = totp.generate(0);
        assert_eq!(totp.verify(&code, 0, 1), Some(0));
    }

    #[test]
    fn builds_uris_that_parse_back() {
        let mut totp = Totp::from_base32("JBSWY3DPEHPK3PXP").unwrap();
        totp.issuer = Some("Passbox (Work)".into());
        totp.account = Some("anna+test@example.com".into());
        let uri = totp.to_uri();
        assert_eq!(
            uri,
            "otpauth://totp/Passbox%20%28Work%29:anna%2Btest@example.com?secret=JBSWY3DPEHPK3PXP\
             &algorithm=SHA1&digits=6&period=30&issuer=Passbox%20%28Work%29"
        );
        let parsed = Totp::from_uri(&uri).unwrap();
        assert_eq!(parsed.issuer.as_deref(), Some("Passbox (Work)"));
        assert_eq!(parsed.account.as_deref(), Some("anna+test@example.com"));
        assert_eq!(parsed.generate(59), totp.generate(59));
    }

    #[test]
    fn input_problems() {
        assert_eq!(Totp::input_problem(""), None);
        assert_eq!(Totp::input_problem("  "), None);
        assert_eq!(Totp::input_problem("482913"), Some("one_time_code"));
        assert_eq!(Totp::input_problem("234 567"), Some("one_time_code"));
        assert_eq!(Totp::input_problem("not a key!"), Some("invalid"));
        assert_eq!(Totp::input_problem("JBSW Y3DP EHPK 3PXP"), None);
        assert_eq!(
            Totp::input_problem("otpauth://totp/Example:a?secret=JBSWY3DPEHPK3PXP"),
            None
        );
        assert_eq!(
            Totp::input_problem("otpauth://totp/broken"),
            Some("invalid")
        );
    }
}
