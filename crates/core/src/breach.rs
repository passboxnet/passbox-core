//! Have I Been Pwned "Pwned Passwords" range queries with k-anonymity.
//!
//! Only the first five hex characters of a password's SHA-1 hash are sent
//! (`GET https://api.pwnedpasswords.com/range/{prefix}` with the header
//! `Add-Padding: true`); the response lists every known hash suffix with
//! that prefix, and the match happens on the device. Mirrors
//! `breachCount` in `packages/client/src/security.ts`.

use sha1::{Digest, Sha1};

/// Base URL of the range API; append the prefix.
pub const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

/// The SHA-1 hash of a password as upper-case hex, split into the 5-character
/// prefix that is sent and the 35-character suffix that stays on the device.
pub fn hash_parts(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
    let (prefix, suffix) = hex.split_at(5);
    (prefix.to_owned(), suffix.to_owned())
}

/// How often `suffix` appears in a range response (`SUFFIX:COUNT` lines).
/// Padding entries have a count of 0. Returns 0 when not found.
pub fn count_in_range(response: &str, suffix: &str) -> u64 {
    response
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(suffix))
        .and_then(|(_, count)| count.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_the_sha1_hash() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = hash_parts("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn counts_matches_and_ignores_padding() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n\
                    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n";
        assert_eq!(
            count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            9_659_365
        );
        assert_eq!(
            count_in_range(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            0
        );
        assert_eq!(
            count_in_range(body, "0000000000000000000000000000000000A"),
            0
        );
    }
}
