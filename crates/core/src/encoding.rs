//! Encoding helpers. Binary values travel as unpadded Base64url in the API.

use data_encoding::BASE64URL_NOPAD;

use crate::{Error, Result};

/// Encodes bytes as unpadded Base64url.
pub fn encode(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// Decodes unpadded Base64url.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(input.as_bytes())
        .map_err(|_| Error::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = [0u8, 1, 2, 250, 251, 252, 253, 254, 255];
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
        assert!(!encode(&bytes).contains(['+', '/', '=']));
    }

    #[test]
    fn rejects_invalid_input() {
        assert_eq!(decode("not base64!"), Err(Error::InvalidEncoding));
    }
}
