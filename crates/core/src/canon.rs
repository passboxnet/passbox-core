//! Canonical binary encoding of signed and hashed objects.
//!
//! Every signed object (public key bundles, attestations, grants, manifests,
//! log entries) is encoded the same way before it is signed or hashed:
//!
//! ```text
//! tag (string) | field 1 | field 2 | ...
//! string, bytes: u32 big-endian length | raw bytes
//! integers:      u64 big-endian (i64 as two's complement)
//! lists:         u32 big-endian count | elements
//! ```
//!
//! The tag is a domain separation string such as `passbox/v1/public-bundle`,
//! so an encoding of one object type never parses as another and a signature
//! over one type cannot be presented as a signature over another. There is
//! exactly one encoding per value, and decoding rejects trailing bytes, so
//! the bytes that were signed are the bytes that are interpreted. Objects
//! travel as Base64url of these bytes; receivers never trust a separate JSON
//! copy of the fields.

use crate::{Error, Result};

/// Upper bound for a single string or byte field.
const MAX_FIELD_LEN: usize = 64 * 1024;
/// Upper bound for list lengths.
const MAX_LIST_LEN: usize = 100_000;

/// Builds a canonical encoding.
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// Starts an object with its type tag.
    pub fn new(tag: &str) -> Self {
        let mut writer = Self {
            out: Vec::with_capacity(256),
        };
        writer.str(tag);
        writer
    }

    pub fn str(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes())
    }

    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).expect("field fits into u32");
        self.out.extend_from_slice(&len.to_be_bytes());
        self.out.extend_from_slice(value);
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn i64(&mut self, value: i64) -> &mut Self {
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn count(&mut self, len: usize) -> &mut Self {
        let len = u32::try_from(len).expect("list fits into u32");
        self.out.extend_from_slice(&len.to_be_bytes());
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }
}

/// Parses a canonical encoding. Every accessor fails with
/// [`Error::InvalidData`] on truncated or oversized input.
pub struct Reader<'a> {
    input: &'a [u8],
}

fn malformed(what: &str) -> Error {
    Error::InvalidData(format!("malformed {what}"))
}

impl<'a> Reader<'a> {
    /// Starts reading and checks the type tag.
    pub fn new(input: &'a [u8], tag: &str) -> Result<Self> {
        let mut reader = Self { input };
        if reader.str()? != tag {
            return Err(Error::InvalidData(format!("expected a {tag} object")));
        }
        Ok(reader)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, rest) = self
            .input
            .split_at_checked(len)
            .ok_or_else(|| malformed("object"))?;
        self.input = rest;
        Ok(head)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        if len > MAX_FIELD_LEN {
            return Err(malformed("object (field too long)"));
        }
        self.take(len)
    }

    /// Reads a field of exactly `N` bytes.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes()?
            .try_into()
            .map_err(|_| malformed("object (field length)"))
    }

    pub fn str(&mut self) -> Result<&'a str> {
        core::str::from_utf8(self.bytes()?).map_err(|_| malformed("object (UTF-8)"))
    }

    pub fn string(&mut self) -> Result<String> {
        self.str().map(str::to_owned)
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub fn u32(&mut self) -> Result<u32> {
        u32::try_from(self.u64()?).map_err(|_| malformed("object (number too large)"))
    }

    pub fn count(&mut self) -> Result<usize> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        if len > MAX_LIST_LEN {
            return Err(malformed("object (list too long)"));
        }
        Ok(len)
    }

    /// Fails unless the whole input was consumed.
    pub fn finish(self) -> Result<()> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(malformed("object (trailing bytes)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = Writer::new("passbox/v1/test")
            .str("héllo")
            .bytes(&[1, 2, 3])
            .u64(7)
            .i64(-5)
            .count(2)
            .finish();
        let mut reader = Reader::new(&bytes, "passbox/v1/test").unwrap();
        assert_eq!(reader.str().unwrap(), "héllo");
        assert_eq!(reader.bytes().unwrap(), &[1, 2, 3]);
        assert_eq!(reader.u64().unwrap(), 7);
        assert_eq!(reader.i64().unwrap(), -5);
        assert_eq!(reader.count().unwrap(), 2);
        reader.finish().unwrap();
    }

    #[test]
    fn layout_is_stable() {
        let bytes = Writer::new("t").str("ab").u64(1).finish();
        assert_eq!(
            bytes,
            [
                0, 0, 0, 1, b't', 0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 0, 0, 0, 1
            ]
        );
    }

    #[test]
    fn rejects_wrong_tag_truncation_and_trailing_bytes() {
        let bytes = Writer::new("a").str("x").finish();
        assert!(Reader::new(&bytes, "b").is_err());
        let mut reader = Reader::new(&bytes[..bytes.len() - 1], "a").unwrap();
        assert!(reader.str().is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        let mut reader = Reader::new(&longer, "a").unwrap();
        reader.str().unwrap();
        assert!(reader.finish().is_err());
    }
}
