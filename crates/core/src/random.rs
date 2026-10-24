//! Access to the operating system's cryptographically secure random number generator.

use crate::{Error, Result};

/// Fills `buf` with cryptographically secure random bytes.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// Returns an array of cryptographically secure random bytes.
pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    fill(&mut buf)?;
    Ok(buf)
}

/// Returns a uniformly distributed random number in `0..bound` using rejection sampling.
///
/// # Panics
///
/// Panics if `bound` is zero.
pub fn below(bound: u32) -> Result<u32> {
    assert!(bound > 0, "bound must be greater than zero");
    // Largest multiple of `bound` that fits into u32; values above it would bias the result.
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let value = u32::from_le_bytes(bytes::<4>()?);
        if value < zone {
            return Ok(value % bound);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_stays_in_range() {
        for bound in [1, 2, 7, 26, 1000] {
            for _ in 0..200 {
                assert!(below(bound).unwrap() < bound);
            }
        }
    }

    #[test]
    fn bytes_are_not_all_zero() {
        assert_ne!(bytes::<32>().unwrap(), [0u8; 32]);
    }
}
