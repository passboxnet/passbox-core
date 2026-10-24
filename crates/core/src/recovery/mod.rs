//! Account recovery (wave C).
//!
//! - [`code`]: the personal recovery code (C2).
//! - [`org`]: recovery through an organization or family (C1): the
//!   organization's recovery key pair, members' escrows, approvals and the
//!   requesting device's ephemeral key.
//!
//! Design and threat model: `docs/architecture/recovery.md`.

pub mod code;
pub mod org;

use crate::canon::Writer;
use crate::identity::{HASH_LEN, object_hash};

/// Hash of an ephemeral X-Wing public key (recovery requests, device
/// links), used as the recipient key hash when sealing to it.
pub fn ephemeral_key_hash(enc_pk: &[u8]) -> [u8; HASH_LEN] {
    object_hash(
        &Writer::new("passbox/v1/ephemeral-key")
            .bytes(enc_pk)
            .finish(),
    )
}
