//! Organizations, groups and shared vaults.
//!
//! - [`objects`]: the signed objects and their canonical encodings.
//! - [`data`]: what the server delivers, and merging of sync deltas.
//! - [`verify`]: verification of rosters, manifest chains and grants.
//! - [`state`]: the verified view a client shows, and key opening.
//! - [`build`]: request builders (create, invite confirmation, share,
//!   rotate) that sign and seal on behalf of the account.
//!
//! The design and threat model are described in
//! `docs/architecture/sharing.md`.

pub mod build;
pub mod data;
pub mod objects;
pub mod state;
pub mod verify;

#[cfg(test)]
pub(crate) mod tests;
