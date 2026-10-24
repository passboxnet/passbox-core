//! Passbox cryptographic core.
//!
//! This crate is the single place where Passbox performs cryptography. Every
//! client (web, browser extension, CLI and, later, desktop and mobile) uses it,
//! either natively or compiled to WebAssembly.
//!
//! The key hierarchy is described in `docs/architecture/cryptography.md`.
//! **The scheme is a draft and has not been reviewed or audited yet.**

pub mod aead;
pub mod canon;
pub mod directory;
pub mod encoding;
pub mod error;
pub mod export;
pub mod generator;
pub mod id;
pub mod identity;
pub mod kdf;
pub mod keyring;
pub mod opaque;
pub mod passkey;
pub mod random;
pub mod secret_key;
pub mod sharing;
pub mod strength;
pub mod totp;
pub mod two_factor;
pub mod webauthn;

pub use error::{Error, Result};
