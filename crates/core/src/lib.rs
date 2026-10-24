//! Passbox cryptographic core.
//!
//! This crate is the single place where Passbox performs cryptography. Every
//! client (web, browser extension, CLI and, later, desktop and mobile) uses it,
//! either natively or compiled to WebAssembly.
//!
//! The key hierarchy is described in `docs/architecture/cryptography.md`.
//! **The scheme is a draft and has not been reviewed or audited yet.**

pub mod aead;
pub mod error;
pub mod generator;
pub mod kdf;
pub mod random;
pub mod secret_key;
pub mod totp;

pub use error::{Error, Result};
