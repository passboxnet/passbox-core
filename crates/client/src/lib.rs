//! Passbox client for native apps and the CLI: sign-up, sign-in, online and
//! offline unlock, incremental sync with an encrypted offline cache, and
//! item editing with conflict detection.
//!
//! The browser clients use the equivalent TypeScript implementation in
//! `packages/client`; both talk to the same API and share the item format.

pub mod api;
pub mod client;
pub mod error;
pub mod model;
pub mod security;
pub mod store;

pub use api::{AccountEvent, SecurityKeyInfo, SessionInfo, TotpSetup, TwoFactorStatus};
pub use client::{Client, Connectivity, Status};
pub use error::{Error, Result};
pub use model::{DeviceAccount, FieldType, Item, ItemCategory, ItemData, ItemField, Vault, field};
pub use store::{FileStore, MemoryStore, Store};
