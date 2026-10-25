//! The Passbox AI gateway for native clients (desktop, CLI, mobile through
//! the FFI later). The TypeScript twin is `packages/ai`; both have the same
//! shape. Concept: `docs/planning/ai-native.md` (German), data flows:
//! `docs/architecture/ai-gateway.md`.
//!
//! The gateway calls a model for Passbox's own features. It has **no vault
//! access and no keys**: this crate cannot depend on `passbox-core` or
//! `passbox-client` (enforced by `tests/boundary.rs`). Features hand it
//! inputs that only the redaction layer can build ([`Redacted`]), and every
//! feature has a deterministic result when AI is off or fails.
//!
//! - [`presets`]: bring-your-own-key presets for cloud providers (Mistral,
//!   IONOS, STACKIT, Scaleway, Langdock, OpenAI, Anthropic).
//! - [`provider`]: where a model runs (on the device, self-hosted
//!   OpenAI-compatible endpoint such as Ollama or vLLM, or a cloud provider
//!   with the user's own key) and how it is called.
//! - [`redact`]: data classes D0–D3 (D4, secrets, cannot be represented),
//!   the [`Redacted`] wrapper and the secret guard.
//! - [`gateway`]: settings (off by default, opt-in per feature), feature
//!   manifests, policy checks, response validation and the local AI log.
//! - [`import_mapping`] (K6) and [`security_copilot`] (K4): the features.

pub mod gateway;
pub mod import_mapping;
pub mod presets;
pub mod provider;
pub mod redact;
pub mod security_copilot;

pub use gateway::{AiLogEntry, AiSettings, FeatureId, FeatureManifest, Gateway, ProviderSettings};
pub use presets::{PROVIDER_PRESETS, ProviderApi, ProviderPreset};
pub use provider::{
    AiProvider, AiRequest, Anthropic, ModelLocation, OpenAiCompatible, provider_from_settings,
};
pub use redact::{DataClass, Redacted, SecretGuard};

/// Errors of the gateway. None of them contains model input.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum AiError {
    /// AI or this feature is switched off, or settings and policy forbid
    /// the provider or the data classes. Use the deterministic fallback.
    #[error("not allowed: {0}")]
    NotAllowed(String),
    /// The provider could not be reached or answered with an error.
    #[error("provider failed: {0}")]
    Provider(String),
    /// The answer was not valid for the feature's schema.
    #[error("invalid answer: {0}")]
    InvalidResponse(String),
    /// The settings are incomplete or invalid (for example no endpoint).
    #[error("invalid settings: {0}")]
    Settings(String),
}

pub type Result<T> = std::result::Result<T, AiError>;
