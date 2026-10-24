use thiserror::Error;

/// Errors returned by the Passbox core.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("the operating system random number generator failed")]
    Random,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("key derivation parameters are below the allowed minimum")]
    WeakKdfParams,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid recovery code")]
    InvalidRecoveryCode,
    #[error("invalid device code")]
    InvalidDeviceCode,
    #[error("malformed envelope")]
    MalformedEnvelope,
    #[error("unsupported envelope version or algorithm")]
    UnsupportedEnvelope,
    #[error("decryption failed")]
    Decryption,
    #[error("invalid one-time password configuration: {0}")]
    InvalidOtp(&'static str),
    #[error("invalid Base64url encoding")]
    InvalidEncoding,
    #[error("authentication protocol error")]
    Protocol,
    #[error("invalid email, password or Secret Key")]
    InvalidCredentials,
    #[error("key not found: {0}")]
    MissingKey(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("the key of {0} changed; compare fingerprints and accept the change first")]
    KeyChanged(String),
    #[error("invalid generator options: {0}")]
    InvalidGeneratorOptions(&'static str),
    #[error("WebAuthn verification failed: {0}")]
    WebAuthn(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;
