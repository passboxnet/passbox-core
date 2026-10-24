use thiserror::Error;

/// Errors returned by the client.
#[derive(Debug, Error)]
pub enum Error {
    #[error("the email, master password or Secret Key is incorrect")]
    InvalidCredentials,
    #[error("there is no account on this device")]
    NoAccount,
    #[error("the vault is locked")]
    Locked,
    #[error("this change needs a connection to the server")]
    Offline,
    #[error("the item was changed on another device; the latest version has been loaded")]
    Conflict,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("the server could not be reached: {0}")]
    Network(String),
    #[error("the server answered with an error ({status}): {message}")]
    Server {
        status: u16,
        code: String,
        message: String,
    },
    #[error("storage error: {0}")]
    Storage(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error(transparent)]
    Core(#[from] passbox_core::Error),
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::InvalidData(err.to_string())
    }
}

pub type Result<T> = core::result::Result<T, Error>;
