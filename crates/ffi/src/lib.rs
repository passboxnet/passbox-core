//! Swift and Kotlin bindings for the Passbox client, generated with UniFFI.
//!
//! All calls are blocking. Apps call them from a background thread or task
//! (Swift `Task.detached`, Kotlin `Dispatchers.IO`).
//!
//! Generate bindings with `crates/ffi/generate-bindings.sh`.

use std::sync::Arc;

use passbox_client as client;
use passbox_core::generator::{self, PasswordOptions};
use passbox_core::secret_key::SecretKey;
use passbox_core::totp::Totp;

uniffi::setup_scaffolding!();

// --- Errors ---------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PassboxError {
    #[error("The email, master password or Secret Key is incorrect.")]
    InvalidCredentials,
    #[error("There is no account on this device.")]
    NoAccount,
    #[error("The vault is locked.")]
    Locked,
    #[error("This change needs a connection to the server.")]
    Offline,
    #[error("The item was changed on another device. The latest version has been loaded.")]
    Conflict,
    #[error("Not found: {message}")]
    NotFound { message: String },
    #[error("The server could not be reached: {message}")]
    Network { message: String },
    #[error("Server error: {message}")]
    Server { message: String },
    #[error("Storage error: {message}")]
    Storage { message: String },
    #[error("Invalid data: {message}")]
    InvalidData { message: String },
}

impl From<client::Error> for PassboxError {
    fn from(err: client::Error) -> Self {
        use client::Error as E;
        match err {
            E::InvalidCredentials => Self::InvalidCredentials,
            E::NoAccount => Self::NoAccount,
            E::Locked => Self::Locked,
            E::Offline => Self::Offline,
            E::Conflict => Self::Conflict,
            E::NotFound(message) => Self::NotFound { message },
            E::Network(message) => Self::Network { message },
            E::Server { message, .. } => Self::Server { message },
            E::Storage(message) => Self::Storage { message },
            other @ (E::InvalidData(_) | E::Core(_)) => Self::InvalidData {
                message: other.to_string(),
            },
        }
    }
}

impl From<passbox_core::Error> for PassboxError {
    fn from(err: passbox_core::Error) -> Self {
        Self::InvalidData {
            message: err.to_string(),
        }
    }
}

// The foreign store reports failures through this error type.
impl From<uniffi::UnexpectedUniFFICallbackError> for PassboxError {
    fn from(err: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Storage {
            message: err.reason,
        }
    }
}

type Result<T> = std::result::Result<T, PassboxError>;

// --- Storage --------------------------------------------------------------------

/// Storage provided by the app, for example backed by the iOS Keychain or
/// Android EncryptedSharedPreferences. Keys are short ASCII identifiers.
#[uniffi::export(with_foreign)]
pub trait SecureStore: Send + Sync {
    fn get(&self, key: String) -> Result<Option<Vec<u8>>>;
    fn put(&self, key: String, value: Vec<u8>) -> Result<()>;
    fn delete(&self, key: String) -> Result<()>;
}

struct ForeignStore(Arc<dyn SecureStore>);

impl client::Store for ForeignStore {
    fn get(&self, key: &str) -> client::Result<Option<Vec<u8>>> {
        self.0
            .get(key.to_owned())
            .map_err(|e| client::Error::Storage(e.to_string()))
    }

    fn put(&self, key: &str, value: &[u8]) -> client::Result<()> {
        self.0
            .put(key.to_owned(), value.to_vec())
            .map_err(|e| client::Error::Storage(e.to_string()))
    }

    fn delete(&self, key: &str) -> client::Result<()> {
        self.0
            .delete(key.to_owned())
            .map_err(|e| client::Error::Storage(e.to_string()))
    }
}

// --- Records --------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ClientStatus {
    SignedOut,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ItemCategory {
    Login,
    Note,
    Card,
    Identity,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FieldType {
    Text,
    Concealed,
    Url,
    Email,
    Totp,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemField {
    pub id: String,
    pub label: String,
    pub field_type: FieldType,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ItemData {
    pub category: ItemCategory,
    pub title: String,
    pub fields: Vec<ItemField>,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    /// Fields unknown to this version (for example passkeys), as a JSON
    /// object. Pass it back unchanged when saving.
    pub extra_json: String,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Item {
    pub id: String,
    pub vault_id: String,
    pub revision: u64,
    /// Unix milliseconds.
    pub updated_at: i64,
    pub data: ItemData,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Vault {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceAccount {
    pub server_url: String,
    pub email: String,
    pub account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultHealth {
    pub weak: Vec<String>,
    pub reused: Vec<Vec<String>>,
    pub insecure_urls: Vec<String>,
    pub without_totp: Vec<String>,
    pub score: u8,
    pub analyzed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Strength {
    pub score: u8,
    pub label: String,
    pub bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

// Conversions between the binding records and the client model.

fn category_to_ffi(category: client::ItemCategory) -> ItemCategory {
    match category {
        client::ItemCategory::Login => ItemCategory::Login,
        client::ItemCategory::Note => ItemCategory::Note,
        client::ItemCategory::Card => ItemCategory::Card,
        client::ItemCategory::Identity => ItemCategory::Identity,
        client::ItemCategory::Other => ItemCategory::Other,
    }
}

fn category_from_ffi(category: ItemCategory) -> client::ItemCategory {
    match category {
        ItemCategory::Login => client::ItemCategory::Login,
        ItemCategory::Note => client::ItemCategory::Note,
        ItemCategory::Card => client::ItemCategory::Card,
        ItemCategory::Identity => client::ItemCategory::Identity,
        ItemCategory::Other => client::ItemCategory::Other,
    }
}

fn field_type_to_ffi(field_type: client::FieldType) -> FieldType {
    match field_type {
        client::FieldType::Text => FieldType::Text,
        client::FieldType::Concealed => FieldType::Concealed,
        client::FieldType::Url => FieldType::Url,
        client::FieldType::Email => FieldType::Email,
        client::FieldType::Totp => FieldType::Totp,
    }
}

fn field_type_from_ffi(field_type: FieldType) -> client::FieldType {
    match field_type {
        FieldType::Text => client::FieldType::Text,
        FieldType::Concealed => client::FieldType::Concealed,
        FieldType::Url => client::FieldType::Url,
        FieldType::Email => client::FieldType::Email,
        FieldType::Totp => client::FieldType::Totp,
    }
}

fn data_to_ffi(data: client::ItemData) -> ItemData {
    ItemData {
        category: category_to_ffi(data.category),
        title: data.title,
        fields: data
            .fields
            .into_iter()
            .map(|f| ItemField {
                id: f.id,
                label: f.label,
                field_type: field_type_to_ffi(f.field_type),
                value: f.value,
            })
            .collect(),
        notes: data.notes,
        tags: data.tags,
        favorite: data.favorite,
        extra_json: serde_json::Value::Object(data.extra).to_string(),
    }
}

fn data_from_ffi(data: ItemData) -> Result<client::ItemData> {
    let extra = if data.extra_json.trim().is_empty() {
        serde_json::Map::new()
    } else {
        match serde_json::from_str(&data.extra_json) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => {
                return Err(PassboxError::InvalidData {
                    message: "extraJson must be a JSON object".into(),
                });
            }
        }
    };
    Ok(client::ItemData {
        v: 1,
        category: category_from_ffi(data.category),
        title: data.title,
        fields: data
            .fields
            .into_iter()
            .map(|f| client::ItemField {
                id: f.id,
                label: f.label,
                field_type: field_type_from_ffi(f.field_type),
                value: f.value,
            })
            .collect(),
        notes: data.notes,
        tags: data.tags,
        favorite: data.favorite,
        extra,
    })
}

fn item_to_ffi(item: client::Item) -> Item {
    Item {
        id: item.id,
        vault_id: item.vault_id,
        revision: item.revision,
        updated_at: item.updated_at,
        data: data_to_ffi(item.data),
    }
}

// --- Client ---------------------------------------------------------------------

/// The Passbox client for one server and one device account.
#[derive(uniffi::Object)]
pub struct PassboxClient {
    inner: client::Client,
}

#[uniffi::export]
impl PassboxClient {
    /// Creates a client that stores its data through the app's `store`.
    #[uniffi::constructor]
    pub fn new(server_url: String, store: Arc<dyn SecureStore>) -> Arc<Self> {
        Arc::new(Self {
            inner: client::Client::new(&server_url, Arc::new(ForeignStore(store))),
        })
    }

    /// Creates a client that stores its data as files in `directory`
    /// (private to the current user). Prefer `new` with platform secure
    /// storage on mobile.
    #[uniffi::constructor]
    pub fn with_directory(server_url: String, directory: String) -> Result<Arc<Self>> {
        let store = client::FileStore::new(directory)?;
        Ok(Arc::new(Self {
            inner: client::Client::new(&server_url, Arc::new(store)),
        }))
    }

    pub fn status(&self) -> Result<ClientStatus> {
        Ok(match self.inner.status()? {
            client::Status::SignedOut => ClientStatus::SignedOut,
            client::Status::Locked => ClientStatus::Locked,
            client::Status::Unlocked => ClientStatus::Unlocked,
        })
    }

    pub fn device_account(&self) -> Result<Option<DeviceAccount>> {
        Ok(self.inner.device_account()?.map(|a| DeviceAccount {
            server_url: a.server_url,
            email: a.email,
            account_id: a.account_id,
        }))
    }

    /// Creates an account and returns the Secret Key for the Emergency Kit.
    pub fn sign_up(&self, email: String, password: String) -> Result<String> {
        Ok(self.inner.sign_up(&email, &password)?)
    }

    pub fn sign_in(&self, email: String, password: String, secret_key: String) -> Result<()> {
        Ok(self.inner.sign_in(&email, &password, &secret_key)?)
    }

    /// Unlocks the account on this device. Returns `true` when the server
    /// was reached, `false` when unlocked offline from the cache.
    pub fn unlock(&self, password: String) -> Result<bool> {
        Ok(self.inner.unlock(&password)? == client::Connectivity::Online)
    }

    pub fn lock(&self) {
        self.inner.lock();
    }

    pub fn sign_out(&self) -> Result<()> {
        Ok(self.inner.sign_out()?)
    }

    pub fn is_online(&self) -> bool {
        self.inner.is_online()
    }

    pub fn sync(&self) -> Result<()> {
        Ok(self.inner.sync()?)
    }

    pub fn vaults(&self) -> Result<Vec<Vault>> {
        Ok(self
            .inner
            .vaults()?
            .into_iter()
            .map(|v| Vault {
                id: v.id,
                name: v.name,
            })
            .collect())
    }

    pub fn items(&self) -> Result<Vec<Item>> {
        Ok(self.inner.items()?.into_iter().map(item_to_ffi).collect())
    }

    pub fn item(&self, id: String) -> Result<Item> {
        Ok(item_to_ffi(self.inner.item(&id)?))
    }

    pub fn create_item(&self, vault_id: String, data: ItemData) -> Result<String> {
        Ok(self.inner.create_item(&vault_id, &data_from_ffi(data)?)?)
    }

    pub fn update_item(&self, id: String, data: ItemData) -> Result<()> {
        Ok(self.inner.update_item(&id, &data_from_ffi(data)?)?)
    }

    pub fn delete_item(&self, id: String) -> Result<()> {
        Ok(self.inner.delete_item(&id)?)
    }

    pub fn create_vault(&self, name: String) -> Result<String> {
        Ok(self.inner.create_vault(&name)?)
    }

    pub fn rename_vault(&self, id: String, name: String) -> Result<()> {
        Ok(self.inner.rename_vault(&id, &name)?)
    }

    pub fn health(&self) -> Result<VaultHealth> {
        let h = self.inner.health()?;
        Ok(VaultHealth {
            weak: h.weak,
            reused: h.reused,
            insecure_urls: h.insecure_urls,
            without_totp: h.without_totp,
            score: h.score,
            analyzed: h.analyzed as u64,
        })
    }
}

// --- Utilities ------------------------------------------------------------------

/// A new item with the default fields of its category.
#[uniffi::export]
pub fn new_item_data(category: ItemCategory, title: String) -> ItemData {
    data_to_ffi(client::ItemData::new(category_from_ffi(category), title))
}

#[uniffi::export]
pub fn generate_password(
    length: u32,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> Result<String> {
    Ok(generator::generate_password(&PasswordOptions {
        length: length as usize,
        digits,
        symbols,
        avoid_ambiguous,
        ..PasswordOptions::default()
    })?)
}

#[uniffi::export]
pub fn generate_pin(length: u32) -> Result<String> {
    Ok(generator::generate_pin(length as usize)?)
}

/// The current one-time password for an `otpauth://` URI or Base32 secret.
#[uniffi::export]
pub fn totp_code(uri_or_secret: String, unix_time: u64) -> Result<TotpCode> {
    let totp = if uri_or_secret.starts_with("otpauth://") {
        Totp::from_uri(&uri_or_secret)?
    } else {
        Totp::from_base32(&uri_or_secret)?
    };
    Ok(TotpCode {
        code: totp.generate(unix_time),
        seconds_remaining: totp.seconds_remaining(unix_time),
        period: totp.period,
    })
}

#[uniffi::export]
pub fn estimate_strength(password: String) -> Strength {
    let strength = client::security::estimate_strength(&password);
    Strength {
        score: strength.score,
        label: strength.label().to_owned(),
        bits: strength.bits,
    }
}

/// Normalizes a Secret Key typed by the user, or fails if it is malformed.
#[uniffi::export]
pub fn normalize_secret_key(input: String) -> Result<String> {
    SecretKey::parse(&input)
        .map(|key| key.to_display_string())
        .map_err(|_| PassboxError::InvalidCredentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_data_round_trips_with_extra_fields() {
        let mut data = new_item_data(ItemCategory::Login, "GitHub".into());
        data.extra_json = r#"{"passkeys":[{"rpId":"github.com"}]}"#.into();
        let back = data_to_ffi(data_from_ffi(data.clone()).unwrap());
        assert_eq!(back.fields, data.fields);
        assert!(back.extra_json.contains("github.com"));
        data.extra_json = "[1]".into();
        assert!(data_from_ffi(data).is_err());
    }

    #[test]
    fn utilities() {
        let code = totp_code("JBSWY3DPEHPK3PXP".into(), 59).unwrap();
        assert_eq!(code.code.len(), 6);
        assert_eq!(code.seconds_remaining, 1);
        assert_eq!(
            generate_password(24, true, true, false)
                .unwrap()
                .chars()
                .count(),
            24
        );
        assert_eq!(generate_pin(6).unwrap().len(), 6);
        assert_eq!(estimate_strength("password".into()).score, 0);
        assert!(normalize_secret_key("nope".into()).is_err());
    }

    #[test]
    fn file_backed_client_starts_signed_out() {
        let dir = tempfile::tempdir().unwrap();
        let client = PassboxClient::with_directory(
            "http://127.0.0.1:9".into(),
            dir.path().to_string_lossy().into(),
        )
        .unwrap();
        assert_eq!(client.status().unwrap(), ClientStatus::SignedOut);
        assert!(matches!(client.items(), Err(PassboxError::Locked)));
    }
}
