//! Swift and Kotlin bindings for the Passbox client, generated with UniFFI.
//!
//! All calls are blocking. Apps call them from a background thread or task
//! (Swift `Task.detached`, Kotlin `Dispatchers.IO`).
//!
//! Generate bindings with `crates/ffi/generate-bindings.sh`.

use std::sync::Arc;

use passbox_client as client;
use passbox_core::generator::{self, PassphraseOptions, PasswordOptions};
use passbox_core::secret_key::SecretKey;
use passbox_core::totp::Totp;

uniffi::setup_scaffolding!();

mod sharing;
pub use sharing::*;

#[cfg(target_os = "android")]
mod android;

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
    /// For HTTP 429 (`rate_limited`) the message is
    /// `too many attempts; try again in <seconds> seconds`.
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
    /// Unix milliseconds when the item was moved to the trash.
    pub trashed_at: Option<i64>,
    /// Earlier passwords, newest first.
    pub password_history: Vec<PasswordHistoryEntry>,
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
    /// Analyzed logins without any problem.
    pub secure: u64,
    pub score: u8,
    pub analyzed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Strength {
    pub score: u8,
    pub label: String,
    pub bits: u32,
    /// Code for a localized warning, for example `recent_year`,
    /// `common_password` or `name` (see `passbox_core::strength`).
    pub warning: Option<String>,
    /// Codes for localized tips, for example `add_words`.
    pub suggestions: Vec<String>,
    /// Good enough for a master password (score ≥ 3 and ≥ 12 characters).
    pub acceptable_master_password: bool,
}

/// A password an item had before.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordHistoryEntry {
    pub value: String,
    /// Unix milliseconds when it was replaced.
    pub replaced_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

/// A device signed in to the account.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceSession {
    pub id: String,
    pub device_name: String,
    /// `web`, `extension`, `desktop`, `ios`, `android`, `cli` or empty.
    pub client_kind: String,
    pub ip: String,
    /// Milliseconds since the Unix epoch.
    pub created_at: i64,
    pub last_used_at: i64,
    /// True for this device.
    pub current: bool,
}

/// An entry of the account activity log.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountEvent {
    pub id: String,
    /// For example `login`, `login_failed`, `session_revoked` or
    /// `password_changed`.
    pub kind: String,
    pub device_name: String,
    pub client_kind: String,
    pub ip: String,
    /// Milliseconds since the Unix epoch.
    pub created_at: i64,
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
        trashed_at: item.data.trashed_at(),
        password_history: item
            .data
            .password_history()
            .into_iter()
            .map(|e| PasswordHistoryEntry {
                value: e.value,
                replaced_at: e.replaced_at,
            })
            .collect(),
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

    /// Sets how this device appears in the account's device list, for
    /// example `("Anna's iPhone", "ios")`. Call before signing in or
    /// unlocking.
    pub fn set_device(&self, name: String, kind: String) {
        self.inner.set_device(&name, &kind);
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

    /// Key for biometric unlock: the derived master keys of the unlocked
    /// session (65 bytes). Store it only in hardware-backed storage that
    /// requires biometric authentication; never the master password.
    pub fn unlock_key(&self) -> Result<Vec<u8>> {
        Ok(self.inner.unlock_key()?.to_vec())
    }

    /// Unlocks with a key from `unlock_key` without running the memory-hard
    /// key derivation (suitable for AutoFill extensions). Returns `true` when
    /// the server was reached.
    pub fn unlock_with_key(&self, key: Vec<u8>) -> Result<bool> {
        Ok(self.inner.unlock_with_key(&key)? == client::Connectivity::Online)
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

    /// Items in the trash, most recently trashed first.
    pub fn trashed_items(&self) -> Result<Vec<Item>> {
        Ok(self
            .inner
            .trashed_items()?
            .into_iter()
            .map(item_to_ffi)
            .collect())
    }

    /// Moves an item to the trash (restorable for 30 days).
    pub fn trash_item(&self, id: String) -> Result<()> {
        Ok(self.inner.trash_item(&id)?)
    }

    pub fn restore_item(&self, id: String) -> Result<()> {
        Ok(self.inner.restore_item(&id)?)
    }

    /// Deletes items trashed more than 30 days ago, or all trashed items
    /// when `all` is set. Call after unlocking. Returns the number deleted.
    pub fn purge_trash(&self, all: bool) -> Result<u32> {
        Ok(u32::try_from(self.inner.purge_trash(all)?).unwrap_or(u32::MAX))
    }

    /// Permanently deletes an item. Prefer `trash_item`.
    pub fn delete_item(&self, id: String) -> Result<()> {
        Ok(self.inner.delete_item(&id)?)
    }

    /// Rates a password with the account email as context.
    pub fn estimate_strength(&self, password: String) -> Result<Strength> {
        Ok(strength_to_ffi(
            &password,
            &self.inner.estimate_strength(&password)?,
        ))
    }

    pub fn create_vault(&self, name: String) -> Result<String> {
        Ok(self.inner.create_vault(&name)?)
    }

    pub fn rename_vault(&self, id: String, name: String) -> Result<()> {
        Ok(self.inner.rename_vault(&id, &name)?)
    }

    /// Devices signed in to the account, most recently used first.
    pub fn sessions(&self) -> Result<Vec<DeviceSession>> {
        Ok(self
            .inner
            .sessions()?
            .into_iter()
            .map(|s| DeviceSession {
                id: s.id,
                device_name: s.device_name,
                client_kind: s.client_kind,
                ip: s.ip,
                created_at: s.created_at,
                last_used_at: s.last_used_at,
                current: s.current,
            })
            .collect())
    }

    /// Signs out another device.
    pub fn revoke_session(&self, id: String) -> Result<()> {
        Ok(self.inner.revoke_session(&id)?)
    }

    /// Signs out every device except this one.
    pub fn revoke_other_sessions(&self) -> Result<()> {
        Ok(self.inner.revoke_other_sessions()?)
    }

    /// Recent account activity, newest first.
    pub fn activity(&self, limit: u32) -> Result<Vec<AccountEvent>> {
        Ok(self
            .inner
            .activity(limit)?
            .into_iter()
            .map(|e| AccountEvent {
                id: e.id,
                kind: e.kind,
                device_name: e.device_name,
                client_kind: e.client_kind,
                ip: e.ip,
                created_at: e.created_at,
            })
            .collect())
    }

    /// Changes the master password. Other devices are signed out. A stored
    /// biometric unlock key stops working; store a new `unlock_key` after
    /// this succeeds.
    pub fn change_master_password(
        &self,
        current_password: String,
        new_password: String,
    ) -> Result<()> {
        Ok(self
            .inner
            .change_master_password(&current_password, &new_password)?)
    }

    /// Vaults and items that could not be decrypted (tampered with, or
    /// written by a newer Passbox version), as technical descriptions. Show
    /// a notice instead of letting them disappear silently.
    pub fn decryption_errors(&self) -> Result<Vec<String>> {
        Ok(self.inner.errors()?)
    }

    /// The Secret Key, for showing the Emergency Kit again. Needs the
    /// unlocked vault and the current master password (checked locally);
    /// fails with `InvalidCredentials` otherwise.
    pub fn reveal_secret_key(&self, password: String) -> Result<String> {
        Ok(self.inner.reveal_secret_key(&password)?)
    }

    pub fn health(&self) -> Result<VaultHealth> {
        let h = self.inner.health()?;
        Ok(VaultHealth {
            weak: h.weak,
            reused: h.reused,
            insecure_urls: h.insecure_urls,
            without_totp: h.without_totp,
            secure: h.secure as u64,
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
    let totp = Totp::parse(&uri_or_secret)?;
    Ok(TotpCode {
        code: totp.generate(unix_time),
        seconds_remaining: totp.seconds_remaining(unix_time),
        period: totp.period,
    })
}

fn strength_to_ffi(password: &str, strength: &client::security::Strength) -> Strength {
    Strength {
        score: strength.score,
        label: strength.label().to_owned(),
        bits: strength.bits,
        warning: strength.warning.map(str::to_owned),
        suggestions: strength
            .suggestions
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        acceptable_master_password: passbox_core::strength::is_acceptable_master_password(
            password, strength,
        ),
    }
}

/// Rates a password. `user_inputs` are words an attacker would try first,
/// such as the email address and name.
#[uniffi::export]
pub fn estimate_strength(password: String, user_inputs: Vec<String>) -> Strength {
    let inputs: Vec<&str> = user_inputs.iter().map(String::as_str).collect();
    strength_to_ffi(
        &password,
        &client::security::estimate_strength(&password, &inputs),
    )
}

/// Generates a word passphrase (EFF word list), easy to type on phones.
#[uniffi::export]
pub fn generate_passphrase(
    words: u32,
    separator: String,
    capitalize: bool,
    include_digit: bool,
) -> Result<String> {
    Ok(generator::generate_passphrase(&PassphraseOptions {
        words: words as usize,
        separator,
        capitalize,
        include_digit,
    })?)
}

/// Checks a one-time password field before saving: `None` when valid or
/// empty, `one_time_code` when a single code was entered instead of the
/// setup key, `invalid` otherwise.
#[uniffi::export]
pub fn totp_input_problem(input: String) -> Option<String> {
    Totp::input_problem(&input).map(str::to_owned)
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
        assert_eq!(estimate_strength("password".into(), vec![]).score, 0);
        assert!(!estimate_strength("Sommer2024!".into(), vec![]).acceptable_master_password);
        assert_eq!(
            generate_passphrase(4, " ".into(), false, false)
                .unwrap()
                .split(' ')
                .count(),
            4
        );
        assert_eq!(
            totp_input_problem("123456".into()).as_deref(),
            Some("one_time_code")
        );
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
        assert!(matches!(
            client.decryption_errors(),
            Err(PassboxError::Locked)
        ));
        assert!(matches!(
            client.reveal_secret_key("password".into()),
            Err(PassboxError::NoAccount)
        ));
    }
}
