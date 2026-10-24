//! Data model shared with the TypeScript clients (`packages/client/src/items.ts`).
//! Unknown JSON fields are preserved, so newer clients' data (for example
//! passkeys) survives edits made by older clients.

use passbox_core::kdf::KdfParams;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// What this device remembers about the signed-in account. The Secret Key
/// is stored on trusted devices so users type it once per device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAccount {
    pub server_url: String,
    pub email: String,
    pub account_id: String,
    pub secret_key: String,
    pub kdf_salt: String,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ItemCategory {
    #[default]
    Login,
    Note,
    Card,
    Identity,
    /// Key/value sets for applications (`.env`), one field per variable.
    Environment,
    /// A file (scan, contract, certificate) with notes; see `attachments`.
    Document,
    BankAccount,
    IdCard,
    Passport,
    DriverLicense,
    SoftwareLicense,
    Wifi,
    Server,
    Database,
    ApiCredential,
    CryptoWallet,
    SshKey,
    /// Also used for categories this version does not know; the original
    /// name is kept (see [`ItemData::category_name`]).
    #[serde(other)]
    Other,
}

impl ItemCategory {
    /// Every category, in menu order.
    pub const ALL: [ItemCategory; 18] = [
        Self::Login,
        Self::Note,
        Self::Card,
        Self::Identity,
        Self::Document,
        Self::BankAccount,
        Self::IdCard,
        Self::Passport,
        Self::DriverLicense,
        Self::SoftwareLicense,
        Self::Wifi,
        Self::Server,
        Self::Database,
        Self::ApiCredential,
        Self::CryptoWallet,
        Self::SshKey,
        Self::Environment,
        Self::Other,
    ];

    /// The stored name (`login`, `bankAccount`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Note => "note",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::Environment => "environment",
            Self::Document => "document",
            Self::BankAccount => "bankAccount",
            Self::IdCard => "idCard",
            Self::Passport => "passport",
            Self::DriverLicense => "driverLicense",
            Self::SoftwareLicense => "softwareLicense",
            Self::Wifi => "wifi",
            Self::Server => "server",
            Self::Database => "database",
            Self::ApiCredential => "apiCredential",
            Self::CryptoWallet => "cryptoWallet",
            Self::SshKey => "sshKey",
            Self::Other => "other",
        }
    }

    /// The category with this stored name; `Other` for unknown names.
    pub fn parse(name: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == name)
            .unwrap_or(Self::Other)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// Also used for types this version does not know.
    #[default]
    Text,
    Concealed,
    Url,
    Email,
    Totp,
}

/// Reads a field type; types this version does not know become `Text`
/// (newer clients add display formats in `format` instead).
fn lenient_field_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<FieldType, D::Error> {
    let name = String::deserialize(d)?;
    Ok(serde_json::from_value(Value::String(name)).unwrap_or_default())
}

/// Display formats of a field (`format` in the JSON). The value is always a
/// string; older clients ignore the format and show the field as text, so
/// no data is lost.
pub mod format {
    /// `YYYY-MM-DD`.
    pub const DATE: &str = "date";
    /// `MM/YYYY` (expiry dates).
    pub const MONTH_YEAR: &str = "monthYear";
    /// A phone number.
    pub const PHONE: &str = "phone";
    /// Text with line breaks (also combined with `concealed`, for keys).
    pub const MULTILINE: &str = "multiline";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemField {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default, rename = "type", deserialize_with = "lenient_field_type")]
    pub field_type: FieldType,
    pub value: String,
    /// How to show and edit the value (see [`format`]); `None` for plain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Well-known field IDs. Clients show these fields with labels in the
/// user's language; the stored label is English.
pub mod field {
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const URL: &str = "url";
    pub const TOTP: &str = "totp";
    pub const CARDHOLDER: &str = "cardholder";
    pub const CARD_NUMBER: &str = "card_number";
    pub const CARD_EXPIRY: &str = "card_expiry";
    pub const CARD_CODE: &str = "card_code";
    pub const FIRST_NAME: &str = "first_name";
    pub const LAST_NAME: &str = "last_name";
    pub const FULL_NAME: &str = "full_name";
    pub const BIRTH_DATE: &str = "birth_date";
    pub const EMAIL: &str = "email";
    pub const PHONE: &str = "phone";
    pub const ADDRESS: &str = "address";
    pub const BANK_NAME: &str = "bank_name";
    pub const ACCOUNT_HOLDER: &str = "account_holder";
    pub const IBAN: &str = "iban";
    pub const BIC: &str = "bic";
    pub const ACCOUNT_NUMBER: &str = "account_number";
    pub const PIN: &str = "pin";
    pub const DOCUMENT_NUMBER: &str = "document_number";
    pub const NATIONALITY: &str = "nationality";
    pub const ISSUE_DATE: &str = "issue_date";
    pub const EXPIRY_DATE: &str = "expiry_date";
    pub const AUTHORITY: &str = "authority";
    pub const LICENSE_CLASSES: &str = "license_classes";
    pub const LICENSE_KEY: &str = "license_key";
    pub const LICENSED_TO: &str = "licensed_to";
    pub const VERSION: &str = "version";
    pub const PURCHASE_DATE: &str = "purchase_date";
    pub const WIFI_SSID: &str = "wifi_ssid";
    pub const WIFI_SECURITY: &str = "wifi_security";
    pub const HOST: &str = "host";
    pub const PORT: &str = "port";
    pub const DATABASE_TYPE: &str = "database_type";
    pub const DATABASE_NAME: &str = "database_name";
    pub const API_KEY: &str = "api_key";
    pub const API_SECRET: &str = "api_secret";
    pub const WALLET_ADDRESS: &str = "wallet_address";
    pub const RECOVERY_PHRASE: &str = "recovery_phrase";
    pub const NETWORK: &str = "network";
    pub const PRIVATE_KEY: &str = "private_key";
    pub const PUBLIC_KEY: &str = "public_key";
    pub const FINGERPRINT: &str = "fingerprint";
    pub const PASSPHRASE: &str = "passphrase";
}

/// The default fields of a category. The TypeScript client has the same
/// templates (`packages/client/src/templates.ts`).
pub fn template(category: ItemCategory) -> Vec<ItemField> {
    use field::*;
    use format::*;
    let f = |id: &str, label: &str, field_type, format: Option<&str>| ItemField {
        id: id.to_owned(),
        label: label.to_owned(),
        field_type,
        value: String::new(),
        format: format.map(str::to_owned),
    };
    let text = |id, label| f(id, label, FieldType::Text, None);
    let secret = |id, label| f(id, label, FieldType::Concealed, None);
    let date = |id, label| f(id, label, FieldType::Text, Some(DATE));
    match category {
        ItemCategory::Login => vec![
            text(USERNAME, "Username"),
            secret(PASSWORD, "Password"),
            f(URL, "Website", FieldType::Url, None),
            f(TOTP, "One-time password", FieldType::Totp, None),
        ],
        ItemCategory::Card => vec![
            text(CARDHOLDER, "Cardholder"),
            secret(CARD_NUMBER, "Number"),
            text(CARD_EXPIRY, "Expiry date"),
            secret(CARD_CODE, "Security code"),
        ],
        ItemCategory::Identity => vec![
            text(FIRST_NAME, "First name"),
            text(LAST_NAME, "Last name"),
            date(BIRTH_DATE, "Date of birth"),
            f(EMAIL, "Email", FieldType::Email, None),
            f(field::PHONE, "Phone", FieldType::Text, Some(format::PHONE)),
            f(ADDRESS, "Address", FieldType::Text, Some(MULTILINE)),
        ],
        ItemCategory::BankAccount => vec![
            text(BANK_NAME, "Bank"),
            text(ACCOUNT_HOLDER, "Account holder"),
            text(IBAN, "IBAN"),
            text(BIC, "BIC"),
            text(ACCOUNT_NUMBER, "Account number"),
            secret(PIN, "PIN"),
        ],
        ItemCategory::IdCard | ItemCategory::Passport => vec![
            text(FULL_NAME, "Full name"),
            text(DOCUMENT_NUMBER, "Number"),
            text(NATIONALITY, "Nationality"),
            date(BIRTH_DATE, "Date of birth"),
            date(ISSUE_DATE, "Issued on"),
            date(EXPIRY_DATE, "Expires on"),
            text(AUTHORITY, "Issuing authority"),
        ],
        ItemCategory::DriverLicense => vec![
            text(FULL_NAME, "Full name"),
            text(DOCUMENT_NUMBER, "Number"),
            text(LICENSE_CLASSES, "Classes"),
            date(BIRTH_DATE, "Date of birth"),
            date(ISSUE_DATE, "Issued on"),
            date(EXPIRY_DATE, "Expires on"),
            text(AUTHORITY, "Issuing authority"),
        ],
        ItemCategory::SoftwareLicense => vec![
            secret(LICENSE_KEY, "License key"),
            text(LICENSED_TO, "Licensed to"),
            f(EMAIL, "Email", FieldType::Email, None),
            text(VERSION, "Version"),
            date(PURCHASE_DATE, "Purchased on"),
            f(URL, "Website", FieldType::Url, None),
        ],
        ItemCategory::Wifi => vec![
            text(WIFI_SSID, "Network name"),
            secret(PASSWORD, "Password"),
            text(WIFI_SECURITY, "Security"),
        ],
        ItemCategory::Server => vec![
            f(URL, "Address", FieldType::Url, None),
            text(PORT, "Port"),
            text(USERNAME, "Username"),
            secret(PASSWORD, "Password"),
        ],
        ItemCategory::Database => vec![
            text(DATABASE_TYPE, "Type"),
            text(HOST, "Server"),
            text(PORT, "Port"),
            text(DATABASE_NAME, "Database"),
            text(USERNAME, "Username"),
            secret(PASSWORD, "Password"),
        ],
        ItemCategory::ApiCredential => vec![
            text(USERNAME, "Username"),
            secret(API_KEY, "API key"),
            secret(API_SECRET, "Secret"),
            f(URL, "Endpoint", FieldType::Url, None),
            date(EXPIRY_DATE, "Expires on"),
        ],
        ItemCategory::CryptoWallet => vec![
            text(WALLET_ADDRESS, "Wallet address"),
            f(
                RECOVERY_PHRASE,
                "Recovery phrase",
                FieldType::Concealed,
                Some(MULTILINE),
            ),
            secret(PASSWORD, "Password"),
            text(NETWORK, "Network"),
        ],
        ItemCategory::SshKey => vec![
            f(
                PRIVATE_KEY,
                "Private key",
                FieldType::Concealed,
                Some(MULTILINE),
            ),
            f(PUBLIC_KEY, "Public key", FieldType::Text, Some(MULTILINE)),
            text(FINGERPRINT, "Fingerprint"),
            secret(PASSPHRASE, "Passphrase"),
        ],
        ItemCategory::Note
        | ItemCategory::Environment
        | ItemCategory::Document
        | ItemCategory::Other => Vec::new(),
    }
}

/// The text of a Wi-Fi QR code (`WIFI:T:WPA;S:name;P:password;;`), which
/// phone cameras offer to join. `None` without a network name.
pub fn wifi_qr_payload(data: &ItemData) -> Option<String> {
    let ssid = data.field(field::WIFI_SSID)?;
    let escape = |value: &str| {
        value.chars().fold(String::new(), |mut out, c| {
            if matches!(c, '\\' | ';' | ',' | ':' | '"') {
                out.push('\\');
            }
            out.push(c);
            out
        })
    };
    let password = data.field(field::PASSWORD).unwrap_or("");
    let security = data
        .field(field::WIFI_SECURITY)
        .unwrap_or("")
        .to_ascii_uppercase();
    let kind = if password.is_empty() || security.contains("NONE") || security.contains("OPEN") {
        "nopass"
    } else if security.contains("WEP") {
        "WEP"
    } else {
        "WPA"
    };
    let mut out = format!("WIFI:T:{kind};S:{};", escape(ssid));
    if kind != "nopass" {
        out.push_str(&format!("P:{};", escape(password)));
    }
    out.push(';');
    Some(out)
}

const TRASHED_AT: &str = "trashedAt";
const ARCHIVED_AT: &str = "archivedAt";
const PASSWORD_HISTORY: &str = "passwordHistory";
const ATTACHMENTS: &str = "attachments";
/// Where the name of a category this version does not know waits in
/// `extra` while the item is in memory (it is written back as `category`).
const CATEGORY: &str = "category";

/// Items stay in the trash this long before clients delete them.
pub const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Number of earlier passwords kept per item.
pub const PASSWORD_HISTORY_LEN: usize = 20;

/// A password the item had before, and when it was replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntry {
    pub value: String,
    /// Unix milliseconds.
    pub replaced_at: i64,
}

/// A file attached to an item (G2). The metadata and the file key live in
/// the encrypted item; the server stores only the encrypted blob under
/// `id` (see `passbox_core::file_crypto`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub id: String,
    pub name: String,
    /// Media type, for example `application/pdf`.
    #[serde(default, rename = "type")]
    pub media_type: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// Base64url file key.
    pub key: String,
    /// Unix milliseconds.
    #[serde(default)]
    pub created_at: i64,
}

/// Plaintext item, version 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "RawItemData", into = "RawItemData")]
pub struct ItemData {
    pub v: u32,
    pub category: ItemCategory,
    pub title: String,
    pub fields: Vec<ItemField>,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    /// Fields this client does not know, kept as they are. For a category
    /// this version does not know, `category` holds its name here (and
    /// `ItemData::category` is `Other`); it is written back unchanged.
    pub extra: Map<String, Value>,
}

/// The JSON shape of [`ItemData`].
#[derive(Serialize, Deserialize)]
struct RawItemData {
    v: u32,
    #[serde(default = "default_category")]
    category: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    fields: Vec<ItemField>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

fn default_category() -> String {
    "login".into()
}

impl From<RawItemData> for ItemData {
    fn from(raw: RawItemData) -> Self {
        let mut data = Self {
            v: raw.v,
            category: ItemCategory::Other,
            title: raw.title,
            fields: raw.fields,
            notes: raw.notes,
            tags: raw.tags,
            favorite: raw.favorite,
            extra: raw.extra,
        };
        data.set_category_name(&raw.category);
        data
    }
}

impl From<ItemData> for RawItemData {
    fn from(data: ItemData) -> Self {
        let category = data.category_name().to_owned();
        let mut extra = data.extra;
        extra.remove(CATEGORY);
        Self {
            v: data.v,
            category,
            title: data.title,
            fields: data.fields,
            notes: data.notes,
            tags: data.tags,
            favorite: data.favorite,
            extra,
        }
    }
}

impl ItemData {
    /// A new item with the default fields of its category (see [`template`]).
    pub fn new(category: ItemCategory, title: impl Into<String>) -> Self {
        Self {
            v: 1,
            category,
            title: title.into(),
            fields: template(category),
            notes: String::new(),
            tags: Vec::new(),
            favorite: false,
            extra: Map::new(),
        }
    }

    /// The stored name of the category, also for categories this version
    /// does not know (those are `Other` in [`ItemData::category`]).
    pub fn category_name(&self) -> &str {
        match (self.category, self.extra.get(CATEGORY)) {
            (ItemCategory::Other, Some(Value::String(name))) if !name.is_empty() => name,
            (category, _) => category.as_str(),
        }
    }

    /// Sets the category from its stored name; unknown names are kept.
    pub fn set_category_name(&mut self, name: &str) {
        self.category = ItemCategory::parse(name);
        if self.category == ItemCategory::Other && !name.is_empty() && name != "other" {
            self.extra
                .insert(CATEGORY.into(), Value::String(name.to_owned()));
        } else {
            self.extra.remove(CATEGORY);
        }
    }

    /// The non-empty value of a field.
    pub fn field(&self, id: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.value.as_str())
            .filter(|v| !v.is_empty())
    }

    /// Sets a field's value, adding the field if it does not exist.
    pub fn set_field(
        &mut self,
        id: &str,
        label: &str,
        field_type: FieldType,
        value: impl Into<String>,
    ) {
        let value = value.into();
        match self.fields.iter_mut().find(|f| f.id == id) {
            Some(existing) => existing.value = value,
            None => self.fields.push(ItemField {
                id: id.to_owned(),
                label: label.to_owned(),
                field_type,
                value,
                format: None,
            }),
        }
    }

    /// When the item was moved to the trash (Unix milliseconds), if it is
    /// there. Stored as `trashedAt` inside the encrypted item.
    pub fn trashed_at(&self) -> Option<i64> {
        self.extra.get(TRASHED_AT).and_then(Value::as_i64)
    }

    pub fn set_trashed_at(&mut self, at: Option<i64>) {
        match at {
            Some(at) => {
                self.extra.insert(TRASHED_AT.into(), Value::from(at));
            }
            None => {
                self.extra.remove(TRASHED_AT);
            }
        }
    }

    /// When the item was archived (Unix milliseconds), if it is. Archived
    /// items are hidden from lists, search and autofill but not deleted.
    /// Stored as `archivedAt` inside the encrypted item; older clients keep
    /// it and show the item as usual.
    pub fn archived_at(&self) -> Option<i64> {
        self.extra.get(ARCHIVED_AT).and_then(Value::as_i64)
    }

    pub fn set_archived_at(&mut self, at: Option<i64>) {
        match at {
            Some(at) => {
                self.extra.insert(ARCHIVED_AT.into(), Value::from(at));
            }
            None => {
                self.extra.remove(ARCHIVED_AT);
            }
        }
    }

    /// Files attached to the item. Stored as `attachments`.
    pub fn attachments(&self) -> Vec<Attachment> {
        self.extra
            .get(ATTACHMENTS)
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn set_attachments(&mut self, attachments: &[Attachment]) {
        if attachments.is_empty() {
            self.extra.remove(ATTACHMENTS);
        } else if let Ok(value) = serde_json::to_value(attachments) {
            self.extra.insert(ATTACHMENTS.into(), value);
        }
    }

    /// Earlier passwords, newest first. Stored as `passwordHistory`.
    pub fn password_history(&self) -> Vec<PasswordHistoryEntry> {
        self.extra
            .get(PASSWORD_HISTORY)
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }

    pub fn set_password_history(&mut self, history: &[PasswordHistoryEntry]) {
        if history.is_empty() {
            self.extra.remove(PASSWORD_HISTORY);
        } else if let Ok(value) = serde_json::to_value(history) {
            self.extra.insert(PASSWORD_HISTORY.into(), value);
        }
    }

    /// The variables of an environment item: fields whose label is a valid
    /// variable name, in order. Later fields win over earlier ones with the
    /// same name.
    pub fn environment_variables(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for field in &self.fields {
            let name = field.label.trim();
            if !is_env_name(name) {
                continue;
            }
            out.retain(|(n, _)| n != name);
            out.push((name.to_owned(), field.value.clone()));
        }
        out
    }

    pub fn from_json(json: &str) -> crate::Result<Self> {
        let data: Self = serde_json::from_str(json)?;
        if data.v != 1 {
            return Err(crate::Error::InvalidData(format!(
                "unsupported item version {}",
                data.v
            )));
        }
        Ok(data)
    }
}

/// Whether `name` can be an environment variable: letters, digits and
/// underscores, not starting with a digit.
pub fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name.len() <= 256
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub id: String,
    pub name: String,
    pub revision: u64,
    /// The organization a shared vault belongs to; `None` for personal vaults.
    pub org_id: Option<String>,
    /// Current key epoch (0 for personal vaults).
    pub key_epoch: u32,
    /// Icon chosen for the vault (`home`, `family`, `briefcase`, …), from the
    /// encrypted metadata; `None` when not set.
    pub icon: Option<String>,
    /// Color chosen for the vault (`blue`, `green`, …); `None` when not set.
    pub color: Option<String>,
    /// The decrypted metadata as received, so that changes keep keys this
    /// version does not know.
    pub meta: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub id: String,
    pub vault_id: String,
    pub revision: u64,
    pub updated_at: i64,
    /// When the item was created (Unix ms); 0 if the server did not say.
    pub created_at: i64,
    /// The vault key epoch the item is encrypted with.
    pub key_epoch: u32,
    pub data: ItemData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_unknown_fields() {
        let json = r#"{"v":1,"category":"login","title":"GitHub","fields":[],"notes":"","tags":[],"favorite":false,"passkeys":[{"rpId":"github.com"}]}"#;
        let data = ItemData::from_json(json).unwrap();
        let back: Value = serde_json::to_value(&data).unwrap();
        assert_eq!(back["passkeys"][0]["rpId"], "github.com");
    }

    #[test]
    fn reads_typescript_items() {
        let json = r#"{"v":1,"category":"card","title":"Visa","fields":[{"id":"card_number","label":"Number","type":"concealed","value":"4111"}],"notes":"","tags":["finance"],"favorite":true}"#;
        let data = ItemData::from_json(json).unwrap();
        assert_eq!(data.category, ItemCategory::Card);
        assert_eq!(data.field(field::CARD_NUMBER), Some("4111"));
        assert!(data.favorite);
    }

    #[test]
    fn environments_and_unknown_categories() {
        let json = r#"{"v":1,"category":"environment","title":"API","fields":[
            {"id":"a","label":"API_KEY","type":"concealed","value":"k1"},
            {"id":"b","label":"not valid","type":"text","value":"x"},
            {"id":"c","label":"API_KEY","type":"concealed","value":"k2"},
            {"id":"d","label":"PORT","type":"text","value":"8080"}]}"#;
        let data = ItemData::from_json(json).unwrap();
        assert_eq!(data.category, ItemCategory::Environment);
        assert_eq!(
            data.environment_variables(),
            [
                ("API_KEY".into(), "k2".into()),
                ("PORT".into(), "8080".into())
            ]
        );
        let future =
            ItemData::from_json(r#"{"v":1,"category":"spaceship","title":"Home"}"#).unwrap();
        assert_eq!(future.category, ItemCategory::Other);
        assert!(is_env_name("_A1") && !is_env_name("1A") && !is_env_name("A-B"));
    }

    #[test]
    fn rejects_unknown_versions() {
        assert!(ItemData::from_json(r#"{"v":2}"#).is_err());
    }

    #[test]
    fn templates_and_set_field() {
        let mut item = ItemData::new(ItemCategory::Login, "Mail");
        assert_eq!(item.fields.len(), 4);
        item.set_field(field::PASSWORD, "Password", FieldType::Concealed, "pw");
        item.set_field("pin", "PIN", FieldType::Concealed, "1234");
        assert_eq!(item.field(field::PASSWORD), Some("pw"));
        assert_eq!(item.field("pin"), Some("1234"));
        assert_eq!(item.field(field::USERNAME), None);
    }

    #[test]
    fn trash_and_history_live_in_the_item() {
        let mut item = ItemData::new(ItemCategory::Login, "Mail");
        assert_eq!(item.trashed_at(), None);
        item.set_trashed_at(Some(1_700_000_000_000));
        item.set_password_history(&[PasswordHistoryEntry {
            value: "old".into(),
            replaced_at: 1,
        }]);
        let json: Value = serde_json::to_value(&item).unwrap();
        assert_eq!(json["trashedAt"], 1_700_000_000_000_i64);
        assert_eq!(json["passwordHistory"][0]["replacedAt"], 1);
        let back = ItemData::from_json(&json.to_string()).unwrap();
        assert_eq!(back.trashed_at(), Some(1_700_000_000_000));
        assert_eq!(back.password_history()[0].value, "old");
        let mut back = back;
        back.set_trashed_at(None);
        back.set_password_history(&[]);
        assert!(back.extra.is_empty());
    }

    #[test]
    fn unknown_categories_and_formats_survive_a_round_trip() {
        let json = r#"{"v":1,"category":"spaceship","title":"Enterprise","fields":[
            {"id":"a","label":"Launch","type":"text","value":"2026-01-01","format":"date"},
            {"id":"b","label":"Hull","type":"hologram","value":"x","format":"future"}]}"#;
        let data = ItemData::from_json(json).unwrap();
        assert_eq!(data.category, ItemCategory::Other);
        assert_eq!(data.category_name(), "spaceship");
        assert_eq!(data.fields[0].format.as_deref(), Some(format::DATE));
        assert_eq!(data.fields[1].field_type, FieldType::Text);
        let back: Value = serde_json::to_value(&data).unwrap();
        assert_eq!(back["category"], "spaceship");
        assert_eq!(back["fields"][0]["format"], "date");
        assert_eq!(back["fields"][1]["format"], "future");
        // Plain fields stay without a format key (old items are unchanged).
        let plain = serde_json::to_value(ItemData::new(ItemCategory::Login, "x")).unwrap();
        assert!(plain["fields"][0].get("format").is_none());

        let mut data = data;
        data.set_category_name("wifi");
        assert_eq!(data.category, ItemCategory::Wifi);
        assert!(!data.extra.contains_key("category"));
        let back: Value = serde_json::to_value(&data).unwrap();
        assert_eq!(back["category"], "wifi");
    }

    #[test]
    fn new_categories_use_camel_case_names() {
        for category in ItemCategory::ALL {
            let json = serde_json::to_value(ItemData::new(category, "x")).unwrap();
            assert_eq!(json["category"], category.as_str());
            assert_eq!(ItemCategory::parse(category.as_str()), category);
            let back = ItemData::from_json(&json.to_string()).unwrap();
            assert_eq!(back.category, category);
            assert!(back.extra.is_empty(), "{category:?}");
        }
        assert_eq!(ItemCategory::BankAccount.as_str(), "bankAccount");
        assert_eq!(
            serde_json::to_value(ItemCategory::SshKey).unwrap(),
            "sshKey"
        );
        let ssh = ItemData::new(ItemCategory::SshKey, "Deploy");
        assert_eq!(ssh.fields[0].id, field::PRIVATE_KEY);
        assert_eq!(ssh.fields[0].field_type, FieldType::Concealed);
        assert_eq!(ssh.fields[0].format.as_deref(), Some(format::MULTILINE));
    }

    #[test]
    fn archive_and_attachments_live_in_the_item() {
        let mut item = ItemData::new(ItemCategory::Document, "Passport scan");
        assert!(item.fields.is_empty());
        item.set_archived_at(Some(5));
        item.set_attachments(&[Attachment {
            id: "f1".into(),
            name: "scan.pdf".into(),
            media_type: "application/pdf".into(),
            size: 12,
            key: "k".into(),
            created_at: 3,
        }]);
        let json: Value = serde_json::to_value(&item).unwrap();
        assert_eq!(json["archivedAt"], 5);
        assert_eq!(json["attachments"][0]["type"], "application/pdf");
        let back = ItemData::from_json(&json.to_string()).unwrap();
        assert_eq!(back.archived_at(), Some(5));
        assert_eq!(back.attachments()[0].name, "scan.pdf");
        let mut back = back;
        back.set_archived_at(None);
        back.set_attachments(&[]);
        assert!(back.extra.is_empty());
    }

    #[test]
    fn wifi_qr_codes() {
        let mut wifi = ItemData::new(ItemCategory::Wifi, "Home");
        assert_eq!(wifi_qr_payload(&wifi), None);
        wifi.set_field(field::WIFI_SSID, "", FieldType::Text, "My;Net");
        wifi.set_field(field::PASSWORD, "", FieldType::Concealed, r#"p:a"ss\"#);
        assert_eq!(
            wifi_qr_payload(&wifi).unwrap(),
            r#"WIFI:T:WPA;S:My\;Net;P:p\:a\"ss\\;;"#
        );
        wifi.set_field(field::WIFI_SECURITY, "", FieldType::Text, "wep");
        assert!(wifi_qr_payload(&wifi).unwrap().starts_with("WIFI:T:WEP;"));
        wifi.set_field(field::PASSWORD, "", FieldType::Concealed, "");
        assert_eq!(
            wifi_qr_payload(&wifi).unwrap(),
            r#"WIFI:T:nopass;S:My\;Net;;"#
        );
    }
}
