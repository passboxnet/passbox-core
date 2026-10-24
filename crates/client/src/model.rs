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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ItemCategory {
    #[default]
    Login,
    Note,
    Card,
    Identity,
    /// Key/value sets for applications (`.env`), one field per variable.
    Environment,
    /// Also used for categories this version does not know.
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    #[default]
    Text,
    Concealed,
    Url,
    Email,
    Totp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemField {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default, rename = "type")]
    pub field_type: FieldType,
    pub value: String,
}

/// Well-known field IDs.
pub mod field {
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const URL: &str = "url";
    pub const TOTP: &str = "totp";
    pub const CARDHOLDER: &str = "cardholder";
    pub const CARD_NUMBER: &str = "card_number";
    pub const CARD_EXPIRY: &str = "card_expiry";
    pub const CARD_CODE: &str = "card_code";
}

const TRASHED_AT: &str = "trashedAt";
const PASSWORD_HISTORY: &str = "passwordHistory";

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

/// Plaintext item, version 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemData {
    pub v: u32,
    #[serde(default)]
    pub category: ItemCategory,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub fields: Vec<ItemField>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Fields this client does not know, kept as they are.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ItemData {
    /// A new item with the default fields of its category.
    pub fn new(category: ItemCategory, title: impl Into<String>) -> Self {
        let field = |id: &str, label: &str, field_type| ItemField {
            id: id.to_owned(),
            label: label.to_owned(),
            field_type,
            value: String::new(),
        };
        let fields = match category {
            ItemCategory::Login => vec![
                field(field::USERNAME, "Username", FieldType::Text),
                field(field::PASSWORD, "Password", FieldType::Concealed),
                field(field::URL, "Website", FieldType::Url),
                field(field::TOTP, "One-time password", FieldType::Totp),
            ],
            ItemCategory::Card => vec![
                field(field::CARDHOLDER, "Cardholder", FieldType::Text),
                field(field::CARD_NUMBER, "Number", FieldType::Concealed),
                field(field::CARD_EXPIRY, "Expiry date", FieldType::Text),
                field(field::CARD_CODE, "Security code", FieldType::Concealed),
            ],
            _ => Vec::new(),
        };
        Self {
            v: 1,
            category,
            title: title.into(),
            fields,
            notes: String::new(),
            tags: Vec::new(),
            favorite: false,
            extra: Map::new(),
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub id: String,
    pub vault_id: String,
    pub revision: u64,
    pub updated_at: i64,
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
        let future = ItemData::from_json(r#"{"v":1,"category":"wifi","title":"Home"}"#).unwrap();
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
}
