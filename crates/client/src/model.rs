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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub id: String,
    pub name: String,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub id: String,
    pub vault_id: String,
    pub revision: u64,
    pub updated_at: i64,
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
}
