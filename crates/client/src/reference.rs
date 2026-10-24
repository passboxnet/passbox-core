//! Secret references: `pbx://<vault>/<item>/<field>` (and
//! `pbx://<vault>/<item>` for a whole item, for example an environment).
//!
//! Vaults are matched by ID or name (ignoring case), items by ID, exact
//! title (ignoring case) or a unique part of the title, fields by ID or
//! label. `notes` names the notes. TOTP fields resolve to the current code.

use passbox_core::totp::Totp;

use crate::model::{FieldType, Item, Vault};
use crate::{Error, Result};

pub const PREFIX: &str = "pbx://";

/// The parts of a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub vault: String,
    pub item: String,
    pub field: Option<String>,
}

fn invalid(message: &str) -> Error {
    Error::InvalidData(message.to_owned())
}

impl Reference {
    pub fn parse(reference: &str) -> Result<Self> {
        let path = reference
            .trim()
            .strip_prefix(PREFIX)
            .ok_or_else(|| invalid("secret references start with pbx://"))?;
        let parts: Vec<&str> = path.split('/').collect();
        match parts.as_slice() {
            [vault, item] if !vault.is_empty() && !item.is_empty() => Ok(Self {
                vault: (*vault).to_owned(),
                item: (*item).to_owned(),
                field: None,
            }),
            [vault, item, field] if !vault.is_empty() && !item.is_empty() && !field.is_empty() => {
                Ok(Self {
                    vault: (*vault).to_owned(),
                    item: (*item).to_owned(),
                    field: Some((*field).to_owned()),
                })
            }
            _ => Err(invalid(
                "secret references look like pbx://<vault>/<item>/<field>",
            )),
        }
    }
}

/// Finds a vault by ID or name.
pub fn find_vault<'a>(vaults: &'a [Vault], query: &str) -> Result<&'a Vault> {
    vaults
        .iter()
        .find(|v| v.id == query)
        .or_else(|| vaults.iter().find(|v| v.name.eq_ignore_ascii_case(query)))
        .ok_or_else(|| Error::NotFound(format!("no vault named {query:?}")))
}

/// Finds one item by ID, exact title, or unique title substring.
pub fn find_item<'a>(items: &'a [Item], query: &str) -> Result<&'a Item> {
    if let Some(item) = items.iter().find(|i| i.id == query) {
        return Ok(item);
    }
    let exact: Vec<&Item> = items
        .iter()
        .filter(|i| i.data.title.eq_ignore_ascii_case(query))
        .collect();
    let matches = if exact.is_empty() {
        let q = query.to_lowercase();
        items
            .iter()
            .filter(|i| i.data.title.to_lowercase().contains(&q))
            .collect()
    } else {
        exact
    };
    match matches.as_slice() {
        [item] => Ok(item),
        [] => Err(Error::NotFound(format!("no item matches {query:?}"))),
        many => Err(Error::InvalidData(format!(
            "{} items match {query:?}; use the ID: {}",
            many.len(),
            many.iter()
                .map(|i| format!("{} ({})", i.data.title, i.id))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// A field's value; TOTP fields return the code for `now` (Unix seconds).
pub fn field_value(item: &Item, field: &str, now: u64) -> Result<String> {
    let found = item
        .data
        .fields
        .iter()
        .find(|f| f.id == field || f.label.eq_ignore_ascii_case(field));
    let value = match (field, found) {
        ("notes", None) => return Ok(item.data.notes.clone()),
        (_, Some(f)) if !f.value.is_empty() => f,
        _ => {
            return Err(Error::NotFound(format!(
                "{:?} has no field {field:?}",
                item.data.title
            )));
        }
    };
    if value.field_type == FieldType::Totp {
        let totp = Totp::parse(&value.value)?;
        return Ok(totp.generate(now));
    }
    Ok(value.value.clone())
}

/// Resolves a reference to its item (and vault).
pub fn resolve_item<'a>(
    vaults: &[Vault],
    items: &'a [Item],
    reference: &Reference,
) -> Result<&'a Item> {
    let vault = find_vault(vaults, &reference.vault)?;
    let in_vault: Vec<&Item> = items.iter().filter(|i| i.vault_id == vault.id).collect();
    let owned: Vec<Item> = in_vault.iter().map(|i| (*i).clone()).collect();
    let found = find_item(&owned, &reference.item)?;
    Ok(in_vault
        .into_iter()
        .find(|i| i.id == found.id)
        .expect("found among the vault's items"))
}

/// Resolves a field reference to its value.
pub fn resolve(vaults: &[Vault], items: &[Item], reference: &str, now: u64) -> Result<String> {
    let parsed = Reference::parse(reference)?;
    let field = parsed
        .field
        .clone()
        .ok_or_else(|| invalid("the reference names no field: pbx://<vault>/<item>/<field>"))?;
    field_value(resolve_item(vaults, items, &parsed)?, &field, now)
}

/// A stable reference for display: names where they are unambiguous and
/// contain no `/`, IDs otherwise.
pub fn reference_for(vault: &Vault, items: &[Item], item: &Item, field: Option<&str>) -> String {
    let vault_part = if vault.name.contains('/') {
        vault.id.clone()
    } else {
        vault.name.clone()
    };
    let unique = items
        .iter()
        .filter(|i| i.vault_id == item.vault_id && i.data.title.eq_ignore_ascii_case(&item.data.title))
        .count()
        == 1;
    let item_part = if unique && !item.data.title.contains('/') && !item.data.title.is_empty() {
        item.data.title.clone()
    } else {
        item.id.clone()
    };
    match field {
        Some(field) => format!("{PREFIX}{vault_part}/{item_part}/{field}"),
        None => format!("{PREFIX}{vault_part}/{item_part}"),
    }
}

/// `{{ pbx://… }}` references in a template, in order of appearance.
pub fn template_references(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let inner = after[..end].trim();
        if inner.starts_with(PREFIX) {
            out.push(inner.to_owned());
        }
        rest = &after[end + 2..];
    }
    out
}

/// Replaces every `{{ pbx://… }}` in `template` with `lookup(reference)`.
/// Other `{{ … }}` sequences are kept as they are.
pub fn render_template(
    template: &str,
    mut lookup: impl FnMut(&str) -> Result<String>,
) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let inner = after[..end].trim();
        if inner.starts_with(PREFIX) {
            out.push_str(&lookup(inner)?);
        } else {
            out.push_str(&rest[start..start + 2 + end + 2]);
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ItemCategory, ItemData};

    fn fixture() -> (Vec<Vault>, Vec<Item>) {
        let vault = Vault {
            id: "v1".into(),
            name: "Work".into(),
            revision: 1,
            org_id: None,
            key_epoch: 0,
        };
        let mut data = ItemData::new(ItemCategory::Login, "GitHub");
        data.set_field("password", "Password", FieldType::Concealed, "hunter2");
        let item = Item {
            id: "i1".into(),
            vault_id: "v1".into(),
            revision: 1,
            updated_at: 0,
            key_epoch: 0,
            data,
        };
        (vec![vault], vec![item])
    }

    #[test]
    fn resolves_references() {
        let (vaults, items) = fixture();
        assert_eq!(
            resolve(&vaults, &items, "pbx://work/github/password", 0).unwrap(),
            "hunter2"
        );
        assert_eq!(
            resolve(&vaults, &items, "pbx://v1/i1/Password", 0).unwrap(),
            "hunter2"
        );
        assert!(resolve(&vaults, &items, "pbx://Work/GitHub", 0).is_err());
        assert!(resolve(&vaults, &items, "pbx://Other/GitHub/password", 0).is_err());
        assert!(resolve(&vaults, &items, "pbx://Work/GitHub/username", 0).is_err());
        assert!(Reference::parse("https://x").is_err());
        assert!(Reference::parse("pbx://a//c").is_err());
        assert_eq!(
            reference_for(&vaults[0], &items, &items[0], Some("password")),
            "pbx://Work/GitHub/password"
        );
    }

    #[test]
    fn renders_templates() {
        let template = "user=admin\npass={{ pbx://Work/GitHub/password }}\nkeep={{ other }}\n{{pbx://x/y/z}}";
        assert_eq!(
            template_references(template),
            ["pbx://Work/GitHub/password", "pbx://x/y/z"]
        );
        let out = render_template(template, |r| Ok(format!("<{r}>"))).unwrap();
        assert_eq!(
            out,
            "user=admin\npass=<pbx://Work/GitHub/password>\nkeep={{ other }}\n<pbx://x/y/z>"
        );
        assert_eq!(render_template("a {{ b", |_| Ok(String::new())).unwrap(), "a {{ b");
    }
}
