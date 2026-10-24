//! Client for service accounts (F2): reads and writes the vaults a service
//! account was granted, with a token instead of a master password.
//!
//! The token's secret stays on this machine: the server receives a derived
//! authentication key, and the private key is decrypted locally
//! (`passbox_core::service_account`). Vault keys are accepted only with a
//! grant signed by the service account's owner.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use passbox_core::agent_grant::Decision;
use passbox_core::service_account::{Permission, ServiceAccountKeyring, Token};
use passbox_core::id;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::api::{Api, HttpTransport, Transport};
use crate::model::{Item, ItemData, Vault};
use crate::{Error, Result};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateGrant {
    vault_id: String,
    key_epoch: u32,
    sealed_key: String,
    grant: String,
    grant_signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateVault {
    id: String,
    encrypted_meta: String,
    key_epoch: u32,
    revision: u64,
    permission: String,
    #[serde(default)]
    org_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateItem {
    id: String,
    vault_id: String,
    revision: u64,
    encrypted_data: String,
    key_epoch: u32,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateResponse {
    id: String,
    name: String,
    expires_at: i64,
    public_key: String,
    encrypted_private: String,
    grants: Vec<StateGrant>,
    vaults: Vec<StateVault>,
    items: Vec<StateItem>,
}

/// A vault as the service account sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceVault {
    pub vault: Vault,
    /// What the service account may do: the lower of its grant and its
    /// owner's current access.
    pub writable: bool,
}

struct Loaded {
    keyring: ServiceAccountKeyring,
    name: String,
    expires_at: i64,
    vaults: BTreeMap<String, ServiceVault>,
    items: BTreeMap<String, Item>,
    errors: Vec<String>,
}

/// Passbox access with a service account token.
pub struct ServiceAccountClient {
    api: Api,
    token: Token,
    bearer: Zeroizing<String>,
    state: Mutex<Option<Loaded>>,
}

impl ServiceAccountClient {
    /// Connects with a token (`pbx_sa_…`) and loads everything the service
    /// account can read.
    pub fn connect(server_url: &str, token: &str) -> Result<Self> {
        Self::connect_with_transport(server_url, token, Box::new(HttpTransport::default()))
    }

    pub fn connect_with_transport(
        server_url: &str,
        token: &str,
        transport: Box<dyn Transport>,
    ) -> Result<Self> {
        let token = Token::parse(token).map_err(|_| {
            Error::InvalidData(
                "PASSBOX_SERVICE_ACCOUNT_TOKEN is not a service account token (pbx_sa_…)".into(),
            )
        })?;
        let bearer = Zeroizing::new(format!("sa.{}.{}", token.id(), token.auth_key()?.as_str()));
        let client = Self {
            api: Api::new(server_url, transport),
            token,
            bearer,
            state: Mutex::new(None),
        };
        client.refresh()?;
        Ok(client)
    }

    fn lock(&self) -> MutexGuard<'_, Option<Loaded>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        match self.api.request(method, path, &self.bearer, body) {
            Err(Error::Server { status: 401, .. }) => Err(Error::InvalidData(
                "the service account token was not accepted (wrong server, or the service account was deleted)"
                    .into(),
            )),
            Err(Error::Server {
                status: 409,
                code,
                message,
            }) if code == "conflict" && message.contains("changed by another device") => {
                Err(Error::Conflict)
            }
            other => other,
        }
    }

    /// Loads the current state from the server.
    pub fn refresh(&self) -> Result<()> {
        let value = self.request("GET", "/api/v1/service-account", None)?;
        let state: StateResponse = serde_json::from_value(value)?;
        if state.id != self.token.id() {
            return Err(Error::InvalidData(
                "the server answered for another service account".into(),
            ));
        }
        let mut keyring =
            ServiceAccountKeyring::unlock(&self.token, &state.public_key, &state.encrypted_private)
                .map_err(|e| match e {
                    passbox_core::Error::InvalidCredentials => Error::InvalidCredentials,
                    other => other.into(),
                })?;
        let mut errors = Vec::new();
        let mut permissions: BTreeMap<String, Permission> = BTreeMap::new();
        for grant in &state.grants {
            match keyring.open_grant(&grant.sealed_key, &grant.grant, &grant.grant_signature) {
                Ok(opened)
                    if opened.vault_id == grant.vault_id && opened.key_epoch == grant.key_epoch =>
                {
                    let entry = permissions
                        .entry(opened.vault_id)
                        .or_insert(opened.permission);
                    *entry = (*entry).max(opened.permission);
                }
                Ok(_) => errors.push(format!(
                    "the grant for vault {} does not match",
                    grant.vault_id
                )),
                Err(e) => errors.push(format!(
                    "the key of vault {} could not be opened: {e}",
                    grant.vault_id
                )),
            }
        }
        let mut vaults = BTreeMap::new();
        for vault in state.vaults {
            if !id::is_valid_id(&vault.id) || !permissions.contains_key(&vault.id) {
                continue;
            }
            let name = keyring
                .decrypt_vault_meta_at(&vault.id, vault.key_epoch, &vault.encrypted_meta)
                .ok()
                .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
                .and_then(|meta| meta["name"].as_str().map(str::to_owned))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "Vault".to_owned());
            // Writing needs both the signed grant and the server's current
            // (owner-limited) permission.
            let writable = vault.permission == "write"
                && permissions.get(&vault.id) == Some(&Permission::Write)
                && keyring.has_vault_key(&vault.id, vault.key_epoch);
            vaults.insert(
                vault.id.clone(),
                ServiceVault {
                    vault: Vault {
                        id: vault.id,
                        name,
                        revision: vault.revision,
                        org_id: vault.org_id,
                        key_epoch: vault.key_epoch,
                    },
                    writable,
                },
            );
        }
        let mut items = BTreeMap::new();
        for item in state.items {
            if !vaults.contains_key(&item.vault_id) || !id::is_valid_id(&item.id) {
                continue;
            }
            if !keyring.has_vault_key(&item.vault_id, item.key_epoch) {
                errors.push(format!(
                    "item {} is encrypted with a newer vault key; ask the owner to renew the service account's access",
                    item.id
                ));
                continue;
            }
            match keyring
                .decrypt_item_at(
                    &item.vault_id,
                    item.key_epoch,
                    &item.id,
                    item.revision,
                    &item.encrypted_data,
                )
                .map_err(Error::from)
                .and_then(|json| ItemData::from_json(&json))
            {
                Ok(data) => {
                    items.insert(
                        item.id.clone(),
                        Item {
                            id: item.id,
                            vault_id: item.vault_id,
                            revision: item.revision,
                            updated_at: item.updated_at,
                            key_epoch: item.key_epoch,
                            data,
                        },
                    );
                }
                Err(e) => errors.push(format!("item {} could not be decrypted: {e}", item.id)),
            }
        }
        *self.lock() = Some(Loaded {
            keyring,
            name: state.name,
            expires_at: state.expires_at,
            vaults,
            items,
            errors,
        });
        Ok(())
    }

    pub fn id(&self) -> &str {
        self.token.id()
    }

    /// The service account's name and expiry (Unix ms, 0 for none).
    pub fn info(&self) -> Result<(String, i64)> {
        let guard = self.lock();
        let state = guard.as_ref().ok_or(Error::Locked)?;
        Ok((state.name.clone(), state.expires_at))
    }

    /// The owner, who approves agent requests made with this token.
    pub fn owner_id(&self) -> Result<String> {
        let guard = self.lock();
        Ok(guard
            .as_ref()
            .ok_or(Error::Locked)?
            .keyring
            .owner_id()
            .to_owned())
    }

    pub fn vaults(&self) -> Result<Vec<ServiceVault>> {
        let guard = self.lock();
        let state = guard.as_ref().ok_or(Error::Locked)?;
        let mut vaults: Vec<ServiceVault> = state.vaults.values().cloned().collect();
        vaults.sort_by_key(|v| v.vault.name.to_lowercase());
        Ok(vaults)
    }

    /// Items sorted by title, without those in the trash.
    pub fn items(&self) -> Result<Vec<Item>> {
        let guard = self.lock();
        let state = guard.as_ref().ok_or(Error::Locked)?;
        let mut items: Vec<Item> = state
            .items
            .values()
            .filter(|i| i.data.trashed_at().is_none())
            .cloned()
            .collect();
        items.sort_by_key(|i| i.data.title.to_lowercase());
        Ok(items)
    }

    pub fn item(&self, id: &str) -> Result<Item> {
        let guard = self.lock();
        guard
            .as_ref()
            .ok_or(Error::Locked)?
            .items
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(id.to_owned()))
    }

    /// Problems found while loading (keys or items that could not be opened).
    pub fn errors(&self) -> Result<Vec<String>> {
        let guard = self.lock();
        Ok(guard.as_ref().ok_or(Error::Locked)?.errors.clone())
    }

    fn write(&self, vault_id: &str, item_id: &str, revision: u64, data: &ItemData) -> Result<()> {
        let json = serde_json::to_string(data)?;
        let (encrypted, epoch) = {
            let guard = self.lock();
            let state = guard.as_ref().ok_or(Error::Locked)?;
            let vault = state
                .vaults
                .get(vault_id)
                .ok_or_else(|| Error::NotFound(vault_id.to_owned()))?;
            if !vault.writable {
                return Err(Error::InvalidData(format!(
                    "this service account can only read the vault {:?}",
                    vault.vault.name
                )));
            }
            let epoch = vault.vault.key_epoch;
            (
                state
                    .keyring
                    .encrypt_item_at(vault_id, epoch, item_id, revision, &json)?,
                epoch,
            )
        };
        let result = self.request(
            "PUT",
            &format!("/api/v1/service-account/items/{item_id}"),
            Some(serde_json::json!({
                "vaultId": vault_id,
                "revision": revision,
                "encryptedData": encrypted,
                "keyEpoch": epoch,
            })),
        );
        match result {
            Ok(_) => self.refresh(),
            Err(Error::Conflict) => {
                self.refresh()?;
                Err(Error::Conflict)
            }
            Err(e) => Err(e),
        }
    }

    /// Creates an item and returns its ID.
    pub fn create_item(&self, vault_id: &str, data: &ItemData) -> Result<String> {
        let item_id = id::new_id()?;
        self.write(vault_id, &item_id, 1, data)?;
        Ok(item_id)
    }

    /// Saves a new version of an item, keeping its password history (see
    /// [`crate::Client::update_item`]).
    pub fn update_item(&self, item_id: &str, data: &ItemData) -> Result<()> {
        let current = self.item(item_id)?;
        let data = crate::client::next_version(&current.data, data);
        self.write(&current.vault_id, item_id, current.revision + 1, &data)
    }

    /// Moves an item to the trash (restorable for 30 days in the apps).
    pub fn trash_item(&self, item_id: &str) -> Result<()> {
        let current = self.item(item_id)?;
        let mut data = current.data;
        data.set_trashed_at(Some(crate::client::now_ms()));
        self.write(&current.vault_id, item_id, current.revision + 1, &data)
    }

    /// Permanently deletes an item.
    pub fn delete_item(&self, item_id: &str) -> Result<()> {
        let current = self.item(item_id)?;
        self.request(
            "DELETE",
            &format!(
                "/api/v1/service-account/items/{item_id}?revision={}",
                current.revision + 1
            ),
            None,
        )?;
        self.refresh()
    }

    /// Verifies an agent decision signed by the owner.
    fn verify_decision(
        &self,
        request: &[u8],
        decision: &str,
        signature: &str,
    ) -> Result<Decision> {
        let guard = self.lock();
        Ok(guard
            .as_ref()
            .ok_or(Error::Locked)?
            .keyring
            .verify_agent_decision(request, decision, signature)?)
    }
}

impl crate::agent::Backend for ServiceAccountClient {
    fn principal(&self) -> Result<(passbox_core::agent_grant::PrincipalKind, String, String)> {
        Ok((
            passbox_core::agent_grant::PrincipalKind::Service,
            self.id().to_owned(),
            self.owner_id()?,
        ))
    }

    fn vaults(&self) -> Result<Vec<(Vault, bool)>> {
        Ok(ServiceAccountClient::vaults(self)?
            .into_iter()
            .map(|v| (v.vault, v.writable))
            .collect())
    }

    fn items(&self) -> Result<Vec<Item>> {
        ServiceAccountClient::items(self)
    }

    fn create_item(&self, vault_id: &str, data: &ItemData) -> Result<String> {
        ServiceAccountClient::create_item(self, vault_id, data)
    }

    fn refresh(&self) -> Result<()> {
        ServiceAccountClient::refresh(self)
    }

    fn agent_call(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.request(method, &format!("/api/v1/service-account/{path}"), body)
    }

    fn verify_decision(&self, request: &[u8], decision: &str, signature: &str) -> Result<Decision> {
        ServiceAccountClient::verify_decision(self, request, decision, signature)
    }
}
