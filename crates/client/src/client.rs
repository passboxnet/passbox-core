//! The client: account lifecycle, online and offline unlock, sync and edits.
//!
//! The client is synchronous. Call it from a background thread in UI apps.
//! All methods take `&self`; an internal lock serializes operations.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use passbox_core::kdf::{self, KdfParams, MasterKeys, SALT_LEN};
use passbox_core::keyring::Keyring;
use passbox_core::opaque::{ClientLoginFlow, ClientRegistrationFlow};
use passbox_core::secret_key::SecretKey;
use passbox_core::{encoding, id};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::api::{Api, HttpTransport, NewVault, SyncItem, SyncResponse, SyncVault, Transport};
use crate::model::{DeviceAccount, Item, ItemData, Vault};
use crate::security::{VaultHealth, analyze_vault};
use crate::store::{ACCOUNT_KEY, CACHE_KEY, Store};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    SignedOut,
    Locked,
    Unlocked,
}

/// Whether an unlock reached the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity {
    Online,
    /// Unlocked from the local cache; changes need a connection.
    Offline,
}

/// Encrypted offline copy of the vault, exactly as received from the server.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cache {
    account_id: String,
    encrypted_account_key: String,
    cursor: i64,
    vaults: BTreeMap<String, SyncVault>,
    items: BTreeMap<String, SyncItem>,
}

struct Session {
    keyring: Keyring,
    /// Kept while unlocked to reconnect after going offline or when the
    /// session token expires.
    auth_secret: Zeroizing<[u8; 32]>,
    token: Option<String>,
    cache: Cache,
    vaults: BTreeMap<String, Vault>,
    items: BTreeMap<String, Item>,
    errors: Vec<String>,
}

/// Passbox client for one server and one device account.
pub struct Client {
    api: Api,
    store: Arc<dyn Store>,
    session: Mutex<Option<Session>>,
}

fn is_network(error: &Error) -> bool {
    matches!(error, Error::Network(_))
}

impl Client {
    /// Creates a client for `server_url` using the default HTTP transport.
    pub fn new(server_url: &str, store: Arc<dyn Store>) -> Self {
        Self::with_transport(server_url, store, Box::new(HttpTransport::default()))
    }

    pub fn with_transport(
        server_url: &str,
        store: Arc<dyn Store>,
        transport: Box<dyn Transport>,
    ) -> Self {
        Self {
            api: Api::new(server_url, transport),
            store,
            session: Mutex::new(None),
        }
    }

    fn lock_session(&self) -> MutexGuard<'_, Option<Session>> {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // --- State -----------------------------------------------------------------

    /// The account remembered on this device, if any.
    pub fn device_account(&self) -> Result<Option<DeviceAccount>> {
        match self.store.get(ACCOUNT_KEY)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn status(&self) -> Result<Status> {
        if self.lock_session().is_some() {
            Ok(Status::Unlocked)
        } else if self.device_account()?.is_some() {
            Ok(Status::Locked)
        } else {
            Ok(Status::SignedOut)
        }
    }

    /// Whether the unlocked session currently has a server connection.
    pub fn is_online(&self) -> bool {
        self.lock_session()
            .as_ref()
            .is_some_and(|s| s.token.is_some())
    }

    /// Vaults sorted by name.
    pub fn vaults(&self) -> Result<Vec<Vault>> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        let mut vaults: Vec<Vault> = session.vaults.values().cloned().collect();
        vaults.sort_by_key(|v| v.name.to_lowercase());
        Ok(vaults)
    }

    /// Items sorted by title.
    pub fn items(&self) -> Result<Vec<Item>> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        let mut items: Vec<Item> = session.items.values().cloned().collect();
        items.sort_by_key(|i| i.data.title.to_lowercase());
        Ok(items)
    }

    pub fn item(&self, id: &str) -> Result<Item> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        session
            .items
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(id.to_owned()))
    }

    /// Entries that could not be decrypted (tampered or unsupported).
    pub fn errors(&self) -> Result<Vec<String>> {
        let guard = self.lock_session();
        Ok(guard.as_ref().ok_or(Error::Locked)?.errors.clone())
    }

    pub fn health(&self) -> Result<VaultHealth> {
        Ok(analyze_vault(&self.items()?))
    }

    // --- Account -----------------------------------------------------------------

    /// Creates an account with a personal vault and unlocks it. Returns the
    /// new Secret Key for the user's Emergency Kit.
    pub fn sign_up(&self, email: &str, password: &str) -> Result<String> {
        let secret_key = SecretKey::generate()?;
        let account = DeviceAccount {
            server_url: self.api.base_url().to_owned(),
            email: email.trim().to_lowercase(),
            account_id: id::new_id()?,
            secret_key: secret_key.to_display_string(),
            kdf_salt: encoding::encode(&kdf::generate_salt()?),
            kdf_params: KdfParams::DEFAULT,
        };
        let keys = derive(&account, password)?;

        let (flow, request) = ClientRegistrationFlow::start(&*keys.auth_secret)?;
        let response = self.api.register_start(
            &account.account_id,
            &account.email,
            &encoding::encode(&request),
        )?;
        let upload = flow.finish(&encoding::decode(&response)?)?;

        let (mut keyring, encrypted_account_key) = Keyring::create(&keys.auk, &account.account_id)?;
        let vault = keyring.create_vault(r#"{"name":"Private"}"#)?;
        self.api.register_finish(serde_json::json!({
            "accountId": account.account_id,
            "email": account.email,
            "registrationUpload": encoding::encode(&upload),
            "kdfSalt": account.kdf_salt,
            "kdfParams": account.kdf_params,
            "encryptedAccountKey": encrypted_account_key,
            "vault": { "id": vault.id, "encryptedKey": vault.encrypted_key, "encryptedMeta": vault.encrypted_meta },
        }))?;
        drop(keyring);

        self.login(&account, &keys)?;
        self.store
            .put(ACCOUNT_KEY, &serde_json::to_vec(&account)?)?;
        self.sync()?;
        Ok(account.secret_key)
    }

    /// Signs in on a new device with email, master password and Secret Key.
    pub fn sign_in(&self, email: &str, password: &str, secret_key: &str) -> Result<()> {
        let secret_key = SecretKey::parse(secret_key).map_err(|_| Error::InvalidCredentials)?;
        let email = email.trim().to_lowercase();
        let prelogin = self.api.prelogin(&email)?;
        let account = DeviceAccount {
            server_url: self.api.base_url().to_owned(),
            email,
            account_id: prelogin.account_id,
            secret_key: secret_key.to_display_string(),
            kdf_salt: prelogin.kdf_salt,
            kdf_params: prelogin.kdf_params,
        };
        let keys = derive(&account, password)?;
        self.login(&account, &keys)?;
        // A different account may have used this device before.
        self.store.delete(CACHE_KEY)?;
        self.store
            .put(ACCOUNT_KEY, &serde_json::to_vec(&account)?)?;
        self.sync()
    }

    /// Unlocks the account remembered on this device. Works offline if the
    /// vault was synced before.
    pub fn unlock(&self, password: &str) -> Result<Connectivity> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        let keys = derive(&account, password)?;
        let cache: Option<Cache> = self
            .store
            .get(CACHE_KEY)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .filter(|cache: &Cache| cache.account_id == account.account_id);

        let Some(cache) = cache else {
            self.login(&account, &keys)?;
            self.sync()?;
            return Ok(Connectivity::Online);
        };

        // Offline first: the cached account key proves the password locally.
        let keyring = Keyring::unlock(&keys.auk, &account.account_id, &cache.encrypted_account_key)
            .map_err(|_| Error::InvalidCredentials)?;
        let mut session = Session {
            keyring,
            auth_secret: Zeroizing::new(*keys.auth_secret),
            token: None,
            cache: Cache::default(),
            vaults: BTreeMap::new(),
            items: BTreeMap::new(),
            errors: Vec::new(),
        };
        apply_cache(&mut session, cache);
        *self.lock_session() = Some(session);

        match self.reconnect() {
            Ok(()) => {
                self.sync()?;
                Ok(Connectivity::Online)
            }
            Err(e) if is_network(&e) => Ok(Connectivity::Offline),
            Err(e) => {
                *self.lock_session() = None;
                Err(e)
            }
        }
    }

    /// Forgets all keys and decrypted data. The account and the encrypted
    /// offline cache stay on this device.
    pub fn lock(&self) {
        let session = self.lock_session().take();
        if let Some(token) = session.and_then(|s| s.token) {
            // Best effort; the session expires anyway.
            let _ = self.api.logout(&token);
        }
    }

    /// Locks and removes the account and its cache from this device.
    pub fn sign_out(&self) -> Result<()> {
        self.lock();
        self.store.delete(CACHE_KEY)?;
        self.store.delete(ACCOUNT_KEY)
    }

    /// Runs the OPAQUE login and replaces the session with a freshly
    /// unlocked one.
    fn login(&self, account: &DeviceAccount, keys: &MasterKeys) -> Result<()> {
        let token = self.opaque_login(&account.email, &keys.auth_secret)?;
        let remote = self.api.account(&token)?;
        let keyring = Keyring::unlock(&keys.auk, &remote.account_id, &remote.encrypted_account_key)
            .map_err(|_| Error::InvalidCredentials)?;
        *self.lock_session() = Some(Session {
            keyring,
            auth_secret: Zeroizing::new(*keys.auth_secret),
            token: Some(token),
            cache: Cache {
                account_id: remote.account_id,
                encrypted_account_key: remote.encrypted_account_key,
                ..Cache::default()
            },
            vaults: BTreeMap::new(),
            items: BTreeMap::new(),
            errors: Vec::new(),
        });
        Ok(())
    }

    fn opaque_login(&self, email: &str, auth_secret: &[u8; 32]) -> Result<String> {
        let (flow, request) = ClientLoginFlow::start(auth_secret)?;
        let start = self.api.login_start(email, &encoding::encode(&request))?;
        let finish = flow
            .finish(&encoding::decode(&start.credential_response)?)
            .map_err(|_| Error::InvalidCredentials)?;
        Ok(self
            .api
            .login_finish(&start.login_id, &encoding::encode(&finish.finalization))?
            .token)
    }

    /// Gets a new session token with the auth secret of the unlocked session.
    fn reconnect(&self) -> Result<()> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        let auth_secret = {
            let guard = self.lock_session();
            Zeroizing::new(*guard.as_ref().ok_or(Error::Locked)?.auth_secret)
        };
        let token = self.opaque_login(&account.email, &auth_secret)?;
        if let Some(session) = self.lock_session().as_mut() {
            session.token = Some(token);
        }
        Ok(())
    }

    /// Runs `call` with a session token, connecting first if needed and
    /// reconnecting once if the token was rejected.
    fn with_token<T>(&self, call: impl Fn(&str) -> Result<T>) -> Result<T> {
        let token = self
            .lock_session()
            .as_ref()
            .ok_or(Error::Locked)?
            .token
            .clone();
        let token = match token {
            Some(token) => token,
            None => {
                self.reconnect()
                    .map_err(|e| if is_network(&e) { Error::Offline } else { e })?;
                self.current_token()?
            }
        };
        match call(&token) {
            Err(Error::Server { status: 401, .. }) => {
                self.reconnect()?;
                call(&self.current_token()?)
            }
            Err(e) if is_network(&e) => {
                if let Some(session) = self.lock_session().as_mut() {
                    session.token = None;
                }
                Err(Error::Offline)
            }
            other => other,
        }
    }

    fn current_token(&self) -> Result<String> {
        self.lock_session()
            .as_ref()
            .and_then(|s| s.token.clone())
            .ok_or(Error::Offline)
    }

    // --- Sync --------------------------------------------------------------------

    /// Fetches and decrypts everything that changed since the last sync and
    /// updates the offline cache.
    pub fn sync(&self) -> Result<()> {
        let since = self
            .lock_session()
            .as_ref()
            .ok_or(Error::Locked)?
            .cache
            .cursor;
        let delta = self.with_token(|token| self.api.sync(token, since))?;
        let mut guard = self.lock_session();
        let session = guard.as_mut().ok_or(Error::Locked)?;
        apply_delta(session, delta);
        self.store
            .put(CACHE_KEY, &serde_json::to_vec(&session.cache)?)
    }

    // --- Editing -----------------------------------------------------------------

    /// Creates an item and returns its ID.
    pub fn create_item(&self, vault_id: &str, data: &ItemData) -> Result<String> {
        let item_id = id::new_id()?;
        self.write_item(vault_id, &item_id, 1, data)?;
        Ok(item_id)
    }

    /// Saves a new version of an item.
    pub fn update_item(&self, item_id: &str, data: &ItemData) -> Result<()> {
        let current = self.item(item_id)?;
        self.write_item(&current.vault_id, item_id, current.revision + 1, data)
    }

    pub fn delete_item(&self, item_id: &str) -> Result<()> {
        let current = self.item(item_id)?;
        let result =
            self.with_token(|token| self.api.delete_item(token, item_id, current.revision + 1));
        self.finish_write(result)
    }

    fn write_item(
        &self,
        vault_id: &str,
        item_id: &str,
        revision: u64,
        data: &ItemData,
    ) -> Result<()> {
        let json = serde_json::to_string(data)?;
        let encrypted = {
            let guard = self.lock_session();
            let session = guard.as_ref().ok_or(Error::Locked)?;
            session
                .keyring
                .encrypt_item(vault_id, item_id, revision, &json)?
        };
        let result = self.with_token(|token| {
            self.api
                .put_item(token, item_id, vault_id, revision, &encrypted)
        });
        self.finish_write(result)
    }

    /// Syncs after a write, so local state always mirrors the server. On a
    /// conflict the latest version is loaded before the error is returned.
    fn finish_write<T>(&self, result: Result<T>) -> Result<()> {
        match result {
            Ok(_) => self.sync(),
            Err(Error::Conflict) => {
                self.sync()?;
                Err(Error::Conflict)
            }
            Err(e) => Err(e),
        }
    }

    pub fn create_vault(&self, name: &str) -> Result<String> {
        let vault = {
            let mut guard = self.lock_session();
            let session = guard.as_mut().ok_or(Error::Locked)?;
            session
                .keyring
                .create_vault(&serde_json::json!({ "name": name }).to_string())?
        };
        let new_vault = NewVault {
            id: vault.id.clone(),
            encrypted_key: vault.encrypted_key,
            encrypted_meta: vault.encrypted_meta,
        };
        let result = self.with_token(|token| self.api.create_vault(token, &new_vault));
        self.finish_write(result)?;
        Ok(vault.id)
    }

    pub fn rename_vault(&self, vault_id: &str, name: &str) -> Result<()> {
        let (revision, encrypted) = {
            let guard = self.lock_session();
            let session = guard.as_ref().ok_or(Error::Locked)?;
            let vault = session
                .vaults
                .get(vault_id)
                .ok_or_else(|| Error::NotFound(vault_id.to_owned()))?;
            let meta = serde_json::json!({ "name": name }).to_string();
            (
                vault.revision + 1,
                session.keyring.encrypt_vault_meta(vault_id, &meta)?,
            )
        };
        let result =
            self.with_token(|token| self.api.update_vault(token, vault_id, revision, &encrypted));
        self.finish_write(result)
    }
}

fn derive(account: &DeviceAccount, password: &str) -> Result<MasterKeys> {
    let secret_key =
        SecretKey::parse(&account.secret_key).map_err(|_| Error::InvalidCredentials)?;
    let salt: [u8; SALT_LEN] = encoding::decode(&account.kdf_salt)?
        .try_into()
        .map_err(|_| Error::InvalidData("KDF salt must be 16 bytes".into()))?;
    Ok(kdf::derive_master_keys(
        password,
        &secret_key,
        &account.account_id,
        &salt,
        account.kdf_params,
    )?)
}

fn apply_cache(session: &mut Session, cache: Cache) {
    let delta = SyncResponse {
        cursor: cache.cursor,
        vaults: cache.vaults.into_values().collect(),
        items: cache.items.into_values().collect(),
    };
    session.cache.account_id = cache.account_id;
    session.cache.encrypted_account_key = cache.encrypted_account_key;
    apply_delta(session, delta);
}

fn apply_delta(session: &mut Session, delta: SyncResponse) {
    for vault in delta.vaults {
        if !id::is_valid_id(&vault.id) {
            continue;
        }
        let decrypted = (|| -> Result<String> {
            if !session.keyring.has_vault(&vault.id) {
                session.keyring.add_vault(&vault.id, &vault.encrypted_key)?;
            }
            let meta: serde_json::Value = serde_json::from_str(
                &session
                    .keyring
                    .decrypt_vault_meta(&vault.id, &vault.encrypted_meta)?,
            )?;
            Ok(meta["name"]
                .as_str()
                .filter(|n| !n.is_empty())
                .unwrap_or("Vault")
                .to_owned())
        })();
        match decrypted {
            Ok(name) => {
                session.vaults.insert(
                    vault.id.clone(),
                    Vault {
                        id: vault.id.clone(),
                        name,
                        revision: vault.revision,
                    },
                );
                session.cache.vaults.insert(vault.id.clone(), vault);
            }
            Err(e) => session
                .errors
                .push(format!("Vault {} could not be decrypted: {e}", vault.id)),
        }
    }
    for item in delta.items {
        if !id::is_valid_id(&item.id) {
            continue;
        }
        let data = match (&item.encrypted_data, item.deleted) {
            (Some(encrypted), false) => encrypted,
            _ => {
                session.items.remove(&item.id);
                session.cache.items.remove(&item.id);
                continue;
            }
        };
        let decrypted = session
            .keyring
            .decrypt_item(&item.vault_id, &item.id, item.revision, data)
            .map_err(Error::from)
            .and_then(|json| ItemData::from_json(&json));
        match decrypted {
            Ok(data) => {
                session.items.insert(
                    item.id.clone(),
                    Item {
                        id: item.id.clone(),
                        vault_id: item.vault_id.clone(),
                        revision: item.revision,
                        updated_at: item.updated_at,
                        data,
                    },
                );
                session.cache.items.insert(item.id.clone(), item);
            }
            Err(e) => {
                session.items.remove(&item.id);
                session
                    .errors
                    .push(format!("Item {} could not be decrypted: {e}", item.id));
            }
        }
    }
    session.cache.cursor = session.cache.cursor.max(delta.cursor);
}
