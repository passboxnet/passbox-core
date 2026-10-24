//! The client: account lifecycle, online and offline unlock, sync and edits.
//!
//! The client is synchronous. Call it from a background thread in UI apps.
//! All methods take `&self`; an internal lock serializes operations.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use passbox_core::aead::SymmetricKey;
use passbox_core::kdf::{self, KdfParams, MasterKeys, SALT_LEN};
use passbox_core::keyring::Keyring;
use passbox_core::opaque::{ClientLoginFlow, ClientRegistrationFlow};
use passbox_core::secret_key::SecretKey;
use passbox_core::{encoding, id};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::api::{
    AccountEvent, Api, HttpTransport, NewVault, SessionInfo, SyncItem, SyncResponse, SyncVault,
    Transport,
};
use crate::model::{
    DeviceAccount, Item, ItemData, PASSWORD_HISTORY_LEN, PasswordHistoryEntry, TRASH_RETENTION_MS,
    Vault, field,
};
use crate::security::{VaultHealth, analyze_vault};
use crate::store::{ACCOUNT_KEY, CACHE_KEY, DEVICE_TOKEN_KEY, Store};
use crate::{Error, Result};
use passbox_core::strength::{self, Strength};

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

/// Version byte of the exported unlock key.
const UNLOCK_KEY_VERSION: u8 = 1;
const UNLOCK_KEY_LEN: usize = 1 + 32 + 32;

struct Session {
    keyring: Keyring,
    /// Kept while unlocked so apps can export an unlock key for biometric unlock.
    auk: SymmetricKey,
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
    /// Device name and client kind shown in the account's device list.
    device: Mutex<(String, String)>,
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
            device: Mutex::new((String::new(), String::new())),
        }
    }

    /// Sets how this device appears in the account's device list, for
    /// example `("Anna's iPhone", "ios")`. Kinds are `web`, `extension`,
    /// `desktop`, `ios`, `android` and `cli`. Applies to the next login.
    pub fn set_device(&self, name: &str, kind: &str) {
        *self
            .device
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            (name.to_owned(), kind.to_owned());
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
    /// Items sorted by title, without those in the trash.
    pub fn items(&self) -> Result<Vec<Item>> {
        self.items_where(|item| item.data.trashed_at().is_none())
    }

    /// Items in the trash, most recently trashed first.
    pub fn trashed_items(&self) -> Result<Vec<Item>> {
        let mut items = self.items_where(|item| item.data.trashed_at().is_some())?;
        items.sort_by_key(|i| std::cmp::Reverse(i.data.trashed_at()));
        Ok(items)
    }

    fn items_where(&self, keep: impl Fn(&Item) -> bool) -> Result<Vec<Item>> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        let mut items: Vec<Item> = session
            .items
            .values()
            .filter(|i| keep(i))
            .cloned()
            .collect();
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
        let email = self.device_account()?.map(|a| a.email).unwrap_or_default();
        Ok(analyze_vault(&self.items()?, &[email.as_str()]))
    }

    /// Rates a password, using the account email as context.
    pub fn estimate_strength(&self, password: &str) -> Result<Strength> {
        let email = self.device_account()?.map(|a| a.email).unwrap_or_default();
        Ok(strength::estimate(password, &[email.as_str()]))
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
        self.unlock_with_master_keys(&account, &keys)
    }

    /// Returns the derived master keys of the unlocked session, for apps that
    /// offer biometric unlock: store them protected by Face ID, Touch ID or
    /// the Android Keystore and pass them to [`Client::unlock_with_key`].
    /// Unlocking this way skips the memory-hard key derivation, which also
    /// makes it usable in memory-constrained places such as the iOS AutoFill
    /// extension. The master password itself is never stored.
    pub fn unlock_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        let mut key = Zeroizing::new(Vec::with_capacity(UNLOCK_KEY_LEN));
        key.push(UNLOCK_KEY_VERSION);
        key.extend_from_slice(session.auk.as_bytes());
        key.extend_from_slice(&*session.auth_secret);
        Ok(key)
    }

    /// Unlocks with a key from [`Client::unlock_key`]. Fails with
    /// [`Error::InvalidCredentials`] if the key does not belong to the account,
    /// for example after the master password was changed.
    pub fn unlock_with_key(&self, key: &[u8]) -> Result<Connectivity> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        if key.len() != UNLOCK_KEY_LEN || key[0] != UNLOCK_KEY_VERSION {
            return Err(Error::InvalidCredentials);
        }
        let mut auk = [0u8; 32];
        let mut auth_secret = Zeroizing::new([0u8; 32]);
        auk.copy_from_slice(&key[1..33]);
        auth_secret.copy_from_slice(&key[33..]);
        let keys = MasterKeys {
            auk: SymmetricKey::from_bytes(auk),
            auth_secret,
        };
        self.unlock_with_master_keys(&account, &keys)
    }

    fn unlock_with_master_keys(
        &self,
        account: &DeviceAccount,
        keys: &MasterKeys,
    ) -> Result<Connectivity> {
        let cache: Option<Cache> = self
            .store
            .get(CACHE_KEY)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .filter(|cache: &Cache| cache.account_id == account.account_id);

        let Some(cache) = cache else {
            self.login(account, keys)?;
            self.sync()?;
            return Ok(Connectivity::Online);
        };

        // Offline first: the cached account key proves the password locally.
        let keyring = Keyring::unlock(&keys.auk, &account.account_id, &cache.encrypted_account_key)
            .map_err(|_| Error::InvalidCredentials)?;
        let mut session = Session {
            keyring,
            auk: keys.auk.clone(),
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

    // --- Devices, activity and master password -----------------------------------

    /// Devices currently signed in to the account, most recently used first.
    pub fn sessions(&self) -> Result<Vec<SessionInfo>> {
        self.with_token(|token| self.api.sessions(token))
    }

    /// Signs out another device. Its app locks on its next request.
    pub fn revoke_session(&self, id: &str) -> Result<()> {
        self.with_token(|token| self.api.revoke_session(token, id))
    }

    /// Signs out every device except this one.
    pub fn revoke_other_sessions(&self) -> Result<()> {
        self.with_token(|token| self.api.revoke_other_sessions(token))
    }

    /// The account's recent activity (sign-ins, failed attempts, password
    /// changes), newest first.
    pub fn activity(&self, limit: u32) -> Result<Vec<AccountEvent>> {
        self.with_token(|token| self.api.account_events(token, limit))
    }

    /// Changes the master password. The Secret Key, the account key and all
    /// vault keys stay the same; only the account key's wrapping and the
    /// server's OPAQUE record change. Other devices are signed out and need
    /// the new password. Fails with [`Error::InvalidCredentials`] if
    /// `current_password` is wrong.
    pub fn change_master_password(&self, current_password: &str, new_password: &str) -> Result<()> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        if self.lock_session().is_none() {
            return Err(Error::Locked);
        }
        let current = derive(&account, current_password)?;
        // A fresh login proves the current password and satisfies the
        // server's recent-login requirement.
        let token = self.opaque_login(&account.email, &current.auth_secret)?;

        let next = DeviceAccount {
            kdf_salt: encoding::encode(&kdf::generate_salt()?),
            ..account.clone()
        };
        let keys = derive(&next, new_password)?;
        let (flow, request) = ClientRegistrationFlow::start(&*keys.auth_secret)?;
        let response = self
            .api
            .password_change_start(&token, &encoding::encode(&request))?;
        let upload = flow.finish(&encoding::decode(&response)?)?;
        let encrypted_account_key = {
            let guard = self.lock_session();
            guard
                .as_ref()
                .ok_or(Error::Locked)?
                .keyring
                .wrap_account_key(&keys.auk)?
        };
        self.api.password_change_finish(
            &token,
            serde_json::json!({
                "registrationUpload": encoding::encode(&upload),
                "kdfSalt": next.kdf_salt,
                "kdfParams": next.kdf_params,
                "encryptedAccountKey": encrypted_account_key,
            }),
        )?;
        self.store.put(ACCOUNT_KEY, &serde_json::to_vec(&next)?)?;

        let mut guard = self.lock_session();
        if let Some(session) = guard.as_mut() {
            session.auk = keys.auk.clone();
            session.auth_secret = Zeroizing::new(*keys.auth_secret);
            session.token = Some(token);
            session.cache.encrypted_account_key = encrypted_account_key;
            self.store
                .put(CACHE_KEY, &serde_json::to_vec(&session.cache)?)?;
        }
        Ok(())
    }

    /// The Secret Key of this device's account, for showing the Emergency
    /// Kit again. Requires the vault to be unlocked and `password` to be the
    /// current master password; the check runs locally (the account key is
    /// unwrapped with the derived key) and fails with
    /// [`Error::InvalidCredentials`] otherwise.
    pub fn reveal_secret_key(&self, password: &str) -> Result<String> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        let encrypted_account_key = {
            let guard = self.lock_session();
            guard
                .as_ref()
                .ok_or(Error::Locked)?
                .cache
                .encrypted_account_key
                .clone()
        };
        let keys = derive(&account, password)?;
        Keyring::unlock(&keys.auk, &account.account_id, &encrypted_account_key)
            .map_err(|_| Error::InvalidCredentials)?;
        Ok(account.secret_key)
    }

    /// Locks and removes the account and its cache from this device.
    pub fn sign_out(&self) -> Result<()> {
        self.lock();
        self.store.delete(CACHE_KEY)?;
        self.store.delete(DEVICE_TOKEN_KEY)?;
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
            auk: keys.auk.clone(),
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
        // The server ignores a token that does not belong to this account.
        let device_token = self
            .store
            .get(DEVICE_TOKEN_KEY)?
            .and_then(|bytes| String::from_utf8(bytes).ok());
        let start =
            self.api
                .login_start(email, &encoding::encode(&request), device_token.as_deref())?;
        let finish = flow
            .finish(&encoding::decode(&start.credential_response)?)
            .map_err(|_| Error::InvalidCredentials)?;
        let (device_name, client_kind) = self
            .device
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let response = self.api.login_finish(
            &start.login_id,
            &encoding::encode(&finish.finalization),
            &device_name,
            &client_kind,
        )?;
        if !response.device_token.is_empty() {
            self.store
                .put(DEVICE_TOKEN_KEY, response.device_token.as_bytes())?;
        }
        Ok(response.token)
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

    /// Runs `call` with a session token, connecting first if needed. A
    /// rejected token means the session expired or this device was signed
    /// out from another one: the client locks and the user has to unlock
    /// again.
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
                *self.lock_session() = None;
                Err(Error::Locked)
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

    /// Saves a new version of an item. A replaced password is added to the
    /// item's password history; the history and trash state always come
    /// from the stored version, not from `data`.
    pub fn update_item(&self, item_id: &str, data: &ItemData) -> Result<()> {
        let current = self.item(item_id)?;
        let mut data = data.clone();
        let mut history = current.data.password_history();
        if let Some(old) = current.data.field(field::PASSWORD)
            && data.field(field::PASSWORD) != Some(old)
        {
            history.insert(
                0,
                PasswordHistoryEntry {
                    value: old.to_owned(),
                    replaced_at: now_ms(),
                },
            );
            history.truncate(PASSWORD_HISTORY_LEN);
        }
        data.set_password_history(&history);
        data.set_trashed_at(current.data.trashed_at());
        self.write_item(&current.vault_id, item_id, current.revision + 1, &data)
    }

    /// Moves an item to the trash. It disappears from [`Client::items`] and
    /// autofill, and can be restored for 30 days.
    pub fn trash_item(&self, item_id: &str) -> Result<()> {
        self.set_trashed(item_id, Some(now_ms()))
    }

    /// Restores an item from the trash.
    pub fn restore_item(&self, item_id: &str) -> Result<()> {
        self.set_trashed(item_id, None)
    }

    fn set_trashed(&self, item_id: &str, at: Option<i64>) -> Result<()> {
        let current = self.item(item_id)?;
        let mut data = current.data;
        data.set_trashed_at(at);
        self.write_item(&current.vault_id, item_id, current.revision + 1, &data)
    }

    /// Permanently deletes items that have been in the trash for more than
    /// 30 days (or all trashed items when `all` is set). Returns how many
    /// were deleted. Items changed on another device in the meantime are
    /// skipped.
    pub fn purge_trash(&self, all: bool) -> Result<usize> {
        let cutoff = now_ms() - TRASH_RETENTION_MS;
        let mut deleted = 0;
        for item in self.trashed_items()? {
            let expired = item.data.trashed_at().is_some_and(|at| at <= cutoff);
            if !(all || expired) {
                continue;
            }
            match self.delete_item(&item.id) {
                Ok(()) => deleted += 1,
                Err(Error::Conflict | Error::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(deleted)
    }

    /// Permanently deletes an item on all devices. Prefer [`Client::trash_item`].
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

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
