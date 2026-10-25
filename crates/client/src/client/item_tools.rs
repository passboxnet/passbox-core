//! Item extras for the apps: version history, website icons, breach checks,
//! device-local usage, per-item health and bulk changes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use passbox_core::breach;
use serde::{Deserialize, Serialize};

use super::{Client, now_ms};
use crate::model::{ItemCategory, ItemData, field};
use crate::security::analyze_vault;
use crate::{Error, Result};

/// Store key of the encrypted item usage map. Like `cache`, it starts with
/// `cache` so apps keep it in (protected) files rather than the keychain.
pub const USAGE_KEY: &str = "cache_usage";
/// Prefix of the store keys of cached website icons.
pub const ICON_KEY_PREFIX: &str = "cache_icon_";
/// Associated-data purpose of the usage map (see `Keyring::encrypt_local`).
const USAGE_PURPOSE: &str = "item-usage";
/// How long a downloaded icon is used before it is fetched again.
pub const ICON_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// How long "no icon" is remembered.
const ICON_MISS_TTL_MS: i64 = 24 * 60 * 60 * 1000;

// --- Version history --------------------------------------------------------------

/// An earlier version of an item from the server's history.
#[derive(Debug, Clone, PartialEq)]
pub struct ItemVersion {
    pub revision: u64,
    /// When this version was saved (Unix ms).
    pub updated_at: i64,
    /// Public ID of the session (device) that saved it, if known; compare
    /// with [`Client::sessions`].
    pub updated_by: Option<String>,
    /// `None` when it cannot be decrypted on this device, for example a
    /// shared vault's version from before a key rotation whose old key this
    /// account never received.
    pub data: Option<ItemData>,
}

// --- Usage ------------------------------------------------------------------------

/// How an item was used on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageKind {
    /// A field was copied.
    Copy,
    /// Filled into an app or website by AutoFill.
    Autofill,
    /// The item was opened.
    Open,
}

/// Device-local usage of an item. Never synced; encrypted at rest with the
/// account key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemUsage {
    /// Last copy, autofill or open (Unix ms; 0 = never).
    pub last_used_at: i64,
    /// Last autofill (Unix ms; 0 = never).
    pub last_autofilled_at: i64,
    pub use_count: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct UsageMap {
    #[serde(default)]
    items: BTreeMap<String, ItemUsage>,
}

// --- Breach checks ----------------------------------------------------------------

/// Fetches Have I Been Pwned range responses. The default uses HTTPS;
/// tests and apps with their own networking can replace it.
pub trait BreachRange: Send + Sync {
    /// The body of `GET https://api.pwnedpasswords.com/range/{prefix}` with
    /// `Add-Padding: true`.
    fn range(&self, prefix: &str) -> Result<String>;
}

/// [`BreachRange`] over HTTPS with `ureq`.
pub struct HibpRange {
    agent: ureq::Agent,
}

impl Default for HibpRange {
    fn default() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(15)))
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl BreachRange for HibpRange {
    fn range(&self, prefix: &str) -> Result<String> {
        let unreachable =
            |e: ureq::Error| Error::Network(format!("Have I Been Pwned could not be reached: {e}"));
        let mut response = self
            .agent
            .get(format!("{}{prefix}", breach::RANGE_URL))
            .header("Add-Padding", "true")
            .call()
            .map_err(unreachable)?;
        if response.status() != 200 {
            return Err(Error::Network(format!(
                "Have I Been Pwned answered with status {}",
                response.status()
            )));
        }
        response
            .body_mut()
            .with_config()
            .limit(4 * 1024 * 1024)
            .read_to_string()
            .map_err(unreachable)
    }
}

/// How breach checks reach Have I Been Pwned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BreachMode {
    /// Through the user's Passbox server when it offers it
    /// (`/api/v1/breach/range/{prefix}`), otherwise directly.
    #[default]
    Auto,
    /// Only through the Passbox server: Have I Been Pwned never sees this
    /// device's IP address. Fails when the server does not offer it.
    Server,
    /// Directly from this device.
    Direct,
}

/// Breach lookups of the unlocked session.
pub(crate) struct BreachState {
    source: Arc<dyn BreachRange>,
    /// A source set with [`Client::set_breach_range`] replaces the server.
    custom: bool,
    pub(crate) mode: BreachMode,
    /// Counts by full SHA-1 hex of the password. Cleared on lock.
    pub(crate) counts: HashMap<String, u64>,
    /// A full check of all items ran in this session.
    pub(crate) checked: bool,
    /// The last email monitoring results (for the security report).
    pub(crate) exposed: Vec<passbox_core::analysis::ExposedEmail>,
}

impl Default for BreachState {
    fn default() -> Self {
        Self {
            source: Arc::new(HibpRange::default()),
            custom: false,
            mode: BreachMode::Auto,
            counts: HashMap::new(),
            checked: false,
            exposed: Vec::new(),
        }
    }
}

/// A login whose password appears in known data breaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreachedItem {
    pub item_id: String,
    /// How often the password appears in Have I Been Pwned.
    pub count: u64,
}

// --- Health -----------------------------------------------------------------------

/// A security problem of one item ("Sicherheits-Check").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemProblem {
    /// The password is weak (strength score ≤ 1).
    Weak,
    /// Another login uses the same password.
    Reused,
    /// The website address starts with `http://`.
    InsecureUrl,
    /// A login with a password but no one-time password (2FA).
    MissingTotp,
    /// The password was found in a data breach (known only after a breach
    /// check in this session).
    Breached,
}

impl ItemProblem {
    /// Stable code: `weak`, `reused`, `insecure_url`, `missing_totp`, `breached`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Reused => "reused",
            Self::InsecureUrl => "insecure_url",
            Self::MissingTotp => "missing_totp",
            Self::Breached => "breached",
        }
    }
}

/// The security check of one item.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ItemHealth {
    /// In the order weak, reused, insecure URL, missing 2FA, breached.
    pub problems: Vec<ItemProblem>,
    /// Strength score 0–4 of the password, if it has one.
    pub strength: Option<u8>,
    /// Other items with the same password.
    pub reused_with: Vec<String>,
    /// Breach count from this session's checks; `None` if not checked.
    pub breach_count: Option<u64>,
}

// --- Bulk changes -----------------------------------------------------------------

/// An item a bulk change could not apply to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkFailure {
    pub item_id: String,
    pub error: String,
}

impl Client {
    // --- Version history ------------------------------------------------------------

    /// Earlier versions of an item (up to 20, newest first), decrypted on
    /// the device. The current version is [`Client::item`]. Restoring a
    /// version means saving its data again with [`Client::update_item`];
    /// that keeps the password history and creates a new version.
    pub fn item_history(&self, item_id: &str) -> Result<Vec<ItemVersion>> {
        let vault_id = self.item(item_id)?.vault_id;
        let records = self.with_token(|token| self.api.item_versions(token, item_id))?;
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        Ok(records
            .into_iter()
            .map(|record| ItemVersion {
                revision: record.revision,
                updated_at: record.updated_at,
                updated_by: record.updated_by,
                data: session
                    .keyring
                    .decrypt_item_at(
                        &vault_id,
                        record.key_epoch,
                        item_id,
                        record.revision,
                        &record.encrypted_data,
                    )
                    .ok()
                    .and_then(|json| ItemData::from_json(&json).ok()),
            })
            .collect())
    }

    // --- Website icons --------------------------------------------------------------

    /// The website icon of `domain` (PNG, ICO, JPEG, GIF or WebP bytes), or
    /// `None`. Popular sites come from the bundled icons the app installed
    /// with [`crate::site_icons::set_bundled_site_icons`], without any
    /// request; the server is never asked for them. Others come through
    /// the user's own server and are cached in the store for 7 days ("no
    /// icon" for a day); offline, a cached icon is returned. Pass the bare
    /// host name (`github.com`, punycode for international names). Showing
    /// icons is a user preference of the app.
    pub fn icon(&self, domain: &str) -> Result<Option<Vec<u8>>> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let valid = !domain.is_empty()
            && domain.len() <= 240
            && domain.contains('.')
            && domain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        if !valid {
            return Ok(None);
        }
        if let Some(icon) = crate::site_icons::bundled_site_icons()
            .and_then(|pack| pack.get(&domain).map(<[u8]>::to_vec))
        {
            return Ok(Some(icon));
        }
        let key = format!("{ICON_KEY_PREFIX}{}", domain.replace('.', "_"));
        let cached = self.store.get(&key)?.and_then(|bytes| decode_icon(&bytes));
        let now = now_ms();
        if let Some((fetched_at, icon)) = &cached {
            let ttl = if icon.is_some() {
                ICON_TTL_MS
            } else {
                ICON_MISS_TTL_MS
            };
            if now - fetched_at < ttl {
                return Ok(icon.clone());
            }
        }
        match self.with_token(|token| self.api.icon(token, &domain)) {
            Ok(icon) => {
                self.store.put(&key, &encode_icon(now, icon.as_deref()))?;
                Ok(icon)
            }
            Err(Error::Offline | Error::Network(_) | Error::Server { status: 429, .. }) => {
                Ok(cached.and_then(|(_, icon)| icon))
            }
            Err(e) => Err(e),
        }
    }

    // --- Breach checks --------------------------------------------------------------

    /// Replaces how Have I Been Pwned is reached (tests, custom networking).
    pub fn set_breach_range(&self, source: Box<dyn BreachRange>) {
        let mut state = self.lock_breach();
        state.source = Arc::from(source);
        state.custom = true;
        state.counts.clear();
        state.checked = false;
    }

    /// Chooses how breach checks reach Have I Been Pwned (default
    /// [`BreachMode::Auto`]: through the Passbox server when available).
    pub fn set_breach_mode(&self, mode: BreachMode) {
        self.lock_breach().mode = mode;
    }

    pub fn breach_mode(&self) -> BreachMode {
        self.lock_breach().mode
    }

    /// One range response, through the server or directly (see [`BreachMode`]).
    fn fetch_range(&self, prefix: &str) -> Result<String> {
        let (source, custom, mode) = {
            let state = self.lock_breach();
            (state.source.clone(), state.custom, state.mode)
        };
        if custom || mode == BreachMode::Direct {
            return source.range(prefix);
        }
        match self.with_token(|token| self.api.breach_range(token, prefix))? {
            Some(body) => Ok(body),
            None if mode == BreachMode::Auto => source.range(prefix),
            None => Err(Error::Network(
                "your Passbox server does not offer breach checks; choose a direct check in the settings"
                    .into(),
            )),
        }
    }

    pub(crate) fn lock_breach(&self) -> std::sync::MutexGuard<'_, BreachState> {
        self.breach
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn clear_breach_results(&self) {
        let mut state = self.lock_breach();
        state.counts.clear();
        state.checked = false;
        state.exposed.clear();
    }

    /// How often `password` appears in known data breaches (0 = not found),
    /// from Have I Been Pwned with k-anonymity: only the first 5 characters
    /// of the password's SHA-1 hash leave the device. Blocking; fails with
    /// [`Error::Network`] when the service cannot be reached. Ask the user
    /// before the first check (opt-in) and explain what is sent.
    pub fn breach_check(&self, password: &str) -> Result<u64> {
        if password.is_empty() {
            return Ok(0);
        }
        let (prefix, suffix) = breach::hash_parts(password);
        let full = format!("{prefix}{suffix}");
        if let Some(count) = self.lock_breach().counts.get(&full) {
            return Ok(*count);
        }
        // No lock while waiting for the network, so locking stays instant.
        let body = self.fetch_range(&prefix)?;
        let count = breach::count_in_range(&body, &suffix);
        self.lock_breach().counts.insert(full, count);
        Ok(count)
    }

    /// Checks the passwords of all logins outside the trash and returns
    /// those found in breaches, most breached first. One request per hash
    /// prefix; results stay in memory until the vault locks (and feed
    /// [`Client::item_health`]). Blocking and slow for large vaults: run it
    /// in the background.
    pub fn check_breached_items(&self) -> Result<Vec<BreachedItem>> {
        let mut by_hash: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for item in self.items()? {
            if item.data.category != ItemCategory::Login {
                continue;
            }
            if let Some(password) = item.data.field(field::PASSWORD) {
                by_hash
                    .entry(breach::hash_parts(password))
                    .or_default()
                    .push(item.id.clone());
            }
        }
        let mut ranges: HashMap<String, String> = HashMap::new();
        let mut found = Vec::new();
        for ((prefix, suffix), ids) in by_hash {
            let full = format!("{prefix}{suffix}");
            let known = self.lock_breach().counts.get(&full).copied();
            let count = match known {
                Some(count) => count,
                None => {
                    if !ranges.contains_key(&prefix) {
                        let body = self.fetch_range(&prefix)?;
                        ranges.insert(prefix.clone(), body);
                    }
                    let count = breach::count_in_range(&ranges[&prefix], &suffix);
                    self.lock_breach().counts.insert(full, count);
                    count
                }
            };
            if count > 0 {
                found.extend(
                    ids.into_iter()
                        .map(|item_id| BreachedItem { item_id, count }),
                );
            }
        }
        found.sort_by(|a, b| b.count.cmp(&a.count).then(a.item_id.cmp(&b.item_id)));
        self.lock_breach().checked = true;
        Ok(found)
    }

    pub(crate) fn known_breach_count(&self, password: &str) -> Option<u64> {
        let (prefix, suffix) = breach::hash_parts(password);
        self.lock_breach()
            .counts
            .get(&format!("{prefix}{suffix}"))
            .copied()
    }

    // --- Usage ----------------------------------------------------------------------

    fn load_usage(&self) -> Result<UsageMap> {
        let Some(bytes) = self.store.get(USAGE_KEY)? else {
            return Ok(UsageMap::default());
        };
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        // Unreadable data (another account, corruption) starts over.
        Ok(String::from_utf8(bytes)
            .ok()
            .and_then(|sealed| session.keyring.decrypt_local(USAGE_PURPOSE, &sealed).ok())
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default())
    }

    /// Records that an item was used on this device (copy, autofill or
    /// open). Device-local and encrypted; never sent to the server. Call it
    /// from the app and the AutoFill extension / Autofill service.
    pub fn record_item_use(&self, item_id: &str, kind: UsageKind) -> Result<ItemUsage> {
        self.item(item_id)?;
        let mut usage = self.load_usage()?;
        let now = now_ms();
        let entry = usage.items.entry(item_id.to_owned()).or_default();
        entry.last_used_at = now;
        if kind == UsageKind::Autofill {
            entry.last_autofilled_at = now;
        }
        entry.use_count += 1;
        let updated = *entry;
        // Forget items that no longer exist.
        let known: BTreeSet<String> = {
            let guard = self.lock_session();
            let session = guard.as_ref().ok_or(Error::Locked)?;
            session.items.keys().cloned().collect()
        };
        usage.items.retain(|id, _| known.contains(id));
        let json = serde_json::to_string(&usage)?;
        let sealed = {
            let guard = self.lock_session();
            let session = guard.as_ref().ok_or(Error::Locked)?;
            session.keyring.encrypt_local(USAGE_PURPOSE, &json)?
        };
        self.store.put(USAGE_KEY, sealed.as_bytes())?;
        Ok(updated)
    }

    /// This device's usage of an item, if it was used here.
    pub fn item_usage(&self, item_id: &str) -> Result<Option<ItemUsage>> {
        Ok(self.load_usage()?.items.get(item_id).copied())
    }

    /// This device's usage of all items, for sorting by "recently used".
    pub fn item_usages(&self) -> Result<BTreeMap<String, ItemUsage>> {
        Ok(self.load_usage()?.items)
    }

    // --- Health ---------------------------------------------------------------------

    /// The security check of one item: the same rules as
    /// [`Client::health`], plus the breach count if a breach check ran in
    /// this session. Items outside the trash only; other categories have no
    /// problems.
    pub fn item_health(&self, item_id: &str) -> Result<ItemHealth> {
        let item = self.item(item_id)?;
        let mut result = ItemHealth::default();
        if item.data.category != ItemCategory::Login || item.data.trashed_at().is_some() {
            return Ok(result);
        }
        let email = self.device_account()?.map(|a| a.email).unwrap_or_default();
        let items = self.items()?;
        let health = analyze_vault(&items, &[email.as_str()]);
        let password = item.data.field(field::PASSWORD);
        if let Some(password) = password {
            result.strength = Some(self.estimate_strength(password)?.score);
        }
        if health.weak.contains(&item.id) {
            result.problems.push(ItemProblem::Weak);
        }
        if let Some(group) = health.reused.iter().find(|g| g.contains(&item.id)) {
            result.problems.push(ItemProblem::Reused);
            result.reused_with = group.iter().filter(|id| **id != item.id).cloned().collect();
        }
        if health.insecure_urls.contains(&item.id) {
            result.problems.push(ItemProblem::InsecureUrl);
        }
        if health.without_totp.contains(&item.id) {
            result.problems.push(ItemProblem::MissingTotp);
        }
        if let Some(password) = password {
            result.breach_count = self.known_breach_count(password);
            if result.breach_count.is_some_and(|count| count > 0) {
                result.problems.push(ItemProblem::Breached);
            }
        }
        Ok(result)
    }

    // --- Bulk changes ---------------------------------------------------------------

    /// Moves items to the trash with one sync at the end. Returns the items
    /// that failed (for example changed on another device meanwhile).
    pub fn trash_items(&self, item_ids: &[String]) -> Result<Vec<BulkFailure>> {
        let now = now_ms();
        self.bulk(item_ids, |data| {
            if data.trashed_at().is_some() {
                return false;
            }
            data.set_trashed_at(Some(now));
            true
        })
    }

    /// Marks items as favorites (or not) with one sync at the end. Returns
    /// the items that failed.
    pub fn set_favorite(&self, item_ids: &[String], favorite: bool) -> Result<Vec<BulkFailure>> {
        self.bulk(item_ids, |data| {
            if data.favorite == favorite {
                return false;
            }
            data.favorite = favorite;
            true
        })
    }

    /// Applies `change` (which returns whether it changed anything) to each
    /// item, writes them one after another and syncs once.
    fn bulk(
        &self,
        item_ids: &[String],
        change: impl Fn(&mut ItemData) -> bool,
    ) -> Result<Vec<BulkFailure>> {
        let mut failures = Vec::new();
        let mut seen = BTreeSet::new();
        let mut wrote = false;
        for item_id in item_ids {
            if !seen.insert(item_id.as_str()) {
                continue;
            }
            let item = match self.item(item_id) {
                Ok(item) => item,
                Err(Error::Locked) => return Err(Error::Locked),
                Err(e) => {
                    failures.push(BulkFailure {
                        item_id: item_id.clone(),
                        error: e.to_string(),
                    });
                    continue;
                }
            };
            let mut data = item.data;
            if !change(&mut data) {
                continue;
            }
            match self.put_item(&item.vault_id, item_id, item.revision + 1, &data) {
                Ok(()) => wrote = true,
                Err(e @ (Error::Locked | Error::Offline)) => {
                    if wrote {
                        let _ = self.sync();
                    }
                    return Err(e);
                }
                Err(e) => failures.push(BulkFailure {
                    item_id: item_id.clone(),
                    error: e.to_string(),
                }),
            }
        }
        if wrote || !failures.is_empty() {
            self.sync()?;
        }
        Ok(failures)
    }
}

/// `fetched_at (8 bytes, big endian) || found (1 byte) || icon bytes`.
fn encode_icon(fetched_at: i64, icon: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = fetched_at.to_be_bytes().to_vec();
    bytes.push(u8::from(icon.is_some()));
    bytes.extend_from_slice(icon.unwrap_or_default());
    bytes
}

fn decode_icon(bytes: &[u8]) -> Option<(i64, Option<Vec<u8>>)> {
    let fetched_at = i64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
    match bytes.get(8)? {
        0 => Some((fetched_at, None)),
        1 => Some((fetched_at, Some(bytes[9..].to_vec()))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_cache_entries_round_trip() {
        assert_eq!(
            decode_icon(&encode_icon(42, Some(b"png"))),
            Some((42, Some(b"png".to_vec())))
        );
        assert_eq!(decode_icon(&encode_icon(7, None)), Some((7, None)));
        assert_eq!(decode_icon(b"short"), None);
    }

    #[test]
    fn problem_codes_are_stable() {
        assert_eq!(ItemProblem::InsecureUrl.as_str(), "insecure_url");
        assert_eq!(ItemProblem::MissingTotp.as_str(), "missing_totp");
    }
}
