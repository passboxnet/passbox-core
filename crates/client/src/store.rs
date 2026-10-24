//! Local storage for the client. Platforms provide their own implementation
//! (for example the iOS Keychain for the account record); [`FileStore`] and
//! [`MemoryStore`] cover desktop, CLI and tests.
//!
//! Everything the client stores is either public (email, KDF parameters) or
//! encrypted by the server-side format already (vault and item ciphertexts),
//! except the Secret Key in the account record. Implementations should keep
//! the `account` key in the platform's secure storage where available.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::{Error, Result};

/// Key under which the device account (including the Secret Key) is stored.
pub const ACCOUNT_KEY: &str = "account";
/// Key under which the encrypted offline cache is stored.
pub const CACHE_KEY: &str = "cache";

pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn put(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

/// In-memory store, for tests and ephemeral sessions.
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, Vec<u8>>>);

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().expect("store lock").get(key).cloned())
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.0
            .lock()
            .expect("store lock")
            .insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().expect("store lock").remove(key);
        Ok(())
    }
}

/// Stores each key in its own file inside a directory. Writes are atomic
/// (write to a temporary file, then rename) and files are private to the
/// current user on Unix.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(Self { dir })
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::Storage(format!("invalid store key {key:?}")));
        }
        Ok(self.dir.join(format!("{key}.json")))
    }
}

impl Store for FileStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match fs::read(self.path(key)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = self.path(key)?;
        let tmp = path.with_extension("json.tmp");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|e| Error::Storage(e.to_string()))?;
        file.write_all(value)
            .and_then(|()| file.sync_all())
            .map_err(|e| Error::Storage(e.to_string()))?;
        fs::rename(&tmp, &path).map_err(|e| Error::Storage(e.to_string()))
    }

    fn delete(&self, key: &str) -> Result<()> {
        match fs::remove_file(self.path(key)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Storage(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(store: &dyn Store) {
        assert_eq!(store.get("account").unwrap(), None);
        store.put("account", b"one").unwrap();
        store.put("account", b"two").unwrap();
        assert_eq!(store.get("account").unwrap().as_deref(), Some(&b"two"[..]));
        store.delete("account").unwrap();
        store.delete("account").unwrap();
        assert_eq!(store.get("account").unwrap(), None);
    }

    #[test]
    fn memory_store() {
        exercise(&MemoryStore::new());
    }

    #[test]
    fn file_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path()).unwrap();
        exercise(&store);
        assert!(store.put("../escape", b"x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_store_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path()).unwrap();
        store.put("account", b"secret").unwrap();
        let mode = fs::metadata(dir.path().join("account.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
}
