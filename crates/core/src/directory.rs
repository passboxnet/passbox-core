//! Key directory (wave A4, first version): an append-only, hash-chained log
//! of published public key bundles with a signed head.
//!
//! ```text
//! entry_hash(n) = SHA-256(object-hash prefix || canonical(
//!     "passbox/v1/key-log-entry", n, account_id, key_version, bundle_hash, entry_hash(n-1)))
//! entry_hash(0) = 32 zero bytes
//! head          = canonical("passbox/v1/key-log-head", size, entry_hash(size), timestamp)
//!                 signed with the server's Ed25519 log key
//! ```
//!
//! Clients keep a [`DirectoryState`]: the log key (trusted on first use),
//! the last verified head and the bundle hashes of accounts they looked up
//! (pins). [`DirectoryState::verify_lookup`] accepts a bundle only if
//!
//! 1. the head is signed by the pinned log key and is not smaller than the
//!    last verified head (no rollback),
//! 2. the entries returned with it form an unbroken hash chain that passes
//!    through the last verified head (consistency: the old log is a prefix of
//!    the new one) and ends at the new head (inclusion),
//! 3. the bundle's entry is in that chain and no later entry for the same
//!    account follows it (the bundle is the account's current key), and
//! 4. the bundle is self-signed.
//!
//! A bundle hash that differs from the pin is reported as
//! [`LookupStatus::Changed`]; callers surface it and must not seal new
//! secrets to the new key until the user accepted the change.
//!
//! What this does and does not give: a server cannot show one client a key
//! and later pretend it never did (the log is append-only for every client
//! that saw it), and cannot replace a key a client pinned without that
//! client noticing. It can still show *different* logs to clients that never
//! compare heads (split view) and can withhold entries. Gossiping heads
//! between clients or external witnesses would close this; see
//! `docs/architecture/sharing.md`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canon::{Reader, Writer};
use crate::identity::{self, HASH_LEN, SIG_PK_LEN, SignatureKey, SignedBundle};
use crate::{Error, Result, encoding};

const ENTRY_TAG: &str = "passbox/v1/key-log-entry";
const HEAD_TAG: &str = "passbox/v1/key-log-head";
/// Most entries a single lookup may need to check.
pub const MAX_LOOKUP_ENTRIES: usize = 10_000;

/// One published bundle in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub seq: u64,
    pub account_id: String,
    pub key_version: u32,
    /// Base64url of the bundle hash.
    pub bundle_hash: String,
    /// Base64url of the previous entry hash.
    pub prev_hash: String,
}

impl LogEntry {
    /// Computes this entry's hash.
    pub fn hash(&self) -> Result<[u8; HASH_LEN]> {
        let bundle_hash = decode_hash(&self.bundle_hash)?;
        let prev_hash = decode_hash(&self.prev_hash)?;
        Ok(entry_hash(
            self.seq,
            &self.account_id,
            self.key_version,
            &bundle_hash,
            &prev_hash,
        ))
    }
}

/// Hash of a log entry (see the module docs).
pub fn entry_hash(
    seq: u64,
    account_id: &str,
    key_version: u32,
    bundle_hash: &[u8; HASH_LEN],
    prev_hash: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    identity::object_hash(
        &Writer::new(ENTRY_TAG)
            .u64(seq)
            .str(account_id)
            .u64(u64::from(key_version))
            .bytes(bundle_hash)
            .bytes(prev_hash)
            .finish(),
    )
}

fn decode_hash(value: &str) -> Result<[u8; HASH_LEN]> {
    encoding::decode(value)?
        .try_into()
        .map_err(|_| Error::InvalidData("hash must be 32 bytes".into()))
}

/// The state of the log at one point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogHead {
    pub size: u64,
    pub root: [u8; HASH_LEN],
    pub timestamp: i64,
}

impl LogHead {
    pub fn to_canonical(&self) -> Vec<u8> {
        Writer::new(HEAD_TAG)
            .u64(self.size)
            .bytes(&self.root)
            .i64(self.timestamp)
            .finish()
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, HEAD_TAG)?;
        let head = Self {
            size: r.u64()?,
            root: r.array()?,
            timestamp: r.i64()?,
        };
        r.finish()?;
        Ok(head)
    }
}

/// A head as served by the API. All binary values are Base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedHead {
    /// Canonical [`LogHead`].
    pub head: String,
    pub signature: String,
    /// The server's log public key.
    pub log_key: String,
}

impl SignedHead {
    /// Checks the signature against the key the head names and parses it.
    pub fn verify(&self) -> Result<(LogHead, [u8; SIG_PK_LEN])> {
        let canonical = encoding::decode(&self.head)?;
        let key: [u8; SIG_PK_LEN] = encoding::decode(&self.log_key)?
            .try_into()
            .map_err(|_| Error::InvalidData("log key must be 32 bytes".into()))?;
        identity::verify(&key, &canonical, &encoding::decode(&self.signature)?)?;
        Ok((LogHead::from_canonical(&canonical)?, key))
    }
}

/// The server's log signing key.
pub struct LogSigner(SignatureKey);

impl LogSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SignatureKey::from_seed(seed))
    }

    pub fn public_key(&self) -> [u8; SIG_PK_LEN] {
        self.0.public_key()
    }

    pub fn sign(&self, head: &LogHead) -> SignedHead {
        let canonical = head.to_canonical();
        SignedHead {
            signature: encoding::encode(&self.0.sign(&canonical)),
            head: encoding::encode(&canonical),
            log_key: encoding::encode(&self.public_key()),
        }
    }
}

/// The answer to `GET /api/v1/keys/{account_id}?since=<size>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupResponse {
    pub bundle: String,
    pub bundle_signature: String,
    /// Sequence number of the bundle's log entry.
    pub seq: u64,
    /// Entries from `seq` (first lookup) or from `min(seq, since + 1)` to the
    /// head, in order.
    pub entries: Vec<LogEntry>,
    pub head: SignedHead,
}

/// What a client remembers about an account's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pin {
    pub key_version: u32,
    /// Base64url bundle hash.
    pub bundle_hash: String,
    pub fingerprint: String,
    /// Sequence number of the entry the pin was verified at, if it came from
    /// the directory (pins from organization attestations have none).
    #[serde(default)]
    pub seq: Option<u64>,
}

/// The client's view of the key directory. Serialize it to persist it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryState {
    /// Base64url log public key, pinned on first use.
    #[serde(default)]
    pub log_key: Option<String>,
    #[serde(default)]
    pub size: u64,
    /// Base64url hash of the last verified head (`entry_hash(size)`).
    #[serde(default)]
    pub root: String,
}

/// Result of [`DirectoryState::verify_lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupStatus {
    /// First time this account's key was seen.
    New,
    /// Same key as pinned.
    Unchanged,
    /// A different key than the pinned one.
    Changed { previous: Pin },
}

#[derive(Debug, Clone)]
pub struct VerifiedLookup {
    pub bundle: SignedBundle,
    pub seq: u64,
    pub status: LookupStatus,
}

impl DirectoryState {
    /// Verifies a lookup response (see the module docs) and advances the
    /// verified head. `pin` is the caller's pin for the account, if any; the
    /// caller stores the new pin from the returned bundle after deciding how
    /// to treat a change.
    pub fn verify_lookup(
        &mut self,
        account_id: &str,
        response: &LookupResponse,
        pin: Option<&Pin>,
    ) -> Result<VerifiedLookup> {
        let bundle = SignedBundle::parse(&response.bundle, &response.bundle_signature)?;
        if bundle.bundle.account_id != account_id {
            return Err(Error::InvalidData(
                "directory returned a bundle for another account".into(),
            ));
        }
        let (head, log_key) = response.head.verify()?;
        let log_key = encoding::encode(&log_key);
        if let Some(pinned) = &self.log_key
            && *pinned != log_key
        {
            return Err(Error::InvalidData("the server's log key changed".into()));
        }
        self.check_chain(&head, &response.entries)?;

        // The bundle's entry and nothing newer for the account.
        let bundle_hash = encoding::encode(&bundle.hash());
        let entry = response
            .entries
            .iter()
            .find(|e| e.seq == response.seq)
            .ok_or_else(|| Error::InvalidData("bundle entry missing from the proof".into()))?;
        if entry.account_id != account_id
            || entry.key_version != bundle.bundle.key_version
            || entry.bundle_hash != bundle_hash
        {
            return Err(Error::InvalidData(
                "bundle does not match its log entry".into(),
            ));
        }
        if response
            .entries
            .iter()
            .any(|e| e.seq > response.seq && e.account_id == account_id)
        {
            return Err(Error::InvalidData(
                "directory returned an outdated key".into(),
            ));
        }

        self.log_key = Some(log_key);
        self.size = head.size;
        self.root = encoding::encode(&head.root);
        let status = match pin {
            None => LookupStatus::New,
            Some(pin) if pin.bundle_hash == bundle_hash => LookupStatus::Unchanged,
            Some(pin) => LookupStatus::Changed {
                previous: pin.clone(),
            },
        };
        Ok(VerifiedLookup {
            bundle,
            seq: response.seq,
            status,
        })
    }

    /// Checks that `entries` chain from a trusted point to `head` and pass
    /// through the last verified head.
    fn check_chain(&self, head: &LogHead, entries: &[LogEntry]) -> Result<()> {
        let broken = |what: &str| Error::InvalidData(format!("key log proof is invalid: {what}"));
        if head.size < self.size {
            return Err(broken("the log shrank"));
        }
        if entries.is_empty() || entries.len() > MAX_LOOKUP_ENTRIES {
            return Err(broken("wrong number of entries"));
        }
        let first = entries[0].seq;
        let mut prev = if self.size == 0 {
            // First contact: trust the first entry's link (trust on first use).
            decode_hash(&entries[0].prev_hash)?
        } else if first == self.size + 1 {
            decode_hash(&self.root)?
        } else if first <= self.size {
            decode_hash(&entries[0].prev_hash)?
        } else {
            return Err(broken("entries do not reach the verified head"));
        };
        let verified_root = if self.size > 0 {
            Some(decode_hash(&self.root)?)
        } else {
            None
        };
        let mut passed_verified = self.size == 0 || first == self.size + 1;
        for (i, entry) in entries.iter().enumerate() {
            if entry.seq != first + i as u64 || entry.seq == 0 {
                return Err(broken("entries are not consecutive"));
            }
            if decode_hash(&entry.prev_hash)? != prev {
                return Err(broken("broken hash chain"));
            }
            prev = entry.hash()?;
            if entry.seq == self.size && Some(prev) == verified_root {
                passed_verified = true;
            } else if entry.seq == self.size {
                return Err(broken("the log was rewritten (fork)"));
            }
        }
        let last = first + entries.len() as u64 - 1;
        if !passed_verified || last != head.size || prev != head.root {
            return Err(broken("entries do not end at the signed head"));
        }
        Ok(())
    }
}

/// Builds the entry that appends a bundle to a log whose last entry hash is
/// `prev` (`[0; 32]` for an empty log).
pub fn append(
    prev: &[u8; HASH_LEN],
    seq: u64,
    account_id: &str,
    key_version: u32,
    bundle_hash: &[u8; HASH_LEN],
) -> LogEntry {
    LogEntry {
        seq,
        account_id: account_id.to_owned(),
        key_version,
        bundle_hash: encoding::encode(bundle_hash),
        prev_hash: encoding::encode(prev),
    }
}

/// Convenience: a map from account ID to pin, as clients persist it.
pub type Pins = BTreeMap<String, Pin>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{EncryptionKey, SignatureKey};

    struct TestLog {
        signer: LogSigner,
        entries: Vec<LogEntry>,
        bundles: Vec<SignedBundle>,
    }

    impl TestLog {
        fn new() -> Self {
            Self {
                signer: LogSigner::from_seed(&[5; 32]),
                entries: Vec::new(),
                bundles: Vec::new(),
            }
        }

        fn publish(&mut self, account_id: &str, key_version: u32) -> SignedBundle {
            let bundle = SignedBundle::create(
                account_id,
                key_version,
                &EncryptionKey::generate().unwrap(),
                &SignatureKey::generate().unwrap(),
                1,
            );
            let prev = self.root();
            let entry = append(
                &prev,
                self.entries.len() as u64 + 1,
                account_id,
                key_version,
                &bundle.hash(),
            );
            self.entries.push(entry);
            self.bundles.push(bundle.clone());
            bundle
        }

        fn root(&self) -> [u8; 32] {
            self.entries.last().map_or([0; 32], |e| e.hash().unwrap())
        }

        fn lookup(&self, account_id: &str, since: u64) -> LookupResponse {
            let index = self
                .entries
                .iter()
                .rposition(|e| e.account_id == account_id)
                .unwrap();
            let seq = index as u64 + 1;
            let from = if since == 0 { seq } else { seq.min(since + 1) };
            LookupResponse {
                bundle: self.bundles[index].encoded(),
                bundle_signature: self.bundles[index].encoded_signature(),
                seq,
                entries: self.entries[from as usize - 1..].to_vec(),
                head: self.signer.sign(&LogHead {
                    size: self.entries.len() as u64,
                    root: self.root(),
                    timestamp: 1,
                }),
            }
        }
    }

    #[test]
    fn lookups_verify_and_advance_the_head() {
        let mut log = TestLog::new();
        let alice = log.publish("alice", 1);
        log.publish("bob", 1);
        let mut state = DirectoryState::default();
        let found = state
            .verify_lookup("alice", &log.lookup("alice", 0), None)
            .unwrap();
        assert_eq!(found.bundle, alice);
        assert_eq!(found.status, LookupStatus::New);
        assert_eq!(state.size, 2);

        log.publish("carol", 1);
        log.publish("dave", 1);
        // Bob's entry lies before the verified head; the proof re-checks the
        // chain through it.
        let found = state
            .verify_lookup("bob", &log.lookup("bob", state.size), None)
            .unwrap();
        assert_eq!(found.bundle.bundle.account_id, "bob");
        assert_eq!(state.size, 4);
        // Pinned keys stay unchanged.
        let pin = Pin {
            key_version: 1,
            bundle_hash: encoding::encode(&alice.hash()),
            fingerprint: alice.fingerprint(),
            seq: Some(1),
        };
        let again = state
            .verify_lookup("alice", &log.lookup("alice", state.size), Some(&pin))
            .unwrap();
        assert_eq!(again.status, LookupStatus::Unchanged);
    }

    #[test]
    fn key_changes_are_reported() {
        let mut log = TestLog::new();
        let alice = log.publish("alice", 1);
        let mut state = DirectoryState::default();
        state
            .verify_lookup("alice", &log.lookup("alice", 0), None)
            .unwrap();
        let pin = Pin {
            key_version: 1,
            bundle_hash: encoding::encode(&alice.hash()),
            fingerprint: alice.fingerprint(),
            seq: Some(1),
        };
        log.publish("alice", 2);
        let found = state
            .verify_lookup("alice", &log.lookup("alice", state.size), Some(&pin))
            .unwrap();
        assert!(matches!(found.status, LookupStatus::Changed { .. }));
    }

    #[test]
    fn outdated_keys_are_rejected() {
        let mut log = TestLog::new();
        log.publish("alice", 1);
        log.publish("alice", 2);
        let mut response = log.lookup("alice", 0);
        // Present the first key with a proof that includes the second.
        response.bundle = log.bundles[0].encoded();
        response.bundle_signature = log.bundles[0].encoded_signature();
        response.seq = 1;
        response.entries = log.entries.clone();
        let mut state = DirectoryState::default();
        assert!(state.verify_lookup("alice", &response, None).is_err());
    }

    #[test]
    fn forks_rollbacks_and_forged_heads_are_rejected() {
        let mut log = TestLog::new();
        log.publish("alice", 1);
        log.publish("bob", 1);
        let mut state = DirectoryState::default();
        state
            .verify_lookup("bob", &log.lookup("bob", 0), None)
            .unwrap();

        // A different history of the same length (fork).
        let mut fork = TestLog::new();
        fork.publish("alice", 1);
        fork.publish("bob", 1);
        fork.publish("carol", 1);
        assert!(
            state
                .clone()
                .verify_lookup("carol", &fork.lookup("carol", state.size), None)
                .is_err()
        );
        let mut alice_fork = fork.lookup("alice", state.size);
        alice_fork.entries = fork.entries.clone();
        assert!(
            state
                .clone()
                .verify_lookup("alice", &alice_fork, None)
                .is_err()
        );

        // Rollback: a smaller head.
        let mut small = TestLog::new();
        small.publish("alice", 1);
        let mut rolled_back = state.clone();
        rolled_back.root = encoding::encode(&log.root());
        assert!(
            rolled_back
                .verify_lookup("alice", &small.lookup("alice", 0), None)
                .is_err()
        );

        // A head signed by another log key.
        log.publish("carol", 1);
        let mut response = log.lookup("carol", state.size);
        response.head = LogSigner::from_seed(&[6; 32]).sign(&LogHead {
            size: 3,
            root: log.root(),
            timestamp: 1,
        });
        assert!(
            state
                .clone()
                .verify_lookup("carol", &response, None)
                .is_err()
        );

        // Tampered entry.
        let mut response = log.lookup("carol", state.size);
        response.entries[0].account_id = "mallory".into();
        assert!(
            state
                .clone()
                .verify_lookup("carol", &response, None)
                .is_err()
        );

        // The genuine extension still verifies.
        state
            .verify_lookup("carol", &log.lookup("carol", state.size), None)
            .unwrap();
        assert_eq!(state.size, 3);
    }

    #[test]
    fn bundle_must_match_its_entry() {
        let mut log = TestLog::new();
        log.publish("alice", 1);
        log.publish("bob", 1);
        let mut response = log.lookup("alice", 0);
        response.bundle = log.bundles[1].encoded();
        response.bundle_signature = log.bundles[1].encoded_signature();
        let mut state = DirectoryState::default();
        assert!(state.verify_lookup("alice", &response, None).is_err());
    }
}
