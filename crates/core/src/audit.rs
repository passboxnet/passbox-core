//! The organization audit log: the hash chain over its entries
//! and the signed events clients report.
//!
//! ```text
//! hash(n)  = hex(SHA-256("passbox/v1/audit-hash\0" || canonical("passbox/v1/audit-entry",
//!              prev_hash, org_id, seq, id, created_at, actor_id, actor_email, device_name,
//!              client_kind, ip, action, target_type, target_id, details, client_event,
//!              client_signature)))
//! prev_hash(n) = hash(n-1), "" for the first entry
//!
//! client event = { org_id, account_id, key_version, action, vault_id, item_id, field,
//!                  occurred_at, nonce }   signed with the account's Ed25519 key
//! ```
//!
//! The server writes the log and computes the chain with these functions;
//! anyone holding an export (JSON) can recompute it with
//! [`verify_chain`], in Rust, through WebAssembly or the FFI. The chain makes
//! later changes and deletions visible; it does not stop whoever controls
//! the database from rewriting everything after a point. Copy the head
//! (`seq`, `hash`) somewhere else regularly (export, SIEM) to anchor it.
//!
//! Viewing, copying and filling happen on the device, so clients report
//! them signed with the account key. The server checks the signature, but
//! so can every reader of the log: a server cannot invent such an event.
//! A modified client can stay silent, which no zero-knowledge design can
//! prevent.

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canon::{Reader, Writer};
use crate::identity::SignedBundle;
use crate::keyring::Keyring;
use crate::sharing::objects::{Canonical, Signed};
use crate::{Error, Result, random};

const HASH_PREFIX: &[u8] = b"passbox/v1/audit-hash\0";
/// At most this many client events per upload.
pub const MAX_CLIENT_EVENTS: usize = 200;

/// One entry of an organization's audit log, as the server stores it and
/// exports it (`GET /api/v1/orgs/{id}/audit`, CSV/JSON export, events API).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub org_id: String,
    pub seq: u64,
    pub id: String,
    pub created_at: i64,
    pub actor_id: String,
    pub actor_email: String,
    pub device_name: String,
    pub client_kind: String,
    pub ip: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    /// JSON object with action-specific details, exactly as hashed.
    pub details: String,
    /// Base64url canonical [`ClientEvent`] for client-reported events, or "".
    #[serde(default)]
    pub client_event: String,
    #[serde(default)]
    pub client_signature: String,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditRecord {
    /// The hash this entry must have, given its `prev_hash`.
    pub fn compute_hash(&self) -> String {
        let canonical = Writer::new("passbox/v1/audit-entry")
            .str(&self.prev_hash)
            .str(&self.org_id)
            .u64(self.seq)
            .str(&self.id)
            .i64(self.created_at)
            .str(&self.actor_id)
            .str(&self.actor_email)
            .str(&self.device_name)
            .str(&self.client_kind)
            .str(&self.ip)
            .str(&self.action)
            .str(&self.target_type)
            .str(&self.target_id)
            .str(&self.details)
            .str(&self.client_event)
            .str(&self.client_signature)
            .finish();
        let mut hasher = Sha256::new();
        hasher.update(HASH_PREFIX);
        hasher.update(&canonical);
        HEXLOWER.encode(&hasher.finalize())
    }
}

/// Result of checking a sequence of entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCheck {
    /// Every entry has the right hash, links to the one before and the
    /// sequence numbers have no gaps.
    pub valid: bool,
    pub length: u64,
    #[serde(default)]
    pub first_seq: Option<u64>,
    #[serde(default)]
    pub last_seq: Option<u64>,
    /// Hash of the last entry checked: the head to anchor elsewhere.
    #[serde(default)]
    pub head_hash: Option<String>,
    /// Sequence number of the first entry that does not verify.
    #[serde(default)]
    pub broken_at: Option<u64>,
    #[serde(default)]
    pub problem: Option<String>,
}

/// Checks entries in ascending order. `anchor` is the `prev_hash` the
/// first entry must have: "" when it is entry 1, the hash of the entry
/// before otherwise (for example the head of an earlier export, or the
/// hash recorded when older entries were deleted by retention). `None`
/// accepts whatever the first entry names.
pub fn verify_chain(records: &[AuditRecord], anchor: Option<&str>) -> ChainCheck {
    let check = ChainCheck {
        valid: true,
        length: records.len() as u64,
        first_seq: records.first().map(|r| r.seq),
        last_seq: records.last().map(|r| r.seq),
        head_hash: records.last().map(|r| r.hash.clone()),
        broken_at: None,
        problem: None,
    };
    let fail = |seq: u64, problem: &str| ChainCheck {
        valid: false,
        broken_at: Some(seq),
        problem: Some(problem.to_owned()),
        ..check.clone()
    };
    let Some(first) = records.first() else {
        return check;
    };
    if first.seq == 1 && !first.prev_hash.is_empty() {
        return fail(1, "the first entry must not link to an earlier one");
    }
    if let Some(anchor) = anchor
        && first.prev_hash != anchor
    {
        return fail(
            first.seq,
            "the first entry does not continue the known head",
        );
    }
    let org_id = &first.org_id;
    let mut previous: Option<&AuditRecord> = None;
    for record in records {
        if &record.org_id != org_id {
            return fail(record.seq, "entries of different organizations");
        }
        if let Some(prev) = previous {
            if record.seq != prev.seq + 1 {
                return fail(prev.seq + 1, "entries are missing");
            }
            if record.prev_hash != prev.hash {
                return fail(record.seq, "the entry does not link to the one before");
            }
        }
        if record.compute_hash() != record.hash {
            return fail(record.seq, "the entry was changed");
        }
        if !record.client_event.is_empty() && record.client_signature.is_empty() {
            return fail(record.seq, "a client event without signature");
        }
        previous = Some(record);
    }
    check
}

// --- Client events ---------------------------------------------------------------------

/// What a client did with an item of an organization's vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAction {
    /// Opened the item's details.
    ItemViewed,
    /// Showed a hidden field (password, card number, ...).
    SecretRevealed,
    /// Copied a field to the clipboard.
    ItemCopied,
    /// Filled the item into a website or app.
    ItemFilled,
}

impl ClientAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ItemViewed => "item_viewed",
            Self::SecretRevealed => "secret_revealed",
            Self::ItemCopied => "item_copied",
            Self::ItemFilled => "item_filled",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "item_viewed" => Ok(Self::ItemViewed),
            "secret_revealed" => Ok(Self::SecretRevealed),
            "item_copied" => Ok(Self::ItemCopied),
            "item_filled" => Ok(Self::ItemFilled),
            other => Err(Error::InvalidData(format!(
                "unknown client action {other:?}"
            ))),
        }
    }
}

/// A client-reported event, signed with the account key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEvent {
    pub org_id: String,
    pub account_id: String,
    pub key_version: u32,
    pub action: ClientAction,
    pub vault_id: String,
    pub item_id: String,
    /// The field concerned (`password`, `username`, `totp`, ...), or "".
    pub field: String,
    pub occurred_at: i64,
    /// Random, so the server can drop duplicates and replays.
    pub nonce: [u8; 16],
}

impl Canonical for ClientEvent {
    const TAG: &'static str = "passbox/v1/client-audit-event";
    fn encode(&self, w: &mut Writer) {
        w.str(&self.org_id)
            .str(&self.account_id)
            .u64(u64::from(self.key_version))
            .str(self.action.as_str())
            .str(&self.vault_id)
            .str(&self.item_id)
            .str(&self.field)
            .i64(self.occurred_at)
            .bytes(&self.nonce);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let event = Self {
            org_id: r.string()?,
            account_id: r.string()?,
            key_version: r.u32()?,
            action: ClientAction::parse(r.str()?)?,
            vault_id: r.string()?,
            item_id: r.string()?,
            field: r.string()?,
            occurred_at: r.i64()?,
            nonce: r.array()?,
        };
        if event.field.len() > 64
            || !event
                .field
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(Error::InvalidData("invalid field name".into()));
        }
        Ok(event)
    }
}

/// What a client wants to report (input to [`Keyring::sign_client_events`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientEventInput {
    pub action: ClientAction,
    pub vault_id: String,
    pub item_id: String,
    #[serde(default)]
    pub field: String,
    pub occurred_at: i64,
}

/// A signed client event (`POST /api/v1/orgs/{id}/audit/client-events`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedClientEvent {
    pub event: String,
    pub signature: String,
}

/// Parses a client event and checks its signature against the account's
/// published bundle.
pub fn verify_client_event(
    bundle: &SignedBundle,
    signed: &SignedClientEvent,
) -> Result<ClientEvent> {
    let event = Signed::<ClientEvent>::parse(&signed.event, &signed.signature)?;
    if event.value.account_id != bundle.bundle.account_id
        || event.value.key_version != bundle.bundle.key_version
    {
        return Err(Error::InvalidData(
            "the event was signed for another account or key".into(),
        ));
    }
    event.verify(&bundle.bundle.sig_pk)?;
    Ok(event.value)
}

impl Keyring {
    /// Signs events about items of an organization's vaults with this
    /// account's key.
    pub fn sign_client_events(
        &self,
        org_id: &str,
        events: &[ClientEventInput],
    ) -> Result<Vec<SignedClientEvent>> {
        if events.len() > MAX_CLIENT_EVENTS {
            return Err(Error::InvalidData("too many events at once".into()));
        }
        let keys = self.account_keys()?;
        events
            .iter()
            .map(|input| {
                let signed = Signed::sign(
                    ClientEvent {
                        org_id: org_id.to_owned(),
                        account_id: self.account_id().to_owned(),
                        key_version: keys.bundle.bundle.key_version,
                        action: input.action,
                        vault_id: input.vault_id.clone(),
                        item_id: input.item_id.clone(),
                        field: input.field.clone(),
                        occurred_at: input.occurred_at,
                        nonce: random::bytes::<16>()?,
                    },
                    &keys.sig,
                );
                Ok(SignedClientEvent {
                    event: signed.encoded(),
                    signature: signed.encoded_signature(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::SymmetricKey;
    use crate::id;

    fn record(seq: u64, prev: &str) -> AuditRecord {
        let mut r = AuditRecord {
            org_id: "org".into(),
            seq,
            id: format!("e{seq}"),
            created_at: 1_000 + seq as i64,
            actor_id: "a".into(),
            actor_email: "a@example.com".into(),
            device_name: "Firefox".into(),
            client_kind: "web".into(),
            ip: "127.0.0.1".into(),
            action: "member_invited".into(),
            target_type: "account".into(),
            target_id: "b".into(),
            details: "{}".into(),
            client_event: String::new(),
            client_signature: String::new(),
            prev_hash: prev.into(),
            hash: String::new(),
        };
        r.hash = r.compute_hash();
        r
    }

    fn chain(n: u64) -> Vec<AuditRecord> {
        let mut out: Vec<AuditRecord> = Vec::new();
        for seq in 1..=n {
            let prev = out.last().map_or(String::new(), |r| r.hash.clone());
            out.push(record(seq, &prev));
        }
        out
    }

    #[test]
    fn an_intact_chain_verifies() {
        let entries = chain(5);
        let check = verify_chain(&entries, Some(""));
        assert!(check.valid, "{check:?}");
        assert_eq!(check.length, 5);
        assert_eq!(check.head_hash.as_deref(), Some(entries[4].hash.as_str()));
        // A later export continues from the head of an earlier one.
        assert!(verify_chain(&entries[2..], Some(&entries[1].hash)).valid);
        assert!(!verify_chain(&entries[2..], Some(&entries[0].hash)).valid);
        assert!(verify_chain(&[], None).valid);
    }

    #[test]
    fn changes_and_deletions_are_detected() {
        let mut changed = chain(4);
        changed[2].actor_email = "someone@else".into();
        assert_eq!(verify_chain(&changed, Some("")).broken_at, Some(3));

        let mut deleted = chain(4);
        deleted.remove(1);
        assert_eq!(verify_chain(&deleted, Some("")).broken_at, Some(2));

        let mut relinked = chain(4);
        relinked[3].prev_hash = "x".into();
        relinked[3].hash = relinked[3].compute_hash();
        assert_eq!(verify_chain(&relinked, Some("")).broken_at, Some(4));
    }

    #[test]
    fn every_field_is_covered_by_the_hash() {
        let base = record(1, "");
        type Change = Box<dyn Fn(&mut AuditRecord)>;
        let variants: Vec<Change> = vec![
            Box::new(|r| r.org_id.push('x')),
            Box::new(|r| r.seq += 1),
            Box::new(|r| r.id.push('x')),
            Box::new(|r| r.created_at += 1),
            Box::new(|r| r.actor_id.push('x')),
            Box::new(|r| r.actor_email.push('x')),
            Box::new(|r| r.device_name.push('x')),
            Box::new(|r| r.client_kind.push('x')),
            Box::new(|r| r.ip.push('x')),
            Box::new(|r| r.action.push('x')),
            Box::new(|r| r.target_type.push('x')),
            Box::new(|r| r.target_id.push('x')),
            Box::new(|r| r.details.push(' ')),
            Box::new(|r| r.client_event.push('x')),
            Box::new(|r| r.client_signature.push('x')),
            Box::new(|r| r.prev_hash.push('x')),
        ];
        for change in variants {
            let mut r = base.clone();
            change(&mut r);
            assert_ne!(r.compute_hash(), base.hash);
        }
    }

    #[test]
    fn client_events_are_signed_by_the_account() {
        let auk = SymmetricKey::generate().unwrap();
        let (mut keyring, _) = Keyring::create(&auk, &id::new_id().unwrap()).unwrap();
        let upload = keyring.create_account_keys(1).unwrap();
        let bundle = SignedBundle::parse(&upload.bundle, &upload.bundle_signature).unwrap();
        let events = keyring
            .sign_client_events(
                "org",
                &[ClientEventInput {
                    action: ClientAction::ItemCopied,
                    vault_id: "v".into(),
                    item_id: "i".into(),
                    field: "password".into(),
                    occurred_at: 5,
                }],
            )
            .unwrap();
        let event = verify_client_event(&bundle, &events[0]).unwrap();
        assert_eq!(event.action, ClientAction::ItemCopied);
        assert_eq!(event.account_id, keyring.account_id());

        // Another account's key does not verify it.
        let (mut other, _) = Keyring::create(&auk, &id::new_id().unwrap()).unwrap();
        let other_upload = other.create_account_keys(1).unwrap();
        let other_bundle =
            SignedBundle::parse(&other_upload.bundle, &other_upload.bundle_signature).unwrap();
        assert!(verify_client_event(&other_bundle, &events[0]).is_err());

        // A tampered event does not verify.
        let mut tampered = events[0].clone();
        tampered.signature = events[0].signature.replacen('A', "B", 1);
        if tampered.signature != events[0].signature {
            assert!(verify_client_event(&bundle, &tampered).is_err());
        }
        assert!(
            keyring
                .sign_client_events(
                    "org",
                    &vec![
                        ClientEventInput {
                            action: ClientAction::ItemViewed,
                            vault_id: "v".into(),
                            item_id: "i".into(),
                            field: String::new(),
                            occurred_at: 1,
                        };
                        MAX_CLIENT_EVENTS + 1
                    ]
                )
                .is_err()
        );
    }
}
