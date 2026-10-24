//! Signed grants for AI agents (wave F7, concept K1/K12 in
//! `docs/planning/ai-native.md`, §6.4).
//!
//! This module only holds the cryptographic part: the canonical encoding of
//! a grant request and of the human's decision, and the signature over the
//! decision. The grant engine, tools and output redaction live in
//! `crates/client` (the agent broker); no AI code is in the core.
//!
//! ```text
//! request  = canonical("passbox/v1/agent-grant-request", id, principal_kind, principal_id,
//!                      client_name, on_behalf_of, [(item_id, vault_id)], [action], [command],
//!                      [path], reason, ttl_ms, max_uses, created_at, nonce)
//! decision = canonical("passbox/v1/agent-grant-decision", object_hash(request), approved,
//!                      not_after, max_uses, approver_id, decided_at)
//! sig      = Ed25519(on_behalf_of.sig_sk, decision)
//! ```
//!
//! The requesting broker keeps the exact request bytes and accepts a
//! decision only if it covers their hash and is signed by the account the
//! request was made on behalf of. The approving device shows what it signs
//! (it parses the same bytes), so a server relaying the request can neither
//! show the person a different request nor approve one by itself.

use crate::canon::{Reader, Writer};
use crate::identity::{self, HASH_LEN, SIG_PK_LEN, SIGNATURE_LEN};
use crate::keyring::Keyring;
use crate::{Error, Result, encoding, id, random};

const REQUEST_TAG: &str = "passbox/v1/agent-grant-request";
const DECISION_TAG: &str = "passbox/v1/agent-grant-decision";

/// Upper bounds that keep requests readable in an approval dialog.
pub const MAX_ITEMS: usize = 50;
pub const MAX_PATTERNS: usize = 20;
pub const MAX_TEXT_LEN: usize = 2000;
/// Longest grant a person can approve (8 hours).
pub const MAX_TTL_MS: i64 = 8 * 60 * 60 * 1000;

/// Actions a grant can cover. `reveal` (handing a secret to the agent) is
/// deliberately not one of them.
pub const ACTIONS: &[&str] = &["run", "inject", "create"];

/// Who asks: a signed-in CLI session of the account, or a service account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    Session,
    Service,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Service => "service",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "session" => Ok(Self::Session),
            "service" => Ok(Self::Service),
            _ => Err(Error::InvalidData(format!("unknown principal {value:?}"))),
        }
    }
}

/// An item a grant covers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrantItem {
    pub item_id: String,
    pub vault_id: String,
}

/// What an agent asks the person to allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    pub id: String,
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    /// The MCP client's name as it introduced itself (for example
    /// "claude-code"). Self-reported, shown as such.
    pub client_name: String,
    pub on_behalf_of: String,
    pub items: Vec<GrantItem>,
    pub actions: Vec<String>,
    /// Allowed commands (exact command lines or prefixes ending in `*`).
    /// Empty means every command needs its own approval.
    pub commands: Vec<String>,
    /// Allowed output paths for `inject`.
    pub paths: Vec<String>,
    /// The agent's reason. Untrusted text.
    pub reason: String,
    pub ttl_ms: i64,
    /// 0 for unlimited uses within the time limit.
    pub max_uses: u64,
    /// Unix milliseconds.
    pub created_at: i64,
    pub nonce: [u8; 16],
}

fn check_text(what: &str, value: &str) -> Result<()> {
    if value.len() > MAX_TEXT_LEN || value.chars().any(|c| c.is_control() && c != '\n') {
        return Err(Error::InvalidData(format!(
            "{what} is too long or contains control characters"
        )));
    }
    Ok(())
}

impl GrantRequest {
    /// A new request with a fresh ID and nonce. Fails for empty or
    /// oversized requests and unknown actions.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal_kind: PrincipalKind,
        principal_id: &str,
        client_name: &str,
        on_behalf_of: &str,
        items: Vec<GrantItem>,
        actions: Vec<String>,
        commands: Vec<String>,
        paths: Vec<String>,
        reason: &str,
        ttl_ms: i64,
        max_uses: u64,
        created_at: i64,
    ) -> Result<Self> {
        let mut request = Self {
            id: id::new_id()?,
            principal_kind,
            principal_id: principal_id.to_owned(),
            client_name: client_name.chars().take(100).collect(),
            on_behalf_of: on_behalf_of.to_owned(),
            items,
            actions,
            commands,
            paths,
            reason: reason.trim().to_owned(),
            ttl_ms,
            max_uses,
            created_at,
            nonce: random::bytes()?,
        };
        request.items.sort();
        request.items.dedup();
        request.actions.sort();
        request.actions.dedup();
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        if self.items.is_empty() || self.items.len() > MAX_ITEMS {
            return Err(Error::InvalidData(format!(
                "a grant covers 1 to {MAX_ITEMS} items"
            )));
        }
        if self
            .items
            .iter()
            .any(|i| !id::is_valid_id(&i.item_id) || !id::is_valid_id(&i.vault_id))
        {
            return Err(Error::InvalidData("invalid item or vault ID".into()));
        }
        if self.actions.is_empty() || self.actions.iter().any(|a| !ACTIONS.contains(&a.as_str())) {
            return Err(Error::InvalidData(format!(
                "actions must be some of {}",
                ACTIONS.join(", ")
            )));
        }
        if self.commands.len() > MAX_PATTERNS || self.paths.len() > MAX_PATTERNS {
            return Err(Error::InvalidData(format!(
                "at most {MAX_PATTERNS} commands and paths"
            )));
        }
        for value in self.commands.iter().chain(&self.paths) {
            if value.trim().is_empty() {
                return Err(Error::InvalidData("empty command or path".into()));
            }
            check_text("a command or path", value)?;
        }
        if self.reason.is_empty() {
            return Err(Error::InvalidData("a reason is required".into()));
        }
        check_text("the reason", &self.reason)?;
        check_text("the client name", &self.client_name)?;
        if !(60_000..=MAX_TTL_MS).contains(&self.ttl_ms) {
            return Err(Error::InvalidData(
                "the time limit must be between 1 minute and 8 hours".into(),
            ));
        }
        if !id::is_valid_id(&self.id)
            || !id::is_valid_id(&self.principal_id)
            || !id::is_valid_id(&self.on_behalf_of)
        {
            return Err(Error::InvalidData("invalid ID".into()));
        }
        Ok(())
    }

    pub fn to_canonical(&self) -> Vec<u8> {
        let mut w = Writer::new(REQUEST_TAG);
        w.str(&self.id)
            .str(self.principal_kind.as_str())
            .str(&self.principal_id)
            .str(&self.client_name)
            .str(&self.on_behalf_of)
            .count(self.items.len());
        for item in &self.items {
            w.str(&item.item_id).str(&item.vault_id);
        }
        for list in [&self.actions, &self.commands, &self.paths] {
            w.count(list.len());
            for value in list {
                w.str(value);
            }
        }
        w.str(&self.reason)
            .i64(self.ttl_ms)
            .u64(self.max_uses)
            .i64(self.created_at)
            .bytes(&self.nonce);
        w.finish()
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, REQUEST_TAG)?;
        let id = r.string()?;
        let principal_kind = PrincipalKind::parse(r.str()?)?;
        let principal_id = r.string()?;
        let client_name = r.string()?;
        let on_behalf_of = r.string()?;
        let count = r.count()?;
        let mut items = Vec::with_capacity(count.min(MAX_ITEMS));
        for _ in 0..count {
            items.push(GrantItem {
                item_id: r.string()?,
                vault_id: r.string()?,
            });
        }
        let mut lists: [Vec<String>; 3] = Default::default();
        for list in &mut lists {
            for _ in 0..r.count()? {
                list.push(r.string()?);
            }
        }
        let [actions, commands, paths] = lists;
        let request = Self {
            id,
            principal_kind,
            principal_id,
            client_name,
            on_behalf_of,
            items,
            actions,
            commands,
            paths,
            reason: r.string()?,
            ttl_ms: r.i64()?,
            max_uses: r.u64()?,
            created_at: r.i64()?,
            nonce: r.array()?,
        };
        r.finish()?;
        request.validate()?;
        Ok(request)
    }

    /// Parses Base64url.
    pub fn decode(encoded: &str) -> Result<Self> {
        Self::from_canonical(&encoding::decode(encoded)?)
    }

    pub fn hash(&self) -> [u8; HASH_LEN] {
        identity::object_hash(&self.to_canonical())
    }

    /// A short code shown both to the agent and in the approval dialog, so
    /// the person can match them: six digits from the request hash.
    pub fn code(&self) -> String {
        let hash = self.hash();
        let value = u32::from_be_bytes([0, hash[0], hash[1], hash[2]]) % 1_000_000;
        format!("{:03} {:03}", value / 1000, value % 1000)
    }
}

/// The person's answer to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub request_hash: [u8; HASH_LEN],
    pub approved: bool,
    /// Unix milliseconds; 0 when denied.
    pub not_after: i64,
    /// The person may lower the request's limit (0 = unlimited).
    pub max_uses: u64,
    pub approver_id: String,
    pub decided_at: i64,
}

impl Decision {
    pub fn to_canonical(&self) -> Vec<u8> {
        Writer::new(DECISION_TAG)
            .bytes(&self.request_hash)
            .u64(u64::from(self.approved))
            .i64(self.not_after)
            .u64(self.max_uses)
            .str(&self.approver_id)
            .i64(self.decided_at)
            .finish()
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, DECISION_TAG)?;
        let decision = Self {
            request_hash: r.array()?,
            approved: match r.u64()? {
                0 => false,
                1 => true,
                _ => return Err(Error::InvalidData("malformed decision".into())),
            },
            not_after: r.i64()?,
            max_uses: r.u64()?,
            approver_id: r.string()?,
            decided_at: r.i64()?,
        };
        r.finish()?;
        Ok(decision)
    }
}

/// Verifies a decision (Base64url) for the exact request bytes, signed by
/// `owner_id`'s key. Rejects approvals that last longer than the request
/// asked for or allow more uses.
pub fn verify_decision(
    owner_sig_pk: &[u8; SIG_PK_LEN],
    owner_id: &str,
    request: &[u8],
    decision: &str,
    signature: &str,
) -> Result<Decision> {
    let canonical = encoding::decode(decision)?;
    let signature = encoding::decode(signature)?;
    if signature.len() != SIGNATURE_LEN {
        return Err(Error::InvalidSignature);
    }
    identity::verify(owner_sig_pk, &canonical, &signature)?;
    let decision = Decision::from_canonical(&canonical)?;
    let parsed = GrantRequest::from_canonical(request)?;
    if decision.request_hash != identity::object_hash(request)
        || decision.approver_id != owner_id
        || parsed.on_behalf_of != owner_id
    {
        return Err(Error::InvalidData(
            "the decision does not belong to this request".into(),
        ));
    }
    if decision.approved {
        let limit = decision.decided_at.max(parsed.created_at) + parsed.ttl_ms;
        let uses_ok = parsed.max_uses == 0
            || (decision.max_uses != 0 && decision.max_uses <= parsed.max_uses);
        if decision.not_after > limit || !uses_ok {
            return Err(Error::InvalidData(
                "the approval exceeds what was requested".into(),
            ));
        }
    }
    Ok(decision)
}

impl Keyring {
    /// Signs the person's decision on an agent grant request (Base64url
    /// request bytes, as relayed by the server). Returns the decision and
    /// its signature, both Base64url. The request must be on behalf of this
    /// account. `not_after` is capped at the requested time limit and
    /// `max_uses` at the requested number of uses.
    pub fn decide_agent_grant(
        &self,
        request: &str,
        approved: bool,
        max_uses: u64,
        decided_at: i64,
    ) -> Result<(String, String)> {
        let keys = self.account_keys()?;
        let bytes = encoding::decode(request)?;
        let parsed = GrantRequest::from_canonical(&bytes)?;
        if parsed.on_behalf_of != self.account_id {
            return Err(Error::InvalidData(
                "the request is for another account".into(),
            ));
        }
        let max_uses = match (parsed.max_uses, max_uses) {
            (0, wanted) => wanted,
            (limit, 0) => limit,
            (limit, wanted) => wanted.min(limit),
        };
        let decision = Decision {
            request_hash: identity::object_hash(&bytes),
            approved,
            not_after: if approved {
                decided_at.max(parsed.created_at) + parsed.ttl_ms
            } else {
                0
            },
            max_uses: if approved { max_uses } else { 0 },
            approver_id: self.account_id.clone(),
            decided_at,
        }
        .to_canonical();
        Ok((
            encoding::encode(&decision),
            encoding::encode(&keys.sig.sign(&decision)),
        ))
    }

    /// Verifies a decision on a request this account made itself (CLI
    /// session principal).
    pub fn verify_agent_decision(
        &self,
        request: &[u8],
        decision: &str,
        signature: &str,
    ) -> Result<Decision> {
        let keys = self.account_keys()?;
        verify_decision(
            &keys.bundle.bundle.sig_pk,
            &self.account_id,
            request,
            decision,
            signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::SymmetricKey;

    fn account() -> Keyring {
        let auk = SymmetricKey::generate().unwrap();
        let (mut keyring, _) = Keyring::create(&auk, &id::new_id().unwrap()).unwrap();
        keyring.create_account_keys(1).unwrap();
        keyring
    }

    fn request(owner: &str, max_uses: u64) -> GrantRequest {
        GrantRequest::new(
            PrincipalKind::Session,
            &id::new_id().unwrap(),
            "claude-code",
            owner,
            vec![GrantItem {
                item_id: id::new_id().unwrap(),
                vault_id: id::new_id().unwrap(),
            }],
            vec!["run".into()],
            vec!["npm run deploy".into()],
            vec![],
            "Deploy the staging app",
            15 * 60 * 1000,
            max_uses,
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_and_code() {
        let owner = account();
        let request = request(owner.account_id(), 0);
        let bytes = request.to_canonical();
        let parsed = GrantRequest::from_canonical(&bytes).unwrap();
        assert_eq!(parsed, request);
        assert_eq!(parsed.code().len(), 7);
        assert_eq!(parsed.code(), request.code());
    }

    #[test]
    fn approve_and_verify() {
        let owner = account();
        let request = request(owner.account_id(), 0);
        let bytes = request.to_canonical();
        let (decision, signature) = owner
            .decide_agent_grant(&encoding::encode(&bytes), true, 0, 2_000)
            .unwrap();
        let verified = owner
            .verify_agent_decision(&bytes, &decision, &signature)
            .unwrap();
        assert!(verified.approved);
        assert_eq!(verified.not_after, 2_000 + 15 * 60 * 1000);

        // A decision does not transfer to another request.
        let other = self::request(owner.account_id(), 0).to_canonical();
        assert!(
            owner
                .verify_agent_decision(&other, &decision, &signature)
                .is_err()
        );
        // Nor does a decision signed by someone else.
        let mallory = account();
        assert!(
            mallory
                .decide_agent_grant(&encoding::encode(&bytes), true, 0, 2_000)
                .is_err()
        );
        let forged = Decision::from_canonical(&encoding::decode(&decision).unwrap()).unwrap();
        let forged = forged.to_canonical();
        let forged_sig = mallory.account_keys().unwrap().sig.sign(&forged);
        assert_eq!(
            owner
                .verify_agent_decision(
                    &bytes,
                    &encoding::encode(&forged),
                    &encoding::encode(&forged_sig)
                )
                .unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn denial_and_use_limits() {
        let owner = account();
        let bytes = request(owner.account_id(), 1).to_canonical();
        let (decision, signature) = owner
            .decide_agent_grant(&encoding::encode(&bytes), false, 0, 2_000)
            .unwrap();
        let verified = owner
            .verify_agent_decision(&bytes, &decision, &signature)
            .unwrap();
        assert!(!verified.approved);
        // A single-use request stays single-use even if the approver asks
        // for more.
        let (decision, signature) = owner
            .decide_agent_grant(&encoding::encode(&bytes), true, 5, 2_000)
            .unwrap();
        let verified = owner
            .verify_agent_decision(&bytes, &decision, &signature)
            .unwrap();
        assert_eq!(verified.max_uses, 1);
    }

    #[test]
    fn rejects_invalid_requests() {
        let owner = account();
        let mut bad = request(owner.account_id(), 0);
        bad.actions = vec!["reveal".into()];
        assert!(GrantRequest::from_canonical(&bad.to_canonical()).is_err());
        let mut bad = request(owner.account_id(), 0);
        bad.ttl_ms = MAX_TTL_MS + 1;
        assert!(GrantRequest::from_canonical(&bad.to_canonical()).is_err());
        let mut bad = request(owner.account_id(), 0);
        bad.reason = "x\u{1b}[2J".into();
        assert!(GrantRequest::from_canonical(&bad.to_canonical()).is_err());
        let mut bad = request(owner.account_id(), 0);
        bad.items.clear();
        assert!(GrantRequest::from_canonical(&bad.to_canonical()).is_err());
    }
}
