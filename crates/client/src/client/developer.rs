//! Service accounts (F2) and agent grant decisions (F7) for the signed-in
//! account. The web app has the same operations in `packages/client`.
//!
//! Deciding on agent grants is deliberately not offered by the CLI: an
//! agent that can run commands could answer its own request. Apps call
//! [`Client::decide_agent_grant`] only from their own user interface.

use passbox_core::service_account::Permission;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Client, now_ms};
use crate::{Error, Result};

/// A vault grant of a service account, as listed for its owner.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountGrant {
    pub vault_id: String,
    pub key_epoch: u32,
    pub permission: String,
    /// The vault's current key epoch. When `key_epoch` is lower, the grant
    /// must be renewed to read items changed since the rotation.
    pub current_key_epoch: u32,
    pub created_at: i64,
}

/// A service account, as listed for its owner.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountInfo {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub public_key_signature: String,
    pub expires_at: i64,
    pub revoked_at: i64,
    pub last_used_at: i64,
    pub last_used_ip: String,
    pub created_at: i64,
    pub grants: Vec<ServiceAccountGrant>,
}

/// An agent grant request waiting for this account's decision.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentGrantRecord {
    pub id: String,
    pub principal_kind: String,
    pub principal_id: String,
    #[serde(default)]
    pub principal_name: Option<String>,
    pub client_name: String,
    /// Base64url canonical request.
    pub request: String,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
}

impl Client {
    fn epoch_of(&self, vault_id: &str) -> Result<u32> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        session
            .vaults
            .get(vault_id)
            .map(|v| v.key_epoch)
            .ok_or_else(|| Error::NotFound(vault_id.to_owned()))
    }

    fn grant_json(
        &self,
        public_key: &str,
        public_key_signature: &str,
        vault_id: &str,
        permission: Permission,
    ) -> Result<Value> {
        let epoch = self.epoch_of(vault_id)?;
        let upload = self.with_keyring(|k| {
            k.grant_service_account(
                public_key,
                public_key_signature,
                vault_id,
                epoch,
                permission,
                now_ms(),
            )
        })?;
        Ok(json!({
            "vaultId": upload.vault_id,
            "keyEpoch": upload.key_epoch,
            "permission": upload.permission.as_str(),
            "sealedKey": upload.sealed_key,
            "grant": upload.grant,
            "grantSignature": upload.grant_signature,
        }))
    }

    /// Creates a service account with access to `vaults`. Returns it and its
    /// token, which is shown once and cannot be recovered. `expires_at` is
    /// Unix ms (0 for no expiry).
    pub fn create_service_account(
        &self,
        name: &str,
        expires_at: i64,
        vaults: &[(String, Permission)],
    ) -> Result<(ServiceAccountInfo, Zeroizing<String>)> {
        let created = self.with_keyring(|k| k.create_service_account(now_ms()))?;
        let grants = vaults
            .iter()
            .map(|(vault_id, permission)| {
                self.grant_json(
                    &created.public_key,
                    &created.public_key_signature,
                    vault_id,
                    *permission,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let value = self.call(
            "POST",
            "/api/v1/service-accounts",
            Some(json!({
                "id": created.id,
                "name": name,
                "publicKey": created.public_key,
                "publicKeySignature": created.public_key_signature,
                "encryptedPrivate": created.encrypted_private,
                "authHash": created.auth_hash,
                "expiresAt": expires_at,
                "grants": grants,
            })),
        )?;
        Ok((serde_json::from_value(value)?, created.token))
    }

    pub fn service_accounts(&self) -> Result<Vec<ServiceAccountInfo>> {
        Ok(serde_json::from_value(self.call(
            "GET",
            "/api/v1/service-accounts",
            None,
        )?)?)
    }

    /// Gives a service account access to a vault (or renews it with the
    /// vault's current key after a rotation).
    pub fn grant_service_account(
        &self,
        service_account_id: &str,
        vault_id: &str,
        permission: Permission,
    ) -> Result<ServiceAccountInfo> {
        let account = self
            .service_accounts()?
            .into_iter()
            .find(|a| a.id == service_account_id)
            .ok_or_else(|| Error::NotFound(service_account_id.to_owned()))?;
        let grant = self.grant_json(
            &account.public_key,
            &account.public_key_signature,
            vault_id,
            permission,
        )?;
        Ok(serde_json::from_value(self.call(
            "PUT",
            &format!("/api/v1/service-accounts/{service_account_id}/grants"),
            Some(json!({ "grants": [grant] })),
        )?)?)
    }

    pub fn revoke_service_account(&self, service_account_id: &str) -> Result<()> {
        self.call(
            "POST",
            &format!("/api/v1/service-accounts/{service_account_id}/revoke"),
            Some(json!({})),
        )?;
        Ok(())
    }

    /// Agent grant requests waiting for this account's decision.
    pub fn agent_grants(&self) -> Result<Vec<AgentGrantRecord>> {
        Ok(serde_json::from_value(self.call(
            "GET",
            "/api/v1/agent-grants",
            None,
        )?)?)
    }

    /// Approves or denies an agent grant request, signed with the account
    /// key. Call only from the app's own approval UI after showing the
    /// parsed request (see the module docs).
    pub fn decide_agent_grant(
        &self,
        grant: &AgentGrantRecord,
        approved: bool,
        max_uses: u64,
    ) -> Result<()> {
        let (decision, signature) = self.with_keyring(|k| {
            k.decide_agent_grant(&grant.request, approved, max_uses, now_ms())
        })?;
        self.call(
            "POST",
            &format!("/api/v1/agent-grants/{}/decision", grant.id),
            Some(json!({ "decision": decision, "decisionSignature": signature })),
        )?;
        Ok(())
    }

    pub fn revoke_agent_grant(&self, grant_id: &str) -> Result<()> {
        self.call(
            "POST",
            &format!("/api/v1/agent-grants/{grant_id}/revoke"),
            Some(json!({})),
        )?;
        Ok(())
    }
}
