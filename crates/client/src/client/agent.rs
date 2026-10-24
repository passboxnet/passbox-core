//! The agent broker's access through a signed-in account (`pbx mcp`
//! without a service account token).

use passbox_core::agent_grant::{Decision, PrincipalKind};
use serde_json::Value;

use super::Client;
use crate::agent::Backend;
use crate::model::{Item, ItemData, Vault};
use crate::{Error, Result};

impl Backend for Client {
    fn principal(&self) -> Result<(PrincipalKind, String, String)> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        Ok((
            PrincipalKind::Session,
            account.account_id.clone(),
            account.account_id,
        ))
    }

    fn vaults(&self) -> Result<Vec<(Vault, bool)>> {
        let vaults = Client::vaults(self)?;
        Ok(vaults
            .into_iter()
            .map(|v| {
                let writable = v.org_id.is_none()
                    || self
                        .vault_access(&v.id)
                        .is_ok_and(|a| a.role.is_some_and(|r| r == "edit" || r == "manage"));
                (v, writable)
            })
            .collect())
    }

    fn items(&self) -> Result<Vec<Item>> {
        Client::items(self)
    }

    fn create_item(&self, vault_id: &str, data: &ItemData) -> Result<String> {
        Client::create_item(self, vault_id, data)
    }

    fn refresh(&self) -> Result<()> {
        self.sync()
    }

    fn agent_call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        self.call(method, &format!("/api/v1/{path}"), body)
    }

    fn verify_decision(
        &self,
        request: &[u8],
        decision: &str,
        signature: &str,
    ) -> Result<Decision> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        Ok(session
            .keyring
            .verify_agent_decision(request, decision, signature)?)
    }
}
