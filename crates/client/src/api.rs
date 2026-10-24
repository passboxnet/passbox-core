//! HTTP access to the Passbox server API (see `docs/api/openapi.yaml`).

use std::time::Duration;

use passbox_core::kdf::KdfParams;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

/// Sends HTTP requests. The default implementation uses `ureq` with the
/// operating system's certificate store; platforms may supply their own.
pub trait Transport: Send + Sync {
    /// Sends a request and returns the status code and body. Network
    /// failures are errors; HTTP error statuses are not.
    fn send(
        &self,
        method: &str,
        url: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>)>;
}

/// `ureq`-based transport.
pub struct HttpTransport {
    agent: ureq::Agent,
}

impl Default for HttpTransport {
    fn default() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
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

impl Transport for HttpTransport {
    fn send(
        &self,
        method: &str,
        url: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>)> {
        let network = |e: ureq::Error| Error::Network(e.to_string());
        let mut builder = ureq::http::Request::builder()
            .method(method)
            .uri(url)
            .header("accept", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(body)
                .map_err(|e| Error::Network(e.to_string()))?,
            None => builder
                .body(Vec::new())
                .map_err(|e| Error::Network(e.to_string()))?,
        };
        let mut response = self.agent.run(request).map_err(network)?;
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(64 * 1024 * 1024)
            .read_to_vec()
            .map_err(network)?;
        Ok((status, bytes))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub account_id: String,
    pub kdf_salt: String,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewVault {
    pub id: String,
    pub encrypted_key: String,
    pub encrypted_meta: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStartResponse {
    pub login_id: String,
    pub credential_response: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginFinishResponse {
    pub token: String,
    #[serde(default)]
    pub session_id: String,
    /// Replaces the device token sent with `login_start`. Empty if the
    /// server is too old to issue one.
    #[serde(default)]
    pub device_token: String,
}

/// A signed-in device (see `GET /api/v1/sessions`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub device_name: String,
    pub client_kind: String,
    pub ip: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub expires_at: i64,
    /// True for the session making the request.
    pub current: bool,
}

/// An entry of the account activity log.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountEvent {
    pub id: String,
    pub kind: String,
    pub device_name: String,
    pub client_kind: String,
    pub ip: String,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub account_id: String,
    pub encrypted_account_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncVault {
    pub id: String,
    pub encrypted_key: String,
    pub encrypted_meta: String,
    pub revision: u64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncItem {
    pub id: String,
    pub vault_id: String,
    pub revision: u64,
    pub encrypted_data: Option<String>,
    pub deleted: bool,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub cursor: i64,
    pub vaults: Vec<SyncVault>,
    pub items: Vec<SyncItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteResponse {
    pub revision: u64,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    details: Option<Value>,
}

/// The message of a `rate_limited` error. Keeps the wait time from
/// `details.retryAfterSeconds` in a fixed format, so apps that only see the
/// message (the FFI) can show "try again in N minutes" in their language.
fn rate_limited_message(message: String, details: Option<&Value>) -> String {
    match details
        .and_then(|d| d.get("retryAfterSeconds"))
        .and_then(Value::as_u64)
    {
        Some(seconds) => format!("too many attempts; try again in {seconds} seconds"),
        None => message,
    }
}

/// Typed wrapper around a [`Transport`] for one server.
pub struct Api {
    base_url: String,
    transport: Box<dyn Transport>,
}

impl Api {
    pub fn new(base_url: &str, transport: Box<dyn Transport>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            transport,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<T> {
        let body = body.map(|b| serde_json::to_vec(&b)).transpose()?;
        let (status, bytes) =
            self.transport
                .send(method, &format!("{}{path}", self.base_url), token, body)?;
        if !(200..300).contains(&status) {
            let parsed: Option<ErrorBody> = serde_json::from_slice(&bytes).ok();
            let (code, message) = parsed
                .map(|b| {
                    let message = if b.error == "rate_limited" {
                        rate_limited_message(b.message, b.details.as_ref())
                    } else {
                        b.message
                    };
                    (b.error, message)
                })
                .unwrap_or_else(|| (String::new(), String::from_utf8_lossy(&bytes).into_owned()));
            return Err(match code.as_str() {
                "invalid_credentials" => Error::InvalidCredentials,
                "conflict"
                    if path.starts_with("/api/v1/items") || path.starts_with("/api/v1/vaults/") =>
                {
                    Error::Conflict
                }
                _ => Error::Server {
                    status,
                    code,
                    message,
                },
            });
        }
        let bytes = if bytes.is_empty() {
            b"null".to_vec()
        } else {
            bytes
        };
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::InvalidData(format!("unexpected response from {path}: {e}")))
    }

    pub fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        self.call(
            "POST",
            "/api/v1/auth/prelogin",
            None,
            Some(serde_json::json!({ "email": email })),
        )
    }

    pub fn register_start(&self, account_id: &str, email: &str, request: &str) -> Result<String> {
        let response: Value = self.call(
            "POST",
            "/api/v1/auth/register/start",
            None,
            Some(serde_json::json!({ "accountId": account_id, "email": email, "registrationRequest": request })),
        )?;
        response["registrationResponse"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::InvalidData("missing registrationResponse".into()))
    }

    pub fn register_finish(&self, body: Value) -> Result<()> {
        let _: Value = self.call("POST", "/api/v1/auth/register/finish", None, Some(body))?;
        Ok(())
    }

    /// Starts a login. `device_token` is the token from this device's last
    /// successful login, which exempts it from the per-email lockout.
    pub fn login_start(
        &self,
        email: &str,
        request: &str,
        device_token: Option<&str>,
    ) -> Result<LoginStartResponse> {
        let mut body = serde_json::json!({ "email": email, "credentialRequest": request });
        if let Some(device_token) = device_token {
            body["deviceToken"] = device_token.into();
        }
        self.call("POST", "/api/v1/auth/login/start", None, Some(body))
    }

    pub fn login_finish(
        &self,
        login_id: &str,
        finalization: &str,
        device_name: &str,
        client_kind: &str,
    ) -> Result<LoginFinishResponse> {
        self.call(
            "POST",
            "/api/v1/auth/login/finish",
            None,
            Some(serde_json::json!({
                "loginId": login_id,
                "credentialFinalization": finalization,
                "deviceName": device_name,
                "clientKind": client_kind,
            })),
        )
    }

    pub fn account_events(&self, token: &str, limit: u32) -> Result<Vec<AccountEvent>> {
        self.call(
            "GET",
            &format!("/api/v1/account/events?limit={limit}"),
            Some(token),
            None,
        )
    }

    pub fn password_change_start(&self, token: &str, request: &str) -> Result<String> {
        let response: Value = self.call(
            "POST",
            "/api/v1/account/password/start",
            Some(token),
            Some(serde_json::json!({ "registrationRequest": request })),
        )?;
        response["registrationResponse"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::InvalidData("missing registrationResponse".into()))
    }

    pub fn password_change_finish(&self, token: &str, body: Value) -> Result<()> {
        let _: Value = self.call(
            "POST",
            "/api/v1/account/password/finish",
            Some(token),
            Some(body),
        )?;
        Ok(())
    }

    pub fn sessions(&self, token: &str) -> Result<Vec<SessionInfo>> {
        self.call("GET", "/api/v1/sessions", Some(token), None)
    }

    pub fn revoke_session(&self, token: &str, id: &str) -> Result<()> {
        let _: Value = self.call(
            "DELETE",
            &format!("/api/v1/sessions/{id}"),
            Some(token),
            None,
        )?;
        Ok(())
    }

    pub fn revoke_other_sessions(&self, token: &str) -> Result<()> {
        let _: Value = self.call(
            "POST",
            "/api/v1/sessions/revoke-others",
            Some(token),
            Some(serde_json::json!({})),
        )?;
        Ok(())
    }

    pub fn logout(&self, token: &str) -> Result<()> {
        let _: Value = self.call(
            "POST",
            "/api/v1/auth/logout",
            Some(token),
            Some(serde_json::json!({})),
        )?;
        Ok(())
    }

    pub fn account(&self, token: &str) -> Result<AccountResponse> {
        self.call("GET", "/api/v1/account", Some(token), None)
    }

    pub fn sync(&self, token: &str, since: i64) -> Result<SyncResponse> {
        self.call(
            "GET",
            &format!("/api/v1/sync?since={since}"),
            Some(token),
            None,
        )
    }

    pub fn create_vault(&self, token: &str, vault: &NewVault) -> Result<WriteResponse> {
        self.call(
            "POST",
            "/api/v1/vaults",
            Some(token),
            Some(serde_json::to_value(vault)?),
        )
    }

    pub fn update_vault(
        &self,
        token: &str,
        id: &str,
        revision: u64,
        encrypted_meta: &str,
    ) -> Result<WriteResponse> {
        self.call(
            "PUT",
            &format!("/api/v1/vaults/{id}"),
            Some(token),
            Some(serde_json::json!({ "revision": revision, "encryptedMeta": encrypted_meta })),
        )
    }

    pub fn put_item(
        &self,
        token: &str,
        id: &str,
        vault_id: &str,
        revision: u64,
        encrypted_data: &str,
    ) -> Result<WriteResponse> {
        self.call(
            "PUT",
            &format!("/api/v1/items/{id}"),
            Some(token),
            Some(serde_json::json!({ "vaultId": vault_id, "revision": revision, "encryptedData": encrypted_data })),
        )
    }

    pub fn delete_item(&self, token: &str, id: &str, revision: u64) -> Result<WriteResponse> {
        self.call(
            "DELETE",
            &format!("/api/v1/items/{id}?revision={revision}"),
            Some(token),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_message_keeps_the_wait_time() {
        let details = serde_json::json!({ "retryAfterSeconds": 300 });
        assert_eq!(
            rate_limited_message("too many attempts".into(), Some(&details)),
            "too many attempts; try again in 300 seconds"
        );
        assert_eq!(
            rate_limited_message("too many attempts".into(), None),
            "too many attempts"
        );
    }
}
