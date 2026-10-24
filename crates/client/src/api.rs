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
                .map(|b| (b.error, b.message))
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

    pub fn login_start(&self, email: &str, request: &str) -> Result<LoginStartResponse> {
        self.call(
            "POST",
            "/api/v1/auth/login/start",
            None,
            Some(serde_json::json!({ "email": email, "credentialRequest": request })),
        )
    }

    pub fn login_finish(&self, login_id: &str, finalization: &str) -> Result<LoginFinishResponse> {
        self.call(
            "POST",
            "/api/v1/auth/login/finish",
            None,
            Some(
                serde_json::json!({ "loginId": login_id, "credentialFinalization": finalization }),
            ),
        )
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
