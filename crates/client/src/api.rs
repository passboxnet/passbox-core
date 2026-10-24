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
    /// Unused recovery codes left, after signing in with one.
    #[serde(default)]
    pub recovery_codes_remaining: Option<i64>,
}

/// Returned by `login/finish` instead of a session when the account needs a
/// second factor on this device.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorChallenge {
    pub two_factor_required: bool,
    pub challenge_token: String,
    pub expires_at: i64,
    /// `totp`, `webauthn` and/or `recovery`.
    pub methods: Vec<String>,
}

/// The answer to `login/finish`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum LoginFinish {
    TwoFactor(TwoFactorChallenge),
    Session(LoginFinishResponse),
}

/// A registered security key (see `GET /api/v1/account/two-factor`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityKeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    /// 0 if never used.
    pub last_used_at: i64,
}

/// Two-factor authentication status of the account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorStatus {
    /// Whether sign-ins need a second factor.
    pub enabled: bool,
    pub totp: bool,
    pub security_keys: Vec<SecurityKeyInfo>,
    pub recovery_codes_remaining: i64,
}

/// A new TOTP secret for an authenticator app.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TotpSetup {
    /// Base32, for typing it in.
    pub secret: String,
    /// `otpauth://` URI, for a QR code.
    pub uri: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCodes {
    #[serde(default)]
    recovery_codes: Option<Vec<String>>,
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
    /// Set for shared vaults (organization vaults).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Key epoch of `encrypted_meta` (0 for personal vaults).
    #[serde(default)]
    pub key_epoch: u32,
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
    /// Vault key epoch of `encrypted_data` (0 for personal vaults).
    #[serde(default)]
    pub key_epoch: u32,
    /// When the item was created (Unix ms); 0 from servers before 0.1 that
    /// did not send it.
    #[serde(default)]
    pub created_at: i64,
}

/// An earlier, still encrypted version of an item
/// (`GET /api/v1/items/{id}/versions`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemVersionRecord {
    pub revision: u64,
    #[serde(default)]
    pub key_epoch: u32,
    pub encrypted_data: String,
    pub updated_at: i64,
    #[serde(default)]
    pub updated_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ItemVersions {
    versions: Vec<ItemVersionRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub cursor: i64,
    pub vaults: Vec<SyncVault>,
    pub items: Vec<SyncItem>,
    /// Organizations, groups and shared vault keys (with `sharing=1`).
    #[serde(default)]
    pub sharing: Option<passbox_core::sharing::data::SharingDelta>,
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
                "invalid_two_factor_code" => Error::InvalidTwoFactorCode,
                "two_factor_expired" => Error::TwoFactorExpired,
                "conflict"
                    if path.starts_with("/api/v1/items")
                        || path.starts_with("/api/v1/vaults/")
                        || path.starts_with("/api/v1/service-account/items") =>
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
    ) -> Result<LoginFinish> {
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

    /// Completes a login with its second factor: `method` is `totp` or
    /// `recovery`. `remember_device` skips the second step on this device
    /// for 30 days.
    pub fn login_two_factor(
        &self,
        challenge_token: &str,
        method: &str,
        code: &str,
        remember_device: bool,
    ) -> Result<LoginFinishResponse> {
        self.call(
            "POST",
            "/api/v1/auth/login/two-factor",
            None,
            Some(serde_json::json!({
                "challengeToken": challenge_token,
                "method": method,
                "code": code,
                "rememberDevice": remember_device,
            })),
        )
    }

    pub fn two_factor_status(&self, token: &str) -> Result<TwoFactorStatus> {
        self.call("GET", "/api/v1/account/two-factor", Some(token), None)
    }

    pub fn totp_start(&self, token: &str) -> Result<TotpSetup> {
        self.call(
            "POST",
            "/api/v1/account/two-factor/totp/start",
            Some(token),
            Some(serde_json::json!({})),
        )
    }

    /// Returns new recovery codes when the account had none.
    pub fn totp_confirm(&self, token: &str, code: &str) -> Result<Option<Vec<String>>> {
        let response: RecoveryCodes = self.call(
            "POST",
            "/api/v1/account/two-factor/totp/confirm",
            Some(token),
            Some(serde_json::json!({ "code": code })),
        )?;
        Ok(response.recovery_codes)
    }

    pub fn totp_remove(&self, token: &str) -> Result<()> {
        let _: Value = self.call(
            "DELETE",
            "/api/v1/account/two-factor/totp",
            Some(token),
            None,
        )?;
        Ok(())
    }

    pub fn webauthn_remove(&self, token: &str, id: &str) -> Result<()> {
        let _: Value = self.call(
            "DELETE",
            &format!("/api/v1/account/two-factor/webauthn/{id}"),
            Some(token),
            None,
        )?;
        Ok(())
    }

    pub fn regenerate_recovery_codes(&self, token: &str) -> Result<Vec<String>> {
        let response: RecoveryCodes = self.call(
            "POST",
            "/api/v1/account/two-factor/recovery-codes",
            Some(token),
            Some(serde_json::json!({})),
        )?;
        Ok(response.recovery_codes.unwrap_or_default())
    }

    /// Turns two-factor authentication off with a code (`totp` or `recovery`).
    pub fn disable_two_factor(&self, token: &str, method: &str, code: &str) -> Result<()> {
        let _: Value = self.call(
            "POST",
            "/api/v1/account/two-factor/disable",
            Some(token),
            Some(serde_json::json!({ "method": method, "code": code })),
        )?;
        Ok(())
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
            &format!("/api/v1/sync?since={since}&sharing=1"),
            Some(token),
            None,
        )
    }

    /// Sends a request with a JSON body (or none) and returns the JSON
    /// answer (`null` for 204). Used by the sharing endpoints.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        self.call(method, path, Some(token), body)
    }

    /// Like [`Api::request`] without a session (recovery and device codes).
    pub fn request_anonymous(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        self.call(method, path, None, body)
    }

    /// `GET /api/v1/invitations/{token}` (no session needed).
    pub fn invitation_preview(&self, token: &str) -> Result<Value> {
        self.call("GET", &format!("/api/v1/invitations/{token}"), None, None)
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
        key_epoch: u32,
    ) -> Result<WriteResponse> {
        self.call(
            "PUT",
            &format!("/api/v1/vaults/{id}"),
            Some(token),
            Some(serde_json::json!({ "revision": revision, "encryptedMeta": encrypted_meta, "keyEpoch": key_epoch })),
        )
    }

    pub fn put_item(
        &self,
        token: &str,
        id: &str,
        vault_id: &str,
        revision: u64,
        encrypted_data: &str,
        key_epoch: u32,
    ) -> Result<WriteResponse> {
        self.call(
            "PUT",
            &format!("/api/v1/items/{id}"),
            Some(token),
            Some(serde_json::json!({ "vaultId": vault_id, "revision": revision, "encryptedData": encrypted_data, "keyEpoch": key_epoch })),
        )
    }

    /// Earlier versions of an item, newest first.
    pub fn item_versions(&self, token: &str, id: &str) -> Result<Vec<ItemVersionRecord>> {
        let versions: ItemVersions = self.call(
            "GET",
            &format!("/api/v1/items/{id}/versions"),
            Some(token),
            None,
        )?;
        Ok(versions.versions)
    }

    /// The website icon of `domain` from `GET /api/v1/icons/{domain}`:
    /// `None` when the server has none (404), refuses the name (400) or has
    /// icons turned off.
    pub fn icon(&self, token: &str, domain: &str) -> Result<Option<Vec<u8>>> {
        let (status, bytes) = self.transport.send(
            "GET",
            &format!("{}/api/v1/icons/{domain}", self.base_url),
            Some(token),
            None,
        )?;
        match status {
            200 => Ok(Some(bytes)),
            400 | 404 => Ok(None),
            401 => Err(Error::Server {
                status,
                code: "unauthorized".into(),
                message: "the session expired".into(),
            }),
            _ => Err(Error::Server {
                status,
                code: String::new(),
                message: String::from_utf8_lossy(&bytes).into_owned(),
            }),
        }
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
    fn login_finish_is_a_session_or_a_challenge() {
        let session: LoginFinish = serde_json::from_str(
            r#"{"token":"t","accountId":"a","sessionId":"s","expiresAt":1,"deviceToken":"d"}"#,
        )
        .unwrap();
        assert!(
            matches!(session, LoginFinish::Session(s) if s.token == "t" && s.device_token == "d")
        );
        let challenge: LoginFinish = serde_json::from_str(
            r#"{"twoFactorRequired":true,"challengeToken":"c","expiresAt":1,"methods":["totp","recovery"],
                "webauthn":{"challenge":"AA","rpId":"x","allowCredentials":[],"timeout":1,"userVerification":"discouraged"}}"#,
        )
        .unwrap();
        assert!(
            matches!(challenge, LoginFinish::TwoFactor(c) if c.challenge_token == "c" && c.methods == ["totp", "recovery"])
        );
    }

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
