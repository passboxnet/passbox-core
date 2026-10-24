//! The vault security analysis for the apps: the report
//! ([`passbox_core::analysis`]), dismissals, email breach monitoring through
//! the server, lookalike checks and email aliases.

use std::collections::BTreeMap;
use std::time::Duration;

use passbox_core::analysis::{
    self, AnalysisItem, AnalysisOptions, BreachInfo, ExposedEmail, FindingKind, ItemView,
    SecurityReport, lookalike,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Client, now_ms};
use crate::model::{FieldType, ItemCategory, ItemData, field};
use crate::{Error, Result};

/// The user's settings for the report (device-local preferences).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportOptions {
    /// Passwords older than this count as old; 0 turns it off.
    pub old_after_days: u32,
    /// Cards and documents expiring within this many days are flagged.
    pub expiring_within_days: u32,
    /// Kinds of findings the user turned off.
    pub disabled: Vec<FindingKind>,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            old_after_days: 365,
            expiring_within_days: 60,
            disabled: Vec::new(),
        }
    }
}

/// A breach a monitored address was found in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailBreach {
    pub name: String,
    pub title: String,
    pub domain: String,
    /// `YYYY-MM-DD`.
    pub breach_date: String,
    #[serde(default)]
    pub pwn_count: i64,
    pub data_classes: Vec<String>,
    /// When this server first saw the address in the breach (Unix ms).
    pub first_seen_at: i64,
}

/// An email address monitored by the server.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitoredEmail {
    pub id: String,
    pub email: String,
    /// Confirmed with the mailed code; only confirmed addresses are checked.
    pub verified: bool,
    /// Last check (Unix ms, 0 = never).
    pub checked_at: i64,
    pub check_error: Option<String>,
    pub breaches: Vec<EmailBreach>,
}

/// The server's email breach monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailMonitoring {
    /// The server operator set up a Have I Been Pwned API key.
    pub available: bool,
    pub check_interval_hours: u64,
    pub emails: Vec<MonitoredEmail>,
}

/// An email alias service ("Alias erstellen" in the generator, G10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasProvider {
    SimpleLogin,
    Addy,
    Fastmail,
    DuckDuckGo,
    FirefoxRelay,
}

impl AliasProvider {
    pub const ALL: [AliasProvider; 5] = [
        Self::SimpleLogin,
        Self::Addy,
        Self::Fastmail,
        Self::DuckDuckGo,
        Self::FirefoxRelay,
    ];

    /// Stable code stored in the provider item.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SimpleLogin => "simplelogin",
            Self::Addy => "addy",
            Self::Fastmail => "fastmail",
            Self::DuckDuckGo => "duckduckgo",
            Self::FirefoxRelay => "firefox_relay",
        }
    }

    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == code)
    }

    /// Display name.
    pub fn name(self) -> &'static str {
        match self {
            Self::SimpleLogin => "SimpleLogin",
            Self::Addy => "addy.io",
            Self::Fastmail => "Fastmail Masked Email",
            Self::DuckDuckGo => "DuckDuckGo Email Protection",
            Self::FirefoxRelay => "Firefox Relay",
        }
    }

    pub fn default_base_url(self) -> &'static str {
        match self {
            Self::SimpleLogin => "https://app.simplelogin.io",
            Self::Addy => "https://app.addy.io",
            Self::Fastmail => "https://api.fastmail.com",
            Self::DuckDuckGo => "https://quack.duckduckgo.com",
            Self::FirefoxRelay => "https://relay.firefox.com",
        }
    }
}

/// Field IDs of an alias provider item (category "other", tag `alias-service`).
pub mod alias_field {
    pub const PROVIDER: &str = "alias_provider";
    pub const API_KEY: &str = "alias_api_key";
    /// Optional: a self-hosted SimpleLogin or addy.io.
    pub const BASE_URL: &str = "alias_base_url";
    /// addy.io: the alias domain (`anonaddy.me`, your own domain).
    pub const DOMAIN: &str = "alias_domain";
}

/// The tag of alias provider items.
pub const ALIAS_TAG: &str = "alias-service";

/// A configured alias service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasService {
    /// The vault item holding the API key.
    pub item_id: String,
    pub provider: AliasProvider,
    pub title: String,
}

/// Sends alias requests. Tests replace it.
pub trait AliasTransport: Send + Sync {
    /// Sends a JSON request with extra headers; returns status and body.
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<(u16, Value)>;
}

/// [`AliasTransport`] over HTTPS with `ureq`.
pub struct HttpAliasTransport {
    agent: ureq::Agent,
}

impl Default for HttpAliasTransport {
    fn default() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(20)))
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

impl AliasTransport for HttpAliasTransport {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<(u16, Value)> {
        let network = |e: ureq::Error| Error::Network(e.to_string());
        let mut builder = ureq::http::Request::builder()
            .method(method)
            .uri(url)
            .header("accept", "application/json")
            .header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        let request = builder
            .body(bytes)
            .map_err(|e| Error::Network(e.to_string()))?;
        let mut response = self.agent.run(request).map_err(network)?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_to_string()
            .map_err(network)?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }
}

/// Creates an alias with a provider's API. Pure request logic, shared with
/// tests. `for_domain` is the website the alias is for (used as note).
pub fn create_alias_with(
    transport: &dyn AliasTransport,
    provider: AliasProvider,
    api_key: &str,
    base_url: Option<&str>,
    alias_domain: Option<&str>,
    for_domain: &str,
) -> Result<String> {
    let base = base_url
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .unwrap_or(provider.default_base_url())
        .trim_end_matches('/');
    if !base.starts_with("https://") {
        return Err(Error::InvalidData(
            "the alias service address must start with https://".into(),
        ));
    }
    let key = api_key.trim().to_owned();
    if key.is_empty() {
        return Err(Error::InvalidData(
            "the alias service has no API key".into(),
        ));
    }
    let note = if for_domain.is_empty() {
        "Created by Passbox".to_owned()
    } else {
        format!("Created by Passbox for {for_domain}")
    };
    let fail = |status: u16, body: &Value| -> Error {
        let detail = ["error", "message", "detail"]
            .iter()
            .find_map(|k| body[*k].as_str())
            .unwrap_or_default()
            .to_owned();
        match status {
            401 | 403 => Error::Server {
                status,
                code: "alias_unauthorized".into(),
                message: format!("{} rejected the API key", provider.name()),
            },
            429 => Error::Server {
                status,
                code: "rate_limited".into(),
                message: format!(
                    "{} asks to wait before creating more aliases",
                    provider.name()
                ),
            },
            _ => Error::Server {
                status,
                code: "alias_failed".into(),
                message: format!("{} answered with status {status} {detail}", provider.name())
                    .trim()
                    .to_owned(),
            },
        }
    };
    let pick = |value: Option<&str>| -> Result<String> {
        value
            .filter(|v| v.contains('@'))
            .map(str::to_owned)
            .ok_or_else(|| Error::InvalidData(format!("{} sent no alias", provider.name())))
    };
    match provider {
        AliasProvider::SimpleLogin => {
            let hostname: String = url_encode(for_domain);
            let (status, body) = transport.send(
                "POST",
                &format!("{base}/api/alias/random/new?hostname={hostname}"),
                &[("Authentication", key)],
                Some(&json!({ "note": note })),
            )?;
            if !(200..300).contains(&status) {
                return Err(fail(status, &body));
            }
            pick(body["alias"].as_str())
        }
        AliasProvider::Addy => {
            let domain = alias_domain
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .unwrap_or("anonaddy.me");
            let (status, body) = transport.send(
                "POST",
                &format!("{base}/api/v1/aliases"),
                &[
                    ("Authorization", format!("Bearer {key}")),
                    ("X-Requested-With", "XMLHttpRequest".into()),
                ],
                Some(&json!({ "domain": domain, "description": note })),
            )?;
            if !(200..300).contains(&status) {
                return Err(fail(status, &body));
            }
            pick(body["data"]["email"].as_str())
        }
        AliasProvider::Fastmail => {
            let auth = [("Authorization", format!("Bearer {key}"))];
            let (status, session) =
                transport.send("GET", &format!("{base}/jmap/session"), &auth, None)?;
            if !(200..300).contains(&status) {
                return Err(fail(status, &session));
            }
            let capability = "https://www.fastmail.com/dev/maskedemail";
            let account = session["primaryAccounts"][capability]
                .as_str()
                .ok_or_else(|| {
                    Error::InvalidData("the Fastmail token has no Masked Email access".into())
                })?
                .to_owned();
            let api_url = session["apiUrl"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{base}/jmap/api/"));
            let (status, body) = transport.send(
                "POST",
                &api_url,
                &auth,
                Some(&json!({
                    "using": ["urn:ietf:params:jmap:core", capability],
                    "methodCalls": [["MaskedEmail/set", {
                        "accountId": account,
                        "create": { "passbox": {
                            "state": "enabled",
                            "forDomain": for_domain,
                            "description": note,
                        }}
                    }, "0"]]
                })),
            )?;
            if !(200..300).contains(&status) {
                return Err(fail(status, &body));
            }
            pick(body["methodResponses"][0][1]["created"]["passbox"]["email"].as_str())
        }
        AliasProvider::DuckDuckGo => {
            let (status, body) = transport.send(
                "POST",
                &format!("{base}/api/email/addresses"),
                &[("Authorization", format!("Bearer {key}"))],
                None,
            )?;
            if !(200..300).contains(&status) {
                return Err(fail(status, &body));
            }
            let address = body["address"]
                .as_str()
                .filter(|a| !a.is_empty())
                .ok_or_else(|| Error::InvalidData("DuckDuckGo sent no alias".into()))?;
            Ok(format!("{address}@duck.com"))
        }
        AliasProvider::FirefoxRelay => {
            let (status, body) = transport.send(
                "POST",
                &format!("{base}/api/v1/relayaddresses/"),
                &[("Authorization", format!("Token {key}"))],
                Some(&json!({ "enabled": true, "generated_for": for_domain, "description": note })),
            )?;
            if !(200..300).contains(&status) {
                return Err(fail(status, &body));
            }
            pick(body["full_address"].as_str())
        }
    }
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Client {
    /// The vault security analysis ("Sicherheits-Check"): score, findings
    /// with fixes and the "fix these first" list, computed on this device.
    /// Breach findings appear after [`Client::check_breached_items`] ran in
    /// this session, email exposures after [`Client::email_monitoring`].
    pub fn security_report(&self, options: &ReportOptions) -> Result<SecurityReport> {
        let items = self.items()?;
        let email = self.device_account()?.map(|a| a.email).unwrap_or_default();
        let (checked, exposed) = {
            let state = self.lock_breach();
            (state.checked, state.exposed.clone())
        };
        let breach_counts = checked.then(|| {
            items
                .iter()
                .filter_map(|item| {
                    let password = item.data.field(field::PASSWORD)?;
                    Some((item.id.clone(), self.known_breach_count(password)?))
                })
                .collect::<BTreeMap<_, _>>()
        });
        let input: Vec<AnalysisItem> = items
            .iter()
            .map(|item| AnalysisItem {
                id: item.id.clone(),
                created_at: item.created_at,
                data: serde_json::to_value(&item.data)
                    .ok()
                    .and_then(|v| serde_json::from_value::<ItemView>(v).ok())
                    .unwrap_or_default(),
            })
            .collect();
        Ok(analysis::analyze(
            &input,
            &AnalysisOptions {
                now: now_ms(),
                user_inputs: vec![email],
                old_after_days: options.old_after_days,
                expiring_within_days: options.expiring_within_days,
                disabled: options.disabled.clone(),
                breach_counts,
                exposed_emails: exposed,
            },
        ))
    }

    /// Dismisses (or restores) one finding of one item. Stored in the item
    /// (`securityIgnore`), so it is encrypted and synced.
    pub fn dismiss_finding(&self, item_id: &str, kind: FindingKind, dismissed: bool) -> Result<()> {
        let item = self.item(item_id)?;
        let mut data = item.data;
        if analysis::set_dismissed(&mut data.extra, kind, dismissed) {
            self.update_item(item_id, &data)?;
        }
        Ok(())
    }

    /// Whether `host` (a website about to be filled or saved) looks like
    /// one of the user's saved login domains or a well-known site. Local.
    pub fn check_lookalike(&self, host: &str) -> Result<Option<lookalike::Lookalike>> {
        let items = self.items()?;
        let saved: Vec<String> = items
            .iter()
            .filter(|i| i.data.category == ItemCategory::Login)
            .filter_map(|i| analysis::domain::parse_url(i.data.field(field::URL)?))
            .map(|u| u.host)
            .collect();
        Ok(lookalike::check_host(
            host,
            saved.iter().map(String::as_str),
            true,
        ))
    }

    // --- Email breach monitoring (server) -------------------------------------------

    fn monitoring_call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        self.with_token(|token| self.api.request(method, path, token, body.clone()))
    }

    /// The server's email breach monitoring and its results. The results
    /// also feed [`Client::security_report`] until the vault locks.
    pub fn email_monitoring(&self) -> Result<EmailMonitoring> {
        let value = self.monitoring_call("GET", "/api/v1/breach/emails", None)?;
        let monitoring: EmailMonitoring = serde_json::from_value(value)?;
        self.remember_exposures(&monitoring.emails);
        Ok(monitoring)
    }

    fn remember_exposures(&self, emails: &[MonitoredEmail]) {
        self.lock_breach().exposed = emails
            .iter()
            .filter(|e| e.verified)
            .map(|e| ExposedEmail {
                email: e.email.clone(),
                breaches: e
                    .breaches
                    .iter()
                    .map(|b| BreachInfo {
                        name: b.name.clone(),
                        title: b.title.clone(),
                        domain: b.domain.clone(),
                        breach_date: b.breach_date.clone(),
                        data_classes: b.data_classes.clone(),
                    })
                    .collect(),
            })
            .collect();
    }

    /// Starts monitoring an address: the server mails a confirmation code
    /// to it. The address (never a password) is sent to Have I Been Pwned
    /// once confirmed; say so before calling this.
    pub fn add_monitored_email(&self, email: &str) -> Result<MonitoredEmail> {
        let value = self.monitoring_call(
            "POST",
            "/api/v1/breach/emails",
            Some(json!({ "email": email })),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    /// Confirms an address with the mailed code; the server checks it right away.
    pub fn verify_monitored_email(&self, id: &str, code: &str) -> Result<MonitoredEmail> {
        let value = self.monitoring_call(
            "POST",
            &format!("/api/v1/breach/emails/{id}/verify"),
            Some(json!({ "code": code })),
        )?;
        let email: MonitoredEmail = serde_json::from_value(value)?;
        let _ = self.email_monitoring();
        Ok(email)
    }

    /// Checks a confirmed address now (at most every ten minutes).
    pub fn check_monitored_email(&self, id: &str) -> Result<MonitoredEmail> {
        let value =
            self.monitoring_call("POST", &format!("/api/v1/breach/emails/{id}/check"), None)?;
        let email: MonitoredEmail = serde_json::from_value(value)?;
        let _ = self.email_monitoring();
        Ok(email)
    }

    /// Stops monitoring an address; the server deletes its results.
    pub fn remove_monitored_email(&self, id: &str) -> Result<()> {
        self.monitoring_call("DELETE", &format!("/api/v1/breach/emails/{id}"), None)?;
        let _ = self.email_monitoring();
        Ok(())
    }

    // --- Email aliases (G10) -------------------------------------------------------------

    /// The alias services set up in the vault (items tagged `alias-service`).
    pub fn alias_services(&self) -> Result<Vec<AliasService>> {
        Ok(self
            .items()?
            .into_iter()
            .filter_map(|item| {
                let provider = AliasProvider::parse(item.data.field(alias_field::PROVIDER)?)?;
                item.data.field(alias_field::API_KEY)?;
                Some(AliasService {
                    item_id: item.id.clone(),
                    provider,
                    title: item.data.title.clone(),
                })
            })
            .collect())
    }

    /// Saves an alias service's API key as a vault item in `vault_id`.
    /// Returns the item ID.
    pub fn add_alias_service(
        &self,
        vault_id: &str,
        provider: AliasProvider,
        api_key: &str,
        base_url: Option<&str>,
        alias_domain: Option<&str>,
    ) -> Result<String> {
        let mut data = ItemData::new(ItemCategory::Other, provider.name());
        data.tags.push(ALIAS_TAG.into());
        data.set_field(
            alias_field::PROVIDER,
            "Provider",
            FieldType::Text,
            provider.as_str(),
        );
        data.set_field(
            alias_field::API_KEY,
            "API key",
            FieldType::Concealed,
            api_key.trim(),
        );
        if let Some(url) = base_url.map(str::trim).filter(|u| !u.is_empty()) {
            data.set_field(alias_field::BASE_URL, "Server", FieldType::Url, url);
        }
        if let Some(domain) = alias_domain.map(str::trim).filter(|d| !d.is_empty()) {
            data.set_field(alias_field::DOMAIN, "Alias domain", FieldType::Text, domain);
        }
        self.create_item(vault_id, &data)
    }

    /// Creates a new email alias with the service stored in `service_item_id`,
    /// for the website `for_domain`. The request goes directly from this
    /// device to the provider; Passbox's server is not involved.
    pub fn create_alias(&self, service_item_id: &str, for_domain: &str) -> Result<String> {
        self.create_alias_via(&HttpAliasTransport::default(), service_item_id, for_domain)
    }

    /// [`Client::create_alias`] with a custom transport (tests).
    pub fn create_alias_via(
        &self,
        transport: &dyn AliasTransport,
        service_item_id: &str,
        for_domain: &str,
    ) -> Result<String> {
        let item = self.item(service_item_id)?;
        let provider = item
            .data
            .field(alias_field::PROVIDER)
            .and_then(AliasProvider::parse)
            .ok_or_else(|| Error::InvalidData("this item is not an alias service".into()))?;
        create_alias_with(
            transport,
            provider,
            item.data.field(alias_field::API_KEY).unwrap_or_default(),
            item.data.field(alias_field::BASE_URL),
            item.data.field(alias_field::DOMAIN),
            for_domain,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct Recorder {
        calls: Mutex<Vec<(String, String, Vec<(String, String)>, Option<Value>)>>,
        answers: Mutex<Vec<(u16, Value)>>,
    }

    impl Recorder {
        fn new(answers: Vec<(u16, Value)>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                answers: Mutex::new(answers.into_iter().rev().collect()),
            }
        }
    }

    impl AliasTransport for Recorder {
        fn send(
            &self,
            method: &str,
            url: &str,
            headers: &[(&str, String)],
            body: Option<&Value>,
        ) -> Result<(u16, Value)> {
            self.calls.lock().unwrap().push((
                method.into(),
                url.into(),
                headers
                    .iter()
                    .map(|(k, v)| ((*k).into(), v.clone()))
                    .collect(),
                body.cloned(),
            ));
            Ok(self.answers.lock().unwrap().pop().unwrap())
        }
    }

    #[test]
    fn creates_aliases_with_each_provider() {
        let cases: Vec<(AliasProvider, Vec<(u16, Value)>, &str, &str)> = vec![
            (
                AliasProvider::SimpleLogin,
                vec![(201, json!({ "alias": "x.y@simplelogin.com" }))],
                "x.y@simplelogin.com",
                "https://app.simplelogin.io/api/alias/random/new?hostname=shop.example",
            ),
            (
                AliasProvider::Addy,
                vec![(201, json!({ "data": { "email": "a1@anonaddy.me" } }))],
                "a1@anonaddy.me",
                "https://app.addy.io/api/v1/aliases",
            ),
            (
                AliasProvider::Fastmail,
                vec![
                    (
                        200,
                        json!({ "apiUrl": "https://api.fastmail.com/jmap/api/",
                                "primaryAccounts": { "https://www.fastmail.com/dev/maskedemail": "u1" } }),
                    ),
                    (
                        200,
                        json!({ "methodResponses": [["MaskedEmail/set", { "created": { "passbox": { "email": "m@fastmail.com" } } }, "0"]] }),
                    ),
                ],
                "m@fastmail.com",
                "https://api.fastmail.com/jmap/session",
            ),
            (
                AliasProvider::DuckDuckGo,
                vec![(201, json!({ "address": "quack123" }))],
                "quack123@duck.com",
                "https://quack.duckduckgo.com/api/email/addresses",
            ),
            (
                AliasProvider::FirefoxRelay,
                vec![(201, json!({ "full_address": "r@mozmail.com" }))],
                "r@mozmail.com",
                "https://relay.firefox.com/api/v1/relayaddresses/",
            ),
        ];
        for (provider, answers, alias, first_url) in cases {
            let recorder = Recorder::new(answers);
            let created =
                create_alias_with(&recorder, provider, " key ", None, None, "shop.example")
                    .unwrap();
            assert_eq!(created, alias, "{provider:?}");
            let calls = recorder.calls.lock().unwrap();
            assert_eq!(calls[0].1, first_url, "{provider:?}");
            assert!(
                calls[0]
                    .2
                    .iter()
                    .any(|(_, v)| v.contains("key") && !v.contains(' ')
                        || v == "Bearer key"
                        || v == "Token key"),
                "{provider:?}: {:?}",
                calls[0].2
            );
        }
    }

    #[test]
    fn alias_errors_say_what_happened() {
        let recorder = Recorder::new(vec![(401, json!({ "error": "bad key" }))]);
        let err =
            create_alias_with(&recorder, AliasProvider::Addy, "k", None, None, "x").unwrap_err();
        assert!(
            err.to_string().contains("addy.io rejected the API key"),
            "{err}"
        );
        let err = create_alias_with(
            &Recorder::new(vec![]),
            AliasProvider::SimpleLogin,
            "k",
            Some("http://insecure.example"),
            None,
            "x",
        )
        .unwrap_err();
        assert!(err.to_string().contains("https://"));
        assert_eq!(
            AliasProvider::parse("firefox_relay"),
            Some(AliasProvider::FirefoxRelay)
        );
    }
}
