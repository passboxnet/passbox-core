//! Model providers: where a model runs and how it is called.
//!
//! Native clients have no on-device model runtime yet (the web app uses the
//! browser's Prompt API, see `packages/ai`); on desktop, Ollama on
//! `localhost` is the on-device option. [`OpenAiCompatible`] covers
//! self-hosted servers (Ollama, vLLM, LocalAI, LiteLLM) and cloud providers
//! with an OpenAI-compatible API and the user's own key.

use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::gateway::FeatureId;
use crate::redact::DataClass;
use crate::{AiError, Result};

/// Where the model runs. Shown to the user when a feature is switched on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelLocation {
    /// On this device (also a model server on `localhost`).
    OnDevice,
    /// A server the user or their organization runs.
    SelfHosted,
    /// A cloud provider, with the user's own API key.
    Cloud,
}

/// One call to a model. Only the gateway builds requests, from
/// [`crate::Redacted`] input.
#[derive(Debug)]
pub struct AiRequest {
    feature: FeatureId,
    system: &'static str,
    input: String,
    classes: Vec<DataClass>,
    schema: Value,
}

impl AiRequest {
    pub(crate) fn new(
        feature: FeatureId,
        system: &'static str,
        input: String,
        classes: Vec<DataClass>,
        schema: Value,
    ) -> Self {
        Self {
            feature,
            system,
            input,
            classes,
            schema,
        }
    }

    pub fn feature(&self) -> FeatureId {
        self.feature
    }

    /// The fixed instructions shipped with the feature.
    pub fn system(&self) -> &str {
        self.system
    }

    /// The redacted input as JSON text.
    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn classes(&self) -> &[DataClass] {
        &self.classes
    }

    /// JSON schema the answer must follow.
    pub fn schema(&self) -> &Value {
        &self.schema
    }
}

/// A model. Answers are JSON values; the gateway validates them.
pub trait AiProvider: Send + Sync {
    /// For the AI log, for example "ollama" or "mistral".
    fn id(&self) -> &str;
    fn location(&self) -> ModelLocation;
    /// Country or region of a cloud provider ("EU", "US"), shown at opt-in.
    fn jurisdiction(&self) -> Option<&str> {
        None
    }
    fn complete(&self, request: &AiRequest) -> Result<Value>;
}

/// Sends a JSON POST request. Replaceable for tests and for platforms with
/// their own HTTP stack.
pub trait HttpPost: Send + Sync {
    fn post(&self, url: &str, headers: &[(&str, String)], body: Vec<u8>) -> Result<(u16, Vec<u8>)>;
}

/// [`HttpPost`] over `ureq` with the platform's certificate store.
pub struct UreqPost {
    agent: ureq::Agent,
}

impl Default for UreqPost {
    fn default() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
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

impl HttpPost for UreqPost {
    fn post(&self, url: &str, headers: &[(&str, String)], body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        let failed = |e: ureq::Error| AiError::Provider(e.to_string());
        let mut builder = ureq::http::Request::builder()
            .method("POST")
            .uri(url)
            .header("content-type", "application/json")
            .header("accept", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let request = builder
            .body(body)
            .map_err(|e| AiError::Provider(e.to_string()))?;
        let mut response = self.agent.run(request).map_err(failed)?;
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(4 * 1024 * 1024)
            .read_to_vec()
            .map_err(failed)?;
        Ok((status, bytes))
    }
}

/// Checks an endpoint URL: `https` always works; plain `http` only for
/// `localhost`, private networks and `.local` names, and never for a cloud
/// provider.
pub fn validate_endpoint(url: &str, location: ModelLocation) -> Result<()> {
    let invalid = |m: &str| Err(AiError::Settings(m.to_owned()));
    let (scheme, rest) = match url.split_once("://") {
        Some(parts) => parts,
        None => return invalid("the endpoint must start with https:// or http://"),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return invalid("the endpoint needs a host and no user name or password");
    }
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    }
    .to_ascii_lowercase();
    if location == ModelLocation::OnDevice && !is_loopback_host(&host) {
        return invalid("an on-device model must run on this device (localhost)");
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(()),
        "http" if location == ModelLocation::Cloud => invalid("a cloud provider needs https://"),
        "http" if is_local_host(&host) => Ok(()),
        "http" => invalid(
            "plain http:// is only allowed for localhost, private networks and .local names",
        ),
        _ => invalid("the endpoint must start with https:// or http://"),
    }
}

/// `localhost` and loopback addresses.
pub fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `localhost`, loopback, private IPv4 ranges, IPv6 loopback and unique
/// local addresses, and `.local`/`.internal`/`.lan` names.
pub fn is_local_host(host: &str) -> bool {
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".lan")
        || host == "::1"
    {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback() || ip.is_private() || ip.is_link_local();
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00;
    }
    false
}

/// A model behind an OpenAI-compatible chat completions API
/// (`POST {base_url}/chat/completions`): Ollama (`http://localhost:11434/v1`),
/// vLLM, LocalAI, LiteLLM, Mistral, OpenAI and others.
pub struct OpenAiCompatible {
    id: String,
    base_url: String,
    model: String,
    api_key: Option<String>,
    location: ModelLocation,
    jurisdiction: Option<String>,
    http: Box<dyn HttpPost>,
}

impl OpenAiCompatible {
    /// `api_key` comes from a vault item; it is sent as the
    /// `Authorization` header, never as part of the prompt.
    pub fn new(
        id: &str,
        base_url: &str,
        model: &str,
        api_key: Option<String>,
        location: ModelLocation,
    ) -> Result<Self> {
        validate_endpoint(base_url, location)?;
        if model.trim().is_empty() {
            return Err(AiError::Settings("choose a model name".into()));
        }
        if location == ModelLocation::Cloud && api_key.as_deref().is_none_or(str::is_empty) {
            return Err(AiError::Settings(
                "a cloud provider needs an API key from a vault item".into(),
            ));
        }
        Ok(Self {
            id: id.to_owned(),
            base_url: base_url.trim_end_matches('/').to_owned(),
            model: model.trim().to_owned(),
            api_key: api_key.filter(|k| !k.is_empty()),
            location,
            jurisdiction: None,
            http: Box::new(UreqPost::default()),
        })
    }

    pub fn with_jurisdiction(mut self, jurisdiction: &str) -> Self {
        self.jurisdiction = Some(jurisdiction.to_owned()).filter(|j| !j.is_empty());
        self
    }

    pub fn with_http(mut self, http: Box<dyn HttpPost>) -> Self {
        self.http = http;
        self
    }
}

/// Removes a Markdown code fence some models put around JSON.
pub(crate) fn strip_fence(text: &str) -> &str {
    let text = text.trim();
    let Some(inner) = text.strip_prefix("```") else {
        return text;
    };
    let inner = inner.trim_start_matches(|c: char| c.is_ascii_alphanumeric());
    inner.strip_suffix("```").unwrap_or(inner).trim()
}

impl AiProvider for OpenAiCompatible {
    fn id(&self) -> &str {
        &self.id
    }

    fn location(&self) -> ModelLocation {
        self.location
    }

    fn jurisdiction(&self) -> Option<&str> {
        self.jurisdiction.as_deref()
    }

    fn complete(&self, request: &AiRequest) -> Result<Value> {
        let system = format!(
            "{}\n\nAnswer with one JSON object that follows this JSON schema, nothing else:\n{}",
            request.system(),
            request.schema()
        );
        let body = json!({
            "model": self.model,
            "temperature": 0,
            "stream": false,
            "response_format": { "type": "json_object" },
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": request.input() },
            ],
        });
        let mut headers = Vec::new();
        if let Some(key) = &self.api_key {
            headers.push(("authorization", format!("Bearer {key}")));
        }
        let (status, bytes) = self.http.post(
            &format!("{}/chat/completions", self.base_url),
            &headers,
            serde_json::to_vec(&body).map_err(|e| AiError::Provider(e.to_string()))?,
        )?;
        if !(200..300).contains(&status) {
            return Err(AiError::Provider(format!(
                "the model server answered with status {status}"
            )));
        }
        let response: Value = serde_json::from_slice(&bytes)
            .map_err(|_| AiError::InvalidResponse("the server did not answer with JSON".into()))?;
        let content = response
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| AiError::InvalidResponse("the answer has no message".into()))?;
        serde_json::from_str(strip_fence(content))
            .map_err(|_| AiError::InvalidResponse("the model did not answer with JSON".into()))
    }
}

/// Version header of Anthropic's Messages API.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Anthropic's native Messages API (`POST {base_url}/messages`, headers
/// `x-api-key` and `anthropic-version`), with the user's own key.
pub struct Anthropic {
    base_url: String,
    model: String,
    api_key: String,
    jurisdiction: Option<String>,
    http: Box<dyn HttpPost>,
}

impl Anthropic {
    /// `api_key` comes from a vault item; it is sent as `x-api-key`, never
    /// as part of the prompt.
    pub fn new(base_url: &str, model: &str, api_key: Option<String>) -> Result<Self> {
        validate_endpoint(base_url, ModelLocation::Cloud)?;
        if model.trim().is_empty() {
            return Err(AiError::Settings("choose a model name".into()));
        }
        let api_key = api_key.filter(|k| !k.is_empty()).ok_or_else(|| {
            AiError::Settings("a cloud provider needs an API key from a vault item".into())
        })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            model: model.trim().to_owned(),
            api_key,
            jurisdiction: None,
            http: Box::new(UreqPost::default()),
        })
    }

    pub fn with_jurisdiction(mut self, jurisdiction: &str) -> Self {
        self.jurisdiction = Some(jurisdiction.to_owned()).filter(|j| !j.is_empty());
        self
    }

    pub fn with_http(mut self, http: Box<dyn HttpPost>) -> Self {
        self.http = http;
        self
    }
}

impl AiProvider for Anthropic {
    fn id(&self) -> &str {
        "anthropic"
    }

    fn location(&self) -> ModelLocation {
        ModelLocation::Cloud
    }

    fn jurisdiction(&self) -> Option<&str> {
        self.jurisdiction.as_deref()
    }

    fn complete(&self, request: &AiRequest) -> Result<Value> {
        let system = format!(
            "{}\n\nAnswer with one JSON object that follows this JSON schema, nothing else:\n{}",
            request.system(),
            request.schema()
        );
        let body = json!({
            "model": self.model,
            "max_tokens": 4096,
            "system": system,
            "messages": [{ "role": "user", "content": request.input() }],
        });
        let headers = [
            ("x-api-key", self.api_key.clone()),
            ("anthropic-version", ANTHROPIC_VERSION.to_owned()),
        ];
        let (status, bytes) = self.http.post(
            &format!("{}/messages", self.base_url),
            &headers,
            serde_json::to_vec(&body).map_err(|e| AiError::Provider(e.to_string()))?,
        )?;
        if !(200..300).contains(&status) {
            return Err(AiError::Provider(format!(
                "the model server answered with status {status}"
            )));
        }
        let response: Value = serde_json::from_slice(&bytes)
            .map_err(|_| AiError::InvalidResponse("the server did not answer with JSON".into()))?;
        let text: String = response
            .get("content")
            .and_then(Value::as_array)
            .map(|blocks| {
                blocks
                    .iter()
                    .filter(|b| b["type"] == "text")
                    .filter_map(|b| b["text"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        if text.is_empty() {
            return Err(AiError::InvalidResponse("the answer has no text".into()));
        }
        serde_json::from_str(strip_fence(&text))
            .map_err(|_| AiError::InvalidResponse("the model did not answer with JSON".into()))
    }
}

/// The provider for settings: Anthropic's Messages API or an
/// OpenAI-compatible endpoint. `api_key` is the value of the settings' API
/// key item, read from the vault by the app.
pub fn provider_from_settings(
    settings: &crate::gateway::ProviderSettings,
    api_key: Option<String>,
) -> Result<Box<dyn AiProvider>> {
    let jurisdiction = settings.jurisdiction.as_deref().unwrap_or_default();
    Ok(match settings.api {
        crate::presets::ProviderApi::Anthropic => {
            if settings.location != ModelLocation::Cloud {
                return Err(AiError::Settings(
                    "Anthropic's API is a cloud provider".into(),
                ));
            }
            Box::new(
                Anthropic::new(&settings.endpoint, &settings.model, api_key)?
                    .with_jurisdiction(jurisdiction),
            )
        }
        crate::presets::ProviderApi::Openai => Box::new(
            OpenAiCompatible::new(
                settings.preset.as_deref().unwrap_or("openai-compatible"),
                &settings.endpoint,
                &settings.model,
                api_key,
                settings.location,
            )?
            .with_jurisdiction(jurisdiction),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type Call = (String, Vec<(String, String)>, Value);
    struct Recorder(std::sync::Mutex<Vec<Call>>, Value);

    impl HttpPost for std::sync::Arc<Recorder> {
        fn post(
            &self,
            url: &str,
            headers: &[(&str, String)],
            body: Vec<u8>,
        ) -> Result<(u16, Vec<u8>)> {
            self.0.lock().unwrap().push((
                url.to_owned(),
                headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), v.clone()))
                    .collect(),
                serde_json::from_slice(&body).unwrap(),
            ));
            Ok((200, serde_json::to_vec(&self.1).unwrap()))
        }
    }

    #[test]
    fn anthropic_messages_api() {
        let recorder = std::sync::Arc::new(Recorder(
            std::sync::Mutex::new(Vec::new()),
            json!({ "content": [
                { "type": "thinking", "thinking": "…" },
                { "type": "text", "text": "```json\n{\"ok\":true}\n```" }
            ] }),
        ));
        let provider = Anthropic::new(
            "https://api.anthropic.com/v1/",
            "claude-opus-5-5",
            Some("sk-ant-test".into()),
        )
        .unwrap()
        .with_jurisdiction("US")
        .with_http(Box::new(recorder.clone()));
        let request = AiRequest::new(
            FeatureId::ImportMapping,
            "Map columns.",
            "{\"columns\":[]}".into(),
            vec![DataClass::D1],
            json!({ "type": "object" }),
        );
        assert_eq!(provider.complete(&request).unwrap(), json!({ "ok": true }));
        assert_eq!(provider.jurisdiction(), Some("US"));
        let calls = recorder.0.lock().unwrap();
        let (url, headers, body) = &calls[0];
        assert_eq!(url, "https://api.anthropic.com/v1/messages");
        assert!(headers.contains(&("x-api-key".into(), "sk-ant-test".into())));
        assert!(headers.contains(&("anthropic-version".into(), ANTHROPIC_VERSION.into())));
        assert!(!headers.iter().any(|(k, _)| k == "authorization"));
        assert_eq!(body["model"], "claude-opus-5-5");
        assert!(body["system"].as_str().unwrap().starts_with("Map columns."));
        assert_eq!(body["messages"][0]["content"], "{\"columns\":[]}");
        // The key never travels in the prompt.
        assert!(!body.to_string().contains("sk-ant-test"));
        assert!(Anthropic::new("https://api.anthropic.com/v1", "m", None).is_err());
        assert!(Anthropic::new("http://api.anthropic.com/v1", "m", Some("k".into())).is_err());
    }

    #[test]
    fn endpoints() {
        use ModelLocation::*;
        assert!(validate_endpoint("https://api.mistral.ai/v1", Cloud).is_ok());
        assert!(validate_endpoint("http://api.mistral.ai/v1", Cloud).is_err());
        assert!(validate_endpoint("http://localhost:11434/v1", OnDevice).is_ok());
        assert!(validate_endpoint("http://192.168.1.20:11434/v1", OnDevice).is_err());
        assert!(validate_endpoint("https://api.example.com/v1", OnDevice).is_err());
        assert!(validate_endpoint("http://127.0.0.1:8000/v1", SelfHosted).is_ok());
        assert!(validate_endpoint("http://192.168.1.20:11434/v1", SelfHosted).is_ok());
        assert!(validate_endpoint("http://[::1]:11434/v1", SelfHosted).is_ok());
        assert!(validate_endpoint("http://gpu.lan/v1", SelfHosted).is_ok());
        assert!(validate_endpoint("http://example.com/v1", SelfHosted).is_err());
        assert!(validate_endpoint("https://user:pw@example.com/v1", SelfHosted).is_err());
        assert!(validate_endpoint("ftp://example.com", SelfHosted).is_err());
        assert!(validate_endpoint("localhost:11434", SelfHosted).is_err());
    }

    #[test]
    fn fences() {
        assert_eq!(strip_fence("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_fence(" {\"a\":1} "), "{\"a\":1}");
    }

    #[test]
    fn cloud_needs_key() {
        assert!(
            OpenAiCompatible::new("x", "https://a.example/v1", "m", None, ModelLocation::Cloud)
                .is_err()
        );
        assert!(
            OpenAiCompatible::new(
                "x",
                "https://a.example/v1",
                "",
                None,
                ModelLocation::SelfHosted
            )
            .is_err()
        );
    }
}
