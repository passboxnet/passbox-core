//! Settings, feature manifests, policy checks and the local AI log.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::provider::{AiProvider, AiRequest, ModelLocation, OpenAiCompatible};
use crate::redact::{DataClass, Redacted};
use crate::{AiError, Result};

/// Passbox features that can use a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeatureId {
    /// Column mapping for unknown CSV files.
    ImportMapping,
    /// A prioritised plan from the security check.
    SecurityCopilot,
}

impl FeatureId {
    pub const ALL: [FeatureId; 2] = [FeatureId::ImportMapping, FeatureId::SecurityCopilot];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImportMapping => "import-mapping",
            Self::SecurityCopilot => "security-copilot",
        }
    }
}

/// What a feature sends and where it may run. Every feature also has a
/// deterministic result without a model (its fallback function).
#[derive(Debug)]
pub struct FeatureManifest {
    pub id: FeatureId,
    /// The data classes the feature's input may contain.
    pub classes: &'static [DataClass],
    /// Where its model may run.
    pub locations: &'static [ModelLocation],
    /// Fixed instructions, shipped with Passbox.
    pub system: &'static str,
    /// JSON schema of the answer.
    pub schema: fn() -> Value,
}

/// Which provider to use. Stored per device; the API key is a vault item
/// (`api_key_item`, a `pbx://` reference or an item ID) that the client
/// resolves when it creates the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSettings {
    pub location: ModelLocation,
    /// For example `http://localhost:11434/v1` (Ollama) or
    /// `https://api.mistral.ai/v1`.
    pub endpoint: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_item: Option<String>,
    /// Country or region of a cloud provider, shown at opt-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    /// Wire format (OpenAI-compatible unless Anthropic's Messages API).
    #[serde(default)]
    pub api: crate::presets::ProviderApi,
    /// The preset the settings came from ([`crate::presets`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
}

/// AI settings. Everything is off by default; each feature is switched on
/// separately.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: Option<ProviderSettings>,
    /// Features the user switched on.
    #[serde(default)]
    pub features: Vec<FeatureId>,
}

impl AiSettings {
    pub fn feature_enabled(&self, feature: FeatureId) -> bool {
        self.enabled && self.provider.is_some() && self.features.contains(&feature)
    }

    /// Builds the provider. `api_key` is the value of `api_key_item`,
    /// resolved by the caller from the vault.
    pub fn provider(&self, api_key: Option<String>) -> Result<OpenAiCompatible> {
        let p = self
            .provider
            .as_ref()
            .ok_or_else(|| AiError::Settings("no provider is configured".into()))?;
        let id = match p.location {
            ModelLocation::OnDevice => "on-device",
            ModelLocation::SelfHosted => "self-hosted",
            ModelLocation::Cloud => "cloud",
        };
        let provider = OpenAiCompatible::new(id, &p.endpoint, &p.model, api_key, p.location)?;
        Ok(match &p.jurisdiction {
            Some(j) => provider.with_jurisdiction(j),
            None => provider,
        })
    }
}

/// Organization policy (later from the server's policies and the
/// extension's managed schema): restricts locations and data classes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiPolicy {
    /// `None` allows every location.
    #[serde(default)]
    pub allowed_locations: Option<Vec<ModelLocation>>,
    #[serde(default)]
    pub forbidden_classes: Vec<DataClass>,
    /// Endpoint the organization requires (prefix match).
    #[serde(default)]
    pub required_endpoint: Option<String>,
}

/// Whether a data class may go to a location: D0 and D1
/// anywhere; D2 to cloud providers only pseudonymized; D3 never to the
/// cloud.
pub fn class_allowed(class: DataClass, location: ModelLocation, pseudonymized: bool) -> bool {
    match class {
        DataClass::D0 | DataClass::D1 => true,
        DataClass::D2 => location != ModelLocation::Cloud || pseudonymized,
        DataClass::D3 => location != ModelLocation::Cloud,
    }
}

/// One request in the local AI log. Never contains the input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiLogEntry {
    pub at_ms: u64,
    pub feature: FeatureId,
    pub provider: String,
    pub location: ModelLocation,
    pub classes: Vec<DataClass>,
    /// Size of the input in bytes.
    pub bytes: usize,
    /// "ok", "failed" or "invalid".
    pub outcome: &'static str,
}

/// Calls models for features, after checking settings, policy and data
/// classes. Holds no vault access.
pub struct Gateway {
    settings: AiSettings,
    policy: AiPolicy,
    provider: Option<Box<dyn AiProvider>>,
    log: Mutex<Vec<AiLogEntry>>,
}

const LOG_LIMIT: usize = 200;

impl Gateway {
    pub fn new(settings: AiSettings, provider: Option<Box<dyn AiProvider>>) -> Self {
        Self {
            settings,
            policy: AiPolicy::default(),
            provider,
            log: Mutex::new(Vec::new()),
        }
    }

    /// A gateway with AI off: every feature uses its fallback.
    pub fn disabled() -> Self {
        Self::new(AiSettings::default(), None)
    }

    pub fn with_policy(mut self, policy: AiPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Whether the feature would call a model.
    pub fn is_enabled(&self, feature: FeatureId) -> bool {
        self.settings.feature_enabled(feature) && self.provider.is_some()
    }

    /// The provider's location, for showing what goes where.
    pub fn location(&self) -> Option<ModelLocation> {
        self.provider.as_ref().map(|p| p.location())
    }

    fn allowed<T>(
        &self,
        manifest: &FeatureManifest,
        input: &Redacted<T>,
    ) -> Result<&dyn AiProvider> {
        if !self.settings.feature_enabled(manifest.id) {
            return Err(AiError::NotAllowed(format!(
                "{} is switched off",
                manifest.id.as_str()
            )));
        }
        let provider = self
            .provider
            .as_deref()
            .ok_or_else(|| AiError::NotAllowed("no provider".into()))?;
        let location = provider.location();
        if !manifest.locations.contains(&location) {
            return Err(AiError::NotAllowed(format!(
                "{} may not use a model at {location:?}",
                manifest.id.as_str()
            )));
        }
        if let Some(allowed) = &self.policy.allowed_locations
            && !allowed.contains(&location)
        {
            return Err(AiError::NotAllowed(format!(
                "the organization does not allow models at {location:?}"
            )));
        }
        if let (Some(required), Some(settings)) =
            (&self.policy.required_endpoint, &self.settings.provider)
            && !settings.endpoint.starts_with(required.as_str())
        {
            return Err(AiError::NotAllowed(format!(
                "the organization requires the endpoint {required}"
            )));
        }
        for class in input.classes() {
            if !manifest.classes.contains(class) {
                return Err(AiError::NotAllowed(format!(
                    "{} does not declare {}",
                    manifest.id.as_str(),
                    class.as_str()
                )));
            }
            if self.policy.forbidden_classes.contains(class) {
                return Err(AiError::NotAllowed(format!(
                    "the organization does not allow {} data",
                    class.as_str()
                )));
            }
            if !class_allowed(*class, location, input.pseudonymized()) {
                return Err(AiError::NotAllowed(format!(
                    "{} data may not go to {location:?}",
                    class.as_str()
                )));
            }
        }
        Ok(provider)
    }

    /// Sends the input to the model and returns its JSON answer. The
    /// feature validates the answer and falls back when anything fails.
    pub(crate) fn complete<T: Serialize>(
        &self,
        manifest: &FeatureManifest,
        input: &Redacted<T>,
    ) -> Result<Value> {
        let provider = self.allowed(manifest, input)?;
        let text = input.to_json();
        let bytes = text.len();
        let request = AiRequest::new(
            manifest.id,
            manifest.system,
            text,
            input.classes().to_vec(),
            (manifest.schema)(),
        );
        let result = provider.complete(&request);
        let outcome = match &result {
            Ok(_) => "ok",
            Err(AiError::InvalidResponse(_)) => "invalid",
            Err(_) => "failed",
        };
        self.record(AiLogEntry {
            at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            feature: manifest.id,
            provider: provider.id().to_owned(),
            location: provider.location(),
            classes: input.classes().to_vec(),
            bytes,
            outcome,
        });
        result
    }

    /// Marks the last log entry of a feature as invalid (the answer did not
    /// pass the feature's validation).
    pub(crate) fn mark_invalid(&self, feature: FeatureId) {
        if let Ok(mut log) = self.log.lock()
            && let Some(entry) = log.iter_mut().rev().find(|e| e.feature == feature)
        {
            entry.outcome = "invalid";
        }
    }

    fn record(&self, entry: AiLogEntry) {
        if let Ok(mut log) = self.log.lock() {
            log.push(entry);
            let excess = log.len().saturating_sub(LOG_LIMIT);
            log.drain(..excess);
        }
    }

    /// The local AI log, oldest first.
    pub fn log(&self) -> Vec<AiLogEntry> {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_off() {
        let settings = AiSettings::default();
        assert!(!settings.enabled);
        for feature in FeatureId::ALL {
            assert!(!settings.feature_enabled(feature));
        }
        let parsed: AiSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, settings);
        assert!(!Gateway::disabled().is_enabled(FeatureId::ImportMapping));
    }

    #[test]
    fn class_rules() {
        use DataClass::*;
        use ModelLocation::*;
        assert!(class_allowed(D1, Cloud, false));
        assert!(!class_allowed(D2, Cloud, false));
        assert!(class_allowed(D2, Cloud, true));
        assert!(class_allowed(D2, SelfHosted, false));
        assert!(!class_allowed(D3, Cloud, true));
        assert!(class_allowed(D3, OnDevice, false));
    }

    #[test]
    fn settings_json_shape() {
        let settings: AiSettings = serde_json::from_str(
            r#"{"enabled":true,"provider":{"location":"self-hosted","endpoint":"http://localhost:11434/v1","model":"llama3.2"},"features":["import-mapping"]}"#,
        )
        .unwrap();
        assert!(settings.feature_enabled(FeatureId::ImportMapping));
        assert!(!settings.feature_enabled(FeatureId::SecurityCopilot));
        assert!(settings.provider(None).is_ok());
    }
}
