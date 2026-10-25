//! Provider presets for "cloud with your own key" (ADR 0006: bring your own
//! model, no Passbox-hosted inference). The same list is in
//! `packages/ai/src/presets.ts`; keep both in sync (a test compares them).
//!
//! A preset only fills in settings (endpoint, API, region, a suggested
//! model). The API key is always a vault item, and the D2/D3 data-class
//! rules apply as for any cloud provider. Base URLs were checked against
//! each provider's official documentation on 25.10.2026; suggested models
//! with `model_checked: false` were not confirmed there.

use serde::Serialize;

use crate::provider::ModelLocation;

/// Wire format of a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProviderApi {
    /// `POST {base}/chat/completions` (OpenAI-compatible).
    #[default]
    Openai,
    /// Anthropic's Messages API, `POST {base}/messages`.
    Anthropic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderPreset {
    pub id: &'static str,
    pub name: &'static str,
    pub api: ProviderApi,
    pub base_url: &'static str,
    pub location: ModelLocation,
    /// Where requests are processed according to the provider ("EU", "US").
    pub jurisdiction: &'static str,
    /// Country of the company or data centre (ISO 3166-1 alpha-2).
    pub country: &'static str,
    /// For the favicon shown next to the preset.
    pub domain: Option<&'static str>,
    /// Suggested model; empty when the account decides.
    pub model: &'static str,
    pub models: &'static [&'static str],
    pub docs: &'static str,
    pub checked: &'static str,
    pub model_checked: bool,
}

pub const PROVIDER_PRESETS: &[ProviderPreset] = &[
    ProviderPreset {
        id: "mistral",
        name: "Mistral AI",
        api: ProviderApi::Openai,
        base_url: "https://api.mistral.ai/v1",
        location: ModelLocation::Cloud,
        jurisdiction: "EU",
        country: "FR",
        domain: Some("mistral.ai"),
        model: "mistral-small-latest",
        models: &[
            "mistral-small-latest",
            "mistral-medium-latest",
            "mistral-large-latest",
        ],
        docs: "https://docs.mistral.ai/api/",
        checked: "2026-10-25",
        model_checked: false,
    },
    ProviderPreset {
        id: "ionos",
        name: "IONOS AI Model Hub",
        api: ProviderApi::Openai,
        base_url: "https://openai.inference.de-txl.ionos.com/v1",
        location: ModelLocation::Cloud,
        jurisdiction: "EU",
        country: "DE",
        domain: Some("ionos.de"),
        model: "meta-llama/Meta-Llama-3.1-8B-Instruct",
        models: &["meta-llama/Meta-Llama-3.1-8B-Instruct"],
        docs: "https://docs.ionos.com/cloud/ai/ai-model-hub",
        checked: "2026-10-25",
        model_checked: true,
    },
    ProviderPreset {
        id: "stackit",
        name: "STACKIT AI Model Serving",
        api: ProviderApi::Openai,
        base_url: "https://api.openai-compat.model-serving.eu01.onstackit.cloud/v1",
        location: ModelLocation::Cloud,
        jurisdiction: "EU",
        country: "DE",
        domain: Some("stackit.de"),
        model: "",
        models: &[],
        docs: "https://docs.stackit.cloud/products/data-and-ai/ai-model-serving/",
        checked: "2026-10-25",
        model_checked: false,
    },
    ProviderPreset {
        id: "scaleway",
        name: "Scaleway Generative APIs",
        api: ProviderApi::Openai,
        base_url: "https://api.scaleway.ai/v1",
        location: ModelLocation::Cloud,
        jurisdiction: "EU",
        country: "FR",
        domain: Some("scaleway.com"),
        model: "llama-3.3-70b-instruct",
        models: &[
            "llama-3.3-70b-instruct",
            "llama-3.1-8b-instruct",
            "mistral-nemo-instruct-2407",
        ],
        docs: "https://www.scaleway.com/en/docs/generative-apis/",
        checked: "2026-10-25",
        model_checked: true,
    },
    ProviderPreset {
        id: "langdock",
        name: "Langdock",
        api: ProviderApi::Openai,
        base_url: "https://api.langdock.com/openai/eu/v1",
        location: ModelLocation::Cloud,
        jurisdiction: "EU",
        country: "DE",
        domain: Some("langdock.com"),
        model: "",
        models: &[],
        docs: "https://docs.langdock.com/en/developer/completion-api/openai",
        checked: "2026-10-25",
        model_checked: false,
    },
    ProviderPreset {
        id: "openai",
        name: "OpenAI",
        api: ProviderApi::Openai,
        base_url: "https://api.openai.com/v1",
        location: ModelLocation::Cloud,
        jurisdiction: "US",
        country: "US",
        domain: Some("openai.com"),
        model: "gpt-4.1-mini",
        models: &["gpt-4.1-mini", "gpt-4.1"],
        docs: "https://platform.openai.com/docs/api-reference/chat",
        checked: "2026-10-25",
        model_checked: false,
    },
    ProviderPreset {
        id: "anthropic",
        name: "Anthropic",
        api: ProviderApi::Anthropic,
        base_url: "https://api.anthropic.com/v1",
        location: ModelLocation::Cloud,
        jurisdiction: "US",
        country: "US",
        domain: Some("anthropic.com"),
        model: "claude-opus-5-5",
        models: &["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"],
        docs: "https://platform.claude.com/docs/en/api/messages",
        checked: "2026-10-25",
        model_checked: true,
    },
];

pub fn preset(id: &str) -> Option<&'static ProviderPreset> {
    PROVIDER_PRESETS.iter().find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::validate_endpoint;

    #[test]
    fn presets_are_valid_cloud_endpoints() {
        let mut ids = std::collections::BTreeSet::new();
        for p in PROVIDER_PRESETS {
            assert!(ids.insert(p.id), "duplicate preset {}", p.id);
            assert!(
                validate_endpoint(p.base_url, p.location).is_ok(),
                "{}",
                p.id
            );
            assert!(p.base_url.starts_with("https://"));
            assert!(["EU", "US"].contains(&p.jurisdiction));
            assert!(
                p.model.is_empty() || p.models.contains(&p.model),
                "{}",
                p.id
            );
        }
        assert_eq!(preset("anthropic").unwrap().api, ProviderApi::Anthropic);
        for id in ["mistral", "ionos", "stackit", "scaleway", "langdock"] {
            assert_eq!(preset(id).unwrap().jurisdiction, "EU");
        }
    }

    /// The TypeScript list must name the same presets with the same URLs.
    #[test]
    fn matches_the_typescript_presets() {
        let ts = include_str!("../../../packages/ai/src/presets.ts");
        for p in PROVIDER_PRESETS {
            assert!(ts.contains(&format!("id: \"{}\"", p.id)), "{}", p.id);
            assert!(
                ts.contains(&format!("baseUrl: \"{}\"", p.base_url)),
                "{}",
                p.id
            );
            assert!(ts.contains(&format!("model: \"{}\"", p.model)), "{}", p.id);
        }
        assert_eq!(
            ts.matches("baseUrl: \"https://").count(),
            PROVIDER_PRESETS.len()
        );
    }
}
