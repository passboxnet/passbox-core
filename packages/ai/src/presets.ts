/**
 * Provider presets for "cloud with your own key" (ADR 0006: bring your own
 * model, no Passbox-hosted inference). The same list is in
 * `crates/ai/src/presets.rs`; keep both in sync. Each preset only fills in
 * the settings (endpoint, API, region, a suggested model); the API key is
 * always a vault item the user picks, and the D2/D3 data-class rules apply
 * exactly as for any cloud provider.
 *
 * Base URLs were checked against each provider's official documentation on
 * 25.10.2026 (`checked`). Model names change more often than endpoints: the
 * suggested model is only a starting point, and `modelChecked: false` marks
 * suggestions the documentation did not confirm.
 */
import type { ModelLocation } from "./types";

/** Wire format: OpenAI-compatible chat completions, or Anthropic's Messages API. */
export type ProviderApi = "openai" | "anthropic";

export interface ProviderPreset {
  id: string;
  /** Product name, the same in every language. */
  name: string;
  api: ProviderApi;
  baseUrl: string;
  location: ModelLocation;
  /** Where requests are processed according to the provider ("EU", "US"). */
  jurisdiction: "EU" | "US";
  /** Country of the company or data centre (ISO 3166-1 alpha-2). */
  country: string;
  /** For the favicon shown next to the preset (added separately). */
  domain?: string;
  /** Suggested model; empty when the account decides (workspace or portal). */
  model: string;
  /** Other models the documentation names. */
  models: readonly string[];
  /** Official API documentation. */
  docs: string;
  /** Date the base URL was checked in the official documentation. */
  checked: string;
  /** Whether the suggested model was confirmed in the documentation too. */
  modelChecked: boolean;
}

export const PROVIDER_PRESETS: readonly ProviderPreset[] = [
  {
    id: "mistral",
    name: "Mistral AI",
    api: "openai",
    baseUrl: "https://api.mistral.ai/v1",
    location: "cloud",
    jurisdiction: "EU",
    country: "FR",
    domain: "mistral.ai",
    model: "mistral-small-latest",
    models: ["mistral-small-latest", "mistral-medium-latest", "mistral-large-latest"],
    docs: "https://docs.mistral.ai/api/",
    checked: "2026-10-25",
    modelChecked: false,
  },
  {
    id: "ionos",
    name: "IONOS AI Model Hub",
    api: "openai",
    baseUrl: "https://openai.inference.de-txl.ionos.com/v1",
    location: "cloud",
    jurisdiction: "EU",
    country: "DE",
    domain: "ionos.de",
    model: "meta-llama/Meta-Llama-3.1-8B-Instruct",
    models: ["meta-llama/Meta-Llama-3.1-8B-Instruct"],
    docs: "https://docs.ionos.com/cloud/ai/ai-model-hub",
    checked: "2026-10-25",
    modelChecked: true,
  },
  {
    id: "stackit",
    name: "STACKIT AI Model Serving",
    api: "openai",
    baseUrl: "https://api.openai-compat.model-serving.eu01.onstackit.cloud/v1",
    location: "cloud",
    jurisdiction: "EU",
    country: "DE",
    domain: "stackit.de",
    // Chat models are listed in the STACKIT portal; choose one there.
    model: "",
    models: [],
    docs: "https://docs.stackit.cloud/products/data-and-ai/ai-model-serving/",
    checked: "2026-10-25",
    modelChecked: false,
  },
  {
    id: "scaleway",
    name: "Scaleway Generative APIs",
    api: "openai",
    baseUrl: "https://api.scaleway.ai/v1",
    location: "cloud",
    jurisdiction: "EU",
    country: "FR",
    domain: "scaleway.com",
    model: "llama-3.3-70b-instruct",
    models: ["llama-3.3-70b-instruct", "llama-3.1-8b-instruct", "mistral-nemo-instruct-2407"],
    docs: "https://www.scaleway.com/en/docs/generative-apis/",
    checked: "2026-10-25",
    modelChecked: true,
  },
  {
    id: "langdock",
    name: "Langdock",
    api: "openai",
    // The `eu` region of Langdock's OpenAI-compatible Completion API.
    baseUrl: "https://api.langdock.com/openai/eu/v1",
    location: "cloud",
    jurisdiction: "EU",
    country: "DE",
    domain: "langdock.com",
    // The models available depend on the workspace (GET …/models lists them).
    model: "",
    models: [],
    docs: "https://docs.langdock.com/en/developer/completion-api/openai",
    checked: "2026-10-25",
    modelChecked: false,
  },
  {
    id: "openai",
    name: "OpenAI",
    api: "openai",
    baseUrl: "https://api.openai.com/v1",
    location: "cloud",
    jurisdiction: "US",
    country: "US",
    domain: "openai.com",
    model: "gpt-4.1-mini",
    models: ["gpt-4.1-mini", "gpt-4.1"],
    docs: "https://platform.openai.com/docs/api-reference/chat",
    checked: "2026-10-25",
    modelChecked: false,
  },
  {
    id: "anthropic",
    name: "Anthropic",
    api: "anthropic",
    baseUrl: "https://api.anthropic.com/v1",
    location: "cloud",
    // Workspaces are stored in the US; inference can be limited to "us", there is no EU option.
    jurisdiction: "US",
    country: "US",
    domain: "anthropic.com",
    model: "claude-opus-5-5",
    models: ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"],
    docs: "https://platform.claude.com/docs/en/api/messages",
    checked: "2026-10-25",
    modelChecked: true,
  },
];

export function presetById(id: string | undefined): ProviderPreset | undefined {
  return id ? PROVIDER_PRESETS.find((p) => p.id === id) : undefined;
}

/** The preset whose base URL the endpoint uses, if any (for settings saved before presets). */
export function presetForEndpoint(endpoint: string): ProviderPreset | undefined {
  const normalized = endpoint.trim().replace(/\/+$/, "").toLowerCase();
  return PROVIDER_PRESETS.find((p) => p.baseUrl.toLowerCase() === normalized);
}
