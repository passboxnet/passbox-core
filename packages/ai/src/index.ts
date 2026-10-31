/**
 * Passbox AI gateway (TypeScript twin of `crates/ai`). Data flows:
 * docs/architecture/ai-gateway.md.
 *
 * Rules this package keeps:
 * - It never imports `@passbox/core-wasm` or `@passbox/client` (no keys, no
 *   vault access); `boundary.test.ts` and the lint configuration enforce it.
 * - Providers only accept `Redacted` input, which only the feature modules
 *   here can build (`seal` is not exported).
 * - AI is off by default and opt-in per feature; every feature has a
 *   deterministic result without a model.
 */
export { AiGateway, type AiLogEntry, classAllowed, type GatewayOptions } from "./gateway";
export {
  type ColumnInput,
  type ColumnProfile,
  classify,
  dominantKind,
  IMPORT_MAPPING,
  IMPORT_TARGETS,
  type ImportTarget,
  type MappingInput,
  type MappingProposal,
  PROFILE_ROWS,
  patternSuggestions,
  profileColumn,
  redactColumns,
  suggestMapping,
  type ValueKind,
} from "./importMapping";
export {
  PROVIDER_PRESETS,
  type ProviderApi,
  type ProviderPreset,
  presetById,
  presetForEndpoint,
} from "./presets";
export {
  ANTHROPIC_VERSION,
  anthropicProvider,
  openAiCompatibleProvider,
  promptApiAvailability,
  promptApiProvider,
  providerFromSettings,
  recordingProvider,
  stripFence,
} from "./providers";
export { Redacted, SecretGuard } from "./redacted";
export {
  categorize,
  cleanText,
  FINDING_KINDS,
  type FindingKind,
  type Findings,
  fallbackPlan,
  type Plan,
  type PlanStep,
  type Priority,
  Pseudonyms,
  redactFindings,
  SECURITY_COPILOT,
  type SiteCategory,
  type SiteFindings,
  securityPlan,
} from "./securityCopilot";
export {
  type AiPolicy,
  type AiSettings,
  DEFAULT_AI_SETTINGS,
  type EndpointProblem,
  endpointProblem,
  featureEnabled,
  isLocalHost,
  isLoopbackHost,
  type ProviderSettings,
  parseAiSettings,
  providerProblem,
} from "./settings";
export {
  AiError,
  type AiErrorCode,
  type AiProvider,
  type AiRequest,
  type DataClass,
  FEATURES,
  type FeatureId,
  type FeatureManifest,
  type JsonSchema,
  MODEL_LOCATIONS,
  type ModelLocation,
} from "./types";
