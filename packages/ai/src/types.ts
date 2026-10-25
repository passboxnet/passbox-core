/**
 * Shapes shared by the gateway, providers and features (concept §6.2,
 * same as `crates/ai`).
 */
import type { Redacted } from "./redacted";

/** Where a model runs. Shown to the user when a feature is switched on. */
export type ModelLocation = "on-device" | "self-hosted" | "cloud";

export const MODEL_LOCATIONS: readonly ModelLocation[] = ["on-device", "self-hosted", "cloud"];

/**
 * Data classes (concept §4): D0 the user's own input, D1 structure (headers,
 * patterns, counts), D2 metadata (titles, domains, usernames), D3 content
 * (notes, custom fields). D4, secrets, is not representable: it never
 * reaches a model.
 */
export type DataClass = "D0" | "D1" | "D2" | "D3";

/** Passbox features that can use a model. */
export type FeatureId = "import-mapping" | "security-copilot";

export const FEATURES: readonly FeatureId[] = ["import-mapping", "security-copilot"];

/** A (tiny) JSON schema, sent to the model and used by the feature to validate. */
export type JsonSchema = Record<string, unknown>;

export interface AiRequest {
  feature: FeatureId;
  /** Checked against the feature manifest, settings and policy. */
  classes: readonly DataClass[];
  /** Fixed instructions shipped with the feature. */
  system: string;
  /** Only constructible by the redaction layer. */
  input: Redacted<unknown>;
  /** The answer must follow it; features validate and fall back. */
  schema: JsonSchema;
  signal?: AbortSignal;
}

export interface AiProvider {
  /** For the AI log, for example "ollama", "chrome-prompt-api" or "cloud". */
  readonly id: string;
  readonly location: ModelLocation;
  /** Country or region of a cloud provider ("EU", "US"), shown at opt-in. */
  readonly jurisdiction?: string;
  /** Structured output only: resolves to the parsed JSON answer. */
  complete(request: AiRequest): Promise<unknown>;
}

/** What a feature sends and where it may run. */
export interface FeatureManifest {
  id: FeatureId;
  classes: readonly DataClass[];
  locations: readonly ModelLocation[];
  system: string;
  schema: JsonSchema;
}

/** Why a feature did not use (or could not use) the model. */
export type AiErrorCode = "not_allowed" | "provider" | "invalid_response" | "settings";

export class AiError extends Error {
  override readonly name = "AiError";
  constructor(
    readonly code: AiErrorCode,
    message: string,
  ) {
    super(message);
  }
}
