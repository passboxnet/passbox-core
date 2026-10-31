/**
 * The gateway: checks settings, policy and data classes, calls the
 * provider and records every request in the local AI log. It has no vault
 * access and no keys; features give it `Redacted` input.
 */
import type { Redacted } from "./redacted";
import { type AiPolicy, type AiSettings, featureEnabled } from "./settings";
import {
  AiError,
  type AiProvider,
  type DataClass,
  type FeatureId,
  type FeatureManifest,
  type ModelLocation,
} from "./types";

/** One request, without its content. */
export interface AiLogEntry {
  at: number;
  feature: FeatureId;
  provider: string;
  location: ModelLocation;
  classes: readonly DataClass[];
  /** Size of the input in bytes. */
  bytes: number;
  outcome: "ok" | "failed" | "invalid";
}

/**
 * Whether a data class may go to a location: D0/D1 anywhere,
 * D2 to the cloud only pseudonymized, D3 never to the cloud.
 */
export function classAllowed(cls: DataClass, location: ModelLocation, pseudonymized: boolean): boolean {
  if (cls === "D0" || cls === "D1") return true;
  if (cls === "D2") return location !== "cloud" || pseudonymized;
  return location !== "cloud";
}

export interface GatewayOptions {
  settings: AiSettings;
  provider?: AiProvider | undefined;
  policy?: AiPolicy;
  /** Called for every request (to show or keep the AI log). */
  onLog?: (entry: AiLogEntry) => void;
  /** Milliseconds before a request is abandoned (default 60 s). */
  timeoutMs?: number;
}

export class AiGateway {
  readonly #options: GatewayOptions;
  readonly #log: AiLogEntry[] = [];

  constructor(options: GatewayOptions) {
    this.#options = options;
  }

  /** A gateway with AI off: every feature uses its fallback. */
  static disabled(): AiGateway {
    return new AiGateway({ settings: { enabled: false, features: [] } });
  }

  isEnabled(feature: FeatureId): boolean {
    return featureEnabled(this.#options.settings, feature) && this.#options.provider !== undefined;
  }

  get location(): ModelLocation | undefined {
    return this.#options.provider?.location;
  }

  get log(): readonly AiLogEntry[] {
    return this.#log;
  }

  #check(manifest: FeatureManifest, input: Redacted<unknown>): AiProvider {
    const { settings, provider, policy } = this.#options;
    const deny = (message: string) => new AiError("not_allowed", message);
    if (!featureEnabled(settings, manifest.id)) throw deny(`${manifest.id} is switched off`);
    if (!provider) throw deny("no provider");
    if (!manifest.locations.includes(provider.location)) throw deny(`${manifest.id} may not run ${provider.location}`);
    if (policy?.allowedLocations && !policy.allowedLocations.includes(provider.location)) {
      throw deny(`the organization does not allow ${provider.location} models`);
    }
    if (policy?.requiredEndpoint && !settings.provider?.endpoint.startsWith(policy.requiredEndpoint)) {
      throw deny(`the organization requires the endpoint ${policy.requiredEndpoint}`);
    }
    for (const cls of input.classes) {
      if (!manifest.classes.includes(cls)) throw deny(`${manifest.id} does not declare ${cls}`);
      if (policy?.forbiddenClasses?.includes(cls)) throw deny(`the organization does not allow ${cls} data`);
      if (!classAllowed(cls, provider.location, input.pseudonymized)) {
        throw deny(`${cls} data may not go to a ${provider.location} model`);
      }
    }
    return provider;
  }

  /**
   * Sends redacted input to the model and validates the answer with
   * `validate` (which throws `AiError("invalid_response")` for answers that
   * do not fit). Throws `AiError` when not allowed, when the provider
   * fails or the answer is invalid; the feature then uses its
   * deterministic fallback.
   */
  async complete<T>(manifest: FeatureManifest, input: Redacted<unknown>, validate: (answer: unknown) => T): Promise<T> {
    const provider = this.#check(manifest, input);
    const bytes = new TextEncoder().encode(JSON.stringify(input.value)).length;
    const entry: AiLogEntry = {
      at: Date.now(),
      feature: manifest.id,
      provider: provider.id,
      location: provider.location,
      classes: input.classes,
      bytes,
      outcome: "ok",
    };
    try {
      const answer = await provider.complete({
        feature: manifest.id,
        classes: input.classes,
        system: manifest.system,
        input,
        schema: manifest.schema,
        signal: AbortSignal.timeout(this.#options.timeoutMs ?? 60_000),
      });
      return validate(answer);
    } catch (error) {
      entry.outcome = error instanceof AiError && error.code === "invalid_response" ? "invalid" : "failed";
      throw error instanceof AiError ? error : new AiError("provider", describe(error));
    } finally {
      this.#record(entry);
    }
  }

  #record(entry: AiLogEntry) {
    this.#log.push(entry);
    if (this.#log.length > 200) this.#log.shift();
    this.#options.onLog?.({ ...entry });
  }
}

function describe(error: unknown): string {
  if (error instanceof Error) return error.name === "TimeoutError" ? "the model did not answer in time" : error.message;
  return String(error);
}
