/**
 * AI settings: off by default, opt-in per feature, one provider. API keys
 * are vault items; settings only hold the item's ID.
 */
import { PROVIDER_PRESETS, type ProviderApi } from "./presets";
import { FEATURES, type FeatureId, MODEL_LOCATIONS, type ModelLocation } from "./types";

export interface ProviderSettings {
  location: ModelLocation;
  /**
   * OpenAI-compatible base URL, for example `http://localhost:11434/v1`
   * (Ollama) or `https://api.mistral.ai/v1`. For "on-device" it may be
   * empty: then the browser's built-in model (Prompt API) is used.
   */
  endpoint: string;
  model: string;
  /** Vault item holding the API key (its password or first concealed field). */
  apiKeyItemId?: string;
  /** Country or region of a cloud provider, shown at opt-in ("EU"). */
  jurisdiction?: string;
  /** Wire format; absent means OpenAI-compatible. */
  api?: ProviderApi;
  /** The preset the settings came from (`presets.ts`), for the UI. */
  preset?: string;
}

export interface AiSettings {
  enabled: boolean;
  provider?: ProviderSettings;
  /** Features the user switched on. */
  features: FeatureId[];
}

export const DEFAULT_AI_SETTINGS: AiSettings = Object.freeze({ enabled: false, features: [] }) as AiSettings;

/** Organization policy (later from server policies and managed storage). */
export interface AiPolicy {
  allowedLocations?: readonly ModelLocation[];
  forbiddenClasses?: readonly ("D0" | "D1" | "D2" | "D3")[];
  /** Endpoint the organization requires (prefix). */
  requiredEndpoint?: string;
}

const str = (v: unknown, max = 2048) => (typeof v === "string" ? v.trim().slice(0, max) : "");

/** Reads stored settings, dropping anything unknown or malformed. */
export function parseAiSettings(raw: unknown): AiSettings {
  if (typeof raw !== "object" || raw === null) return { ...DEFAULT_AI_SETTINGS, features: [] };
  const r = raw as Record<string, unknown>;
  const p = (typeof r.provider === "object" && r.provider !== null ? r.provider : undefined) as
    | Record<string, unknown>
    | undefined;
  const location = MODEL_LOCATIONS.find((l) => l === p?.location);
  const provider: ProviderSettings | undefined =
    p && location
      ? {
          location,
          endpoint: str(p.endpoint),
          model: str(p.model, 200),
          ...(str(p.apiKeyItemId, 100) ? { apiKeyItemId: str(p.apiKeyItemId, 100) } : {}),
          ...(str(p.jurisdiction, 40) ? { jurisdiction: str(p.jurisdiction, 40) } : {}),
          ...(p.api === "anthropic" ? { api: "anthropic" as const } : {}),
          ...(PROVIDER_PRESETS.some((preset) => preset.id === p.preset) ? { preset: p.preset as string } : {}),
        }
      : undefined;
  const features = Array.isArray(r.features) ? FEATURES.filter((f) => (r.features as unknown[]).includes(f)) : [];
  return { enabled: r.enabled === true, ...(provider ? { provider } : {}), features };
}

export function featureEnabled(settings: AiSettings, feature: FeatureId): boolean {
  return settings.enabled && settings.provider !== undefined && settings.features.includes(feature);
}

export type EndpointProblem =
  | "missing"
  | "scheme"
  | "credentials"
  | "cloud_https"
  | "http_not_local"
  | "on_device_local"
  | "model_missing"
  | "key_missing";

function hostOf(authority: string): string {
  if (authority.startsWith("[")) return authority.slice(1, authority.indexOf("]")).toLowerCase();
  return (authority.split(":")[0] ?? "").toLowerCase();
}

export function isLoopbackHost(host: string): boolean {
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "::1" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
  );
}

/** Loopback, private IPv4 ranges, IPv6 unique local, `.local`/`.internal`/`.lan`. */
export function isLocalHost(host: string): boolean {
  if (isLoopbackHost(host) || /\.(local|internal|lan)$/.test(host)) return true;
  const ip = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ip) {
    const [a, b] = [Number(ip[1]), Number(ip[2])];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  return /^f[cd][0-9a-f]{2}:/i.test(host);
}

/**
 * Checks an endpoint: https always; plain http only for local hosts and
 * never for a cloud provider; "on-device" endpoints must be this device.
 * Same rules as `crates/ai/src/provider.rs`.
 */
export function endpointProblem(url: string, location: ModelLocation): EndpointProblem | undefined {
  const trimmed = url.trim();
  if (!trimmed) return location === "on-device" ? undefined : "missing";
  const match = trimmed.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)/i);
  if (!match) return "scheme";
  const scheme = (match[1] ?? "").toLowerCase();
  const authority = match[2] ?? "";
  if (!authority || authority.includes("@")) return "credentials";
  const host = hostOf(authority);
  if (scheme !== "https" && scheme !== "http") return "scheme";
  if (location === "on-device" && !isLoopbackHost(host)) return "on_device_local";
  if (scheme === "http" && location === "cloud") return "cloud_https";
  if (scheme === "http" && !isLocalHost(host)) return "http_not_local";
  return undefined;
}

/** The first problem of the provider settings, if any. */
export function providerProblem(provider: ProviderSettings): EndpointProblem | undefined {
  const endpoint = endpointProblem(provider.endpoint, provider.location);
  if (endpoint) return endpoint;
  if (provider.endpoint.trim() && !provider.model.trim()) return "model_missing";
  if (provider.location === "cloud" && !provider.apiKeyItemId) return "key_missing";
  return undefined;
}
