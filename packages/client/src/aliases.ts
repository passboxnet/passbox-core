/**
 * Email aliases in the generator (G10): SimpleLogin, addy.io, Fastmail
 * Masked Email, DuckDuckGo Email Protection and Firefox Relay. The API key
 * is stored as a vault item (category "other", tag `alias-service`); the
 * request goes directly from this device to the provider, never through
 * the Passbox server. Mirrors `crates/client/src/client/analysis.rs`.
 */

export type AliasProvider = "simplelogin" | "addy" | "fastmail" | "duckduckgo" | "firefox_relay";

export const ALIAS_PROVIDERS: readonly AliasProvider[] = [
  "simplelogin",
  "addy",
  "fastmail",
  "duckduckgo",
  "firefox_relay",
];

export const ALIAS_PROVIDER_NAMES: Record<AliasProvider, string> = {
  simplelogin: "SimpleLogin",
  addy: "addy.io",
  fastmail: "Fastmail Masked Email",
  duckduckgo: "DuckDuckGo Email Protection",
  firefox_relay: "Firefox Relay",
};

export const ALIAS_DEFAULT_URLS: Record<AliasProvider, string> = {
  simplelogin: "https://app.simplelogin.io",
  addy: "https://app.addy.io",
  fastmail: "https://api.fastmail.com",
  duckduckgo: "https://quack.duckduckgo.com",
  firefox_relay: "https://relay.firefox.com",
};

/** Where users create the API key, for the setup dialog. */
export const ALIAS_KEY_HELP: Record<AliasProvider, string> = {
  simplelogin: "https://app.simplelogin.io/dashboard/api_key",
  addy: "https://app.addy.io/settings/api",
  fastmail: "https://app.fastmail.com/settings/security/tokens",
  duckduckgo: "https://duckduckgo.com/email/settings",
  firefox_relay: "https://relay.firefox.com/accounts/profile/",
};

/** Field IDs of an alias service item. */
export const ALIAS_FIELD = {
  provider: "alias_provider",
  apiKey: "alias_api_key",
  baseUrl: "alias_base_url",
  domain: "alias_domain",
} as const;

export const ALIAS_TAG = "alias-service";

export interface AliasSettings {
  provider: AliasProvider;
  apiKey: string;
  /** A self-hosted SimpleLogin or addy.io (https). */
  baseUrl?: string | undefined;
  /** addy.io: the alias domain. */
  aliasDomain?: string | undefined;
}

/** An error from an alias provider, with a code the UI translates. */
export class AliasError extends Error {
  constructor(
    readonly code: "unauthorized" | "rate_limited" | "failed" | "no_alias" | "insecure_url" | "no_key" | "network",
    readonly provider: AliasProvider,
    message: string,
  ) {
    super(message);
    this.name = "AliasError";
  }
}

export function isAliasProvider(value: unknown): value is AliasProvider {
  return typeof value === "string" && (ALIAS_PROVIDERS as readonly string[]).includes(value);
}

/** Creates an alias for the website `forDomain`. */
export async function createAlias(
  settings: AliasSettings,
  forDomain: string,
  fetchImpl: typeof globalThis.fetch = globalThis.fetch.bind(globalThis),
): Promise<string> {
  const { provider } = settings;
  const base = (settings.baseUrl?.trim() || ALIAS_DEFAULT_URLS[provider]).replace(/\/+$/, "");
  if (!base.startsWith("https://")) throw new AliasError("insecure_url", provider, "the address must use https");
  const key = settings.apiKey.trim();
  if (!key) throw new AliasError("no_key", provider, "no API key");
  const note = forDomain ? `Created by Passbox for ${forDomain}` : "Created by Passbox";

  async function send(method: string, url: string, headers: Record<string, string>, body?: unknown) {
    let response: Response;
    try {
      const init: RequestInit = {
        method,
        headers: { accept: "application/json", "content-type": "application/json", ...headers },
      };
      if (body !== undefined) init.body = JSON.stringify(body);
      response = await fetchImpl(url, init);
    } catch (error) {
      throw new AliasError("network", provider, error instanceof Error ? error.message : String(error));
    }
    let json: Record<string, unknown> = {};
    try {
      json = (await response.json()) as Record<string, unknown>;
    } catch {
      json = {};
    }
    if (response.status === 401 || response.status === 403)
      throw new AliasError("unauthorized", provider, "the API key was rejected");
    if (response.status === 429) throw new AliasError("rate_limited", provider, "too many aliases");
    if (!response.ok) throw new AliasError("failed", provider, `status ${response.status}`);
    // biome-ignore lint/suspicious/noExplicitAny: provider answers are untyped JSON; `pick` validates what is used.
    return json as Record<string, any>;
  }
  const pick = (value: unknown) => {
    if (typeof value === "string" && value.includes("@")) return value;
    throw new AliasError("no_alias", provider, "no alias in the answer");
  };

  switch (provider) {
    case "simplelogin": {
      const body = await send(
        "POST",
        `${base}/api/alias/random/new?hostname=${encodeURIComponent(forDomain)}`,
        { Authentication: key },
        { note },
      );
      return pick(body.alias);
    }
    case "addy": {
      const body = await send(
        "POST",
        `${base}/api/v1/aliases`,
        { Authorization: `Bearer ${key}`, "X-Requested-With": "XMLHttpRequest" },
        { domain: settings.aliasDomain?.trim() || "anonaddy.me", description: note },
      );
      return pick(body.data?.email);
    }
    case "fastmail": {
      const auth = { Authorization: `Bearer ${key}` };
      const capability = "https://www.fastmail.com/dev/maskedemail";
      const session = await send("GET", `${base}/jmap/session`, auth);
      const accountId = session.primaryAccounts?.[capability];
      if (typeof accountId !== "string") throw new AliasError("unauthorized", provider, "no Masked Email access");
      const apiUrl = typeof session.apiUrl === "string" ? session.apiUrl : `${base}/jmap/api/`;
      const body = await send("POST", apiUrl, auth, {
        using: ["urn:ietf:params:jmap:core", capability],
        methodCalls: [
          [
            "MaskedEmail/set",
            { accountId, create: { passbox: { state: "enabled", forDomain, description: note } } },
            "0",
          ],
        ],
      });
      return pick(body.methodResponses?.[0]?.[1]?.created?.passbox?.email);
    }
    case "duckduckgo": {
      const body = await send("POST", `${base}/api/email/addresses`, { Authorization: `Bearer ${key}` });
      if (typeof body.address !== "string" || !body.address)
        throw new AliasError("no_alias", provider, "no alias in the answer");
      return `${body.address}@duck.com`;
    }
    case "firefox_relay": {
      const body = await send(
        "POST",
        `${base}/api/v1/relayaddresses/`,
        { Authorization: `Token ${key}` },
        { enabled: true, generated_for: forDomain, description: note },
      );
      return pick(body.full_address);
    }
  }
}
