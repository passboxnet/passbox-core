/**
 * Icons of the third-party services Passbox names in its UI, bundled with the
 * apps (no request reaches these services at run time). The marks belong to
 * their owners and are used only to identify the services; see
 * THIRD_PARTY_NOTICES.md. Refresh with `node scripts/update-brand-icons.mjs`.
 *
 * Website icons of vault items are a different thing: they come through the
 * user's own server (`client.iconUrl(domain)`).
 */
import manifest from "../manifest.json";
import { ICON_URLS } from "./generated";

export interface BrandIconInfo {
  /** Stable ID, for example `okta` or `1password`. */
  id: string;
  /** The service's name, for alt text: "Okta", "Microsoft Entra ID". */
  name: string;
  /** URL of the 64 px PNG (an asset URL of the bundle). */
  url: string;
  /** The icon fills its whole square (an app icon); others need some padding on a tile. */
  bleed: boolean;
}

interface ManifestEntry {
  id: string;
  name: string;
  domain?: string;
  aliases?: string[];
  bleed?: boolean;
}

const byKey = new Map<string, BrandIconInfo>();
for (const entry of manifest.icons as ManifestEntry[]) {
  const url = ICON_URLS[entry.id];
  if (!url) continue;
  const info: BrandIconInfo = { id: entry.id, name: entry.name, url, bleed: entry.bleed ?? false };
  for (const key of [entry.id, entry.domain, ...(entry.aliases ?? [])]) {
    if (key && !byKey.has(key.toLowerCase())) byKey.set(key.toLowerCase(), info);
  }
}

function normalize(value: string): string {
  let key = value.trim().toLowerCase();
  // Accept URLs ("https://www.okta.com/login") as well as host names and IDs.
  if (key.includes("://")) {
    try {
      key = new URL(key).hostname;
    } catch {
      return key;
    }
  }
  return key.replace(/^www\./, "").replace(/\.$/, "");
}

/**
 * The bundled icon of a service, by ID (`okta`), host name (`okta.com`,
 * `acme.okta.com`) or URL, or `undefined` when there is none. Subdomains fall
 * back to their parent domain (`eu.api.mistral.ai` → `mistral.ai`).
 */
export function brandIconInfo(domainOrId: string | undefined | null): BrandIconInfo | undefined {
  if (!domainOrId) return undefined;
  let key = normalize(domainOrId);
  while (key) {
    const info = byKey.get(key);
    if (info) return info;
    const dot = key.indexOf(".");
    // Stop before a bare top-level domain ("com").
    if (dot < 0 || key.indexOf(".", dot + 1) < 0) return undefined;
    key = key.slice(dot + 1);
  }
  return undefined;
}

/** URL of the bundled icon of a service (see `brandIconInfo`), or `undefined`. */
export function brandIcon(domainOrId: string | undefined | null): string | undefined {
  return brandIconInfo(domainOrId)?.url;
}

/** Every bundled icon, in the order of the manifest. */
export function brandIcons(): BrandIconInfo[] {
  return [...new Set(byKey.values())];
}
