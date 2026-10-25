/**
 * Have I Been Pwned through the user's own server (G6, G11): the Pwned
 * Passwords range proxy and email breach monitoring. See
 * docs/architecture/security-analysis.md.
 */

/** A breach a monitored address appeared in (Have I Been Pwned breach model). */
export interface EmailBreach {
  name: string;
  title: string;
  domain: string;
  /** `YYYY-MM-DD`. */
  breachDate: string;
  addedDate: string;
  pwnCount: number;
  /** Kinds of exposed data, for example `Passwords`. */
  dataClasses: string[];
  /** When this server first saw the address in the breach (Unix ms). */
  firstSeenAt: number;
}

export interface MonitoredEmail {
  id: string;
  email: string;
  /** Confirmed with the mailed code; only confirmed addresses are checked. */
  verified: boolean;
  /** Last check (Unix ms, 0 = never). */
  checkedAt: number;
  checkError: string | null;
  createdAt: number;
  breaches: EmailBreach[];
}

export interface EmailMonitoring {
  /** The operator configured a Have I Been Pwned API key. */
  available: boolean;
  checkIntervalHours: number;
  emails: MonitoredEmail[];
}

/**
 * One entry of the public breach catalogue (Have I Been Pwned, CC BY 4.0):
 * a breached website. Clients match it against their own logins locally.
 */
export interface SiteBreach {
  /** Have I Been Pwned's stable name (`Adobe`). */
  name: string;
  title: string;
  /** The breached site, lower case. */
  domain: string;
  /** When the breach happened (`YYYY-MM-DD`, often approximate). */
  breachDate: string;
  /** When it was published (ISO 8601). */
  addedDate: string;
  modifiedDate: string;
  pwnCount: number;
  dataClasses: string[];
  verified: boolean;
  /** A sensitive breach: keep its name off lock screens. */
  sensitive: boolean;
}

/** The catalogue document (`GET /api/v1/breaches/catalog`). */
export interface BreachCatalog {
  version: string;
  /** Newest added or modified date of the entries (Unix ms). */
  updatedAt: number;
  source: string;
  sourceUrl: string;
  license: string;
  breaches: SiteBreach[];
}

/** `GET /api/v1/breaches/catalog/version`. */
export interface BreachCatalogVersion {
  version: string;
  updatedAt: number;
  entries: number;
  /** The server has not fetched the catalogue yet and serves its bundled snapshot. */
  bundled: boolean;
  source: string;
  sourceUrl: string;
  license: string;
}

/** Result of a conditional catalogue request. */
export type CatalogResponse =
  | { status: "ok"; catalog: BreachCatalog; etag: string | null }
  | { status: "not_modified" }
  /** The server turned the catalogue off or is too old to have one. */
  | { status: "unavailable" };

export interface BreachApi {
  /**
   * The padded Pwned Passwords range for a 5-character SHA-1 prefix through
   * the server, or `null` when the server does not offer it (404).
   */
  range(prefix: string): Promise<string | null>;
  emails(): Promise<EmailMonitoring>;
  /** Adds an address; the server mails a confirmation code to it. */
  addEmail(email: string, locale?: string): Promise<MonitoredEmail>;
  verifyEmail(id: string, code: string): Promise<MonitoredEmail>;
  checkEmail(id: string): Promise<MonitoredEmail>;
  removeEmail(id: string): Promise<void>;
  /** The breach catalogue; sends `If-None-Match` when `etag` is given. No session needed. */
  catalog(etag?: string | null): Promise<CatalogResponse>;
  /** Version and date of the catalogue, or `null` when the server has none. */
  catalogVersion(): Promise<BreachCatalogVersion | null>;
}

/** A GET without a session that reports status, `ETag` and the JSON body. */
export type FetchJson = (
  path: string,
  headers: Record<string, string>,
) => Promise<{ status: number; etag: string | null; body: unknown }>;

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;

export function breachApi(
  call: Call,
  text: (path: string) => Promise<string | null>,
  fetchJson?: FetchJson,
): BreachApi {
  const e = encodeURIComponent;
  const getJson: FetchJson =
    fetchJson ??
    (async (path) => {
      const body = await call<unknown>("GET", path);
      return { status: 200, etag: null, body };
    });
  return {
    catalog: async (etag) => {
      const headers: Record<string, string> = { accept: "application/json" };
      if (etag) headers["if-none-match"] = etag;
      const response = await getJson("/api/v1/breaches/catalog", headers);
      if (response.status === 304) return { status: "not_modified" };
      if (response.status === 404) return { status: "unavailable" };
      return { status: "ok", catalog: response.body as BreachCatalog, etag: response.etag };
    },
    catalogVersion: async () => {
      const response = await getJson("/api/v1/breaches/catalog/version", { accept: "application/json" });
      return response.status === 404 ? null : (response.body as BreachCatalogVersion);
    },
    range: (prefix) => text(`/api/v1/breach/range/${e(prefix.toUpperCase())}`),
    emails: () => call("GET", "/api/v1/breach/emails"),
    addEmail: (email, locale) => call("POST", "/api/v1/breach/emails", { email, locale }),
    verifyEmail: (id, code) => call("POST", `/api/v1/breach/emails/${e(id)}/verify`, { code }),
    checkEmail: (id) => call("POST", `/api/v1/breach/emails/${e(id)}/check`, {}),
    removeEmail: (id) => call("DELETE", `/api/v1/breach/emails/${e(id)}`),
  };
}
