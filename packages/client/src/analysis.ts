/**
 * The vault security analysis ("Sicherheits-Check"). The engine runs in the
 * shared core (`passbox_core::analysis`, WebAssembly), so web, extension,
 * desktop and mobile compute the same score and findings. Everything runs
 * on decrypted data in memory; see docs/architecture/security-analysis.md
 * for what leaves the device.
 */

import type { BreachCatalog } from "@passbox/api-client";

export type FindingKind =
  | "breached"
  | "exposed_email"
  | "breached_site"
  | "lookalike"
  | "reused"
  | "weak"
  | "similar"
  | "insecure_url"
  | "missing_two_factor"
  | "expired"
  | "expiring"
  | "old"
  | "passkey_available"
  | "duplicate"
  | "missing_url"
  | "missing_username"
  | "totp_in_same_item";

/** All kinds in priority order. */
export const FINDING_KINDS: readonly FindingKind[] = [
  "breached",
  "exposed_email",
  "breached_site",
  "lookalike",
  "reused",
  "weak",
  "similar",
  "insecure_url",
  "missing_two_factor",
  "expired",
  "expiring",
  "old",
  "passkey_available",
  "duplicate",
  "missing_url",
  "missing_username",
  "totp_in_same_item",
];

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FixAction =
  | "change_password"
  | "enable_two_factor"
  | "add_passkey"
  | "use_https"
  | "check_website"
  | "renew"
  | "review_duplicates"
  | "add_website"
  | "add_username"
  | "separate_totp";

export type LookalikeReason = "homograph" | "mixed_script" | "confusable" | "typo";

export interface Finding {
  kind: FindingKind;
  severity: Severity;
  itemId: string;
  fix: FixAction;
  /** Other items of the same group (reused, similar, duplicate, lookalike target). */
  related: string[];
  dismissed: boolean;
  breachCount?: number;
  strength?: number;
  ageDays?: number;
  domain?: string;
  documentationUrl?: string;
  lookalikeOf?: string;
  lookalikeReason?: LookalikeReason;
  /** `YYYY-MM` or `YYYY-MM-DD`. */
  expires?: string;
  daysLeft?: number;
  email?: string;
  /** ExposedEmail, BreachedSite: breach titles. */
  breaches?: string[];
  similarToPrevious?: boolean;
  /** BreachedSite: Have I Been Pwned names of the breaches (details in `SecurityReport.breachedSites`). */
  breachNames?: string[];
  /** BreachedSite: date of the most recent breach (`YYYY-MM-DD`). */
  breachDate?: string;
  /** BreachedSite: kinds of exposed data (Have I Been Pwned's names). */
  dataClasses?: string[];
  /** BreachedSite: when the password was set is unknown. */
  possibly?: boolean;
}

/** A breached website that concerns saved logins. */
export interface BreachedSite {
  name: string;
  title: string;
  domain: string;
  /** `YYYY-MM-DD`. */
  breachDate: string;
  /** When the breach was published (ISO 8601). */
  addedDate: string;
  pwnCount: number;
  dataClasses: string[];
  verified: boolean;
  /** Keep the name off lock screens and notifications. */
  sensitive: boolean;
  exposesCredentials: boolean;
  /** Item IDs whose password is older than the breach. */
  affected: string[];
  /** Item IDs where it is unknown when the password was set. */
  possibly: string[];
  /** Item IDs whose password was changed after the breach. */
  fixed: string[];
}

/** The breach catalogue a report used. */
export interface CatalogInfo {
  version: string;
  /** Newest added or modified date of its entries (Unix ms). */
  updatedAt: number;
  entries: number;
  /** The snapshot bundled with the app (no catalogue from the server yet). */
  bundled: boolean;
  source: string;
  sourceUrl: string;
  license: string;
}

export interface CategorySummary {
  kind: FindingKind;
  severity: Severity;
  count: number;
  dismissed: number;
  /** Score points this category costs. */
  points: number;
  /** False when turned off or not checked yet. */
  checked: boolean;
}

export interface Priority {
  itemId: string;
  kinds: FindingKind[];
  severity: Severity;
  fix: FixAction;
  /** Score points gained by fixing this item. */
  points: number;
}

export interface SecurityReport {
  /** 0–100, higher is better. */
  score: number;
  rating: "excellent" | "good" | "fair" | "poor";
  items: number;
  logins: number;
  scored: number;
  breachChecked: boolean;
  categories: CategorySummary[];
  findings: Finding[];
  fixFirst: Priority[];
  reusedGroups: string[][];
  similarGroups: string[][];
  duplicateGroups: string[][];
  /** Snapshot dates of the bundled 2FA and passkey site lists. */
  directoryDates: [string, string];
  /** Breached websites of saved logins, open ones first, newest first. */
  breachedSites: BreachedSite[];
  breachCatalog: CatalogInfo;
}

/** The user's report settings (device-local). */
export interface ReportOptions {
  /** Passwords older than this many days count as old; 0 turns it off. */
  oldAfterDays: number;
  expiringWithinDays: number;
  /** Kinds the user turned off. */
  disabled: FindingKind[];
}

export const DEFAULT_REPORT_OPTIONS: ReportOptions = { oldAfterDays: 365, expiringWithinDays: 60, disabled: [] };

/** A breach of a monitored email address, as the analysis needs it. */
export interface ExposedEmail {
  email: string;
  breaches: { name: string; title: string; domain: string; breachDate: string; dataClasses: string[] }[];
}

export interface Lookalike {
  /** The checked domain (registrable, Unicode). */
  domain: string;
  /** The domain it imitates; empty for `mixed_script`. */
  looksLike: string;
  reason: LookalikeReason;
  /** `looksLike` is one of the user's saved domains. */
  saved: boolean;
}

/** What the bundled 2FA/passkey directories know about a site. */
export interface SiteSupport {
  domain: string;
  totp: boolean;
  securityKey: boolean;
  otherTwoFactor: boolean;
  passkeySignIn: boolean;
  passkeyTwoFactor: boolean;
  twoFactorDocs: string | null;
  passkeyDocs: string | null;
}

/** The part of `@passbox/core-wasm` the analysis needs. */
export interface AnalysisCore {
  analyzeSecurity(itemsJson: string, optionsJson: string): string;
  /** Present in builds with the breach catalogue. */
  bundledBreachCatalog?(): string;
  checkLookalike(host: string, savedJson: string): string | undefined;
  siteSupport(host: string): string | undefined;
}

export interface AnalysisInputItem {
  id: string;
  createdAt?: number;
  data: object;
}

export interface AnalysisInput extends ReportOptions {
  now: number;
  userInputs: string[];
  /** Breach counts by item ID; omit when no breach check ran. */
  breachCounts?: Record<string, number> | undefined;
  exposedEmails?: ExposedEmail[] | undefined;
  /** The breach catalogue from the server; omit to use the bundled snapshot. */
  siteBreaches?: BreachCatalog | undefined;
}

/** Runs the analysis in the shared core. */
export function analyzeSecurity(
  core: AnalysisCore,
  items: readonly AnalysisInputItem[],
  input: AnalysisInput,
): SecurityReport {
  const json = core.analyzeSecurity(
    JSON.stringify(items.map((item) => ({ id: item.id, createdAt: item.createdAt ?? 0, data: item.data }))),
    JSON.stringify({
      ...input,
      breachCounts: input.breachCounts ?? null,
      exposedEmails: input.exposedEmails ?? [],
      siteBreaches: input.siteBreaches ?? null,
    }),
  );
  return JSON.parse(json) as SecurityReport;
}

/**
 * Whether `host` looks like one of `savedHosts` (the user's login hosts) or
 * a well-known site: IDN homographs, confusable characters, typos. Local.
 */
export function checkLookalike(core: AnalysisCore, host: string, savedHosts: readonly string[]): Lookalike | null {
  const json = core.checkLookalike(host, JSON.stringify(savedHosts));
  return json ? (JSON.parse(json) as Lookalike) : null;
}

/** What the bundled directories know about a host, or null. */
export function siteSupport(core: AnalysisCore, host: string): SiteSupport | null {
  const json = core.siteSupport(host);
  return json ? (JSON.parse(json) as SiteSupport) : null;
}

/** The item key that holds dismissed finding codes (encrypted and synced with the item). */
export const SECURITY_IGNORE_KEY = "securityIgnore";

/** A copy of `data` with `kind` dismissed (or restored), or `undefined` when nothing changes. */
export function withDismissed<T extends object>(data: T, kind: FindingKind, dismissed: boolean): T | undefined {
  const raw = (data as Record<string, unknown>)[SECURITY_IGNORE_KEY];
  const codes = Array.isArray(raw) ? raw.filter((c): c is string => typeof c === "string") : [];
  if (codes.includes(kind) === dismissed) return undefined;
  const next = dismissed ? [...codes, kind] : codes.filter((c) => c !== kind);
  const copy = { ...data } as Record<string, unknown>;
  if (next.length === 0) delete copy[SECURITY_IGNORE_KEY];
  else copy[SECURITY_IGNORE_KEY] = next;
  return copy as T;
}

/** The catalogue bundled with the WebAssembly core (without entries). */
export function bundledBreachCatalog(core: AnalysisCore): Omit<CatalogInfo, "bundled"> | null {
  return core.bundledBreachCatalog ? (JSON.parse(core.bundledBreachCatalog()) as Omit<CatalogInfo, "bundled">) : null;
}

/** Data classes that let an attacker sign in (as in the core). */
export const CREDENTIAL_CLASSES: readonly string[] = [
  "Passwords",
  "Password hints",
  "Historical passwords",
  "Auth tokens",
  "Security questions and answers",
  "PINs",
];

/** Have I Been Pwned's data classes with their own translation (`dataClass.<key>`). */
export const DATA_CLASS_KEYS: Readonly<Record<string, string>> = {
  Passwords: "passwords",
  "Password hints": "passwordHints",
  "Historical passwords": "historicalPasswords",
  "Auth tokens": "authTokens",
  "Security questions and answers": "securityQuestions",
  PINs: "pins",
  "Email addresses": "emailAddresses",
  Usernames: "usernames",
  Names: "names",
  "Phone numbers": "phoneNumbers",
  "Physical addresses": "physicalAddresses",
  "Dates of birth": "datesOfBirth",
  "IP addresses": "ipAddresses",
  Genders: "genders",
  "Geographic locations": "geographicLocations",
  "Credit cards": "creditCards",
  "Partial credit card data": "partialCreditCards",
  "Bank account numbers": "bankAccounts",
  "Government issued IDs": "governmentIds",
  "Passport numbers": "passportNumbers",
  "Social security numbers": "socialSecurityNumbers",
  "Private messages": "privateMessages",
  Purchases: "purchases",
  "Job titles": "jobTitles",
  Employers: "employers",
  "Social media profiles": "socialMediaProfiles",
  "Website activity": "websiteActivity",
  "Device information": "deviceInformation",
};

/** The `dataClass.*` translation key of a data class, or `undefined` (show Have I Been Pwned's English name). */
export function dataClassKey(dataClass: string): string | undefined {
  return DATA_CLASS_KEYS[dataClass];
}

/** Counts of one breach in an organization's aggregate (no item details). */
export interface SiteBreachCount {
  name: string;
  title: string;
  /** Logins still affected or possibly affected. */
  open: number;
  /** Logins whose password was changed after the breach. */
  fixed: number;
}

/**
 * Per-breach counts of the items in `itemIds` (an organization's vaults).
 * Sensitive breaches are left out: the organization learns nothing about
 * what kind of sites its members use beyond the shared logins.
 */
export function siteBreachCounts(report: SecurityReport, itemIds: ReadonlySet<string>): SiteBreachCount[] {
  const counts: SiteBreachCount[] = [];
  for (const site of report.breachedSites) {
    if (site.sensitive) continue;
    const open = [...site.affected, ...site.possibly].filter((id) => itemIds.has(id)).length;
    const fixed = site.fixed.filter((id) => itemIds.has(id)).length;
    if (open + fixed > 0) counts.push({ name: site.name, title: site.title, open, fixed });
  }
  return counts.slice(0, 500);
}

/** How breach checks reach Have I Been Pwned. */
export type BreachMode = "auto" | "server" | "direct";
