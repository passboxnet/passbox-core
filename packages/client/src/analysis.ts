/**
 * The vault security analysis ("Sicherheits-Check"). The engine runs in the
 * shared core (`passbox_core::analysis`, WebAssembly), so web, extension,
 * desktop and mobile compute the same score and findings. Everything runs
 * on decrypted data in memory; see docs/architecture/security-analysis.md
 * for what leaves the device.
 */

export type FindingKind =
  | "breached"
  | "exposed_email"
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
  breaches?: string[];
  similarToPrevious?: boolean;
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
}

/** Runs the analysis in the shared core. */
export function analyzeSecurity(
  core: AnalysisCore,
  items: readonly AnalysisInputItem[],
  input: AnalysisInput,
): SecurityReport {
  const json = core.analyzeSecurity(
    JSON.stringify(items.map((item) => ({ id: item.id, createdAt: item.createdAt ?? 0, data: item.data }))),
    JSON.stringify({ ...input, breachCounts: input.breachCounts ?? null, exposedEmails: input.exposedEmails ?? [] }),
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

/** How breach checks reach Have I Been Pwned. */
export type BreachMode = "auto" | "server" | "direct";
