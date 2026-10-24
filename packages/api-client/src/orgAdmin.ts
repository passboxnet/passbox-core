/**
 * Organization administration (wave D): signed policies, the audit log,
 * reports, settings, offboarding and the events API. Policy bodies are
 * signed by `@passbox/core-wasm`; see docs/architecture/administration.md.
 */

/** Rules of an organization policy (mirrors `passbox_core::policy::PolicyRules`). */
export interface PolicyRules {
  requireTwoFactor: boolean;
  /** 0–4, 0 = no requirement. */
  minPasswordScore: number;
  /** 0 = no limit. */
  maxAutoLockMinutes: number;
  forbidExport: boolean;
  forbidExternalSharing: boolean;
  shareLinks: "allowed" | "restricted" | "forbidden";
  shareLinkMaxDays: number;
  shareLinkMaxViews: number;
  requireRecoveryEnrollment: boolean;
  allowPersonalVault: boolean;
  reportItemUsage: boolean;
}

/** A signed policy as the server stores it. */
export interface PolicyRecord {
  orgId: string;
  version: number;
  policy: string;
  signature: string;
}

export interface PolicyState {
  current: PolicyRecord | null;
  /** Every version, oldest first (admins only). */
  history: PolicyRecord[];
}

/** One entry of an organization's audit log (mirrors `passbox_core::audit::AuditRecord`). */
export interface AuditRecord {
  orgId: string;
  seq: number;
  id: string;
  createdAt: number;
  actorId: string;
  actorEmail: string;
  deviceName: string;
  clientKind: string;
  ip: string;
  action: string;
  targetType: string;
  targetId: string;
  /** JSON object, exactly as hashed. */
  details: string;
  clientEvent: string;
  clientSignature: string;
  prevHash: string;
  hash: string;
}

export interface AuditHead {
  seq: number;
  hash: string;
  prunedSeq: number;
  prunedHash: string;
}

export interface AuditQuery {
  before?: number;
  after?: number;
  limit?: number;
  /** Exact action or a prefix ending in `*`. */
  action?: string;
  actor?: string;
  target?: string;
  from?: number;
  to?: number;
  source?: "client" | "server";
}

export interface AuditPage {
  events: AuditRecord[];
  head: AuditHead;
}

export interface ChainCheck {
  valid: boolean;
  length: number;
  firstSeq?: number | null;
  lastSeq?: number | null;
  headHash?: string | null;
  brokenAt?: number | null;
  problem?: string | null;
}

export interface AuditExport {
  format: "passbox-audit-log";
  version: 1;
  orgId: string;
  exportedAt: number;
  head: AuditHead;
  events: AuditRecord[];
}

export interface SignedClientEvent {
  event: string;
  signature: string;
}

export interface SecurityAggregate {
  score: number;
  total: number;
  weak: number;
  reused: number;
  unsecured: number;
  /** 1 met, 0 did not meet, -1 unknown. */
  passwordPolicy: number;
  reportedAt: number;
}

export interface MemberReport {
  accountId: string;
  email: string;
  role: string;
  status: string;
  joinedAt: number;
  twoFactor: boolean;
  twoFactorMethods: ("totp" | "webauthn")[];
  recoveryEnrolled: boolean;
  lastSignInAt: number;
  groups: string[];
  vaultCount: number;
  security: SecurityAggregate | null;
}

export interface VaultReport {
  vaultId: string;
  createdAt: number;
  keyEpoch: number;
  rotationPending: boolean;
  itemCount: number;
  lastWriteAt: number;
  lastUsedAt: number;
  unused: boolean;
  members: { principalType: "account" | "group"; principalId: string; role: "view" | "edit" | "manage" }[];
  managers: string[];
}

export interface AccessEntry {
  accountId: string;
  vaultId: string;
  role: "view" | "edit" | "manage";
  /** `direct` and/or group IDs. */
  via: string[];
}

export interface OrgReport {
  generatedAt: number;
  unusedAfterDays: number;
  members: MemberReport[];
  vaults: VaultReport[];
  access: AccessEntry[];
  pendingInvitations: number;
  pendingRecoveryRequests: number;
  recoverySetUp: boolean;
  policyVersion: number;
}

export interface OrgSettings {
  /** 0 = keep forever, otherwise 30–3650. */
  auditRetentionDays: number;
}

export interface EventToken {
  id: string;
  name: string;
  createdBy: string;
  createdAt: number;
  lastUsedAt: number;
}

export interface Webhook {
  id: string;
  url: string;
  active: boolean;
  cursorSeq: number;
  failures: number;
  lastStatus: number;
  lastError: string;
  lastDeliveryAt: number;
  createdAt: number;
}

export interface OrgAdminApi {
  policy(orgId: string): Promise<PolicyState>;
  putPolicy(orgId: string, body: { version: number; policy: string; signature: string }): Promise<PolicyRecord>;
  audit(orgId: string, query?: AuditQuery): Promise<AuditPage>;
  verifyAudit(orgId: string): Promise<ChainCheck>;
  exportAudit(orgId: string, format: "json", query?: AuditQuery): Promise<AuditExport>;
  exportAuditCsv(orgId: string, query?: AuditQuery): Promise<string>;
  clientEvents(orgId: string, events: SignedClientEvent[]): Promise<{ accepted: number; duplicates: number }>;
  reports(orgId: string): Promise<OrgReport>;
  putSecurityReport(
    orgId: string,
    report: {
      score: number;
      total: number;
      weak: number;
      reused: number;
      unsecured: number;
      passwordMeetsPolicy?: boolean;
    },
  ): Promise<void>;
  settings(orgId: string): Promise<OrgSettings>;
  putSettings(orgId: string, settings: OrgSettings): Promise<OrgSettings>;
  endSessions(orgId: string, accountId: string): Promise<{ sessions: number }>;
  eventTokens(orgId: string): Promise<EventToken[]>;
  createEventToken(orgId: string, name: string): Promise<{ id: string; token: string }>;
  revokeEventToken(orgId: string, tokenId: string): Promise<void>;
  webhooks(orgId: string): Promise<Webhook[]>;
  createWebhook(orgId: string, url: string, fromStart?: boolean): Promise<{ id: string; secret: string }>;
  deleteWebhook(orgId: string, webhookId: string): Promise<void>;
}

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;

function query(params: object): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export function orgAdminApi(call: Call): OrgAdminApi {
  const e = encodeURIComponent;
  const org = (id: string) => `/api/v1/orgs/${e(id)}`;
  return {
    policy: (orgId) => call("GET", `${org(orgId)}/policy`),
    putPolicy: (orgId, body) => call("PUT", `${org(orgId)}/policy`, body),
    audit: (orgId, q = {}) => call("GET", `${org(orgId)}/audit${query(q)}`),
    verifyAudit: (orgId) => call("GET", `${org(orgId)}/audit/verify`),
    exportAudit: (orgId, format, q = {}) => call("GET", `${org(orgId)}/audit/export${query({ ...q, format })}`),
    exportAuditCsv: (orgId, q = {}) => call("GET", `${org(orgId)}/audit/export${query({ ...q, format: "csv" })}`),
    clientEvents: (orgId, events) => call("POST", `${org(orgId)}/audit/client-events`, { events }),
    reports: (orgId) => call("GET", `${org(orgId)}/reports`),
    putSecurityReport: (orgId, report) => call("PUT", `${org(orgId)}/security-report`, report),
    settings: (orgId) => call("GET", `${org(orgId)}/settings`),
    putSettings: (orgId, settings) => call("PUT", `${org(orgId)}/settings`, settings),
    endSessions: (orgId, accountId) => call("POST", `${org(orgId)}/members/${e(accountId)}/end-sessions`, {}),
    eventTokens: (orgId) => call("GET", `${org(orgId)}/event-tokens`),
    createEventToken: (orgId, name) => call("POST", `${org(orgId)}/event-tokens`, { name }),
    revokeEventToken: (orgId, tokenId) => call("DELETE", `${org(orgId)}/event-tokens/${e(tokenId)}`),
    webhooks: (orgId) => call("GET", `${org(orgId)}/webhooks`),
    createWebhook: (orgId, url, fromStart = false) => call("POST", `${org(orgId)}/webhooks`, { url, fromStart }),
    deleteWebhook: (orgId, webhookId) => call("DELETE", `${org(orgId)}/webhooks/${e(webhookId)}`),
  };
}
