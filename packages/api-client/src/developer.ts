/**
 * Service accounts (wave F2) and AI agent grants (wave F7). Bodies with
 * keys and signatures are built by `@passbox/core-wasm`; see
 * docs/architecture/service-accounts.md and docs/architecture/ai-agents.md.
 */

export type ServiceAccountPermission = "read" | "write";

/** A vault key sealed to a service account and signed by its owner. */
export interface ServiceAccountGrantUpload {
  vaultId: string;
  keyEpoch: number;
  permission: ServiceAccountPermission;
  sealedKey: string;
  grant: string;
  grantSignature: string;
}

export interface ServiceAccountGrantRecord {
  vaultId: string;
  keyEpoch: number;
  permission: ServiceAccountPermission;
  /** The vault's current key epoch; a lower `keyEpoch` needs renewing. */
  currentKeyEpoch: number;
  createdAt: number;
}

export interface ServiceAccountRecord {
  id: string;
  name: string;
  publicKey: string;
  publicKeySignature: string;
  /** Unix ms; 0 for no expiry. */
  expiresAt: number;
  /** Unix ms; 0 while active. */
  revokedAt: number;
  lastUsedAt: number;
  lastUsedIp: string;
  createdAt: number;
  grants: ServiceAccountGrantRecord[];
}

export interface ServiceAccountEventRecord {
  id: string;
  /** `created`, `read`, `item_written`, `item_deleted`, `access_granted`, `access_removed`, `updated`, `revoked`. */
  kind: string;
  detail: string;
  ip: string;
  createdAt: number;
}

export type AgentGrantStatus = "pending" | "approved" | "denied" | "expired" | "revoked";

export interface AgentGrantRecord {
  id: string;
  principalKind: "session" | "service";
  principalId: string;
  /** The service account's name, for service principals. */
  principalName?: string;
  /** Self-reported by the agent's MCP client. */
  clientName: string;
  /** Base64url canonical request: parse it with the core and show that. */
  request: string;
  status: AgentGrantStatus;
  notAfter: number;
  decidedDevice: string;
  ip: string;
  createdAt: number;
  expiresAt: number;
  decidedAt: number;
}

export interface AgentEventRecord {
  id: string;
  grantId: string;
  principalKind: "session" | "service";
  principalId: string;
  clientName: string;
  tool: "search" | "request_access" | "run" | "inject" | "create" | "generate";
  itemIds: string[];
  /** For commands: first word and hash, never the command line. */
  target: string;
  result: "ok" | "failed" | "denied" | "expired" | "blocked";
  ip: string;
  createdAt: number;
}

/** The fair-use limit for AI agents and service accounts (they never count as members). */
export interface AgentUsage {
  /** 0 = unlimited. */
  limitPerMember: number;
  used: number;
  /** 0 = unlimited. */
  allowed: number;
  pool: "personal" | "organization";
  orgId?: string;
  members?: number;
}

export interface DeveloperApi {
  serviceAccounts(): Promise<ServiceAccountRecord[]>;
  agentLimit(): Promise<AgentUsage>;
  createServiceAccount(body: {
    id: string;
    name: string;
    publicKey: string;
    publicKeySignature: string;
    encryptedPrivate: string;
    authHash: string;
    expiresAt: number;
    grants: ServiceAccountGrantUpload[];
  }): Promise<ServiceAccountRecord>;
  updateServiceAccount(id: string, body: { name?: string; expiresAt?: number }): Promise<ServiceAccountRecord>;
  putServiceAccountGrants(id: string, grants: ServiceAccountGrantUpload[]): Promise<ServiceAccountRecord>;
  deleteServiceAccountGrant(id: string, vaultId: string): Promise<void>;
  revokeServiceAccount(id: string): Promise<void>;
  deleteServiceAccount(id: string): Promise<void>;
  serviceAccountEvents(id: string, limit?: number): Promise<ServiceAccountEventRecord[]>;
  /** `pending` (default) or the last 30 days with `all`. */
  agentGrants(status?: "pending" | "all"): Promise<AgentGrantRecord[]>;
  decideAgentGrant(id: string, body: { decision: string; decisionSignature: string }): Promise<unknown>;
  revokeAgentGrant(id: string): Promise<void>;
  agentEvents(limit?: number): Promise<AgentEventRecord[]>;
}

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;

export function developerApi(call: Call): DeveloperApi {
  const e = encodeURIComponent;
  const sa = (id: string) => `/api/v1/service-accounts/${e(id)}`;
  return {
    serviceAccounts: () => call("GET", "/api/v1/service-accounts"),
    agentLimit: () => call("GET", "/api/v1/agent-limit"),
    createServiceAccount: (body) => call("POST", "/api/v1/service-accounts", body),
    updateServiceAccount: (id, body) => call("PUT", sa(id), body),
    putServiceAccountGrants: (id, grants) => call("PUT", `${sa(id)}/grants`, { grants }),
    deleteServiceAccountGrant: (id, vaultId) => call("DELETE", `${sa(id)}/grants/${e(vaultId)}`),
    revokeServiceAccount: (id) => call("POST", `${sa(id)}/revoke`, {}),
    deleteServiceAccount: (id) => call("DELETE", sa(id)),
    serviceAccountEvents: (id, limit = 50) => call("GET", `${sa(id)}/events?limit=${e(limit)}`),
    agentGrants: (status = "pending") => call("GET", `/api/v1/agent-grants?status=${e(status)}`),
    decideAgentGrant: (id, body) => call("POST", `/api/v1/agent-grants/${e(id)}/decision`, body),
    revokeAgentGrant: (id) => call("POST", `/api/v1/agent-grants/${e(id)}/revoke`, {}),
    agentEvents: (limit = 100) => call("GET", `/api/v1/agent-events?limit=${e(limit)}`),
  };
}
