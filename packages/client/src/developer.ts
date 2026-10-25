/**
 * Types for service accounts (wave F2) and AI agent grants (wave F7). The
 * operations are methods of `PassboxClient`; see
 * docs/architecture/service-accounts.md and docs/architecture/ai-agents.md.
 */
import type { AgentGrantRecord, ServiceAccountPermission, ServiceAccountRecord } from "@passbox/api-client";

export type {
  AgentEventRecord,
  AgentUsage,
  ServiceAccountEventRecord,
  ServiceAccountPermission,
} from "@passbox/api-client";

/** A service account with its vault access, as its owner sees it. */
export type ServiceAccount = ServiceAccountRecord & {
  /** `active`, `expired` or `revoked`. */
  state: "active" | "expired" | "revoked";
};

/** What `createServiceAccount` returns. Show `token` once; it cannot be recovered. */
export interface CreatedServiceAccount {
  account: ServiceAccount;
  token: string;
}

export interface ServiceAccountVaultChoice {
  vaultId: string;
  permission: ServiceAccountPermission;
}

/** An agent grant request, parsed from the exact bytes the approval signs. */
export interface AgentRequest {
  id: string;
  /** Six digits the agent also shows, for matching the request. */
  code: string;
  principalKind: "session" | "service";
  principalId: string;
  /** The service account's name, from the server (for display only). */
  principalName?: string;
  /** Self-reported by the agent: untrusted. */
  clientName: string;
  items: { itemId: string; vaultId: string }[];
  actions: string[];
  commands: string[];
  paths: string[];
  /** The agent's reason: untrusted text. */
  reason: string;
  ttlMs: number;
  /** 0 for unlimited within the time limit. */
  maxUses: number;
  createdAt: number;
  /** When the request stops waiting for an answer (Unix ms). */
  expiresAt: number;
  status: AgentGrantRecord["status"];
  notAfter: number;
  decidedDevice: string;
  decidedAt: number;
  /** Base64url request, as signed. */
  raw: string;
}

export function serviceAccountState(record: ServiceAccountRecord, now = Date.now()): ServiceAccount["state"] {
  if (record.revokedAt > 0) return "revoked";
  if (record.expiresAt > 0 && record.expiresAt <= now) return "expired";
  return "active";
}
