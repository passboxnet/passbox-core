/**
 * Organization administration: policy types and enforcement
 * helpers, the security aggregate members report, and audit log helpers.
 * The cryptography (signing and verifying policies, signing client events,
 * checking the audit hash chain) lives in `@passbox/core-wasm`.
 */
import type { AuditRecord, PolicyRules } from "@passbox/api-client";
import type { VaultHealth } from "./security";

export type { AuditRecord, PolicyRules } from "@passbox/api-client";

/** The rules of a policy that restricts nothing. */
export const DEFAULT_POLICY_RULES: PolicyRules = {
  requireTwoFactor: false,
  minPasswordScore: 0,
  maxAutoLockMinutes: 0,
  forbidExport: false,
  forbidExternalSharing: false,
  shareLinks: "allowed",
  shareLinkMaxDays: 0,
  shareLinkMaxViews: 0,
  requireRecoveryEnrollment: false,
  allowPersonalVault: true,
  reportItemUsage: false,
  allowAgentReveal: false,
};

/**
 * The first policy of a new organization: recovery
 * through the organization is required, everything else restricts nothing
 * (mirrors `PolicyRules::new_org_defaults`).
 */
export const NEW_ORG_POLICY_RULES: PolicyRules = { ...DEFAULT_POLICY_RULES, requireRecoveryEnrollment: true };

/** The policy in force for one organization (mirrors `passbox_core::policy::OrgPolicyView`). */
export interface OrgPolicy {
  orgId: string;
  version: number;
  hash: string;
  rules: PolicyRules;
  /** Rules this app does not know yet: ask to update. */
  unknownRules: string[];
  signerId: string;
  signedAt: number;
  /** `verified` now, or `pinned` (the server's copy was missing, older or invalid). */
  source: "verified" | "pinned";
  /** The signer is no longer an owner or admin; an admin should sign the policy again. */
  needsResign: boolean;
}

/** Every policy this account is bound by, combined (mirrors `passbox_core::policy::EffectivePolicy`). */
export interface EffectivePolicy {
  requireTwoFactor: boolean;
  twoFactorOrgs: string[];
  minPasswordScore: number;
  maxAutoLockMinutes: number | null;
  allowPersonalVault: boolean;
  personalVaultOrgs: string[];
  recoveryEnrollmentOrgs: string[];
  exportBlockedOrgs: string[];
  externalSharingBlockedOrgs: string[];
  itemUsageOrgs: string[];
  /** Organizations whose policy lets members reveal values to AI agents (older cores omit it). */
  agentRevealOrgs?: string[];
  hasUnknownRules: boolean;
}

/**
 * Whether an approver may tick "Allow revealing the value to the agent" for
 * items of this vault: personal vaults yes, an organization's vaults only
 * with `allowAgentReveal` in its policy.
 */
export function agentRevealAllowed(policy: EffectivePolicy, vault: { orgId?: string | undefined }): boolean {
  return !vault.orgId || (policy.agentRevealOrgs ?? []).includes(vault.orgId);
}

export const NO_POLICY: EffectivePolicy = {
  requireTwoFactor: false,
  twoFactorOrgs: [],
  minPasswordScore: 0,
  maxAutoLockMinutes: null,
  allowPersonalVault: true,
  personalVaultOrgs: [],
  recoveryEnrollmentOrgs: [],
  exportBlockedOrgs: [],
  externalSharingBlockedOrgs: [],
  itemUsageOrgs: [],
  agentRevealOrgs: [],
  hasUnknownRules: false,
};

/** Thrown when an action is not allowed by an organization's policy. */
export class PolicyViolationError extends Error {
  constructor(
    /** `personal_vault`, `export`, `external_sharing`, `share_link` or `two_factor`. */
    readonly rule: string,
    readonly orgIds: string[],
    message: string,
  ) {
    super(message);
    this.name = "PolicyViolationError";
  }
}

/** Auto-lock minutes (0 = never) within the policy limit. */
export function clampAutoLock(policy: EffectivePolicy, minutes: number): number {
  const limit = policy.maxAutoLockMinutes;
  if (!limit) return minutes;
  return minutes === 0 || minutes > limit ? limit : minutes;
}

/** Whether a vault (personal: no `orgId`) may be exported. */
export function canExportVault(policy: EffectivePolicy, vault: { orgId?: string | undefined }): boolean {
  return !(vault.orgId && policy.exportBlockedOrgs.includes(vault.orgId));
}

/**
 * Whether an item may be moved or copied from `from` to `to`: items of an
 * organization that keeps its items inside may only go to vaults of the
 * same organization.
 */
export function canMoveBetween(
  policy: EffectivePolicy,
  from: { orgId?: string | undefined },
  to: { orgId?: string | undefined },
): boolean {
  if (!from.orgId || !policy.externalSharingBlockedOrgs.includes(from.orgId)) return true;
  return to.orgId === from.orgId;
}

/** Something the account has to do to comply with a policy. */
export interface PolicyTask {
  kind: "two_factor" | "password_strength" | "recovery_enrollment" | "update_app";
  orgIds: string[];
}

/**
 * Open tasks for the account. `passwordScore` is the strength score of the
 * master password as entered at the last unlock (unknown: `undefined`).
 */
export function policyTasks(
  policy: EffectivePolicy,
  state: { twoFactor: boolean | undefined; passwordScore: number | undefined; enrolledOrgs: readonly string[] },
): PolicyTask[] {
  const tasks: PolicyTask[] = [];
  if (policy.requireTwoFactor && state.twoFactor === false) {
    tasks.push({ kind: "two_factor", orgIds: policy.twoFactorOrgs });
  }
  if (
    policy.minPasswordScore > 0 &&
    state.passwordScore !== undefined &&
    state.passwordScore < policy.minPasswordScore
  ) {
    tasks.push({ kind: "password_strength", orgIds: [] });
  }
  const missing = policy.recoveryEnrollmentOrgs.filter((org) => !state.enrolledOrgs.includes(org));
  if (missing.length > 0) tasks.push({ kind: "recovery_enrollment", orgIds: missing });
  if (policy.hasUnknownRules) tasks.push({ kind: "update_app", orgIds: [] });
  return tasks;
}

/** What a member's app reports to an organization: numbers only. */
export interface SecurityAggregate {
  score: number;
  total: number;
  weak: number;
  reused: number;
  unsecured: number;
  passwordMeetsPolicy?: boolean;
}

/** The aggregate of a Watchtower analysis (no item IDs, no passwords). */
export function securityAggregate(health: VaultHealth, passwordMeetsPolicy?: boolean): SecurityAggregate {
  const reused = new Set(health.reused.flat()).size;
  return {
    score: Math.max(0, Math.min(100, Math.round(health.score))),
    total: health.analyzed,
    weak: Math.min(health.weak.length, health.analyzed),
    reused: Math.min(reused, health.analyzed),
    unsecured: Math.min(health.insecureUrls.length, health.analyzed),
    ...(passwordMeetsPolicy === undefined ? {} : { passwordMeetsPolicy }),
  };
}

/** Audit actions grouped for filters (the server may log more). */
export const AUDIT_CATEGORIES: Record<string, readonly string[]> = {
  signIn: [
    "member_signed_in",
    "member_sign_in_failed",
    "member_two_factor_failed",
    "member_sessions_ended",
    "member_sessions_revoked",
  ],
  members: [
    "member_invited",
    "invitation_revoked",
    "member_joined",
    "member_confirmed",
    "member_role_changed",
    "member_reattested",
    "member_suspended",
    "member_reactivated",
    "member_removed",
    "member_left",
  ],
  groups: [
    "group_created",
    "group_renamed",
    "group_deleted",
    "group_member_added",
    "group_member_removed",
    "group_key_rotated",
  ],
  access: ["vault_created", "vault_renamed", "vault_access_granted", "vault_access_revoked", "vault_key_rotated"],
  items: ["item_created", "item_updated", "item_deleted", "vault_items_written"],
  usage: ["item_viewed", "secret_revealed", "item_copied", "item_filled"],
  recovery: [
    "recovery_key_created",
    "recovery_admin_added",
    "recovery_enrolled",
    "recovery_withdrawn",
    "recovery_requested",
    "recovery_request_approved",
    "recovery_request_denied",
    "recovery_completed",
  ],
  security: [
    "member_password_changed",
    "member_two_factor_added",
    "member_two_factor_removed",
    "member_two_factor_disabled",
    "member_recovery_codes_regenerated",
    "member_recovery_code_used",
    "member_account_recovery_code_created",
    "member_account_recovery_code_removed",
    "member_device_added",
    "member_emergency_access_used",
  ],
  admin: [
    "org_created",
    "org_renamed",
    "org_key_rotated",
    "policy_updated",
    "settings_updated",
    "audit_exported",
    "event_token_created",
    "event_token_revoked",
    "webhook_created",
    "webhook_deleted",
  ],
};

/** The category of an action, or `other`. */
export function auditCategory(action: string): string {
  for (const [category, actions] of Object.entries(AUDIT_CATEGORIES)) {
    if (actions.includes(action)) return category;
  }
  return "other";
}

/** The parsed `details` of an entry (an empty object if unreadable). */
export function auditDetails(record: Pick<AuditRecord, "details">): Record<string, unknown> {
  try {
    const value = JSON.parse(record.details) as unknown;
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
