/**
 * Types of the verified sharing state, as produced by the Rust core
 * (`passbox_core::sharing::state`). Everything here has been verified by
 * the core: roles come from signed attestations and manifests, not from
 * what the server claims (the server's view is in `serverRole`).
 */

import type { OrgLock } from "@passbox/api-client";
import type { EffectivePolicy, OrgPolicy } from "./admin";

export type OrgKind = "family" | "team";
export type OrgRole = "owner" | "admin" | "member" | "guest";
export type VaultRole = "view" | "edit" | "manage";
export type PrincipalType = "account" | "group";

export interface OrgMember {
  accountId: string;
  email?: string | null;
  role: OrgRole | string;
  /** `accepted` (waiting for confirmation), `confirmed` or `suspended`. */
  status: string;
  /** Fingerprint of the member's current key (12 groups of five digits). */
  fingerprint?: string | null;
  /** The key is attested by the owner or an admin. */
  verified: boolean;
  /** The key differs from the one pinned on this device. */
  keyChanged: boolean;
  attestedBy?: string | null;
}

export interface OrgGroup {
  id: string;
  orgId: string;
  name?: string | null;
  keyVersion: number;
  members: string[];
  /** Members come from signed grants (only known to group members). */
  membersVerified: boolean;
  verified: boolean;
  /** This account holds the group's current key. */
  isMember: boolean;
}

export interface Org {
  id: string;
  kind: OrgKind | string;
  name?: string | null;
  /** This account's role and status. */
  role: OrgRole | string;
  status: string;
  /** The family vault of a family organization. */
  defaultVaultId?: string | null;
  /** Organization fingerprint, as in invitation links (8 groups of five digits). */
  fingerprint: string;
  rootHash: string;
  verified: boolean;
  members: OrgMember[];
  groups: OrgGroup[];
  /**
   * Set when the server holds the organization read-only, for example on
   * the hosted service when a payment is overdue. Not signed: it comes from
   * the server and only explains what the server refuses (403 `org_read_only`).
   */
  lock?: OrgLock | null | undefined;
}

export interface SharedVaultMember {
  principalType: PrincipalType | string;
  principalId: string;
  role: VaultRole | string;
}

export interface SharedVault {
  vaultId: string;
  orgId: string;
  /** Role from the verified manifest; `null` if unverified. */
  role?: VaultRole | null;
  /** Role the server enforces. */
  serverRole: VaultRole | string;
  keyEpoch: number;
  manifestVersion: number;
  members: SharedVaultMember[];
  verified: boolean;
  hasKey: boolean;
  /** A member was removed; a manager must rotate the key (`rotateVaultKey`). */
  rotationPending: boolean;
}

export type SharingWarningKind =
  | "key_changed"
  | "own_key_changed"
  | "org_root_changed"
  | "org_unverified"
  | "member_unverified"
  | "manifest_invalid"
  | "grant_invalid"
  | "role_mismatch"
  | "membership_mismatch"
  | "group_unverified"
  | "policy_invalid"
  | "policy_rollback"
  | "policy_conflict"
  | "policy_missing"
  | "policy_needs_resign";

export interface SharingWarning {
  kind: SharingWarningKind | string;
  /** Account, organization, group or vault concerned. */
  subjectId: string;
  orgId?: string | null;
  message: string;
}

export interface SharingView {
  orgs: Org[];
  vaults: SharedVault[];
  warnings: SharingWarning[];
  /** Policies in force per organization. */
  policies?: OrgPolicy[];
  effectivePolicy?: EffectivePolicy;
}

export interface SharingReport {
  view: SharingView;
  wrappedKeys: { vaultId: string; keyEpoch: number; wrappedKey: string }[];
}

export interface KeyLookup {
  accountId: string;
  fingerprint: string;
  bundleHash: string;
  /** `new` (now pinned), `unchanged` or `changed` (see `acceptKeyChange`). */
  status: "new" | "unchanged" | "changed";
  previousFingerprint?: string | null;
}

/** A new invitation; the link is shown once. */
export interface Invitation {
  id: string;
  token: string;
  /** `{base}/invite/{token}#org={fingerprint}`; pass it on through a channel you trust. */
  link: string;
  expiresAt: number;
}

/** Who owns a vault and what this account may do with it. */
export interface VaultAccess {
  vaultId: string;
  /** `undefined` for personal vaults. */
  orgId: string | undefined;
  role: VaultRole | undefined;
  verified: boolean;
}

/** Splits an invitation link (or a bare token) into token and organization root hash. */
export function parseInvitationLink(link: string): { token: string; orgRoot: string | undefined } {
  const hashIndex = link.indexOf("#");
  const path = hashIndex >= 0 ? link.slice(0, hashIndex) : link;
  const fragment = hashIndex >= 0 ? link.slice(hashIndex + 1) : "";
  const marker = path.lastIndexOf("/invite/");
  const token = (marker >= 0 ? path.slice(marker + "/invite/".length) : path).replace(/^\/+|\/+$/g, "");
  const orgRoot = fragment
    .split("&")
    .find((part) => part.startsWith("org="))
    ?.slice(4);
  return { token, orgRoot: orgRoot || undefined };
}

/** Whether the server holds the organization read-only. */
export function isOrgLocked(org: Pick<Org, "lock"> | undefined): boolean {
  return !!org?.lock;
}

/**
 * The locks of the organizations in a sync's `sharing` part. The server
 * sends every organization of the account each time; one without `lock`
 * is not locked.
 */
export function orgLocks(sharing: Record<string, unknown> | undefined): Map<string, OrgLock> {
  const locks = new Map<string, OrgLock>();
  const orgs = sharing?.orgs;
  if (!Array.isArray(orgs)) return locks;
  for (const org of orgs as { id?: unknown; lock?: unknown }[]) {
    const lock = org?.lock as Partial<OrgLock> | null | undefined;
    if (typeof org?.id === "string" && lock && typeof lock.reason === "string") {
      locks.set(org.id, { reason: lock.reason, source: typeof lock.source === "string" ? lock.source : "" });
    }
  }
  return locks;
}

/** The verified view with each organization's lock added (the core does not carry it). */
export function withOrgLocks(view: SharingView, locks: Map<string, OrgLock>): SharingView {
  if (locks.size === 0 && !view.orgs.some((org) => org.lock)) return view;
  return { ...view, orgs: view.orgs.map((org) => ({ ...org, lock: locks.get(org.id) ?? null })) };
}
