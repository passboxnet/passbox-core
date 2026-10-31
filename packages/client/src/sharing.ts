/**
 * Types of the verified sharing state, as produced by the Rust core
 * (`passbox_core::sharing::state`). Everything here has been verified by
 * the core: roles come from signed attestations and manifests, not from
 * what the server claims (the server's view is in `serverRole`).
 */

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
