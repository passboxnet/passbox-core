/**
 * Moving items between vaults, attachments, share links
 * and access requests. Ciphertexts are built by `@passbox/core-wasm`;
 * see docs/architecture/attachments.md and docs/architecture/sharing.md.
 */

export interface MoveItemUpload {
  id: string;
  /** One higher than the stored revision. */
  revision: number;
  encryptedData: string;
  /** Earlier versions re-encrypted for the target vault (others are dropped). */
  versions: { revision: number; encryptedData: string }[];
}

export interface MoveRequest {
  targetVaultId: string;
  keyEpoch: number;
  items: MoveItemUpload[];
}

export interface AttachmentUsage {
  /** `account` (personal vaults) or an organization ID. */
  owner: string;
  used: number;
  /** 0 = unlimited. */
  quota: number;
}

export interface AttachmentUsageResponse {
  /** Largest encrypted file in bytes. */
  maxFileSize: number;
  usage: AttachmentUsage[];
}

export interface ShareLinkUpload {
  id: string;
  /** The link's label, encrypted with the account key (only the creator reads it). */
  encryptedLabel: string;
  blob: string;
  authHash: string;
  salt?: string | null;
  /** Unix ms, at most 365 days ahead. */
  expiresAt: number;
  /** 0 = unlimited. */
  maxViews: number;
  /** The vault the shared item comes from (its organization's policy applies). */
  vaultId?: string;
}

export interface ShareLinkRecord {
  id: string;
  encryptedLabel: string;
  vaultId: string | null;
  expiresAt: number;
  maxViews: number;
  views: number;
  hasPassphrase: boolean;
  createdAt: number;
  /** 0 = never viewed. */
  lastViewedAt: number;
}

export interface PublicShareLinkInfo {
  /** Passphrase salt; `null` without a passphrase. */
  salt: string | null;
  expiresAt: number;
  /** `null` = unlimited. */
  viewsLeft: number | null;
}

export interface OpenedShareLink {
  blob: string;
  expiresAt: number;
  viewsLeft: number | null;
}

export type AccessRequestStatus = "pending" | "approved" | "denied" | "cancelled";

export interface AccessRequestRecord {
  id: string;
  vaultId: string;
  orgId: string;
  accountId: string;
  email: string;
  role: "view" | "edit" | "manage";
  status: AccessRequestStatus;
  createdAt: number;
  /** 0 while pending. */
  decidedAt: number;
}

export interface ComfortApi {
  moveItems(req: MoveRequest): Promise<{ moved: { id: string; revision: number; seq: number }[] }>;
  /** Uploads an encrypted attachment blob for an item. */
  uploadAttachment(id: string, itemId: string, blob: Uint8Array): Promise<{ id: string; size: number }>;
  /** The encrypted blob. */
  downloadAttachment(id: string): Promise<Uint8Array>;
  deleteAttachment(id: string): Promise<void>;
  attachmentUsage(): Promise<AttachmentUsageResponse>;
  createShareLink(req: ShareLinkUpload): Promise<ShareLinkRecord>;
  shareLinks(): Promise<{ links: ShareLinkRecord[] }>;
  deleteShareLink(id: string): Promise<void>;
  /** No session needed. */
  publicShareLink(id: string): Promise<PublicShareLinkInfo>;
  /** No session needed; counts a view. */
  openShareLink(id: string, auth: string): Promise<OpenedShareLink>;
  vaultAccessRequest(
    vaultId: string,
  ): Promise<{ orgId: string; hasAccess: boolean; request: AccessRequestRecord | null }>;
  requestVaultAccess(vaultId: string, role: "view" | "edit" | "manage"): Promise<AccessRequestRecord>;
  accessRequests(): Promise<{ incoming: AccessRequestRecord[]; outgoing: AccessRequestRecord[] }>;
  approveAccessRequest(id: string): Promise<void>;
  denyAccessRequest(id: string): Promise<void>;
  cancelAccessRequest(id: string): Promise<void>;
}

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;
type Raw = (method: string, path: string, body?: Uint8Array) => Promise<Response>;

export function comfortApi(call: Call, raw: Raw): ComfortApi {
  const e = encodeURIComponent;
  return {
    moveItems: (req) => call("POST", "/api/v1/items/move", req),
    uploadAttachment: async (id, itemId, blob) => {
      const response = await raw("PUT", `/api/v1/attachments/${e(id)}?itemId=${e(itemId)}`, blob);
      return (await response.json()) as { id: string; size: number };
    },
    downloadAttachment: async (id) => {
      const response = await raw("GET", `/api/v1/attachments/${e(id)}`);
      return new Uint8Array(await response.arrayBuffer());
    },
    deleteAttachment: (id) => call("DELETE", `/api/v1/attachments/${e(id)}`),
    attachmentUsage: () => call("GET", "/api/v1/attachments/usage"),
    createShareLink: (req) => call("POST", "/api/v1/share-links", req),
    shareLinks: () => call("GET", "/api/v1/share-links"),
    deleteShareLink: (id) => call("DELETE", `/api/v1/share-links/${e(id)}`),
    publicShareLink: (id) => call("GET", `/api/v1/public/share-links/${e(id)}`),
    openShareLink: (id, auth) => call("POST", `/api/v1/public/share-links/${e(id)}/open`, { auth }),
    vaultAccessRequest: (vaultId) => call("GET", `/api/v1/vaults/${e(vaultId)}/access-request`),
    requestVaultAccess: (vaultId, role) => call("POST", `/api/v1/vaults/${e(vaultId)}/access-requests`, { role }),
    accessRequests: () => call("GET", "/api/v1/access-requests"),
    approveAccessRequest: (id) => call("POST", `/api/v1/access-requests/${e(id)}/approve`, {}),
    denyAccessRequest: (id) => call("POST", `/api/v1/access-requests/${e(id)}/deny`, {}),
    cancelAccessRequest: (id) => call("DELETE", `/api/v1/access-requests/${e(id)}`),
  };
}
