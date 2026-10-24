/**
 * Single sign-on (OIDC), trusted devices and SCIM provisioning (wave E).
 * See docs/architecture/sso.md and docs/api/openapi.yaml (tag `sso`).
 */

import type { LoginFinishResponse } from "./index";

/** Identity provider presets (labels only; every provider uses generic OIDC). */
export type SsoProvider = "generic" | "entra" | "google" | "okta" | "keycloak" | "authentik" | "zitadel";

export type TokenAuthMethod = "client_secret_basic" | "client_secret_post" | "none";

/** What an admin edits. */
export interface SsoSettings {
  enabled: boolean;
  /** Members (not owners and admins) must sign in with SSO. */
  required: boolean;
  /** Members may unlock with SSO on trusted devices. */
  allowDeviceUnlock: boolean;
  provider: SsoProvider;
  displayName: string;
  issuer: string;
  clientId: string;
  /** Write only: omit to keep the stored secret, `""` to remove it. */
  clientSecret?: string;
  tokenAuthMethod: TokenAuthMethod;
  scopes: string;
  emailClaim: string;
  requireVerifiedEmail: boolean;
  nameClaim: string;
  groupsClaim: string;
  allowedDomains: string[];
  reauthHours: number;
}

export interface SsoDiscovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
}

export interface SsoConfig extends Omit<SsoSettings, "clientSecret"> {
  hasClientSecret: boolean;
  /** Register this at the identity provider; `null` without `PASSBOX_PUBLIC_URL`. */
  redirectUri: string | null;
  discovery: SsoDiscovery | null;
  updatedAt: number;
}

export interface SsoCheck {
  ok: boolean;
  discovery: SsoDiscovery | null;
  keys: number;
  algorithms: string[];
  problem: { code: string; message: string } | null;
  redirectUri: string | null;
}

/** The result of a "test connection" sign-in. */
export interface SsoTestResult {
  /** `ok`, or the error code a real sign-in would end with. */
  outcome: string;
  subject: string;
  email: string | null;
  emailVerified: boolean;
  name: string;
  groups: string[];
  accountFound: boolean;
  claims: Record<string, string>;
}

/** The organization whose identity provider signs in an email domain. */
export interface SsoOption {
  orgId: string;
  displayName: string;
  provider: SsoProvider;
  required: boolean;
  deviceUnlock: boolean;
}

export interface SsoStart {
  authorizationUrl: string;
  /** Keep it in this tab and send it with the ticket. */
  flowSecret: string;
  expiresAt: number;
}

export interface SsoRedeemed {
  status: "ok" | "no_account";
  orgId: string;
  email: string;
  accountId?: string;
  /** For `loginFinish` (`ssoProof`), `unlock` or `requestDevice` (10 minutes, single use). */
  proof?: string;
  proofExpiresAt?: number;
  deviceUnlock: boolean;
  deviceTrusted: boolean;
}

/** Mirrors `passbox_core::trusted_device::TrustedDeviceUpload`. */
export interface TrustedDeviceUpload {
  deviceId: string;
  publicKey: string;
  sealedKey: string;
  grant: string;
  grantSignature: string;
}

/** Mirrors `passbox_core::trusted_device::TrustedDeviceUnlock`. */
export interface TrustedDeviceUnlockRecord {
  accountId: string;
  deviceId: string;
  sealedKey: string;
  grant: string;
  grantSignature: string;
  bundle: string;
  bundleSignature: string;
  encryptedPrivate: string;
}

export interface SsoUnlockResponse {
  session: LoginFinishResponse;
  unlock: TrustedDeviceUnlockRecord;
  email: string;
}

export interface TrustedDeviceInfo {
  id: string;
  name: string;
  /** The device that approved it; empty when it trusted itself. */
  approvedBy: string;
  createdAt: number;
  lastUsedAt: number;
}

export interface DeviceRequestInfo {
  id: string;
  deviceName: string;
  clientKind: string;
  ip: string;
  publicKey: string;
  createdAt: number;
  expiresAt: number;
}

export interface TrustedDevicesResponse {
  allowed: boolean;
  orgId: string | null;
  devices: TrustedDeviceInfo[];
  requests: DeviceRequestInfo[];
}

export interface DeviceRequestCreated {
  requestId: string;
  requestToken: string;
  expiresAt: number;
  approvalCode: string;
}

export interface DeviceRequestStatus {
  status: "pending" | "approved" | "denied";
  result?: SsoUnlockResponse;
}

export type ProvisionedStatus =
  | "invited"
  | "not_joined"
  | "pending_confirmation"
  | "confirmed"
  | "suspended"
  | "deactivated";

export interface ScimOverview {
  baseUrl: string;
  tokens: { id: string; name: string; createdBy: string; createdAt: number; expiresAt: number; lastUsedAt: number }[];
  users: {
    id: string;
    userName: string;
    email: string;
    displayName: string;
    active: boolean;
    status: ProvisionedStatus;
    accountId: string | null;
    groups: string[];
    updatedAt: number;
  }[];
  groups: { id: string; displayName: string; members: number }[];
}

export interface ScimTokenCreated {
  id: string;
  /** Shown once. */
  token: string;
  expiresAt: number;
  baseUrl: string;
}

export interface SsoApi {
  config(orgId: string): Promise<SsoConfig | null>;
  saveConfig(orgId: string, settings: SsoSettings): Promise<SsoConfig>;
  removeConfig(orgId: string): Promise<void>;
  check(orgId: string, issuer?: string): Promise<SsoCheck>;
  testStart(orgId: string): Promise<SsoStart>;
  testResult(orgId: string, req: { ticket: string; flowSecret: string }): Promise<SsoTestResult>;
  discover(email: string): Promise<{ sso: SsoOption | null }>;
  start(req: { orgId: string; email?: string }): Promise<SsoStart>;
  redeem(req: { ticket: string; flowSecret: string; deviceId?: string }): Promise<SsoRedeemed>;
  unlock(req: {
    proof: string;
    deviceId: string;
    deviceName?: string;
    clientKind?: string;
  }): Promise<SsoUnlockResponse>;
  requestDevice(req: {
    proof: string;
    publicKey: string;
    deviceName?: string;
    clientKind?: string;
  }): Promise<DeviceRequestCreated>;
  deviceRequestStatus(requestToken: string): Promise<DeviceRequestStatus>;
  trustedDevices(): Promise<TrustedDevicesResponse>;
  trustDevice(upload: TrustedDeviceUpload & { name?: string }): Promise<TrustedDeviceInfo>;
  removeTrustedDevice(id: string): Promise<void>;
  approveDevice(requestId: string, upload: TrustedDeviceUpload): Promise<void>;
  denyDevice(requestId: string): Promise<void>;
  scim(orgId: string): Promise<ScimOverview>;
  createScimToken(orgId: string, req: { name: string; expiresInDays?: number }): Promise<ScimTokenCreated>;
  revokeScimToken(orgId: string, id: string): Promise<void>;
}

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;

export function ssoApi(call: Call): SsoApi {
  const e = encodeURIComponent;
  const org = (id: string) => `/api/v1/orgs/${e(id)}`;
  return {
    config: (orgId) => call("GET", `${org(orgId)}/sso`),
    saveConfig: (orgId, settings) => call("PUT", `${org(orgId)}/sso`, settings),
    removeConfig: (orgId) => call("DELETE", `${org(orgId)}/sso`),
    check: (orgId, issuer) => call("POST", `${org(orgId)}/sso/check`, issuer ? { issuer } : {}),
    testStart: (orgId) => call("POST", `${org(orgId)}/sso/test/start`, {}),
    testResult: (orgId, req) => call("POST", `${org(orgId)}/sso/test/result`, req),
    discover: (email) => call("POST", "/api/v1/sso/discover", { email }),
    start: (req) => call("POST", "/api/v1/sso/start", req),
    redeem: (req) => call("POST", "/api/v1/sso/redeem", req),
    unlock: (req) => call("POST", "/api/v1/sso/unlock", req),
    requestDevice: (req) => call("POST", "/api/v1/sso/device-requests", req),
    deviceRequestStatus: (requestToken) => call("POST", "/api/v1/sso/device-requests/status", { requestToken }),
    trustedDevices: () => call("GET", "/api/v1/account/trusted-devices"),
    trustDevice: (upload) => call("POST", "/api/v1/account/trusted-devices", upload),
    removeTrustedDevice: (id) => call("DELETE", `/api/v1/account/trusted-devices/${e(id)}`),
    approveDevice: (requestId, upload) =>
      call("POST", `/api/v1/account/trusted-devices/requests/${e(requestId)}/approve`, upload),
    denyDevice: (requestId) => call("POST", `/api/v1/account/trusted-devices/requests/${e(requestId)}/deny`, {}),
    scim: (orgId) => call("GET", `${org(orgId)}/scim`),
    createScimToken: (orgId, req) => call("POST", `${org(orgId)}/scim/tokens`, req),
    revokeScimToken: (orgId, id) => call("DELETE", `${org(orgId)}/scim/tokens/${e(id)}`),
  };
}
