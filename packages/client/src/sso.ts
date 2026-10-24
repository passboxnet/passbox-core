/**
 * Single sign-on and trusted devices (wave E1/E2) on the client side. The
 * cryptography (sealing the account key to a device key, verifying the
 * grant) is in the Rust core; see docs/architecture/sso.md.
 */

import { ApiError } from "@passbox/api-client";

/**
 * A trusted device's identity on this device. The `seed` opens the account
 * key together with an SSO sign-in, so platforms keep it in protected
 * storage (the web app wraps it with a non-extractable WebCrypto key).
 */
export interface TrustedDeviceSecret {
  accountId: string;
  deviceId: string;
  /** X-Wing seed (Base64url). */
  seed: string;
}

/** A new device waiting for approval by a trusted device. */
export interface PendingDeviceApproval {
  requestId: string;
  requestToken: string;
  /** Compare it with the code the approving device shows. */
  approvalCode: string;
  expiresAt: number;
  /** Kept in memory only, until the request is approved. */
  seed: string;
}

/** The SSO flow a tab started: kept in `sessionStorage` across the redirect. */
export interface SsoFlowState {
  flowSecret: string;
  orgId: string;
  /** `login` signs in; `test` shows the claims to an admin. */
  purpose: "login" | "test";
  email?: string;
  startedAt: number;
}

export const SSO_FLOW_KEY = "passbox.ssoFlow";

/** Reads `ticket` or `error` from a `#/sso?…` callback hash. */
export function parseSsoCallback(hash: string): { ticket?: string; error?: string; test: boolean } | undefined {
  const match = /^#\/sso(?:\?(.*))?$/.exec(hash);
  if (!match) return undefined;
  const params = new URLSearchParams(match[1] ?? "");
  const ticket = params.get("ticket") ?? undefined;
  const error = params.get("error") ?? undefined;
  // `test=1`: the end of a connection test, in the popup an admin opened.
  return { ...(ticket ? { ticket } : {}), ...(error ? { error } : {}), test: params.get("test") === "1" };
}

/** The `sso_…` error code of an API error, if it is one. */
export function ssoErrorCode(error: unknown): string | undefined {
  return error instanceof ApiError && error.code?.startsWith("sso_") ? error.code : undefined;
}
