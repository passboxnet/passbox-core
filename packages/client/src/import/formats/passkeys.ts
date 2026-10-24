/** Conversions for passkeys exported by other managers. */
import type { Passkey } from "../../items";

/** Converts standard or URL-safe Base64 (with or without padding) to unpadded Base64url. */
export function toBase64url(value: string): string | undefined {
  const v = value.trim().replace(/\s+/g, "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return /^[A-Za-z0-9_-]*$/.test(v) ? v : undefined;
}

export function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const GUID = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;

/**
 * Bitwarden writes credential IDs as a GUID (the 16 raw bytes) or as
 * `b64.` followed by Base64url.
 */
export function bitwardenCredentialId(value: string): string | undefined {
  const v = value.trim();
  if (v.startsWith("b64.")) return toBase64url(v.slice(4));
  if (GUID.test(v)) {
    const hex = v.replace(/-/g, "");
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytesToBase64url(bytes);
  }
  return toBase64url(v);
}

/** The DER body of a PEM "PRIVATE KEY" (PKCS#8) block, as Base64url. */
export function pemToBase64url(pem: string): string | undefined {
  const match = /-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/.exec(pem);
  return match?.[1] ? toBase64url(match[1]) : undefined;
}

export function makePasskey(input: {
  credentialId: string | undefined;
  privateKey: string | undefined;
  rpId: string | undefined;
  rpName?: string | undefined;
  userHandle?: string | undefined;
  userName?: string | undefined;
  userDisplayName?: string | undefined;
  signCount?: number | undefined;
  createdAt?: number | undefined;
}): Passkey | undefined {
  const { credentialId, privateKey, rpId } = input;
  if (!credentialId || !privateKey || !rpId) return undefined;
  const userHandle = toBase64url(input.userHandle ?? "") ?? "";
  return {
    credentialId,
    rpId,
    rpName: input.rpName?.trim() || rpId,
    userHandle,
    userName: input.userName ?? "",
    userDisplayName: input.userDisplayName ?? "",
    privateKey,
    algorithm: -7,
    signCount:
      Number.isSafeInteger(input.signCount) && (input.signCount as number) > 0 ? (input.signCount as number) : 0,
    createdAt: Number.isFinite(input.createdAt) ? (input.createdAt as number) : Date.now(),
  };
}
