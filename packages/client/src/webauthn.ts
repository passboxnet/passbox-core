/**
 * WebAuthn glue for two-factor sign-in with security keys and passkeys.
 *
 * The server sends options with binary values as Base64url and expects the
 * browser's answers in the same form. These helpers convert between that
 * JSON and the binary `navigator.credentials` API. All verification happens
 * on the server (`crates/core/src/webauthn.rs`); nothing here is secret.
 */
import type {
  WebAuthnAssertionJson,
  WebAuthnAttestationJson,
  WebAuthnCreationOptionsJson,
  WebAuthnRequestOptionsJson,
} from "@passbox/api-client";

/** The part of `navigator.credentials` used here, so tests can pass a fake. */
export interface CredentialsContainerLike {
  create(options: CredentialCreationOptions): Promise<Credential | null>;
  get(options: CredentialRequestOptions): Promise<Credential | null>;
}

export function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64Url(data: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Server JSON → options for `navigator.credentials.create`. */
export function creationOptions(json: WebAuthnCreationOptionsJson): PublicKeyCredentialCreationOptions {
  return {
    challenge: base64UrlToBytes(json.challenge),
    rp: json.rp,
    user: { id: base64UrlToBytes(json.user.id), name: json.user.name, displayName: json.user.displayName },
    pubKeyCredParams: json.pubKeyCredParams,
    timeout: json.timeout,
    attestation: json.attestation,
    excludeCredentials: json.excludeCredentials.map((c) => ({ type: c.type, id: base64UrlToBytes(c.id) })),
    authenticatorSelection: json.authenticatorSelection,
  };
}

/** Server JSON → options for `navigator.credentials.get`. */
export function requestOptions(json: WebAuthnRequestOptionsJson): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64UrlToBytes(json.challenge),
    rpId: json.rpId,
    allowCredentials: json.allowCredentials.map((c) => ({ type: c.type, id: base64UrlToBytes(c.id) })),
    timeout: json.timeout,
    userVerification: json.userVerification,
  };
}

function publicKeyCredential(credential: Credential | null): PublicKeyCredential {
  if (credential?.type !== "public-key") throw new Error("no security key response");
  return credential as PublicKeyCredential;
}

/** A registration response → JSON for `webauthnRegisterFinish`. */
export function attestationJson(credential: Credential | null): WebAuthnAttestationJson {
  const response = publicKeyCredential(credential).response as AuthenticatorAttestationResponse;
  return {
    clientDataJson: bytesToBase64Url(response.clientDataJSON),
    attestationObject: bytesToBase64Url(response.attestationObject),
  };
}

/** An assertion → JSON for the `webauthn` second factor. */
export function assertionJson(credential: Credential | null): WebAuthnAssertionJson {
  const key = publicKeyCredential(credential);
  const response = key.response as AuthenticatorAssertionResponse;
  return {
    credentialId: bytesToBase64Url(key.rawId),
    clientDataJson: bytesToBase64Url(response.clientDataJSON),
    authenticatorData: bytesToBase64Url(response.authenticatorData),
    signature: bytesToBase64Url(response.signature),
  };
}

/** Asks the browser to create a credential (the user touches the key). */
export async function createCredential(
  container: CredentialsContainerLike,
  json: WebAuthnCreationOptionsJson,
  signal?: AbortSignal,
): Promise<WebAuthnAttestationJson> {
  return attestationJson(await container.create({ publicKey: creationOptions(json), ...(signal ? { signal } : {}) }));
}

/** Asks the browser for an assertion (the user touches the key). */
export async function getAssertion(
  container: CredentialsContainerLike,
  json: WebAuthnRequestOptionsJson,
  signal?: AbortSignal,
): Promise<WebAuthnAssertionJson> {
  return assertionJson(await container.get({ publicKey: requestOptions(json), ...(signal ? { signal } : {}) }));
}

/** Whether this browser can use security keys at all. */
export function webAuthnAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && window.isSecureContext;
}
