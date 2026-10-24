import { describe, expect, it } from "vitest";
import {
  assertionJson,
  base64UrlToBytes,
  bytesToBase64Url,
  creationOptions,
  getAssertion,
  requestOptions,
} from "./webauthn";

describe("WebAuthn conversions", () => {
  it("round-trips Base64url without padding", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const encoded = bytesToBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect([...base64UrlToBytes(encoded)]).toEqual([...bytes]);
    expect(bytesToBase64Url(bytes.buffer)).toBe(encoded);
    expect(bytesToBase64Url(new Uint8Array(bytes.buffer, 3, 2))).toBe(bytesToBase64Url(new Uint8Array([250, 251])));
    expect(base64UrlToBytes("")).toHaveLength(0);
  });

  it("decodes binary fields of the server's options", () => {
    const created = creationOptions({
      challenge: "AQID",
      rp: { id: "passbox.example", name: "Passbox" },
      user: { id: "YWNjb3VudA", name: "anna@example.com", displayName: "anna@example.com" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 120000,
      attestation: "none",
      excludeCredentials: [{ type: "public-key", id: "BAU" }],
      authenticatorSelection: { residentKey: "discouraged", userVerification: "discouraged" },
    });
    expect([...new Uint8Array(created.challenge as ArrayBuffer)]).toEqual([1, 2, 3]);
    expect(new TextDecoder().decode(created.user.id as Uint8Array)).toBe("account");
    expect([...((created.excludeCredentials?.[0]?.id as Uint8Array | undefined) ?? [])]).toEqual([4, 5]);
    expect(created.rp.id).toBe("passbox.example");

    const request = requestOptions({
      challenge: "AQID",
      rpId: "passbox.example",
      allowCredentials: [{ type: "public-key", id: "BAU" }],
      timeout: 1000,
      userVerification: "discouraged",
    });
    expect(request.rpId).toBe("passbox.example");
    expect([...((request.allowCredentials?.[0]?.id as Uint8Array | undefined) ?? [])]).toEqual([4, 5]);
  });

  it("encodes an assertion for the server", async () => {
    const credential = {
      type: "public-key",
      rawId: new Uint8Array([9, 9]).buffer,
      response: {
        clientDataJSON: new TextEncoder().encode("{}").buffer,
        authenticatorData: new Uint8Array([1]).buffer,
        signature: new Uint8Array([2]).buffer,
      },
    } as unknown as Credential;
    expect(assertionJson(credential)).toEqual({
      credentialId: "CQk",
      clientDataJson: "e30",
      authenticatorData: "AQ",
      signature: "Ag",
    });
    expect(() => assertionJson(null)).toThrow();
    const container = {
      create: async () => null,
      get: async (options: CredentialRequestOptions) => {
        expect(options.publicKey?.rpId).toBe("x.example");
        return credential;
      },
    };
    await expect(
      getAssertion(container, {
        challenge: "AA",
        rpId: "x.example",
        allowCredentials: [],
        timeout: 1,
        userVerification: "discouraged",
      }),
    ).resolves.toMatchObject({ credentialId: "CQk" });
  });
});
