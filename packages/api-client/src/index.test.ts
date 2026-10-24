import { describe, expect, it, vi } from "vitest";
import { ApiError, createClient, isTwoFactorChallenge } from "./index";

function fakeFetch(status: number, body: unknown) {
  return vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(status === 204 ? null : JSON.stringify(body), { status }),
  );
}

describe("createClient", () => {
  it("requests the meta endpoint relative to the base URL", async () => {
    const fetch = fakeFetch(200, { name: "passbox", apiVersion: 1 });
    const client = createClient({ baseUrl: "https://vault.example.com/", fetch });

    const meta = await client.meta();

    expect(meta.apiVersion).toBe(1);
    expect(fetch).toHaveBeenCalledWith("https://vault.example.com/api/v1/meta", expect.anything());
  });

  it("sends the session token and JSON bodies", async () => {
    const fetch = fakeFetch(200, { revision: 1, seq: 7 });
    const client = createClient({ fetch, getToken: () => "tok" });

    await client.putItem("item1", { vaultId: "v", revision: 1, encryptedData: "abc" });

    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("/api/v1/items/item1");
    expect(init?.method).toBe("PUT");
    expect((init?.headers as Record<string, string> | undefined)?.authorization).toBe("Bearer tok");
    expect(JSON.parse(init?.body as string)).toEqual({ vaultId: "v", revision: 1, encryptedData: "abc" });
  });

  it("handles empty 204 responses", async () => {
    const client = createClient({ fetch: fakeFetch(204, null) });
    await expect(client.logout()).resolves.toBeUndefined();
  });

  it("throws ApiError with the server's error code", async () => {
    const client = createClient({
      fetch: fakeFetch(409, { error: "conflict", message: "changed", details: { currentRevision: 3 } }),
    });

    const error = await client.deleteItem("x", 2).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 409, code: "conflict", message: "changed" });
    expect((error as ApiError).body?.details?.currentRevision).toBe(3);
  });

  it("tells a two-factor challenge from a session", async () => {
    const challenge = { twoFactorRequired: true, challengeToken: "c", expiresAt: 1, methods: ["totp"] };
    const client = createClient({ fetch: fakeFetch(200, challenge) });
    const result = await client.loginFinish({ loginId: "l", credentialFinalization: "f", origin: "https://x" });
    expect(isTwoFactorChallenge(result)).toBe(true);
    expect(isTwoFactorChallenge({ token: "t", accountId: "a", sessionId: "s", expiresAt: 1, deviceToken: "d" })).toBe(
      false,
    );
  });

  it("sends the second factor to login/two-factor", async () => {
    const fetch = fakeFetch(200, { token: "t" });
    const client = createClient({ fetch });
    await client.loginTwoFactor({ challengeToken: "c", method: "totp", code: "123456", rememberDevice: true });
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("/api/v1/auth/login/two-factor");
    expect(JSON.parse(init?.body as string)).toEqual({
      challengeToken: "c",
      method: "totp",
      code: "123456",
      rememberDevice: true,
    });
  });
});
