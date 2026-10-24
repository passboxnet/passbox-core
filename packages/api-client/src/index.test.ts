import { describe, expect, it, vi } from "vitest";
import { ApiError, createClient } from "./index";

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

  it("calls the admin endpoints with query strings and bodies", async () => {
    const fetch = fakeFetch(200, { users: [], total: 0 });
    const client = createClient({ fetch, getToken: () => "tok" });

    await client.adminUsers({ q: "ada smith", limit: 20, offset: 40 });
    await client.adminUsers();
    await client.disableUser("abc/def");
    await client.sendTestMail();
    await client.sendTestMail("ops@example.com");
    await client.adminEvents({ before: 7 });
    await client.updatePreferences({ notifyNewDevice: false });

    const calls = fetch.mock.calls.map(([url, init]) => [url, init?.method, init?.body]);
    expect(calls).toEqual([
      ["/api/v1/admin/users?q=ada+smith&limit=20&offset=40", "GET", undefined],
      ["/api/v1/admin/users", "GET", undefined],
      ["/api/v1/admin/users/abc%2Fdef/disable", "POST", "{}"],
      ["/api/v1/admin/mail/test", "POST", "{}"],
      ["/api/v1/admin/mail/test", "POST", JSON.stringify({ to: "ops@example.com" })],
      ["/api/v1/admin/events?before=7", "GET", undefined],
      ["/api/v1/account/preferences", "PUT", JSON.stringify({ notifyNewDevice: false })],
    ]);
  });

  it("exposes the registration error codes", async () => {
    const client = createClient({
      fetch: fakeFetch(403, { error: "registration_closed", message: "registration requires an invitation" }),
    });
    const error = await client
      .registerStart({ accountId: "a", email: "x@example.com", registrationRequest: "r", inviteToken: "t" })
      .catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 403, code: "registration_closed" });
  });
});
