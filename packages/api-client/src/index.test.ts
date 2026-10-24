import { describe, expect, it, vi } from "vitest";
import { ApiError, createClient } from "./index";

function fakeFetch(status: number, body: unknown) {
  return vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify(body), { status }),
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

  it("throws ApiError on non-2xx responses", async () => {
    const client = createClient({ fetch: fakeFetch(503, { error: "down" }) });

    await expect(client.health()).rejects.toBeInstanceOf(ApiError);
    await expect(client.health()).rejects.toMatchObject({ status: 503, path: "/health" });
  });
});
