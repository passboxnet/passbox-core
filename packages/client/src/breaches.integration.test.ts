/**
 * Breached websites against a real server (see client.integration.test.ts
 * for how to start one). The catalogue endpoints are answered by a fake, so
 * the test controls when a breach is published; everything else goes to
 * the server.
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { PassboxClient } from "./client";
import { FIELD, type ItemData, newItemData } from "./items";
import { memoryStorage } from "./storage";

const serverUrl = process.env.PASSBOX_TEST_SERVER_URL;

function login(title: string, password: string, url: string): ItemData {
  const data = newItemData("login", title);
  data.fields = data.fields.map((f) =>
    f.id === FIELD.password ? { ...f, value: password } : f.id === FIELD.url ? { ...f, value: url } : f,
  );
  return data;
}

function iso(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

describe.skipIf(!serverUrl)("breached websites against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("downloads a newer catalogue, alerts once and resolves after a password change", async () => {
    let publishedAt = 0;
    const requests: { path: string; ifNoneMatch: string | null }[] = [];
    const catalog = () => ({
      version: `v-${publishedAt}`,
      updatedAt: publishedAt,
      source: "Have I Been Pwned",
      sourceUrl: "https://haveibeenpwned.com/",
      license: "CC BY 4.0",
      breaches: [
        {
          name: "Netflix",
          title: "Netflix",
          domain: "netflix.com",
          breachDate: iso(publishedAt).slice(0, 10),
          addedDate: iso(publishedAt),
          modifiedDate: iso(publishedAt),
          pwnCount: 5000,
          dataClasses: ["Email addresses", "Passwords"],
          verified: true,
          sensitive: false,
        },
      ],
    });
    const fetchWithFake = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const path = new URL(url).pathname;
      if (path.startsWith("/api/v1/breaches/catalog")) {
        const headers = new Headers(init?.headers);
        requests.push({ path, ifNoneMatch: headers.get("if-none-match") });
        const doc = catalog();
        if (path.endsWith("/version")) {
          return Response.json({ ...doc, breaches: undefined, entries: 1, bundled: false });
        }
        const etag = `"${doc.version}"`;
        if (headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers: { etag } });
        return Response.json(doc, { headers: { etag } });
      }
      return globalThis.fetch(input, init);
    }) as typeof globalThis.fetch;

    const storage = memoryStorage();
    let client: PassboxClient | undefined;
    const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token, fetch: fetchWithFake });
    client = new PassboxClient({ core, api, storage });
    await client.signUp(`${core.newId()}@example.com`, "correct horse battery staple");
    const vault = client.getSnapshot().vaults[0];
    if (!vault) throw new Error("no vault");
    const id = await client.createItem(vault.id, login("Netflix", "x9$Lq!2vR#pW7zK@", "https://www.netflix.com"));

    // The bundled snapshot until a catalogue is downloaded; no alerts.
    expect(client.securityReport().breachCatalog.bundled).toBe(true);
    expect(client.breachAlerts()).toEqual([]);

    // A breach is published after the login was saved.
    publishedAt = Date.now() + 1000;
    const status = await client.refreshBreachCatalog();
    expect(status).toMatchObject({ available: true, changed: true, bundled: false, entries: 1 });
    const report = client.securityReport();
    expect(report.breachCatalog.bundled).toBe(false);
    expect(report.findings.find((f) => f.kind === "breached_site")).toMatchObject({
      itemId: id,
      breaches: ["Netflix"],
    });

    // Alerted once.
    expect(client.breachAlerts().map((s) => s.name)).toEqual(["Netflix"]);
    client.acknowledgeBreachAlerts();
    expect(client.breachAlerts()).toEqual([]);

    // Nothing new: the version check stops before the download.
    const before = requests.length;
    expect((await client.refreshBreachCatalog()).changed).toBe(false);
    expect(requests.slice(before).map((r) => r.path)).toEqual(["/api/v1/breaches/catalog/version"]);

    // Changing the password after the breach resolves the finding.
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const data = client.getSnapshot().items.find((i) => i.id === id)?.data as ItemData;
    await client.updateItem(id, {
      ...data,
      fields: data.fields.map((f) => (f.id === FIELD.password ? { ...f, value: "N3w!pass#Word$2026" } : f)),
    });
    const after = client.securityReport();
    expect(after.findings.some((f) => f.kind === "breached_site")).toBe(false);
    expect(after.breachedSites[0]).toMatchObject({ name: "Netflix", fixed: [id], affected: [] });
  });
});
