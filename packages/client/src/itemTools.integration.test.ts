/**
 * Item history, usage, health, breach results and bulk changes against a
 * real server (see client.integration.test.ts for how to start one).
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { PassboxClient } from "./client";
import { FIELD, fieldValue, type ItemData, newItemData } from "./items";
import { memoryStorage } from "./storage";

const serverUrl = process.env.PASSBOX_TEST_SERVER_URL;

function login(title: string, password: string, url: string): ItemData {
  const data = newItemData("login", title);
  data.fields = data.fields.map((f) =>
    f.id === FIELD.password ? { ...f, value: password } : f.id === FIELD.url ? { ...f, value: url } : f,
  );
  return data;
}

/** Have I Been Pwned stand-in: "password" is breached (SHA-1 5BAA61E4…). */
const fakePwned = (async (input: RequestInfo | URL) =>
  new Response(
    String(input).endsWith("/5BAA6")
      ? "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0000000000000000000000000000000000A:0"
      : "0000000000000000000000000000000000A:0",
  )) as typeof globalThis.fetch;

describe.skipIf(!serverUrl)("item extras against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("keeps history, usage, health and bulk changes", async () => {
    const storage = memoryStorage();
    let client: PassboxClient | undefined;
    const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token });
    client = new PassboxClient({ core, api, storage });
    await client.signUp(`${core.newId()}@example.com`, "correct horse battery staple");
    const vault = client.getSnapshot().vaults[0];
    if (!vault) throw new Error("no vault");

    // Creation time and version history; restoring = updateItem with old data.
    const id = await client.createItem(vault.id, login("GitHub", "password", "https://github.com"));
    const createdAt = client.getSnapshot().items[0]?.createdAt ?? 0;
    expect(createdAt).toBeGreaterThan(0);
    const first = client.getSnapshot().items[0]?.data as ItemData;
    await client.updateItem(id, { ...first, title: "GitHub (work)" });
    await client.sync();
    expect(client.getSnapshot().items[0]?.createdAt).toBe(createdAt);
    const history = await client.itemHistory(id);
    expect(history.map((v) => v.data?.title)).toEqual(["GitHub"]);
    expect(history[0]?.revision).toBe(1);
    expect(history[0]?.updatedBy).toBeTruthy();
    await client.updateItem(id, history[0]?.data as ItemData);
    expect(client.getSnapshot().items[0]?.data.title).toBe("GitHub");
    expect(await client.itemHistory(id)).toHaveLength(2);

    // Icons: invalid names are refused by the server without any fetch.
    expect(await client.iconUrl("not a domain")).toBeNull();

    // Breach results feed the item's security check.
    const reused = await client.createItem(vault.id, login("Mail", "password", "http://mail.example"));
    const breached = await client.checkBreachedItems(fakePwned);
    expect(breached.map((b) => b.itemId).sort()).toEqual([id, reused].sort());
    const health = client.itemHealth(reused);
    expect(health.problems).toEqual(["weak", "reused", "insecure_url", "missing_totp", "breached"]);
    expect(health.reusedWith).toEqual([id]);
    expect(health.breachCount).toBe(9659365);

    // The security report uses the same results; dismissals are synced in the item.
    const report = client.securityReport();
    expect(report.breachChecked).toBe(true);
    expect(report.fixFirst[0]?.kinds[0]).toBe("breached");
    await client.dismissFinding(reused, "insecure_url", true);
    await client.sync();
    const stored = client.getSnapshot().items.find((item) => item.id === reused)?.data as ItemData & {
      securityIgnore?: string[];
    };
    expect(stored.securityIgnore).toEqual(["insecure_url"]);
    expect(
      client.securityReport().findings.find((f) => f.itemId === reused && f.kind === "insecure_url")?.dismissed,
    ).toBe(true);
    await client.dismissFinding(reused, "insecure_url", false);
    expect(client.checkLookalike("githuh.com")?.looksLike).toBe("github.com");
    // Email monitoring needs an API key on the server.
    expect((await client.emailMonitoring()).available).toBe(false);

    // Usage stays on this device, encrypted.
    expect(client.itemUsage(id)).toBeUndefined();
    client.recordItemUse(id, "copy");
    const usage = client.recordItemUse(id, "autofill");
    expect(usage.useCount).toBe(2);
    expect(usage.lastAutofilledAt).toBeGreaterThan(0);
    expect(client.itemUsages()[id]).toEqual(usage);

    // Bulk changes report failures and sync once.
    const failed = await client.setFavorite([id, reused, "missing"], true);
    expect(failed).toEqual([{ itemId: "missing", error: "unknown item" }]);
    expect(client.getSnapshot().items.every((item) => item.data.favorite)).toBe(true);
    expect(await client.trashItems([reused, reused])).toEqual([]);
    expect(client.getSnapshot().trash.map((item) => item.id)).toEqual([reused]);
    expect(fieldValue(client.getSnapshot().items[0]?.data as ItemData, FIELD.password)).toBe("password");

    // Locking forgets breach results; usage survives on the device.
    client.lock();
    expect(() => client?.itemUsage(id)).toThrow();
  });
});
