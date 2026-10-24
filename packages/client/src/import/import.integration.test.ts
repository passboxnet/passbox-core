/**
 * Imports into a real Passbox server. Start one and set
 * PASSBOX_TEST_SERVER_URL (see client.integration.test.ts). Set
 * PASSBOX_IMPORT_BENCH=10000 to also time a large import.
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { PassboxClient } from "../client";
import { FIELD, fieldValue } from "../items";
import { memoryStorage } from "../storage";
import { writeCsv } from "./csv";
import { findDuplicates, mergeItem, parseImport } from "./index";

const serverUrl = process.env.PASSBOX_TEST_SERVER_URL;
const bench = Number(process.env.PASSBOX_IMPORT_BENCH ?? 0);
const concurrency = process.env.PASSBOX_IMPORT_CONCURRENCY ? Number(process.env.PASSBOX_IMPORT_CONCURRENCY) : undefined;

function newClient() {
  let client: PassboxClient | undefined;
  const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token });
  client = new PassboxClient({ core, api, storage: memoryStorage() });
  return client;
}

function chromeCsv(count: number): Uint8Array {
  const rows = [["name", "url", "username", "password", "note"]];
  for (let i = 0; i < count; i++) {
    rows.push([`Site ${i}`, `https://site${i}.example.com/login`, `user${i}@example.com`, `Pass-${i}-xyz`, ""]);
  }
  return new TextEncoder().encode(writeCsv(rows));
}

describe.skipIf(!serverUrl)("importing into a server", { timeout: 60_000 }, () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("creates items, updates duplicates and reports progress", async () => {
    const client = newClient();
    await client.signUp(`${core.newId()}@example.com`, "correct horse battery staple");
    const vault = client.getSnapshot().vaults[0];
    if (!vault) throw new Error("no vault");

    expect(await client.verifyMasterPassword("not my password")).toBe(false);
    expect(await client.verifyMasterPassword("correct horse battery staple")).toBe(true);

    const first = parseImport({ name: "a.csv", bytes: chromeCsv(30) });
    const progress: number[] = [];
    const created = await client.importItems(
      vault.id,
      first.items.map((i) => ({ data: i.data })),
      { onProgress: (done) => progress.push(done), batchSize: 10 },
    );
    expect(created).toMatchObject({ created: 30, updated: 0, failed: [] });
    expect(progress.at(-1)).toBe(30);
    expect(client.getSnapshot().items).toHaveLength(30);

    // Import again: every item is a duplicate; update one, skip the rest.
    const again = parseImport({ name: "a.csv", bytes: chromeCsv(30) });
    again.items[0]?.data.fields.forEach((f) => {
      if (f.id === FIELD.password) f.value = "Changed-Pass";
    });
    const matches = findDuplicates(again.items, client.getSnapshot().items);
    expect(matches).toHaveLength(30);
    const match = matches[0];
    if (!match) throw new Error("no match");
    const existing = client.getSnapshot().items.find((i) => i.id === match.existingId);
    if (!existing) throw new Error("no existing item");
    const updated = await client.importItems(vault.id, [
      { data: mergeItem(existing.data, again.items[0]?.data ?? existing.data), updateId: match.existingId },
    ]);
    expect(updated).toMatchObject({ created: 0, updated: 1 });
    const after = client.getSnapshot().items.find((i) => i.id === match.existingId);
    expect(after && fieldValue(after.data, FIELD.password)).toBe("Changed-Pass");
    expect(after?.data.passwordHistory?.[0]?.value).toBe("Pass-0-xyz");
    expect(client.getSnapshot().items).toHaveLength(30);
  });

  it.skipIf(!bench)(
    "imports a large file",
    async () => {
      const client = newClient();
      await client.signUp(`${core.newId()}@example.com`, "correct horse battery staple");
      const vault = client.getSnapshot().vaults[0];
      if (!vault) throw new Error("no vault");
      const bytes = chromeCsv(bench);
      const t0 = performance.now();
      const result = parseImport({ name: "big.csv", bytes });
      const t1 = performance.now();
      const duplicates = findDuplicates(result.items, client.getSnapshot().items);
      const t2 = performance.now();
      let longestGap = 0;
      let last = performance.now();
      const outcome = await client.importItems(
        vault.id,
        result.items.map((i) => ({ data: i.data })),
        {
          ...(concurrency ? { concurrency } : {}),
          onProgress: () => {
            const now = performance.now();
            longestGap = Math.max(longestGap, now - last);
            last = now;
          },
        },
      );
      const t3 = performance.now();
      console.log(
        `import bench: ${bench} items, parse ${(t1 - t0).toFixed(0)} ms, duplicates ${(t2 - t1).toFixed(0)} ms, ` +
          `upload ${((t3 - t2) / 1000).toFixed(1)} s (${((bench / (t3 - t2)) * 1000).toFixed(0)} items/s), ` +
          `longest gap between items ${longestGap.toFixed(0)} ms`,
      );
      expect(duplicates).toHaveLength(0);
      expect(outcome.created).toBe(bench);
      expect(client.getSnapshot().items).toHaveLength(bench);
    },
    600_000,
  );
});
