/**
 * Runs the full client against a real Passbox server. Start one and set
 * PASSBOX_TEST_SERVER_URL, for example:
 *
 *   PASSBOX_DATABASE_URL=sqlite::memory: cargo run -p passbox-server &
 *   PASSBOX_TEST_SERVER_URL=http://127.0.0.1:8080 pnpm --filter @passbox/client test
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { ConflictError, InvalidCredentialsError, PassboxClient } from "./client";
import { FIELD, fieldValue, newItemData } from "./items";
import { memoryStorage } from "./storage";

const serverUrl = process.env.PASSBOX_TEST_SERVER_URL;

function newClient() {
  const storage = memoryStorage();
  let client: PassboxClient | undefined;
  const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token });
  client = new PassboxClient({ core, api, storage });
  return client;
}

describe.skipIf(!serverUrl)("PassboxClient against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("signs up, edits items and syncs them to a second device", async () => {
    const email = `${core.newId()}@example.com`;
    const laptop = newClient();
    const { secretKey } = await laptop.signUp(email, "correct horse battery staple");
    expect(laptop.getSnapshot().status).toBe("unlocked");
    const [vault] = laptop.getSnapshot().vaults;
    expect(vault?.name).toBe("Private");
    if (!vault) return;

    const data = newItemData("login", "GitHub");
    data.fields = data.fields.map((f) => (f.id === FIELD.password ? { ...f, value: "hunter2" } : f));
    const itemId = await laptop.createItem(vault.id, data);

    // A second device signs in with the Secret Key and sees the item.
    const phone = newClient();
    await phone.signIn(email.toUpperCase(), "correct horse battery staple", secretKey.toLowerCase());
    const synced = phone.getSnapshot().items.find((item) => item.id === itemId);
    expect(synced && fieldValue(synced.data, FIELD.password)).toBe("hunter2");

    // Concurrent edits: the second writer gets a conflict and the latest data.
    await laptop.updateItem(itemId, { ...data, title: "GitHub (work)" });
    await expect(phone.updateItem(itemId, { ...data, title: "GitHub (phone)" })).rejects.toBeInstanceOf(ConflictError);
    expect(phone.getSnapshot().items.find((item) => item.id === itemId)?.data.title).toBe("GitHub (work)");

    // Vaults can be added and renamed from any device.
    const workId = await phone.createVault("Work");
    await laptop.sync();
    await laptop.renameVault(workId, "Office");
    await phone.sync();
    expect(phone.getSnapshot().vaults.map((v) => v.name)).toEqual(["Office", "Private"]);

    await phone.deleteItem(itemId);
    await laptop.sync();
    expect(laptop.getSnapshot().items).toHaveLength(0);

    // Lock and unlock with the remembered account. Locking ends the server session.
    const oldToken = laptop.token;
    laptop.lock();
    expect(laptop.getSnapshot()).toMatchObject({ status: "locked", items: [] });
    await new Promise((resolve) => setTimeout(resolve, 200));
    const stale = createClient({ baseUrl: serverUrl ?? "", getToken: () => oldToken });
    await expect(stale.account()).rejects.toMatchObject({ status: 401 });
    await expect(laptop.unlock("wrong password")).rejects.toBeInstanceOf(InvalidCredentialsError);
    await laptop.unlock("correct horse battery staple");
    expect(laptop.getSnapshot().status).toBe("unlocked");
  });

  it("rejects a wrong Secret Key", async () => {
    const email = `${core.newId()}@example.com`;
    await newClient().signUp(email, "pw-123456");
    await expect(newClient().signIn(email, "pw-123456", core.generateSecretKey())).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
    await expect(newClient().signIn(email, "pw-123456", "not a key")).rejects.toBeInstanceOf(InvalidCredentialsError);
  });
});
