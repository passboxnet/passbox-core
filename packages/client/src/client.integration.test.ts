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

    // Devices, activity and master password change.
    const sessions = await laptop.sessions();
    expect(sessions.some((session) => session.current)).toBe(true);
    const phoneSession = (await phone.sessions()).find((session) => session.current);
    expect(phoneSession).toBeDefined();
    await laptop.revokeSession(phoneSession?.id ?? "");
    await expect(phone.sync()).rejects.toMatchObject({ status: 401 });
    expect((await laptop.activity()).map((event) => event.kind)).toContain("session_revoked");
    await expect(laptop.changeMasterPassword("wrong password", "new horse battery staple")).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
    await laptop.changeMasterPassword("correct horse battery staple", "new horse battery staple");
    // The offline check follows the change right away.
    expect(await laptop.verifyMasterPassword("new horse battery staple")).toBe(true);
    expect(await laptop.verifyMasterPassword("correct horse battery staple")).toBe(false);
    laptop.lock();
    await expect(laptop.unlock("correct horse battery staple")).rejects.toBeInstanceOf(InvalidCredentialsError);
    await laptop.unlock("new horse battery staple");
    await laptop.changeMasterPassword("new horse battery staple", "correct horse battery staple");

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

    // A restarted process resumes the session from the exported state.
    const state = laptop.exportSession();
    expect(state).toBeDefined();
    if (!state) return;
    const storage = memoryStorage();
    storage.setItem("passbox.account", JSON.stringify(laptop.deviceAccount));
    let resumed: PassboxClient | undefined;
    resumed = new PassboxClient({
      core,
      api: createClient({ baseUrl: serverUrl ?? "", getToken: () => resumed?.token }),
      storage,
    });
    await resumed.restoreSession(state);
    expect(resumed.getSnapshot()).toMatchObject({ status: "unlocked", vaults: laptop.getSnapshot().vaults });
    await expect(resumed.restoreSession({ ...state, accountId: "other" })).rejects.toThrow(/another account/);
  }, 60_000);

  it("keeps password history and a trash shared with other clients", async () => {
    const client = newClient();
    await client.signUp(`${core.newId()}@example.com`, "correct horse battery staple");
    const vault = client.getSnapshot().vaults[0];
    if (!vault) throw new Error("no vault");
    const data = newItemData("login", "Bank");
    data.fields = data.fields.map((f) => (f.id === FIELD.password ? { ...f, value: "first" } : f));
    // Keys from newer clients survive.
    const id = await client.createItem(vault.id, { ...data, futureField: { x: 1 } } as typeof data);

    const stored = () =>
      client
        .getSnapshot()
        .items.concat(client.getSnapshot().trash)
        .find((i) => i.id === id);
    const current = stored()?.data ?? data;
    await client.updateItem(id, {
      ...current,
      fields: current.fields.map((f) => (f.id === FIELD.password ? { ...f, value: "second" } : f)),
    });
    await client.updateItem(id, { ...(stored()?.data ?? data), title: "My bank", passwordHistory: [] });
    expect(stored()?.data.passwordHistory?.map((e) => e.value)).toEqual(["first"]);
    expect((stored()?.data as unknown as { futureField?: unknown } | undefined)?.futureField).toEqual({ x: 1 });

    await client.trashItem(id);
    expect(client.getSnapshot().items).toHaveLength(0);
    expect(client.getSnapshot().trash.map((i) => i.id)).toEqual([id]);
    expect(client.health().analyzed).toBe(0);
    expect(await client.purgeTrash()).toBe(0);
    await client.restoreItem(id);
    expect(client.getSnapshot().items.map((i) => i.data.title)).toEqual(["My bank"]);
    await client.trashItem(id);
    expect(await client.purgeTrash(true)).toBe(1);
    expect(client.getSnapshot().trash).toHaveLength(0);
  }, 30_000);

  it("keeps a device token that every login replaces and sign out removes", async () => {
    const storage = memoryStorage();
    let client: PassboxClient | undefined;
    const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token });
    client = new PassboxClient({ core, api, storage });
    await client.signUp(`${core.newId()}@example.com`, "pw-123456");
    const first = storage.getItem("passbox.deviceToken");
    expect(first).toBeTruthy();
    client.lock();
    await client.unlock("pw-123456");
    const second = storage.getItem("passbox.deviceToken");
    expect(second).toBeTruthy();
    expect(second).not.toBe(first);
    client.signOut();
    expect(storage.getItem("passbox.deviceToken")).toBeNull();
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
