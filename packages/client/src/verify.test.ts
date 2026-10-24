import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { PassboxApi } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { type DeviceAccount, PassboxClient } from "./client";
import { memoryStorage } from "./storage";

const PASSWORD = "correct horse battery staple";

beforeAll(async () => {
  const require = createRequire(import.meta.url);
  const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
  await core.default({ module_or_path: await readFile(wasmPath) });
});

/** An unlocked client resumed from a session, with an API that records every call. */
async function unlockedClient() {
  const account: DeviceAccount = {
    email: "anna@example.com",
    accountId: core.newId(),
    secretKey: core.generateSecretKey(),
    kdfSalt: core.generateKdfSalt(),
    // The minimum cost keeps the test fast.
    kdfParams: { memoryKib: 64 * 1024, iterations: 3, parallelism: 1 },
  };
  const keys = core.MasterKeys.derive(
    PASSWORD,
    account.secretKey,
    account.accountId,
    account.kdfSalt,
    JSON.stringify(account.kdfParams),
  );
  const keyring = core.Keyring.create(keys, account.accountId);
  const encryptedAccountKey = keyring.encryptedAccountKey ?? "";
  // Key pairs exist already, so unlocking makes no extra key requests.
  keyring.createAccountKeys(1);
  const session = JSON.parse(keyring.exportSession()) as { sessionKey: string; blob: string };
  keys.free();
  keyring.free();

  const calls: string[] = [];
  const api = new Proxy({} as PassboxApi, {
    get: (_target, name: string) => async () => {
      calls.push(name);
      if (name === "sync") return { cursor: 0, vaults: [], items: [] };
      if (name === "account") return { ...account, encryptedAccountKey };
      throw new Error(`unexpected call ${name}`);
    },
  });
  const storage = memoryStorage();
  storage.setItem("passbox.account", JSON.stringify(account));
  const client = new PassboxClient({ core, api, storage });
  await client.restoreSession({ accountId: account.accountId, ...session, token: "t" });
  return { client, calls };
}

describe("verifyMasterPassword", () => {
  it("accepts the right password and rejects others without extra server calls", async () => {
    const { client, calls } = await unlockedClient();
    expect(await client.verifyMasterPassword(PASSWORD)).toBe(true);
    const afterFirst = calls.length;
    expect(await client.verifyMasterPassword("correct horse battery stapler")).toBe(false);
    expect(await client.verifyMasterPassword("")).toBe(false);
    expect(await client.verifyMasterPassword(PASSWORD)).toBe(true);
    // A resumed session fetches the encrypted account key once, then works offline.
    expect(calls.filter((name) => name === "account")).toHaveLength(1);
    expect(calls.length).toBe(afterFirst);
    expect(client.getSnapshot().status).toBe("unlocked");
  }, 60_000);

  it("requires an unlocked vault", async () => {
    const { client } = await unlockedClient();
    client.lock();
    await expect(client.verifyMasterPassword(PASSWORD)).rejects.toThrow(/locked/);
  }, 60_000);
});
