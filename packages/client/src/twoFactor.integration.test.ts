/**
 * Two-factor sign-in against a real Passbox server (see
 * client.integration.test.ts for how to start one).
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import {
  InvalidCredentialsError,
  InvalidTwoFactorCodeError,
  PassboxClient,
  TwoFactorExpiredError,
  TwoFactorRequiredError,
} from "./client";
import { memoryStorage } from "./storage";
import { base64UrlToBytes, bytesToBase64Url, type CredentialsContainerLike } from "./webauthn";

const serverUrl = process.env.PASSBOX_TEST_SERVER_URL;
const ORIGIN = "http://localhost:5173";
const PASSWORD = "correct horse battery staple";

function newClient(origin?: string) {
  const storage = memoryStorage();
  let client: PassboxClient | undefined;
  const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token });
  client = new PassboxClient({ core, api, storage, ...(origin ? { origin } : {}) });
  return client;
}

function code(secret: string, steps = 0): string {
  return core.totpCode(secret, Date.now() / 1000 + steps * 30);
}

/** A security key built on the core's passkey authenticator. */
function fakeSecurityKey(origin: string): CredentialsContainerLike {
  const encoder = new TextEncoder();
  let key: { credentialId: string; privateKey: string; attestationObject: string } | undefined;
  const buffer = (bytes: Uint8Array) => bytes.slice().buffer;
  return {
    async create(options) {
      const publicKey = options.publicKey;
      if (!publicKey?.rp.id) throw new Error("no options");
      key = JSON.parse(core.passkeyCreate(publicKey.rp.id, false));
      if (!key) throw new Error("no key");
      const clientData = JSON.stringify({
        type: "webauthn.create",
        challenge: bytesToBase64Url(publicKey.challenge as ArrayBuffer),
        origin,
      });
      return {
        type: "public-key",
        id: key.credentialId,
        rawId: buffer(base64UrlToBytes(key.credentialId)),
        response: {
          clientDataJSON: buffer(encoder.encode(clientData)),
          attestationObject: buffer(base64UrlToBytes(key.attestationObject)),
        },
      } as unknown as Credential;
    },
    async get(options) {
      const publicKey = options.publicKey;
      if (!publicKey?.rpId || !key) throw new Error("no options or key");
      const clientData = JSON.stringify({
        type: "webauthn.get",
        challenge: bytesToBase64Url(publicKey.challenge as ArrayBuffer),
        origin,
      });
      const signed = JSON.parse(core.passkeyAssert(key.privateKey, publicKey.rpId, clientData, 0, false)) as {
        authenticatorData: string;
        signature: string;
      };
      return {
        type: "public-key",
        id: key.credentialId,
        rawId: buffer(base64UrlToBytes(key.credentialId)),
        response: {
          clientDataJSON: buffer(encoder.encode(clientData)),
          authenticatorData: buffer(base64UrlToBytes(signed.authenticatorData)),
          signature: buffer(base64UrlToBytes(signed.signature)),
        },
      } as unknown as Credential;
    },
  };
}

describe.skipIf(!serverUrl)("two-factor sign-in against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("enrolls TOTP, asks for it on sign-in and unlock, and remembers devices", async () => {
    const email = `${core.newId()}@example.com`;
    const laptop = newClient();
    const { secretKey } = await laptop.signUp(email, PASSWORD);
    expect(laptop.hasRecentLogin).toBe(true);
    expect(await laptop.twoFactorStatus()).toMatchObject({ enabled: false, recoveryCodesRemaining: 0 });

    const { secret, uri } = await laptop.startTotpSetup();
    expect(uri).toContain(`secret=${secret}`);
    await expect(laptop.confirmTotpSetup("000000")).rejects.toBeInstanceOf(InvalidTwoFactorCodeError);
    const { recoveryCodes = [] } = await laptop.confirmTotpSetup(code(secret));
    expect(recoveryCodes).toHaveLength(10);
    expect(await laptop.twoFactorStatus()).toMatchObject({ enabled: true, totp: true, recoveryCodesRemaining: 10 });

    // A new device: the password step succeeds, then the code is needed.
    const phone = newClient();
    const required = await phone.signIn(email, PASSWORD, secretKey).catch((e: unknown) => e);
    expect(required).toBeInstanceOf(TwoFactorRequiredError);
    expect((required as TwoFactorRequiredError).methods).toEqual(["totp", "recovery"]);
    expect(phone.getSnapshot().status).toBe("signed-out");
    expect(phone.pendingTwoFactor?.methods).toEqual(["totp", "recovery"]);
    await expect(phone.completeTwoFactor({ method: "totp", code: "000000" })).rejects.toBeInstanceOf(
      InvalidTwoFactorCodeError,
    );
    // The confirmation code was used up (replay protection).
    await expect(phone.completeTwoFactor({ method: "totp", code: code(secret) })).rejects.toBeInstanceOf(
      InvalidTwoFactorCodeError,
    );
    await phone.completeTwoFactor({ method: "totp", code: code(secret, 1) }, { rememberDevice: true });
    expect(phone.getSnapshot()).toMatchObject({ status: "unlocked", email });
    expect(phone.pendingTwoFactor).toBeUndefined();

    // The remembered phone unlocks without a code.
    phone.lock();
    await phone.unlock(PASSWORD);
    expect(phone.getSnapshot().status).toBe("unlocked");

    // The laptop was not remembered: unlocking needs a factor, here a recovery code.
    laptop.lock();
    await expect(laptop.unlock("wrong password")).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(laptop.unlock(PASSWORD)).rejects.toBeInstanceOf(TwoFactorRequiredError);
    expect(laptop.getSnapshot().status).toBe("locked");
    const used = await laptop.completeTwoFactor({ method: "recovery", code: recoveryCodes[0] ?? "" });
    expect(used.recoveryCodesRemaining).toBe(9);
    expect(laptop.getSnapshot().status).toBe("unlocked");

    // A recent login is enough for a master password change.
    await laptop.changeMasterPassword(PASSWORD, "new horse battery staple");
    await laptop.changeMasterPassword("new horse battery staple", PASSWORD);

    // Pending logins can be cancelled; completing then fails.
    laptop.lock();
    await expect(laptop.unlock(PASSWORD)).rejects.toBeInstanceOf(TwoFactorRequiredError);
    laptop.cancelTwoFactor();
    await expect(laptop.completeTwoFactor({ method: "totp", code: "123456" })).rejects.toBeInstanceOf(
      TwoFactorExpiredError,
    );
    await expect(laptop.unlock(PASSWORD)).rejects.toBeInstanceOf(TwoFactorRequiredError);
    await laptop.completeTwoFactor({ method: "recovery", code: recoveryCodes[1] ?? "" });

    const fresh = await laptop.regenerateRecoveryCodes();
    expect(fresh).toHaveLength(10);
    const kinds = (await laptop.activity()).map((event) => event.kind);
    expect(kinds).toEqual(expect.arrayContaining(["two_factor_enabled", "login_two_factor", "recovery_code_used"]));

    // Turning it off needs a second factor.
    await expect(laptop.disableTwoFactor({ method: "recovery", code: recoveryCodes[2] ?? "" })).rejects.toBeInstanceOf(
      InvalidTwoFactorCodeError,
    );
    await laptop.disableTwoFactor({ method: "recovery", code: fresh[0] ?? "" });
    expect((await laptop.twoFactorStatus()).enabled).toBe(false);
    laptop.lock();
    await laptop.unlock(PASSWORD);
  }, 60_000);

  it("uses a security key as the second factor", async () => {
    const email = `${core.newId()}@example.com`;
    const key = fakeSecurityKey(ORIGIN);
    const laptop = newClient(ORIGIN);
    const { secretKey } = await laptop.signUp(email, PASSWORD);
    const { recoveryCodes = [] } = await laptop.addSecurityKey("Test key", { credentials: key });
    expect(recoveryCodes).toHaveLength(10);
    const status = await laptop.twoFactorStatus();
    expect(status).toMatchObject({ enabled: true, totp: false });
    expect(status.securityKeys.map((k) => k.name)).toEqual(["Test key"]);

    const tablet = newClient(ORIGIN);
    const required = await tablet.signIn(email, PASSWORD, secretKey).catch((e: unknown) => e);
    expect(required).toBeInstanceOf(TwoFactorRequiredError);
    expect((required as TwoFactorRequiredError).webauthn?.rpId).toBe("localhost");
    await tablet.completeTwoFactorWithSecurityKey({ credentials: key });
    expect(tablet.getSnapshot().status).toBe("unlocked");

    // Removing the only factor is refused; turning 2FA off with the key works.
    const keyId = status.securityKeys[0]?.id ?? "";
    await expect(laptop.removeSecurityKey(keyId)).rejects.toMatchObject({ status: 409 });
    await laptop.disableTwoFactor({ method: "webauthn", credentials: key });
    expect((await laptop.twoFactorStatus()).enabled).toBe(false);
  }, 60_000);

  it("asks for the master password again before changes after 10 minutes", async () => {
    const client = newClient();
    await client.signUp(`${core.newId()}@example.com`, PASSWORD);
    await expect(client.reauthenticate("wrong password")).rejects.toBeInstanceOf(InvalidCredentialsError);
    expect(client.getSnapshot().status).toBe("unlocked");
    await client.reauthenticate(PASSWORD);
    expect(client.hasRecentLogin).toBe(true);
    const { secret } = await client.startTotpSetup();
    await client.confirmTotpSetup(code(secret));
    // Reauthenticating with 2FA on needs the second factor too.
    await expect(client.reauthenticate(PASSWORD)).rejects.toBeInstanceOf(TwoFactorRequiredError);
    expect(client.getSnapshot().status).toBe("unlocked");
    await client.completeTwoFactor({ method: "totp", code: code(secret, 1) });
    expect(client.getSnapshot().status).toBe("unlocked");
    expect(client.hasRecentLogin).toBe(true);
  }, 60_000);
});
