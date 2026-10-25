/**
 * The decisions of 25.10.2026 against a real server: recovery on by
 * default, view-only guests that are not billable, and the agent fair-use
 * limit endpoint. Start a server and set PASSBOX_TEST_SERVER_URL (see
 * client.integration.test.ts).
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { ApiError, createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_POLICY_RULES } from "./admin";
import { PassboxClient } from "./client";
import { FIELD, newItemData } from "./items";
import { memoryStorage } from "./storage";

const serverUrl = process.env.PASSBOX_TEST_SERVER_URL;
const PASSWORD = "correct horse battery staple";

function newClient() {
  const storage = memoryStorage();
  let client: PassboxClient | undefined;
  const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token });
  client = new PassboxClient({ core, api, storage, linkBase: "https://passbox.example" });
  return client;
}

async function person(name: string) {
  const client = newClient();
  const email = `${name}-${core.newId()}@example.com`;
  const { accountId } = await client.signUp(email, PASSWORD);
  return { client, email, id: accountId };
}

async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return error instanceof ApiError ? error.code : String(error);
  }
}

describe.skipIf(!serverUrl)("decisions of 25.10.2026 against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("sets up recovery for new organizations and keeps guests view-only", { timeout: 180_000 }, async () => {
    const alice = await person("alice");
    const bob = await person("bob");
    const gina = await person("gina");
    const orgId = await alice.client.createTeam("Agency");
    expect((await alice.client.orgRecovery(orgId)).enrolled).toBe(true);
    expect(alice.client.orgPolicy(orgId)?.rules.requireRecoveryEnrollment).toBe(true);

    for (const [member, role, recovery] of [
      [bob, "member", true],
      [gina, "guest", false],
    ] as const) {
      const invitation = await alice.client.invite(orgId, member.email, role);
      expect((await member.client.previewInvitation(invitation.link)).recovery).toBe(recovery);
      await member.client.acceptInvitation(invitation.link);
      await alice.client.confirmMember(orgId, member.id);
      await member.client.sync();
    }
    expect(await bob.client.enrollRequiredOrgRecovery()).toEqual([orgId]);
    expect(gina.client.getSnapshot().effectivePolicy.recoveryEnrollmentOrgs).toEqual([]);
    expect(await gina.client.enrollRequiredOrgRecovery()).toEqual([]);

    const vaultId = await alice.client.createSharedVault(orgId, "Client X");
    const data = newItemData("login", "CMS");
    data.fields = data.fields.map((f) => (f.id === FIELD.password ? { ...f, value: "cms-secret" } : f));
    const itemId = await alice.client.createItem(vaultId, data);
    await expect(alice.client.shareVault(vaultId, "account", gina.id, "edit")).rejects.toThrow();
    await alice.client.shareVault(vaultId, "account", gina.id, "view");
    await gina.client.sync();
    const item = gina.client.getSnapshot().items.find((i) => i.id === itemId);
    expect(item?.data.fields.find((f) => f.id === FIELD.password)?.value).toBe("cms-secret");
    expect(gina.client.getSnapshot().vaults.find((v) => v.id === vaultId)?.role).toBe("view");
    expect(
      await code(
        gina.client.createShareLink({
          snapshot: { v: 1, title: "CMS", category: "login", fields: [], notes: "", createdAt: Date.now() },
          label: "x",
          expiresAt: Date.now() + 60_000,
          maxViews: 1,
          vaultId,
          linkBase: "https://passbox.example",
        }),
      ),
    ).toBe("guest_view_only");

    const report = await alice.client.orgAdmin.reports(orgId);
    expect(report).toMatchObject({ memberCount: 2, guestCount: 1 });

    // Turning recovery off: only after the policy stops requiring it.
    expect(await code(alice.client.turnOffOrgRecovery(orgId))).toBe("recovery_required");
    await alice.client.setOrgPolicy(orgId, DEFAULT_POLICY_RULES);
    await alice.client.turnOffOrgRecovery(orgId);
    expect((await alice.client.orgRecovery(orgId)).available).toBe(false);
  });

  it("reports the fair-use limit for agents", async () => {
    const alice = await person("alice");
    const usage = await alice.client.agentLimit();
    expect(usage).toMatchObject({ pool: "personal", used: 0 });
    expect(usage.allowed).toBe(usage.limitPerMember);
  });
});
