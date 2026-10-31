/**
 * Organization administration against a real server: signed
 * policies and their enforcement, item usage events, the audit log export
 * with its hash chain checked on the device, reports and offboarding.
 * Start a server and set PASSBOX_TEST_SERVER_URL (see client.integration.test.ts).
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_POLICY_RULES, PolicyViolationError } from "./admin";
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

describe.skipIf(!serverUrl)("organization administration against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("signs, verifies and enforces policies, logs usage and offboards", { timeout: 180_000 }, async () => {
    const alice = await person("alice");
    const bob = await person("bob");
    const carol = await person("carol");
    const orgId = await alice.client.createTeam("Acme");
    for (const member of [bob, carol]) {
      const invitation = await alice.client.invite(orgId, member.email, member === carol ? "admin" : "member");
      await member.client.acceptInvitation(invitation.link);
      await alice.client.confirmMember(orgId, member.id);
    }

    // New organizations start with recovery required (policy version 1).
    expect(alice.client.orgPolicy(orgId)).toMatchObject({ version: 1, rules: { requireRecoveryEnrollment: true } });

    // Carol (admin) signs the policy.
    await carol.client.sync();
    const policy = await carol.client.setOrgPolicy(orgId, {
      ...DEFAULT_POLICY_RULES,
      allowPersonalVault: false,
      maxAutoLockMinutes: 10,
      forbidExport: true,
      reportItemUsage: true,
    });
    expect(policy).toMatchObject({ version: 2, source: "verified", signerId: carol.id });
    await expect(bob.client.setOrgPolicy(orgId, DEFAULT_POLICY_RULES)).rejects.toThrow();

    await bob.client.sync();
    const effective = bob.client.getSnapshot().effectivePolicy;
    expect(effective).toMatchObject({ allowPersonalVault: false, maxAutoLockMinutes: 10, exportBlockedOrgs: [orgId] });
    await expect(bob.client.createVault("Mine")).rejects.toBeInstanceOf(PolicyViolationError);
    const personal = bob.client.getSnapshot().vaults.find((v) => !v.orgId);
    await expect(bob.client.createItem(personal?.id ?? "", newItemData("login", "x"))).rejects.toBeInstanceOf(
      PolicyViolationError,
    );

    // Item usage in a shared vault is signed and uploaded.
    const vaultId = await alice.client.createSharedVault(orgId, "Ops");
    await alice.client.shareVault(vaultId, "account", bob.id, "edit");
    await bob.client.sync();
    const data = newItemData("login", "Router");
    data.fields = data.fields.map((f) => (f.id === FIELD.password ? { ...f, value: "router-secret" } : f));
    const itemId = await bob.client.createItem(vaultId, data);
    bob.client.reportItemUsage(itemId, "item_copied", "password");
    bob.client.reportItemUsage(itemId, "secret_revealed", "password");
    expect(await bob.client.flushItemUsage()).toBe(2);
    expect(await bob.client.flushItemUsage()).toBe(0);
    expect(await bob.client.reportSecurityAggregates()).toBe(1);
    expect(await bob.client.reportSecurityAggregates()).toBe(0);

    // The audit log, checked on the device.
    const { data: log, check } = await alice.client.exportAuditLog(orgId);
    expect(check.valid).toBe(true);
    const actions = log.events.map((e) => e.action);
    expect(actions).toEqual(
      expect.arrayContaining(["policy_updated", "item_created", "item_copied", "secret_revealed"]),
    );
    const page = await alice.client.orgAdmin.audit(orgId, { source: "client" });
    expect(page.events.map((e) => e.action).sort()).toEqual(["item_copied", "secret_revealed"]);
    const csv = await alice.client.orgAdmin.exportAuditCsv(orgId);
    expect(csv.split("\n")[0]).toMatch(/^seq,id,created_at/);

    const report = await alice.client.orgAdmin.reports(orgId);
    expect(report.members.find((m) => m.accountId === bob.id)?.security?.total).toBe(1);
    expect(report.policyVersion).toBe(2);
    // Members and guests are counted separately (guests are never billable).
    expect(report).toMatchObject({ memberCount: 3, guestCount: 0 });

    // Offboarding Carol, who signed the policy: Alice signs it again.
    const result = await alice.client.offboardMember(orgId, carol.id);
    expect(result.pendingRotation).toEqual([]);
    expect(alice.client.orgPolicy(orgId)).toMatchObject({ version: 3, signerId: alice.id, source: "verified" });
    await bob.client.sync();
    expect(bob.client.orgPolicy(orgId)).toMatchObject({ version: 3, needsResign: false });
    expect(bob.client.getSnapshot().effectivePolicy.allowPersonalVault).toBe(false);

    // Offboarding Bob signs him out everywhere.
    const after = await alice.client.offboardMember(orgId, bob.id, { endSessions: true });
    expect(after.pendingRotation).toEqual([]);
    await expect(bob.client.sync()).rejects.toMatchObject({ status: 401 });
    const history = await alice.client.policyHistory(orgId);
    expect(history.map((p) => p.version)).toEqual([3, 2, 1]);
  });
});
