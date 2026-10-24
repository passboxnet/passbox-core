/**
 * Organizations, invitations, groups and shared vaults against a real
 * server. Start one and set PASSBOX_TEST_SERVER_URL (see
 * client.integration.test.ts).
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { ApiError, createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { PassboxClient } from "./client";
import { FIELD, fieldValue, newItemData } from "./items";
import { parseInvitationLink } from "./sharing";
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

function secret(title: string, password: string) {
  const data = newItemData("login", title);
  data.fields = data.fields.map((f) => (f.id === FIELD.password ? { ...f, value: password } : f));
  return data;
}

describe("invitation links", () => {
  it("parse token and organization fingerprint", () => {
    expect(parseInvitationLink("https://x/invite/abc#org=R")).toEqual({ token: "abc", orgRoot: "R" });
    expect(parseInvitationLink("abc")).toEqual({ token: "abc", orgRoot: undefined });
  });
});

describe.skipIf(!serverUrl)("sharing against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("shares a family vault, enforces roles and rotates keys on removal", { timeout: 120_000 }, async () => {
    const alice = await person("alice");
    const bob = await person("bob");
    const carol = await person("carol");
    const fingerprint = alice.client.ownFingerprint();
    expect(fingerprint.split(" ")).toHaveLength(12);
    expect((await alice.client.verifyOwnKey()).fingerprint).toBe(fingerprint);

    const orgId = await alice.client.createFamily("Doe family", "Family");
    const org = alice.client.org(orgId);
    expect(org.name).toBe("Doe family");
    expect(org.verified).toBe(true);
    const vaultId = org.defaultVaultId ?? "";
    expect(alice.client.vaultAccess(vaultId)).toMatchObject({ orgId, role: "manage" });
    const personal = alice.client.getSnapshot().vaults.find((v) => !v.orgId);
    expect(personal?.role).toBe("manage");
    const itemId = await alice.client.createItem(vaultId, secret("Netflix", "family-secret"));

    const invitation = await alice.client.invite(orgId, bob.email, "member");
    expect(invitation.link).toMatch(/^https:\/\/passbox\.example\/invite\/.+#org=/);
    expect(await alice.client.invitations(orgId)).toHaveLength(1);
    expect((await bob.client.previewInvitation(invitation.link)).orgKind).toBe("family");
    await expect(carol.client.acceptInvitation(invitation.link)).rejects.toBeInstanceOf(ApiError);
    expect(await bob.client.acceptInvitation(invitation.link)).toBe(orgId);
    expect(bob.client.getSnapshot().sharedVaults).toHaveLength(0);
    const confirmed = await alice.client.confirmMember(orgId, bob.id);
    expect(confirmed).toBe(bob.client.ownFingerprint());

    await bob.client.sync();
    expect(bob.client.sharingWarnings()).toEqual([]);
    expect(bob.client.vaultAccess(vaultId).role).toBe("edit");
    const shared = bob.client.getSnapshot().items.find((i) => i.id === itemId);
    expect(shared && fieldValue(shared.data, FIELD.password)).toBe("family-secret");
    expect(bob.client.getSnapshot().orgs[0]?.members.every((m) => m.verified)).toBe(true);

    // View only: the server refuses writes.
    await alice.client.shareVault(vaultId, "account", bob.id, "view");
    await bob.client.sync();
    expect(bob.client.vaultAccess(vaultId).role).toBe("view");
    await expect(bob.client.updateItem(itemId, secret("Netflix", "x"))).rejects.toMatchObject({ status: 403 });

    // A group with Carol gets a second vault.
    const invite = await alice.client.invite(orgId, carol.email, "member");
    await carol.client.acceptInvitation(invite.link);
    await alice.client.confirmMember(orgId, carol.id);
    const groupId = await alice.client.createGroup(orgId, "Kids", [carol.id]);
    expect(alice.client.groups(orgId)[0]?.name).toBe("Kids");
    const kidsVault = await alice.client.createSharedVault(orgId, "Kids");
    const game = await alice.client.createItem(kidsVault, secret("Game", "kids"));
    await alice.client.shareVault(kidsVault, "group", groupId, "view");
    await carol.client.sync();
    expect(carol.client.getSnapshot().items.some((i) => i.id === game)).toBe(true);

    // Removing Bob rotates the family vault and re-encrypts its items.
    const epoch = alice.client.vaultMembers(vaultId).keyEpoch;
    await alice.client.removeMember(orgId, bob.id);
    expect(alice.client.vaultMembers(vaultId).keyEpoch).toBe(epoch + 1);
    expect(alice.client.getSnapshot().items.find((i) => i.id === itemId)?.keyEpoch).toBe(epoch + 1);
    await bob.client.sync();
    expect(bob.client.getSnapshot().items.some((i) => i.id === itemId)).toBe(false);
    expect(bob.client.getSnapshot().orgs).toHaveLength(0);
    await carol.client.sync();
    expect(carol.client.sharingWarnings()).toEqual([]);
    expect(carol.client.org(orgId).name).toBe("Doe family");

    // Removing Carol from the group rotates the group's vault.
    await alice.client.removeGroupMember(orgId, groupId, carol.id);
    await carol.client.sync();
    expect(carol.client.getSnapshot().items.some((i) => i.id === game)).toBe(false);
    expect(alice.client.vaultMembers(kidsVault).keyEpoch).toBe(2);

    // A session export keeps key pairs and shared keys.
    const state = alice.client.exportSession();
    const restored = newClient();
    // The restored client needs the device account in its storage.
    await restored.signIn(alice.email, PASSWORD, alice.client.deviceAccount?.secretKey ?? "");
    if (state) await restored.restoreSession({ ...state, token: restored.token ?? state.token });
    expect(restored.ownFingerprint()).toBe(fingerprint);
    expect(restored.getSnapshot().items.some((i) => i.id === itemId)).toBe(true);
  });
});
