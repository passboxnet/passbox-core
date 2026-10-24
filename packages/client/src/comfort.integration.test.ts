/**
 * Moving items, archive, attachments and share links against a real
 * server (see client.integration.test.ts for how to start one).
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { PassboxClient } from "./client";
import { FIELD, type ItemData, newItemData } from "./items";
import { openShareLink, shareLinkInfo, shareSnapshot, WrongPassphraseError } from "./shareLinks";
import { memoryStorage } from "./storage";

const serverUrl = process.env.PASSBOX_TEST_SERVER_URL;

describe.skipIf(!serverUrl)("moves, archive, attachments and links against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("moves, archives, attaches and shares", async () => {
    let client: PassboxClient | undefined;
    const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token });
    client = new PassboxClient({ core, api, storage: memoryStorage() });
    await client.signUp(`${core.newId()}@example.com`, "correct horse battery staple");
    const personal = client.getSnapshot().vaults[0]?.id as string;

    const wifi = newItemData("wifi", "Home");
    wifi.fields = wifi.fields.map((f) => (f.id === FIELD.password ? { ...f, value: "first" } : f));
    const id = await client.createItem(personal, wifi);
    const stored = () => client?.getSnapshot().items.find((i) => i.id === id);
    await client.updateItem(id, { ...(stored()?.data as ItemData), title: "Home Wi-Fi" });

    // Attachments are encrypted here, the server only stores ciphertext.
    const bytes = new TextEncoder().encode("%PDF-1.7 hello");
    const attachment = await client.addAttachment(id, { name: "router.pdf", type: "application/pdf", data: bytes });
    expect(stored()?.data.attachments?.[0]?.name).toBe("router.pdf");
    const raw = await api.comfort.downloadAttachment(attachment.id);
    expect(new TextDecoder().decode(raw)).not.toContain("hello");
    expect(await client.attachmentData(id, attachment.id)).toEqual(bytes);

    // Move into a shared vault: same ID, history and attachment.
    const orgId = await client.createTeam("Acme");
    const shared = await client.createSharedVault(orgId, "Ops");
    const preview = client.movePreview([id], shared);
    expect(preview.gain).toHaveLength(0);
    expect(preview.lose).toHaveLength(0);
    expect(await client.moveItems([id, id], shared)).toEqual([id]);
    expect(stored()?.vaultId).toBe(shared);
    expect(stored()?.data.category).toBe("wifi");
    const history = await client.itemHistory(id);
    expect(history.length).toBeGreaterThanOrEqual(2);
    expect(history.every((v) => v.data !== null)).toBe(true);
    expect(await client.attachmentData(id, attachment.id)).toEqual(bytes);

    // Archive.
    await client.archiveItem(id);
    expect(client.getSnapshot().items.some((i) => i.id === id)).toBe(false);
    expect(client.getSnapshot().archive[0]?.id).toBe(id);
    const archived = client.getSnapshot().archive[0]?.data as ItemData;
    const { archivedAt: _a, ...withoutArchive } = archived;
    await client.updateItem(id, { ...withoutArchive, title: "Old Wi-Fi" });
    expect(client.getSnapshot().archive[0]?.data.title).toBe("Old Wi-Fi");
    await client.unarchiveItem(id);
    expect(stored()?.data.archivedAt).toBeUndefined();

    await client.removeAttachment(id, attachment.id);
    expect(stored()?.data.attachments).toBeUndefined();

    // A share link, opened without an account.
    const item = stored();
    if (!item) throw new Error("no item");
    const link = await client.createShareLink({
      snapshot: shareSnapshot(item),
      label: "For the guest",
      expiresAt: Date.now() + 60 * 60 * 1000,
      maxViews: 2,
      passphrase: "open sesame",
      vaultId: shared,
      linkBase: "https://pb.example.com",
    });
    expect(link.url).toMatch(/^https:\/\/pb\.example\.com\/s\/[0-9a-z]{26}#[A-Za-z0-9_-]+$/);
    const key = link.url.split("#")[1] as string;
    expect((await client.shareLinks())[0]?.label).toBe("For the guest");
    const anonymous = createClient({ baseUrl: serverUrl ?? "" });
    expect(await shareLinkInfo(anonymous, link.id)).toMatchObject({
      status: "ready",
      needsPassphrase: true,
      viewsLeft: 2,
    });
    await expect(openShareLink(anonymous, core, link.id, key, "wrong")).rejects.toBeInstanceOf(WrongPassphraseError);
    const opened = await openShareLink(anonymous, core, link.id, key, "open sesame");
    expect(opened.snapshot.title).toBe("Old Wi-Fi");
    expect(opened.snapshot.fields.find((f) => f.value === "first")).toBeTruthy();
    expect(opened.viewsLeft).toBe(1);
    await client.deleteShareLink(link.id);
    expect(await shareLinkInfo(anonymous, link.id)).toEqual({ status: "gone" });
  });
});
