import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { parseCsvTable } from "../import/csv";
import { detectFormat, parseImport } from "../import/index";
import { FIELD, fieldValue, type ItemData, newItemData } from "../items";
import {
  buildExportPayload,
  CSV_COLUMNS,
  countExportItems,
  createCsvExport,
  createEncryptedExport,
  type ExportSource,
  exportFileName,
  readEncryptedExport,
} from "./index";

beforeAll(async () => {
  const require = createRequire(import.meta.url);
  const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
  await core.default({ module_or_path: await readFile(wasmPath) });
});

function login(title: string, username: string, password: string, url: string): ItemData {
  const item = newItemData("login", title);
  item.fields = item.fields.map((f) => {
    if (f.id === FIELD.username) return { ...f, value: username };
    if (f.id === FIELD.password) return { ...f, value: password };
    if (f.id === FIELD.url) return { ...f, value: url };
    if (f.id === FIELD.totp) return { ...f, value: "JBSWY3DPEHPK3PXP" };
    return f;
  });
  return item;
}

const mail = login("Mail", "alice@example.com", 'p"a,ss\nword', "https://mail.example.com");
mail.fields.push({ id: "custom_1", label: "PIN", type: "concealed", value: "1234" });
mail.tags = ["Work", "Email"];
mail.favorite = true;
mail.passwordHistory = [{ value: "old", replacedAt: 1 }];
mail.passkeys = [
  {
    credentialId: "Y3JlZA",
    rpId: "mail.example.com",
    rpName: "Mail",
    userHandle: "dTE",
    userName: "alice",
    userDisplayName: "Alice",
    privateKey: "cHJpdg",
    algorithm: -7,
    signCount: 3,
    createdAt: 5,
  },
];
const note = { ...newItemData("note", "Door code"), notes: "4711" };
const trashed = { ...login("Old", "x", "y", "https://old.example.com"), trashedAt: 10 };

const source: ExportSource = {
  vaults: [
    { id: "v1", name: "Private" },
    { id: "v2", name: "Family" },
  ],
  items: [
    { vaultId: "v1", data: mail },
    { vaultId: "v2", data: note },
  ],
  trash: [{ vaultId: "v1", data: trashed }],
};

// Each export derives a key with Argon2id (128 MiB), which takes a while in WebAssembly.
describe("encrypted export", { timeout: 60_000 }, () => {
  it("round-trips through the core and the importer", () => {
    const envelope = createEncryptedExport(core, source, "export password 1");
    expect(JSON.parse(envelope)).toMatchObject({ format: "passbox-export", version: 1, cipher: "xchacha20poly1305" });
    expect(envelope).not.toContain("alice@example.com");

    const payload = readEncryptedExport(core, envelope, "export password 1");
    expect(payload.vaults.map((v) => v.name)).toEqual(["Private", "Family"]);
    expect(payload.vaults[0]?.items[0]).toEqual(mail);

    const bytes = new TextEncoder().encode(envelope);
    const exportFile = { name: "backup.pbx-export", bytes };
    expect(detectFormat(exportFile)).toBe("passbox");
    expect(() => parseImport(exportFile)).toThrow(expect.objectContaining({ code: "password_required" }));
    expect(() => parseImport(exportFile, { password: "wrong", core })).toThrow(
      expect.objectContaining({ code: "wrong_password" }),
    );
    const result = parseImport(exportFile, { password: "export password 1", core });
    expect(result.items.map((i) => [i.sourceVault, i.data.title])).toEqual([
      ["Private", "Mail"],
      ["Family", "Door code"],
    ]);
    expect(result.items[0]?.data.passkeys).toEqual(mail.passkeys);
    expect(result.items[0]?.data.passwordHistory).toEqual(mail.passwordHistory);
  });

  it("detects a modified file", () => {
    const envelope = JSON.parse(createEncryptedExport(core, source, "pw-123456")) as Record<string, unknown>;
    envelope.kdf = { ...(envelope.kdf as object), iterations: 4 };
    expect(() => readEncryptedExport(core, JSON.stringify(envelope), "pw-123456")).toThrow(
      expect.objectContaining({ name: "ExportDecryptionError" }),
    );
  });

  it("excludes trashed items unless asked and can select vaults", () => {
    expect(countExportItems(source)).toBe(2);
    expect(countExportItems(source, { includeTrash: true })).toBe(3);
    const payload = buildExportPayload(source, { vaultIds: ["v1"], includeTrash: true }, 42);
    expect(payload).toMatchObject({ exportedAt: 42, vaults: [{ name: "Private" }] });
    expect(payload.vaults[0]?.items.map((i) => i.title)).toEqual(["Mail", "Old"]);
  });
});

describe("CSV export", () => {
  it("writes Bitwarden-compatible columns that Passbox can import again", () => {
    const csv = createCsvExport(source);
    const table = parseCsvTable(csv);
    expect(table.headers).toEqual([...CSV_COLUMNS]);
    expect(table.rows).toHaveLength(2);
    expect(detectFormat({ name: "x.csv", bytes: new TextEncoder().encode(csv) })).toBe("bitwarden-csv");

    const result = parseImport({ name: "x.csv", bytes: new TextEncoder().encode(csv) });
    const imported = result.items[0]?.data as ItemData;
    expect(imported.title).toBe("Mail");
    expect(fieldValue(imported, FIELD.password)).toBe('p"a,ss\nword');
    expect(fieldValue(imported, FIELD.totp)).toBe("JBSWY3DPEHPK3PXP");
    expect(imported.favorite).toBe(true);
    expect(imported.tags).toEqual(["Private/Work"]);
    expect(imported.fields.find((f) => f.label === "PIN")?.value).toBe("1234");
    expect(result.items[1]?.data).toMatchObject({ category: "note", notes: "4711", tags: ["Family"] });
  });

  it("leaves out the trash by default", () => {
    expect(createCsvExport(source)).not.toContain("old.example.com");
    expect(createCsvExport(source, { includeTrash: true })).toContain("old.example.com");
  });

  it("names files by date", () => {
    const date = new Date("2026-10-24T12:00:00Z");
    expect(exportFileName("encrypted", date)).toBe("passbox-export-2026-10-24.pbx-export");
    expect(exportFileName("csv", date)).toBe("passbox-export-2026-10-24.csv");
  });
});
