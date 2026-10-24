/**
 * Export of vault contents: an encrypted Passbox export (`.pbx-export`,
 * recommended) and a plain CSV file in Bitwarden's column layout, which most
 * password managers can import.
 *
 * The encryption (Argon2id + XChaCha20-Poly1305) happens in the core; this
 * module only builds and reads the payload.
 */
import { writeCsv } from "../import/csv";
import { FIELD, type ItemData, parseItemData } from "../items";

/** The core functions this module needs (from `@passbox/core-wasm`). */
export interface ExportCore {
  encryptExport(password: string, plaintext: string): string;
  decryptExport(password: string, envelope: string): string;
}

export interface ExportSource {
  vaults: readonly { id: string; name: string }[];
  items: readonly { vaultId: string; data: ItemData }[];
  /** Items in the trash; exported only with `includeTrash`. */
  trash?: readonly { vaultId: string; data: ItemData }[];
}

export interface ExportOptions {
  /** Export these vaults only (default: all). */
  vaultIds?: readonly string[];
  /** Also export items in the trash. Off by default. */
  includeTrash?: boolean;
}

export const EXPORT_PAYLOAD_FORMAT = "passbox-export-payload";
export const EXPORT_FILE_EXTENSION = ".pbx-export";

/** The decrypted content of a `.pbx-export` file. */
export interface ExportPayload {
  format: typeof EXPORT_PAYLOAD_FORMAT;
  version: 1;
  /** Unix milliseconds. */
  exportedAt: number;
  vaults: { name: string; items: ItemData[] }[];
}

function selected(source: ExportSource, options: ExportOptions) {
  const vaults = source.vaults.filter((v) => !options.vaultIds || options.vaultIds.includes(v.id));
  const items = [...source.items, ...(options.includeTrash ? (source.trash ?? []) : [])].filter(
    (item) => options.includeTrash || item.data.trashedAt === undefined,
  );
  return vaults.map((vault) => ({
    vault,
    items: items.filter((item) => item.vaultId === vault.id).map((i) => i.data),
  }));
}

/** Number of items an export with these options contains. */
export function countExportItems(source: ExportSource, options: ExportOptions = {}): number {
  return selected(source, options).reduce((sum, v) => sum + v.items.length, 0);
}

export function buildExportPayload(source: ExportSource, options: ExportOptions = {}, now = Date.now()): ExportPayload {
  return {
    format: EXPORT_PAYLOAD_FORMAT,
    version: 1,
    exportedAt: now,
    vaults: selected(source, options).map(({ vault, items }) => ({ name: vault.name, items })),
  };
}

/** Creates the content of a `.pbx-export` file. Key derivation takes a second or two. */
export function createEncryptedExport(
  core: ExportCore,
  source: ExportSource,
  password: string,
  options: ExportOptions = {},
): string {
  return core.encryptExport(password, JSON.stringify(buildExportPayload(source, options)));
}

/**
 * Decrypts and validates a `.pbx-export` file. Throws an error named
 * `ExportDecryptionError` for a wrong password or a modified file.
 */
export function readEncryptedExport(
  core: Pick<ExportCore, "decryptExport">,
  envelope: string,
  password: string,
): ExportPayload {
  const raw = JSON.parse(core.decryptExport(password, envelope)) as Partial<ExportPayload>;
  if (raw.format !== EXPORT_PAYLOAD_FORMAT || raw.version !== 1 || !Array.isArray(raw.vaults)) {
    throw new Error("unsupported Passbox export");
  }
  return {
    format: EXPORT_PAYLOAD_FORMAT,
    version: 1,
    exportedAt: typeof raw.exportedAt === "number" ? raw.exportedAt : 0,
    vaults: raw.vaults.map((vault) => ({
      name: typeof vault?.name === "string" ? vault.name : "Vault",
      items: (Array.isArray(vault?.items) ? vault.items : []).flatMap((item) => {
        try {
          return [parseItemData(JSON.stringify(item))];
        } catch {
          return [];
        }
      }),
    })),
  };
}

/** Bitwarden's CSV columns, understood by Bitwarden, Proton Pass, 1Password and others. */
export const CSV_COLUMNS = [
  "folder",
  "favorite",
  "type",
  "name",
  "notes",
  "fields",
  "reprompt",
  "login_uri",
  "login_username",
  "login_password",
  "login_totp",
] as const;

const LOGIN_FIELDS = new Set<string>([FIELD.username, FIELD.password, FIELD.url, FIELD.totp]);

/**
 * Plain CSV export. Everything, including passwords, is unencrypted. Cards,
 * identities and other items become notes whose fields are listed in the
 * `fields` column; passkeys and password history are not included.
 */
export function createCsvExport(source: ExportSource, options: ExportOptions = {}): string {
  const rows: string[][] = [[...CSV_COLUMNS]];
  const groups = selected(source, options);
  for (const { vault, items } of groups) {
    for (const item of items) {
      const isLogin = item.category === "login";
      const value = (id: string) => item.fields.find((f) => f.id === id)?.value ?? "";
      const extra = item.fields.filter((f) => f.value && (!isLogin || !LOGIN_FIELDS.has(f.id)));
      const urls = isLogin ? item.fields.filter((f) => f.type === "url" && f.value).map((f) => f.value) : [];
      const extraNonUrl = isLogin ? extra.filter((f) => f.type !== "url") : extra;
      // Bitwarden has one folder per item: the first tag, under the vault name when several vaults are exported.
      const folder = [groups.length > 1 ? vault.name : undefined, item.tags[0]].filter(Boolean).join("/");
      rows.push([
        folder,
        item.favorite ? "1" : "",
        isLogin ? "login" : "note",
        item.title,
        item.notes,
        extraNonUrl.map((f) => `${f.label.replace(/: /g, ":")}: ${f.value.replace(/\r?\n/g, " ")}`).join("\n"),
        "0",
        urls.join(","),
        isLogin ? value(FIELD.username) : "",
        isLogin ? value(FIELD.password) : "",
        isLogin ? value(FIELD.totp) : "",
      ]);
    }
  }
  return writeCsv(rows);
}

/** A file name such as `passbox-export-2026-10-24.pbx-export`. */
export function exportFileName(kind: "encrypted" | "csv", now = new Date()): string {
  const date = now.toISOString().slice(0, 10);
  return `passbox-export-${date}${kind === "encrypted" ? EXPORT_FILE_EXTENSION : ".csv"}`;
}
