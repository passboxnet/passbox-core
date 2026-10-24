/**
 * Import from other password managers and browsers. Everything here is a
 * pure function over the file content: nothing is sent anywhere, and the
 * result is a list of Passbox items for `PassboxClient.importItems`.
 *
 *   const file = { name: "Chrome Passwords.csv", bytes };
 *   const result = parseImport(file);                    // format is detected
 *   const duplicates = findDuplicates(result.items, snapshot.items);
 */
import { unzipSync } from "fflate";
import { type ExportCore, readEncryptedExport } from "../export";
import { isEmptyItem } from "./build";
import { type CsvTable, parseCsvTable } from "./csv";
import { isBitwardenJson, parseBitwardenJson } from "./formats/bitwarden";
import {
  CSV_FORMATS,
  CSV_FORMATS_BY_ID,
  type CsvFormat,
  dashlaneCsv,
  dashlaneNotesCsv,
  detectCsvFormat,
  parseCsvWith,
} from "./formats/csvFormats";
import { isKeePassXml, parseKeePassXml } from "./formats/keepassXml";
import { is1puxData, parse1pux, read1pux } from "./formats/onepassword";
import { isProtonPassJson, parseProtonPassJson, readProtonPassZip } from "./formats/protonpass";
import { type ColumnMapping, detectColumns, parseGenericCsv } from "./generic";
import { ImportError, type ImportedItem, type ImportFormat, type ImportResult, WarningCollector } from "./types";

export { hostOf, normalizeTotp, normalizeUrl } from "./build";
export { type CsvTable, detectDelimiter, parseCsv, parseCsvTable, writeCsv } from "./csv";
export {
  type DuplicateDecision,
  type DuplicateMatch,
  duplicateKey,
  findDuplicates,
  mergeItem,
} from "./duplicates";
export {
  type ColumnMapping,
  type ColumnTarget,
  detectColumns,
  mappingProblem,
  parseGenericCsv,
  SINGLE_TARGETS,
} from "./generic";
export {
  ImportError,
  type ImportedItem,
  type ImportFormat,
  type ImportResult,
  type ImportWarning,
  type ImportWarningCode,
} from "./types";

export interface ImportFile {
  name: string;
  bytes: Uint8Array;
}

export interface ImportOptions {
  /** Skip detection and read the file in this format. */
  format?: ImportFormat;
  /** Column mapping for generic CSV files (default: `detectColumns`). */
  mapping?: ColumnMapping;
  /** Password of an encrypted Passbox export. */
  password?: string;
  /** Needed for Passbox exports: `core.decryptExport`. */
  core?: Pick<ExportCore, "decryptExport">;
}

const isZip = (bytes: Uint8Array) => bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;

/**
 * Decodes text as UTF-8, falling back to Windows-1252 (what Excel on a
 * German Windows writes when saving "CSV (Trennzeichen-getrennt)").
 */
export function decodeText(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes).replace(/^﻿/, "");
  } catch {
    return new TextDecoder("windows-1252").decode(bytes);
  }
}

function zipEntries(bytes: Uint8Array): string[] {
  const names: string[] = [];
  try {
    unzipSync(bytes, {
      filter: (file) => {
        names.push(file.name);
        return false;
      },
    });
  } catch {
    throw new ImportError("invalid_file", "The ZIP file could not be opened.");
  }
  return names;
}

function tryJson(text: string): unknown {
  const trimmed = text.trimStart();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

function isPassboxExport(value: unknown): boolean {
  return typeof value === "object" && value !== null && (value as { format?: unknown }).format === "passbox-export";
}

/** Recognizes the format from the file name and content, or `undefined`. */
export function detectFormat(file: ImportFile): ImportFormat | undefined {
  const { bytes } = file;
  const name = file.name.toLowerCase();
  if (isZip(bytes)) {
    const entries = zipEntries(bytes);
    if (entries.includes("export.data")) return "1password-1pux";
    if (entries.some((e) => e.endsWith("data.json"))) return "protonpass-json";
    if (entries.some((e) => /credentials\.csv$/i.test(e))) return "dashlane-zip";
    return undefined;
  }
  const text = decodeText(bytes);
  const json = tryJson(text);
  if (json !== undefined) {
    if (isPassboxExport(json)) return "passbox";
    if (isBitwardenJson(json)) return "bitwarden-json";
    if (is1puxData(json)) return "1password-1pux";
    if (isProtonPassJson(json)) return "protonpass-json";
    return undefined;
  }
  if (isKeePassXml(text)) return "keepass-xml";
  if (name.endsWith(".json") || name.endsWith(".xml")) return undefined;
  const table = parseCsvTable(text);
  if (table.headers.length < 2) return undefined;
  return detectCsvFormat(table.headers)?.id ?? "generic-csv";
}

/** Headers, the first rows and the suggested mapping of a CSV file, for the mapping step. */
export function previewCsv(file: ImportFile, rows = 5): { table: CsvTable; mapping: ColumnMapping; total: number } {
  const table = parseCsvTable(decodeText(file.bytes));
  return {
    table: { headers: table.headers, rows: table.rows.slice(0, rows) },
    mapping: detectColumns(table.headers),
    total: table.rows.length,
  };
}

function finish(format: ImportFormat, items: ImportedItem[], warnings: WarningCollector): ImportResult {
  const kept = items.filter((item) => {
    if (!isEmptyItem(item.data)) return true;
    warnings.add("empty_skipped", "");
    return false;
  });
  return { format, items: kept, warnings: warnings.list() };
}

function parseCsvFile(format: ImportFormat, text: string, candidates: readonly CsvFormat[] | undefined): ImportResult {
  const table = parseCsvTable(text);
  const layout = detectCsvFormat(table.headers, candidates ?? CSV_FORMATS);
  if (!layout) {
    throw new ImportError(
      "unknown_format",
      "The columns of this file do not match the selected format. Choose “Excel/CSV” to assign the columns yourself.",
    );
  }
  const { items, warnings } = parseCsvWith(layout, table);
  return finish(format, items, warnings);
}

/**
 * Reads an export file. Throws `ImportError` for unknown, encrypted or
 * damaged files (and for Passbox exports without the right password).
 */
export function parseImport(file: ImportFile, options: ImportOptions = {}): ImportResult {
  const format = options.format ?? detectFormat(file);
  if (!format) throw new ImportError("unknown_format", "This file is not an export format Passbox can read.");
  const text = () => decodeText(file.bytes);
  const json = () => {
    const value = tryJson(text());
    if (value === undefined) throw new ImportError("invalid_file", "The file is not valid JSON.");
    return value as never;
  };
  switch (format) {
    case "passbox": {
      if (!options.password || !options.core) throw new ImportError("password_required", "Enter the export password.");
      let payload: ReturnType<typeof readEncryptedExport>;
      try {
        payload = readEncryptedExport(options.core, text(), options.password);
      } catch (error) {
        if (error instanceof Error && error.name === "ExportDecryptionError") {
          throw new ImportError("wrong_password", "The export password is wrong, or the file was changed.");
        }
        throw new ImportError("invalid_file", "The Passbox export could not be read.");
      }
      const items = payload.vaults.flatMap((vault) => vault.items.map((data) => ({ data, sourceVault: vault.name })));
      return finish(format, items, new WarningCollector());
    }
    case "bitwarden-json": {
      const { items, warnings } = parseBitwardenJson(json());
      return finish(format, items, warnings);
    }
    case "1password-1pux": {
      const data = isZip(file.bytes) ? read1pux(file.bytes) : json();
      const { items, warnings } = parse1pux(data);
      return finish(format, items, warnings);
    }
    case "protonpass-json": {
      const data = isZip(file.bytes) ? readProtonPassZip(file.bytes) : tryJson(text());
      if (!data) throw new ImportError("invalid_file", "The Proton Pass file is damaged.");
      const { items, warnings } = parseProtonPassJson(data);
      return finish(format, items, warnings);
    }
    case "keepass-xml": {
      const { items, warnings } = parseKeePassXml(text());
      return finish(format, items, warnings);
    }
    case "dashlane-zip": {
      const files = unzipSync(file.bytes, { filter: (f) => f.name.toLowerCase().endsWith(".csv") });
      const items: ImportedItem[] = [];
      const warnings = new WarningCollector();
      for (const [, bytes] of Object.entries(files).sort(([a], [b]) => a.localeCompare(b))) {
        const table = parseCsvTable(decodeText(bytes));
        const layout = detectCsvFormat(table.headers, [dashlaneCsv, dashlaneNotesCsv]);
        if (layout) items.push(...parseCsvWith(layout, table, warnings).items);
      }
      return finish(format, items, warnings);
    }
    case "generic-csv": {
      const table = parseCsvTable(text());
      const { items, warnings } = parseGenericCsv(table, options.mapping ?? detectColumns(table.headers));
      return finish(format, items, warnings);
    }
    default:
      return parseCsvFile(format, text(), CSV_FORMATS_BY_ID[format]);
  }
}
