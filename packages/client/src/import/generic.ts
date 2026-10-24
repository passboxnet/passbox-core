/**
 * Generic CSV import (Excel, other managers): every column is mapped to a
 * Passbox field. `detectColumns` suggests a mapping from English and German
 * header names; the user can change it before importing.
 */
import { buildLogin, buildNote, clean, type ExtraField, folderTag, isEmptyItem, isTrue } from "./build";
import type { CsvTable } from "./csv";
import { type ImportedItem, WarningCollector } from "./types";

export type ColumnTarget =
  | "title"
  | "username"
  | "email"
  | "password"
  | "url"
  | "totp"
  | "notes"
  | "folder"
  | "tags"
  | "favorite"
  /** Keep as a text field labelled with the header. */
  | "field"
  /** Keep as a concealed field labelled with the header. */
  | "secret"
  /** Do not import. */
  | "skip";

/** One target per column, in column order. */
export type ColumnMapping = ColumnTarget[];

/** Targets that can be assigned to at most one column. */
export const SINGLE_TARGETS: readonly ColumnTarget[] = [
  "title",
  "username",
  "email",
  "password",
  "url",
  "totp",
  "notes",
  "folder",
  "tags",
  "favorite",
];

const SYNONYMS: Record<Exclude<ColumnTarget, "field" | "secret" | "skip">, string[]> = {
  title: [
    "title",
    "name",
    "titel",
    "bezeichnung",
    "eintrag",
    "account",
    "accountname",
    "konto",
    "service",
    "dienst",
    "itemname",
    "entry",
    "anwendung",
    "application",
    "app",
    "system",
  ],
  username: [
    "username",
    "user",
    "username1",
    "loginname",
    "login",
    "benutzer",
    "benutzername",
    "anmeldename",
    "nutzername",
    "kennung",
    "userid",
    "benutzerkennung",
    "loginusername",
    "account id",
  ],
  email: ["email", "emailaddress", "mail", "emailadresse", "mailadresse"],
  password: [
    "password",
    "passwort",
    "kennwort",
    "pass",
    "pw",
    "pwd",
    "passcode",
    "loginpassword",
    "secret",
    "geheimnis",
  ],
  url: [
    "url",
    "website",
    "websiteurl",
    "webseite",
    "site",
    "web",
    "webadresse",
    "adresse",
    "address",
    "link",
    "domain",
    "uri",
    "loginuri",
    "homepage",
    "internetadresse",
  ],
  totp: [
    "totp",
    "otp",
    "otpauth",
    "otpsecret",
    "otpurl",
    "2fa",
    "mfa",
    "twofactor",
    "authenticator",
    "einmalpasswort",
    "einmalcode",
    "logintotp",
    "totpsecret",
  ],
  notes: [
    "notes",
    "note",
    "comment",
    "comments",
    "notizen",
    "notiz",
    "bemerkung",
    "bemerkungen",
    "kommentar",
    "kommentare",
    "beschreibung",
    "description",
    "extra",
    "info",
    "hinweis",
    "hinweise",
  ],
  folder: [
    "folder",
    "group",
    "ordner",
    "gruppe",
    "kategorie",
    "category",
    "collection",
    "grouping",
    "vault",
    "tresor",
    "path",
    "pfad",
    "bereich",
  ],
  tags: ["tags", "tag", "labels", "label", "schlagwörter", "stichwörter", "schlagworte"],
  favorite: ["favorite", "favourite", "fav", "favorit", "starred", "pinned", "favoriten"],
};

/** Lower-case letters and digits only ("E-Mail-Adresse" → "emailadresse"). */
function key(header: string): string {
  return header
    .toLowerCase()
    .replace(/ß/g, "ss")
    .replace(/[^a-z0-9äöü]/g, "");
}

/**
 * Suggests a target for every column. Exact synonyms win over partial
 * matches ("Passwort (alt)" is a field when "Passwort" exists too); each
 * single target is used once; columns nobody claims are kept as fields.
 */
export function detectColumns(headers: readonly string[]): ColumnMapping {
  const keys = headers.map(key);
  const mapping: ColumnMapping = headers.map(() => "field");
  const used = new Set<ColumnTarget>();
  const assign = (matcher: (k: string, synonyms: string[]) => boolean) => {
    for (const target of SINGLE_TARGETS) {
      if (used.has(target)) continue;
      const synonyms = SYNONYMS[target as keyof typeof SYNONYMS].map(key);
      const index = keys.findIndex((k, i) => mapping[i] === "field" && k !== "" && matcher(k, synonyms));
      if (index !== -1) {
        mapping[index] = target;
        used.add(target);
      }
    }
  };
  assign((k, synonyms) => synonyms.includes(k));
  assign((k, synonyms) => synonyms.some((s) => s.length >= 4 && (k.startsWith(s) || k.endsWith(s))));
  // A lone email column is the username.
  if (!used.has("username") && used.has("email")) {
    mapping[mapping.indexOf("email")] = "username";
  }
  // Mark obviously secret leftovers.
  headers.forEach((header, i) => {
    if (mapping[i] === "field" && /pin|passw|kennw|secret|geheim|cvv|cvc|code/i.test(header)) mapping[i] = "secret";
  });
  return mapping;
}

/** Whether a mapping can produce useful items. */
export function mappingProblem(mapping: ColumnMapping): "no_columns" | "duplicate_target" | undefined {
  if (!mapping.some((t) => ["title", "username", "email", "password", "url", "notes"].includes(t))) return "no_columns";
  for (const target of SINGLE_TARGETS) {
    if (mapping.filter((t) => t === target).length > 1) return "duplicate_target";
  }
  return undefined;
}

/** Converts rows with a column mapping into logins (or notes, when only a note is set). */
export function parseGenericCsv(
  table: CsvTable,
  mapping: ColumnMapping,
): { items: ImportedItem[]; warnings: WarningCollector } {
  const warnings = new WarningCollector();
  const items: ImportedItem[] = [];
  for (const row of table.rows) {
    const value = (target: ColumnTarget) => {
      const index = mapping.indexOf(target);
      return index === -1 ? "" : (row[index] ?? "");
    };
    const fields: ExtraField[] = [];
    mapping.forEach((target, i) => {
      if (target === "field" || target === "secret") {
        fields.push({
          label: table.headers[i] || `Column ${i + 1}`,
          value: row[i] ?? "",
          type: target === "secret" ? "concealed" : "text",
        });
      }
    });
    const email = clean(value("email"));
    const username = clean(value("username"));
    if (email && username && email !== username) fields.unshift({ label: "Email", value: email, type: "email" });
    const input = {
      title: value("title"),
      username: username ?? email,
      password: value("password"),
      urls: [value("url")],
      totp: value("totp"),
      notes: value("notes"),
      tags: [folderTag(value("folder")), ...value("tags").split(/[;,]/)],
      favorite: isTrue(value("favorite")),
      fields,
    };
    const onlyNote =
      !clean(input.username) &&
      !clean(input.password) &&
      !clean(value("url")) &&
      !clean(input.totp) &&
      !!clean(input.notes);
    const data = onlyNote ? buildNote(input) : buildLogin(input, warnings);
    if (isEmptyItem(data)) {
      warnings.add("empty_skipped", "");
      continue;
    }
    items.push({ data });
  }
  return { items, warnings };
}
