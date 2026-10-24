/**
 * 1Password 1PUX export: a ZIP file with `export.data` (JSON: accounts →
 * vaults → items) and the attachments under `files/`. 1Password does not
 * export passkeys in a usable form.
 */
import { strFromU8, unzipSync } from "fflate";
import type { FieldType, PasswordHistoryEntry } from "../../items";
import {
  buildCard,
  buildIdentity,
  buildLogin,
  buildNote,
  buildOther,
  clean,
  type ExtraField,
  type IdentityKey,
  normalizeTotp,
} from "../build";
import { ImportError, type ImportedItem, WarningCollector } from "../types";

// biome-ignore lint/suspicious/noExplicitAny: external JSON is checked field by field
type Json = any;

const s = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");

const CATEGORY_NAMES: Record<string, string> = {
  "006": "Document",
  "100": "Software License",
  "101": "Bank Account",
  "102": "Database",
  "103": "Driver License",
  "104": "Outdoor License",
  "105": "Membership",
  "106": "Passport",
  "107": "Reward Program",
  "108": "Social Security Number",
  "109": "Wireless Router",
  "110": "Server",
  "111": "Email Account",
  "112": "API Credential",
  "113": "Medical Record",
  "114": "SSH Key",
  "115": "Crypto Wallet",
};

/** Reads `export.data` from a 1PUX file. */
export function read1pux(bytes: Uint8Array): Json {
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(bytes, { filter: (file) => file.name === "export.data" });
  } catch {
    throw new ImportError("invalid_file", "The 1PUX file could not be opened.");
  }
  const data = files["export.data"];
  if (!data) throw new ImportError("invalid_file", "The 1PUX file does not contain export.data.");
  try {
    return JSON.parse(strFromU8(data));
  } catch {
    throw new ImportError("invalid_file", "The 1PUX file is damaged.");
  }
}

export function is1puxData(value: Json): boolean {
  return typeof value === "object" && value !== null && Array.isArray(value.accounts);
}

interface Converted {
  value: string;
  type: FieldType;
}

function formatMonthYear(value: number): string {
  const text = String(value);
  return text.length === 6 ? `${text.slice(4)}/${text.slice(0, 4)}` : text;
}

function formatDate(seconds: number): string {
  return new Date(seconds * 1000).toISOString().slice(0, 10);
}

/** Converts a 1PUX section field value. */
function convertValue(value: Json): Converted | undefined {
  if (!value || typeof value !== "object") return undefined;
  if ("concealed" in value) return { value: s(value.concealed), type: "concealed" };
  if ("totp" in value) return { value: s(value.totp), type: "totp" };
  if ("string" in value) return { value: s(value.string), type: "text" };
  if ("email" in value) return { value: s(value.email?.email_address ?? value.email), type: "email" };
  if ("url" in value) return { value: s(value.url), type: "url" };
  if ("phone" in value) return { value: s(value.phone), type: "text" };
  if ("creditCardNumber" in value) return { value: s(value.creditCardNumber), type: "concealed" };
  if ("creditCardType" in value) return { value: s(value.creditCardType), type: "text" };
  if ("monthYear" in value)
    return { value: typeof value.monthYear === "number" ? formatMonthYear(value.monthYear) : "", type: "text" };
  if ("date" in value) return { value: typeof value.date === "number" ? formatDate(value.date) : "", type: "text" };
  if ("menu" in value) return { value: s(value.menu), type: "text" };
  if ("gender" in value) return { value: s(value.gender), type: "text" };
  if ("address" in value && value.address) {
    const a = value.address;
    return {
      value: [a.street, [a.zip, a.city].filter(Boolean).join(" "), a.state, a.country]
        .map(s)
        .filter(Boolean)
        .join("\n"),
      type: "text",
    };
  }
  if ("sshKey" in value) return { value: s(value.sshKey?.privateKey), type: "concealed" };
  if ("file" in value) return undefined;
  if ("reference" in value) return undefined;
  const [first] = Object.values(value);
  return typeof first === "string" || typeof first === "number" ? { value: String(first), type: "text" } : undefined;
}

interface SectionField {
  id: string;
  title: string;
  value: Json;
  converted: Converted | undefined;
}

function sectionFields(details: Json): SectionField[] {
  const out: SectionField[] = [];
  for (const section of Array.isArray(details?.sections) ? details.sections : []) {
    for (const field of Array.isArray(section?.fields) ? section.fields : []) {
      out.push({
        id: s(field?.id),
        title: s(field?.title),
        value: field?.value,
        converted: convertValue(field?.value),
      });
    }
  }
  return out;
}

export function parse1pux(data: Json): { items: ImportedItem[]; warnings: WarningCollector } {
  const warnings = new WarningCollector();
  const items: ImportedItem[] = [];
  for (const account of Array.isArray(data.accounts) ? data.accounts : []) {
    for (const vault of Array.isArray(account?.vaults) ? account.vaults : []) {
      const vaultName = clean(vault?.attrs?.name);
      for (const item of Array.isArray(vault?.items) ? vault.items : []) {
        const imported = convertItem(item, warnings);
        if (imported) items.push(vaultName ? { data: imported, sourceVault: vaultName } : { data: imported });
      }
    }
  }
  return { items, warnings };
}

function convertItem(item: Json, warnings: WarningCollector) {
  if (!item || typeof item !== "object") return undefined;
  const overview = item.overview ?? {};
  const details = item.details ?? {};
  const title = s(overview.title);
  if (item.state === "deleted" || item.trashed === true) {
    warnings.add("trashed_skipped", title);
    return undefined;
  }
  const tags: string[] = Array.isArray(overview.tags) ? overview.tags.map(s) : [];
  if (item.state === "archived") tags.push("Archived");
  const passwordHistory: PasswordHistoryEntry[] = (
    Array.isArray(details.passwordHistory) ? details.passwordHistory : []
  )
    .filter((h: Json) => typeof h?.value === "string")
    .map((h: Json) => ({ value: h.value, replacedAt: typeof h.time === "number" ? h.time * 1000 : 0 }));
  if (details.passkey || overview.passkey) warnings.add("passkeys_not_exported", title);
  if (details.documentAttributes) warnings.add("attachments_not_imported", title);
  const fields = sectionFields(details);
  if (fields.some((f) => f.value && typeof f.value === "object" && "file" in f.value))
    warnings.add("attachments_not_imported", title);
  const base = { title, notes: s(details.notesPlain), tags, favorite: Number(item.favIndex) > 0, passwordHistory };
  const extras = (list: SectionField[]): ExtraField[] =>
    list
      .filter((f) => f.converted && f.converted.value !== "")
      .map((f) => {
        const { value, type } = f.converted as Converted;
        // A field Passbox could not generate codes from stays readable as a secret.
        return { label: f.title || f.id, value, type: type === "totp" && !normalizeTotp(value) ? "concealed" : type };
      });

  switch (s(item.categoryUuid)) {
    case "001":
    case "005": {
      const loginFields: Json[] = Array.isArray(details.loginFields) ? details.loginFields : [];
      const designated = (name: string) => loginFields.find((f) => f?.designation === name);
      const username = s(designated("username")?.value);
      const password = s(designated("password")?.value) || s(details.password);
      const otherLoginFields: ExtraField[] = loginFields
        .filter(
          (f) =>
            f &&
            !f.designation &&
            s(f.value) !== "" &&
            f.fieldType !== "C" &&
            f.fieldType !== "B" &&
            f.fieldType !== "I",
        )
        .map((f) => ({
          label: s(f.name) || s(f.id),
          value: s(f.value),
          type: f.fieldType === "P" ? "concealed" : f.fieldType === "E" ? "email" : "text",
        }));
      // The first valid one-time password becomes the item's code; others stay fields.
      let totp: string | undefined;
      const rest = fields.filter((f) => {
        if (!totp && f.converted?.type === "totp" && normalizeTotp(f.converted.value)) {
          totp = f.converted.value;
          return false;
        }
        return true;
      });
      const urls: string[] =
        Array.isArray(overview.urls) && overview.urls.length > 0
          ? overview.urls.map((u: Json) => s(u?.url))
          : [s(overview.url)];
      return buildLogin(
        { ...base, username, password, totp, urls, fields: [...otherLoginFields, ...extras(rest)] },
        warnings,
      );
    }
    case "002": {
      const byId = (id: string) => fields.find((f) => f.id === id);
      const used = new Set(["cardholder", "type", "ccnum", "cvv", "expiry"]);
      return buildCard({
        ...base,
        cardholder: byId("cardholder")?.converted?.value,
        brand: byId("type")?.converted?.value,
        number: byId("ccnum")?.converted?.value,
        code: byId("cvv")?.converted?.value,
        expiry: byId("expiry")?.converted?.value,
        fields: extras(fields.filter((f) => !used.has(f.id))),
      });
    }
    case "003":
      return buildNote({ ...base, fields: extras(fields) });
    case "004": {
      const map: Record<string, IdentityKey> = {
        firstname: "first_name",
        initial: "middle_name",
        lastname: "last_name",
        birthdate: "birth_date",
        gender: "gender",
        company: "company",
        jobtitle: "job_title",
        address: "address",
        defphone: "phone",
        cellphone: "mobile",
        email: "email",
        username: "username",
        website: "website",
      };
      const identity: Partial<Record<IdentityKey, string>> = {};
      const rest: SectionField[] = [];
      for (const field of fields) {
        const key = map[field.id];
        if (key && field.converted && !identity[key]) identity[key] = field.converted.value;
        else rest.push(field);
      }
      return buildIdentity({ ...base, identity, fields: extras(rest) });
    }
    default: {
      const category = CATEGORY_NAMES[s(item.categoryUuid)] ?? "Item";
      warnings.add("converted_to_other", title);
      const loginFields: Json[] = Array.isArray(details.loginFields) ? details.loginFields : [];
      const fromLogin: ExtraField[] = loginFields
        .filter((f) => s(f?.value) !== "")
        .map((f) => ({
          label: s(f.name) || s(f.designation) || "Field",
          value: s(f.value),
          type: f.fieldType === "P" ? "concealed" : "text",
        }));
      if (s(details.password)) fromLogin.push({ label: "Password", value: s(details.password), type: "concealed" });
      return buildOther({ ...base, tags: [...tags, category], fields: [...fromLogin, ...extras(fields)] });
    }
  }
}
