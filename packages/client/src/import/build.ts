/** Helpers that turn source records into Passbox item data. */
import {
  FIELD,
  type FieldType,
  type ItemCategory,
  type ItemData,
  type ItemField,
  type Passkey,
  type PasswordHistoryEntry,
  templateFields,
} from "../items";
import type { WarningCollector } from "./types";

/** An extra field before it gets an ID. */
export interface ExtraField {
  label: string;
  value: string;
  type?: FieldType;
}

export interface ItemInput {
  title?: string | undefined;
  username?: string | undefined;
  password?: string | undefined;
  urls?: readonly (string | undefined)[] | undefined;
  totp?: string | undefined;
  notes?: string | undefined;
  tags?: readonly (string | undefined)[] | undefined;
  favorite?: boolean | undefined;
  fields?: readonly ExtraField[] | undefined;
  passkeys?: readonly Passkey[] | undefined;
  passwordHistory?: readonly PasswordHistoryEntry[] | undefined;
}

const str = (value: unknown): string => (typeof value === "string" ? value : value == null ? "" : String(value));

/** Trims a value and returns `undefined` for blanks. */
export function clean(value: unknown): string | undefined {
  const s = str(value).trim();
  return s ? s : undefined;
}

/**
 * Adds `https://` to bare host names ("example.com", "intranet:8080") so they
 * work as links. Other schemes (`android://`, `ftp://`) stay as they are.
 */
export function normalizeUrl(value: string | undefined): string | undefined {
  const url = clean(value);
  if (!url) return undefined;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) return url;
  if (/^[^\s/]+\.[^\s/]+(\/.*)?$/.test(url) || /^[\w-]+:\d+(\/.*)?$/.test(url)) return `https://${url}`;
  return url;
}

/** Lower-case host name without `www.`, used for titles and duplicate detection. */
export function hostOf(value: string | undefined): string | undefined {
  const url = normalizeUrl(value);
  if (!url) return undefined;
  try {
    const host = new URL(url).hostname.toLowerCase().replace(/\.$/, "");
    return host ? host.replace(/^www\./, "") : undefined;
  } catch {
    return undefined;
  }
}

const BASE32 = /^[A-Z2-7]+=*$/;

/**
 * Normalizes a one-time password value to something Passbox accepts: an
 * `otpauth://totp/` URI or a Base32 setup key. Returns `undefined` when the
 * value is neither (for example a six-digit code or an HOTP counter).
 */
export function normalizeTotp(value: string | undefined): string | undefined {
  let v = clean(value);
  if (!v) return undefined;
  if (/^otpauth:\/\/totp\//i.test(v)) return v;
  if (/^otpauth:\/\//i.test(v)) return undefined;
  // KeePass 1.x/KeePassXC legacy "key=SECRET&step=30".
  const legacy = /^key=([^&]+)/i.exec(v);
  if (legacy?.[1]) v = decodeURIComponent(legacy[1]);
  const secret = v.replace(/[\s-]/g, "").toUpperCase();
  if (secret.length >= 16 && BASE32.test(secret)) return secret.replace(/=+$/, "");
  return undefined;
}

/** Folder paths ("Work\\Servers", "Work/Servers") become one tag "Work/Servers". */
export function folderTag(value: string | undefined): string | undefined {
  const folder = clean(value)
    ?.replace(/\\/g, "/")
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean)
    .join("/");
  if (!folder || folder === "(none)") return undefined;
  return folder;
}

function uniqueTags(tags: readonly (string | undefined)[] | undefined): string[] {
  const out: string[] = [];
  for (const tag of tags ?? []) {
    const t = clean(tag);
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

/** Truthy spellings used by exporters for favourites and flags. */
export function isTrue(value: unknown): boolean {
  if (value === true || value === 1) return true;
  const s = str(value).trim().toLowerCase();
  return s === "1" || s === "true" || s === "yes" || s === "ja" || s === "x" || s === "on";
}

/** Assigns field IDs and drops empty extra fields. */
function extraFields(fields: readonly ExtraField[] | undefined, taken: Set<string>): ItemField[] {
  const out: ItemField[] = [];
  let n = 1;
  for (const field of fields ?? []) {
    const value = str(field.value);
    if (!value.trim()) continue;
    while (taken.has(`custom_${n}`)) n++;
    const id = `custom_${n}`;
    taken.add(id);
    let type = field.type ?? "text";
    let fieldValue = value;
    if (type === "totp") {
      // Keep values Passbox cannot generate codes from readable, as a secret.
      const totp = normalizeTotp(value);
      if (totp) fieldValue = totp;
      else type = "concealed";
    }
    out.push({ id, label: clean(field.label) ?? "Field", type, value: fieldValue });
  }
  return out;
}

function finish(
  category: ItemCategory,
  fields: ItemField[],
  input: ItemInput,
  fallbackTitle: string | undefined,
): ItemData {
  const data: ItemData = {
    v: 1,
    category,
    title: clean(input.title) ?? fallbackTitle ?? "Imported item",
    fields,
    notes: str(input.notes).replace(/\r\n/g, "\n").trim(),
    tags: uniqueTags(input.tags),
    favorite: input.favorite === true,
  };
  if (input.passkeys && input.passkeys.length > 0) data.passkeys = [...input.passkeys];
  if (input.passwordHistory && input.passwordHistory.length > 0) data.passwordHistory = [...input.passwordHistory];
  return data;
}

/**
 * Builds a login. Extra URLs become additional website fields; an invalid
 * one-time password value is kept as a text field.
 */
export function buildLogin(input: ItemInput, warnings?: WarningCollector): ItemData {
  const urls = (input.urls ?? []).map(normalizeUrl).filter((u): u is string => u !== undefined);
  const distinctUrls = urls.filter((u, i) => urls.indexOf(u) === i);
  const totpRaw = clean(input.totp);
  const totp = normalizeTotp(totpRaw);
  const fields = templateFields("login");
  const set = (id: string, value: string | undefined) => {
    const field = fields.find((f) => f.id === id);
    if (field && value !== undefined) field.value = value;
  };
  set(FIELD.username, str(input.username).trim());
  set(FIELD.password, str(input.password));
  set(FIELD.url, distinctUrls[0] ?? "");
  set(FIELD.totp, totp ?? "");
  const extra: ExtraField[] = distinctUrls.slice(1).map((u) => ({ label: "Website", value: u, type: "url" }));
  if (totpRaw && !totp) {
    extra.push({ label: "One-time password", value: totpRaw, type: "concealed" });
    warnings?.add("invalid_totp", clean(input.title) ?? "");
  }
  extra.push(...(input.fields ?? []));
  const taken = new Set(fields.map((f) => f.id));
  const title = hostOf(distinctUrls[0]) ?? clean(input.username);
  return finish("login", [...fields, ...extraFields(extra, taken)], input, title);
}

/** Builds a secure note. */
export function buildNote(input: ItemInput): ItemData {
  return finish("note", extraFields(input.fields, new Set()), input, undefined);
}

export interface CardInput extends ItemInput {
  cardholder?: string | undefined;
  number?: string | undefined;
  /** Any of "MM/YYYY", "MM/YY", "YYYY-MM", "YYYYMM" or separate month/year. */
  expiry?: string | undefined;
  expMonth?: string | undefined;
  expYear?: string | undefined;
  code?: string | undefined;
  brand?: string | undefined;
  pin?: string | undefined;
}

/** Formats an expiry date as "MM/YYYY" when it can be understood. */
export function formatExpiry(
  expiry: string | undefined,
  month?: string | undefined,
  year?: string | undefined,
): string | undefined {
  let m = clean(month);
  let y = clean(year);
  const e = clean(expiry);
  if (!m && !y && e) {
    const iso = /^(\d{4})-?(\d{1,2})$/.exec(e);
    const slash = /^(\d{1,2})\s*[/.-]\s*(\d{2}|\d{4})$/.exec(e);
    if (iso) [, y, m] = iso;
    else if (slash) [, m, y] = slash;
    else return e;
  }
  if (!m && !y) return undefined;
  const monthNumber = Number(m);
  const mm =
    m && Number.isInteger(monthNumber) && monthNumber >= 1 && monthNumber <= 12
      ? String(monthNumber).padStart(2, "0")
      : m;
  const yyyy = y && y.length === 2 ? `20${y}` : y;
  return [mm, yyyy].filter(Boolean).join("/");
}

export function buildCard(input: CardInput): ItemData {
  const fields = templateFields("card");
  const set = (id: string, value: string | undefined) => {
    const field = fields.find((f) => f.id === id);
    if (field) field.value = value ?? "";
  };
  set(FIELD.cardholder, clean(input.cardholder));
  set(FIELD.cardNumber, clean(input.number)?.replace(/\s+/g, " "));
  set(FIELD.cardExpiry, formatExpiry(input.expiry, input.expMonth, input.expYear));
  set(FIELD.cardCode, clean(input.code));
  const extra: ExtraField[] = [];
  if (clean(input.brand)) extra.push({ label: "Brand", value: str(input.brand).trim() });
  if (clean(input.pin)) extra.push({ label: "PIN", value: str(input.pin).trim(), type: "concealed" });
  extra.push(...(input.fields ?? []));
  const taken = new Set(fields.map((f) => f.id));
  return finish("card", [...fields, ...extraFields(extra, taken)], input, clean(input.brand) ?? "Card");
}

/** Identity fields in display order. IDs are stable so later versions can map them. */
export const IDENTITY_FIELDS = [
  ["title", "Title", "text"],
  ["first_name", "First name", "text"],
  ["middle_name", "Middle name", "text"],
  ["last_name", "Last name", "text"],
  ["full_name", "Full name", "text"],
  ["birth_date", "Date of birth", "text"],
  ["gender", "Gender", "text"],
  ["email", "Email", "email"],
  ["phone", "Phone", "text"],
  ["mobile", "Mobile", "text"],
  ["company", "Company", "text"],
  ["job_title", "Job title", "text"],
  ["address", "Address", "text"],
  ["postal_code", "Postal code", "text"],
  ["city", "City", "text"],
  ["state", "State", "text"],
  ["country", "Country", "text"],
  ["username", "Username", "text"],
  ["website", "Website", "url"],
  ["ssn", "Social security number", "concealed"],
  ["passport_number", "Passport number", "concealed"],
  ["license_number", "Driver's license number", "concealed"],
] as const satisfies readonly (readonly [string, string, FieldType])[];

export type IdentityKey = (typeof IDENTITY_FIELDS)[number][0];

export interface IdentityInput extends ItemInput {
  identity: Partial<Record<IdentityKey, string | undefined>>;
}

export function buildIdentity(input: IdentityInput): ItemData {
  const fields: ItemField[] = [];
  for (const [id, label, type] of IDENTITY_FIELDS) {
    const value = clean(input.identity[id]);
    if (value) fields.push({ id, label, type, value });
  }
  const taken = new Set(fields.map((f) => f.id));
  const { first_name, last_name, full_name } = input.identity;
  const name = clean(full_name) ?? clean([first_name, last_name].filter(Boolean).join(" "));
  return finish("identity", [...fields, ...extraFields(input.fields, taken)], input, name ?? "Identity");
}

/** Builds an "other" item from fields only (SSH keys, licences, Wi-Fi …). */
export function buildOther(input: ItemInput): ItemData {
  return finish("other", extraFields(input.fields, new Set()), input, undefined);
}

/** Whether a login has anything worth importing. */
export function isEmptyItem(data: ItemData): boolean {
  return (
    data.title === "Imported item" &&
    !data.notes &&
    data.fields.every((f) => !f.value) &&
    !(data.passkeys && data.passkeys.length > 0)
  );
}

/** Joins "key: value" lines for data kept in the notes. */
export function appendNotes(notes: string | undefined, lines: readonly (string | undefined)[]): string {
  const extra = lines.filter((l): l is string => !!l && l.trim() !== "");
  return [str(notes).trim(), extra.join("\n")].filter(Boolean).join("\n\n");
}
