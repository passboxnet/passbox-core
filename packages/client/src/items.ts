/**
 * Plaintext item format (version 1). Items are encrypted as JSON in this
 * shape; the server never sees it.
 */

/** `environment`: key/value sets for applications (`.env`), one field per variable. */
export type ItemCategory = "login" | "note" | "card" | "identity" | "environment" | "other";

export type FieldType = "text" | "concealed" | "url" | "email" | "totp";

export interface ItemField {
  /** Stable within the item. Well-known IDs: see `FIELD`. */
  id: string;
  label: string;
  type: FieldType;
  value: string;
}

/**
 * A WebAuthn credential (ES256) stored on a login. The private key is
 * encrypted with the rest of the item; UIs must never display it.
 */
export interface Passkey {
  /** Base64url credential ID. */
  credentialId: string;
  /** Relying party ID, for example `github.com`. */
  rpId: string;
  /** Relying party display name at creation time. */
  rpName: string;
  /** Base64url user handle chosen by the relying party. */
  userHandle: string;
  userName: string;
  userDisplayName: string;
  /** PKCS#8 DER private key, Base64url. */
  privateKey: string;
  /** COSE algorithm, always -7 (ES256) for now. */
  algorithm: number;
  signCount: number;
  /** Unix milliseconds. */
  createdAt: number;
}

/** A password an item had before. */
export interface PasswordHistoryEntry {
  value: string;
  /** Unix milliseconds when it was replaced. */
  replacedAt: number;
}

/** Items stay in the trash this long before clients delete them. */
export const TRASH_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
/** Number of earlier passwords kept per item. */
export const PASSWORD_HISTORY_LEN = 20;

/**
 * Item contents. Keys this version does not know are kept as they are
 * (see `parseItemData`), so data from newer clients survives edits.
 */
export interface ItemData {
  v: 1;
  category: ItemCategory;
  title: string;
  fields: ItemField[];
  notes: string;
  tags: string[];
  favorite: boolean;
  /** Passkeys of a login. Absent when there are none. */
  passkeys?: Passkey[];
  /** Unix milliseconds when the item was moved to the trash. */
  trashedAt?: number;
  /** Earlier passwords, newest first. Maintained by `PassboxClient.updateItem`. */
  passwordHistory?: PasswordHistoryEntry[];
}

const KNOWN_KEYS = new Set([
  "v",
  "category",
  "title",
  "fields",
  "notes",
  "tags",
  "favorite",
  "passkeys",
  "trashedAt",
  "passwordHistory",
]);

/** Well-known field IDs used for autofill and display. */
export const FIELD = {
  username: "username",
  password: "password",
  url: "url",
  totp: "totp",
  cardholder: "cardholder",
  cardNumber: "card_number",
  cardExpiry: "card_expiry",
  cardCode: "card_code",
} as const;

/** Default fields for a new item of each category. */
export function templateFields(category: ItemCategory): ItemField[] {
  switch (category) {
    case "login":
      return [
        { id: FIELD.username, label: "Username", type: "text", value: "" },
        { id: FIELD.password, label: "Password", type: "concealed", value: "" },
        { id: FIELD.url, label: "Website", type: "url", value: "" },
        { id: FIELD.totp, label: "One-time password", type: "totp", value: "" },
      ];
    case "card":
      return [
        { id: FIELD.cardholder, label: "Cardholder", type: "text", value: "" },
        { id: FIELD.cardNumber, label: "Number", type: "concealed", value: "" },
        { id: FIELD.cardExpiry, label: "Expiry date", type: "text", value: "" },
        { id: FIELD.cardCode, label: "Security code", type: "concealed", value: "" },
      ];
    default:
      return [];
  }
}

export function newItemData(category: ItemCategory, title = ""): ItemData {
  return { v: 1, category, title, fields: templateFields(category), notes: "", tags: [], favorite: false };
}

/** Whether `name` can be an environment variable (letters, digits, `_`, not starting with a digit). */
export function isEnvName(name: string): boolean {
  return name.length <= 256 && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

/**
 * The variables of an environment item: fields whose label is a valid
 * variable name, in order; a later field wins over an earlier one with the
 * same name. Mirrors `ItemData::environment_variables` in Rust.
 */
export function environmentVariables(item: ItemData): [string, string][] {
  const out = new Map<string, string>();
  for (const field of item.fields) {
    const name = field.label.trim();
    if (!isEnvName(name)) continue;
    out.delete(name);
    out.set(name, field.value);
  }
  return [...out.entries()];
}

export function fieldValue(item: ItemData, id: string): string | undefined {
  const value = item.fields.find((field) => field.id === id)?.value;
  return value ? value : undefined;
}

const CATEGORIES: readonly ItemCategory[] = ["login", "note", "card", "identity", "environment", "other"];
const FIELD_TYPES: readonly FieldType[] = ["text", "concealed", "url", "email", "totp"];

const BASE64URL = /^[A-Za-z0-9_-]*$/;

function parsePasskey(raw: unknown): Passkey | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const p = raw as Record<string, unknown>;
  const str = (key: string) => (typeof p[key] === "string" ? (p[key] as string) : "");
  const credentialId = str("credentialId");
  const privateKey = str("privateKey");
  const rpId = str("rpId");
  const userHandle = str("userHandle");
  if (!credentialId || !privateKey || !rpId) return undefined;
  if (![credentialId, privateKey, userHandle].every((value) => BASE64URL.test(value))) return undefined;
  const count = typeof p.signCount === "number" && Number.isSafeInteger(p.signCount) ? p.signCount : 0;
  return {
    credentialId,
    rpId,
    rpName: str("rpName") || rpId,
    userHandle,
    userName: str("userName"),
    userDisplayName: str("userDisplayName"),
    privateKey,
    algorithm: typeof p.algorithm === "number" ? p.algorithm : -7,
    signCount: Math.max(0, count),
    createdAt: typeof p.createdAt === "number" ? p.createdAt : 0,
  };
}

function parseHistory(raw: unknown): PasswordHistoryEntry[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter(
      (e): e is PasswordHistoryEntry =>
        typeof e?.value === "string" && typeof e?.replacedAt === "number" && Number.isFinite(e.replacedAt),
    )
    .map((e) => ({ value: e.value, replacedAt: e.replacedAt }))
    .slice(0, PASSWORD_HISTORY_LEN);
}

/**
 * Validates decrypted JSON and fills defaults. Throws on unknown versions.
 * Unknown keys are kept unchanged.
 */
export function parseItemData(json: string): ItemData {
  const raw = JSON.parse(json) as Partial<ItemData> & { v?: unknown } & Record<string, unknown>;
  if (raw.v !== 1) throw new Error(`unsupported item version ${String(raw.v)}`);
  const fields = Array.isArray(raw.fields) ? raw.fields : [];
  const passkeys = Array.isArray(raw.passkeys)
    ? (raw.passkeys as unknown[]).map(parsePasskey).filter((p): p is Passkey => p !== undefined)
    : [];
  const unknown = Object.fromEntries(Object.entries(raw).filter(([key]) => !KNOWN_KEYS.has(key)));
  const data: ItemData = {
    ...unknown,
    v: 1,
    category: CATEGORIES.includes(raw.category as ItemCategory) ? (raw.category as ItemCategory) : "other",
    title: typeof raw.title === "string" ? raw.title : "",
    fields: fields
      .filter((f): f is ItemField => typeof f?.id === "string" && typeof f?.value === "string")
      .map((f) => ({
        id: f.id,
        label: typeof f.label === "string" ? f.label : f.id,
        type: FIELD_TYPES.includes(f.type) ? f.type : "text",
        value: f.value,
      })),
    notes: typeof raw.notes === "string" ? raw.notes : "",
    tags: Array.isArray(raw.tags) ? raw.tags.filter((t): t is string => typeof t === "string") : [],
    favorite: raw.favorite === true,
  };
  if (passkeys.length > 0) data.passkeys = passkeys;
  if (typeof raw.trashedAt === "number" && Number.isFinite(raw.trashedAt)) data.trashedAt = raw.trashedAt;
  const history = parseHistory(raw.passwordHistory);
  if (history.length > 0) data.passwordHistory = history;
  return data;
}

export interface VaultMeta {
  name: string;
}

export function parseVaultMeta(json: string): VaultMeta {
  const raw = JSON.parse(json) as Partial<VaultMeta>;
  return { name: typeof raw.name === "string" && raw.name ? raw.name : "Vault" };
}
