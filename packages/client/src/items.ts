/**
 * Plaintext item format (version 1). Items are encrypted as JSON in this
 * shape; the server never sees it.
 */

export type ItemCategory = "login" | "note" | "card" | "identity" | "other";

export type FieldType = "text" | "concealed" | "url" | "email" | "totp";

export interface ItemField {
  /** Stable within the item. Well-known IDs: see `FIELD`. */
  id: string;
  label: string;
  type: FieldType;
  value: string;
}

export interface ItemData {
  v: 1;
  category: ItemCategory;
  title: string;
  fields: ItemField[];
  notes: string;
  tags: string[];
  favorite: boolean;
}

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

export function fieldValue(item: ItemData, id: string): string | undefined {
  const value = item.fields.find((field) => field.id === id)?.value;
  return value ? value : undefined;
}

const CATEGORIES: readonly ItemCategory[] = ["login", "note", "card", "identity", "other"];
const FIELD_TYPES: readonly FieldType[] = ["text", "concealed", "url", "email", "totp"];

/** Validates decrypted JSON and fills defaults. Throws on unknown versions. */
export function parseItemData(json: string): ItemData {
  const raw = JSON.parse(json) as Partial<ItemData> & { v?: unknown };
  if (raw.v !== 1) throw new Error(`unsupported item version ${String(raw.v)}`);
  const fields = Array.isArray(raw.fields) ? raw.fields : [];
  return {
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
}

export interface VaultMeta {
  name: string;
}

export function parseVaultMeta(json: string): VaultMeta {
  const raw = JSON.parse(json) as Partial<VaultMeta>;
  return { name: typeof raw.name === "string" && raw.name ? raw.name : "Vault" };
}
