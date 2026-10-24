/**
 * Duplicate detection for imports. Two logins are duplicates when they have
 * the same normalized host and username (case-insensitive); other items when
 * category and title match.
 */
import { FIELD, type ItemData, type ItemField } from "../items";
import { hostOf } from "./build";
import type { ImportedItem } from "./types";

/** What to do with an imported item that already exists. */
export type DuplicateDecision = "skip" | "update" | "keep";

export function duplicateKey(data: ItemData): string | undefined {
  const value = (id: string) => data.fields.find((f) => f.id === id)?.value ?? "";
  if (data.category === "login") {
    const host = hostOf(value(FIELD.url));
    const username = value(FIELD.username).trim().toLowerCase();
    if (host) return `login\n${host}\n${username}`;
    if (!username && !data.title) return undefined;
    return `login-title\n${data.title.trim().toLowerCase()}\n${username}`;
  }
  const title = data.title.trim().toLowerCase();
  return title ? `${data.category}\n${title}` : undefined;
}

export interface DuplicateMatch {
  /** Index in the imported list. */
  index: number;
  /** ID of the existing item it matches. */
  existingId: string;
}

/**
 * Finds imported items that match existing items. Each imported item
 * matches at most one existing item (the first found).
 */
export function findDuplicates(
  imported: readonly ImportedItem[],
  existing: readonly { id: string; data: ItemData }[],
): DuplicateMatch[] {
  const index = new Map<string, string>();
  for (const item of existing) {
    if (item.data.trashedAt !== undefined) continue;
    const key = duplicateKey(item.data);
    if (key && !index.has(key)) index.set(key, item.id);
  }
  const matches: DuplicateMatch[] = [];
  imported.forEach((item, i) => {
    const key = duplicateKey(item.data);
    const existingId = key ? index.get(key) : undefined;
    if (existingId) matches.push({ index: i, existingId });
  });
  return matches;
}

/**
 * Merges an imported item into an existing one for the "update" decision:
 * imported values replace existing ones, new fields are added, tags and
 * passkeys are combined and different notes are appended. The password
 * history is kept by `PassboxClient.updateItem`.
 */
export function mergeItem(existing: ItemData, imported: ItemData): ItemData {
  const fields: ItemField[] = existing.fields.map((f) => ({ ...f }));
  const ids = new Set(fields.map((f) => f.id));
  for (const field of imported.fields) {
    if (!field.value) continue;
    const same = fields.find((f) => f.id === field.id && (!f.id.startsWith("custom_") || f.label === field.label));
    if (same) {
      same.value = field.value;
      continue;
    }
    if (fields.some((f) => f.label === field.label && f.value === field.value)) continue;
    let id = field.id;
    for (let n = 1; ids.has(id); n++) id = `custom_${n}`;
    ids.add(id);
    fields.push({ ...field, id });
  }
  const notes =
    !imported.notes || existing.notes.includes(imported.notes)
      ? existing.notes
      : existing.notes
        ? `${existing.notes}\n\n${imported.notes}`
        : imported.notes;
  const merged: ItemData = {
    ...existing,
    title: existing.title || imported.title,
    fields,
    notes,
    tags: [...new Set([...existing.tags, ...imported.tags])],
    favorite: existing.favorite || imported.favorite,
  };
  const passkeys = [...(existing.passkeys ?? [])];
  for (const passkey of imported.passkeys ?? []) {
    if (!passkeys.some((p) => p.credentialId === passkey.credentialId)) passkeys.push(passkey);
  }
  if (passkeys.length > 0) merged.passkeys = passkeys;
  return merged;
}
