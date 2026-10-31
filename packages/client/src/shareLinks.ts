/**
 * Share links for people without an account: the snapshot format and
 * opening a link on the public viewer page (no session, no keyring).
 * Cryptography is in `passbox_core::share_link` (WebAssembly).
 */
import { ApiError, type PassboxApi, type ShareLinkRecord } from "@passbox/api-client";
import type * as Core from "@passbox/core-wasm";
import { categoryName, type ItemData } from "./items";

/** What a share link shows: a copy of an item (or free text) at the time of sharing. */
export interface ShareSnapshot {
  v: 1;
  title: string;
  /** Item category name, or `text` for free text. */
  category: string;
  fields: { label: string; type: string; value: string; format?: string }[];
  notes: string;
  /** Unix milliseconds. */
  createdAt: number;
}

/** A share link of this account with its decrypted label. */
export interface ShareLink extends ShareLinkRecord {
  label: string;
}

/** `{base}/s/{id}#{key}`: the key never reaches the server. */
export function shareLinkUrl(linkBase: string, id: string, key: string): string {
  return `${linkBase.replace(/\/+$/, "")}/s/${encodeURIComponent(id)}#${key}`;
}

/**
 * A snapshot of an item for a link. `fieldIds` picks the fields to include
 * (all non-empty fields when omitted); passkeys, password history,
 * attachments and one-time password secrets are never included.
 */
export function shareSnapshot(
  item: { data: ItemData },
  options: {
    fieldIds?: readonly string[];
    includeNotes?: boolean;
    labels?: (id: string, label: string) => string;
  } = {},
): ShareSnapshot {
  const fields = item.data.fields
    .filter((f) => f.value && f.type !== "totp")
    .filter((f) => !options.fieldIds || options.fieldIds.includes(f.id))
    .map((f) => ({
      label: options.labels ? options.labels(f.id, f.label) : f.label,
      type: f.type,
      value: f.value,
      ...(f.format ? { format: f.format } : {}),
    }));
  return {
    v: 1,
    title: item.data.title,
    category: categoryName(item.data),
    fields,
    notes: options.includeNotes === false ? "" : item.data.notes,
    createdAt: Date.now(),
  };
}

/** A free-text snapshot. */
export function textSnapshot(title: string, text: string): ShareSnapshot {
  return { v: 1, title, category: "text", fields: [], notes: text, createdAt: Date.now() };
}

function parseSnapshot(json: string): ShareSnapshot {
  const raw = JSON.parse(json) as Partial<ShareSnapshot>;
  if (raw.v !== 1) throw new Error("unsupported share link");
  return {
    v: 1,
    title: typeof raw.title === "string" ? raw.title : "",
    category: typeof raw.category === "string" ? raw.category : "other",
    fields: Array.isArray(raw.fields)
      ? raw.fields
          .filter((f) => typeof f?.label === "string" && typeof f?.value === "string")
          .map((f) => ({
            label: f.label,
            type: typeof f.type === "string" ? f.type : "text",
            value: f.value,
            ...(typeof f.format === "string" ? { format: f.format } : {}),
          }))
      : [],
    notes: typeof raw.notes === "string" ? raw.notes : "",
    createdAt: typeof raw.createdAt === "number" ? raw.createdAt : 0,
  };
}

export type ShareLinkState =
  | { status: "ready"; needsPassphrase: boolean; expiresAt: number; viewsLeft: number | null }
  | { status: "gone" };

/** What the viewer needs before opening (does not count a view). */
export async function shareLinkInfo(api: PassboxApi, id: string): Promise<ShareLinkState> {
  try {
    const info = await api.comfort.publicShareLink(id);
    return {
      status: "ready",
      needsPassphrase: info.salt !== null,
      expiresAt: info.expiresAt,
      viewsLeft: info.viewsLeft,
    };
  } catch (error) {
    if (error instanceof ApiError && (error.status === 404 || error.status === 400)) return { status: "gone" };
    throw error;
  }
}

export class WrongPassphraseError extends Error {
  constructor() {
    super("The passphrase is not correct.");
    this.name = "WrongPassphraseError";
  }
}

/**
 * Opens a link: derives the access token (and key) here, fetches the
 * encrypted snapshot (which counts a view) and decrypts it.
 */
export async function openShareLink(
  api: PassboxApi,
  core: Pick<typeof Core, "shareLinkAuthToken" | "shareLinkOpen">,
  id: string,
  key: string,
  passphrase?: string,
): Promise<{ snapshot: ShareSnapshot; viewsLeft: number | null; expiresAt: number }> {
  const info = await api.comfort.publicShareLink(id);
  const salt = info.salt ?? undefined;
  const secret = salt ? passphrase : undefined;
  const auth = core.shareLinkAuthToken(id, key, secret, salt);
  let opened: Awaited<ReturnType<PassboxApi["comfort"]["openShareLink"]>>;
  try {
    opened = await api.comfort.openShareLink(id, auth);
  } catch (error) {
    if (error instanceof ApiError && error.code === "wrong_passphrase") throw new WrongPassphraseError();
    throw error;
  }
  const json = core.shareLinkOpen(id, key, secret, salt, opened.blob);
  return { snapshot: parseSnapshot(json), viewsLeft: opened.viewsLeft, expiresAt: opened.expiresAt };
}
