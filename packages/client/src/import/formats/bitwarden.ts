/**
 * Bitwarden JSON export (unencrypted, personal or organization). Types:
 * 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key.
 */
import type { FieldType, Passkey, PasswordHistoryEntry } from "../../items";
import {
  appendNotes,
  buildCard,
  buildIdentity,
  buildLogin,
  buildNote,
  buildOther,
  clean,
  type ExtraField,
  folderTag,
} from "../build";
import { ImportError, type ImportedItem, WarningCollector } from "../types";
import { bitwardenCredentialId, makePasskey, toBase64url } from "./passkeys";

// biome-ignore lint/suspicious/noExplicitAny: external JSON is checked field by field
type Json = any;

const s = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");

export function isBitwardenJson(value: Json): boolean {
  return typeof value === "object" && value !== null && Array.isArray(value.items) && "encrypted" in value;
}

export function parseBitwardenJson(value: Json): { items: ImportedItem[]; warnings: WarningCollector } {
  if (value.encrypted === true) {
    throw new ImportError(
      "encrypted_export",
      'This Bitwarden export is encrypted. Export again with the format "JSON" (not "JSON (Encrypted)").',
    );
  }
  const warnings = new WarningCollector();
  const folders = new Map<string, string>();
  for (const folder of [...(value.folders ?? []), ...(value.collections ?? [])]) {
    if (folder?.id) folders.set(folder.id, s(folder.name));
  }
  const items: ImportedItem[] = [];
  for (const item of value.items as Json[]) {
    if (!item || typeof item !== "object") continue;
    const title = s(item.name);
    if (item.deletedDate) {
      warnings.add("trashed_skipped", title);
      continue;
    }
    const tags = [
      folderTag(folders.get(item.folderId)),
      ...(Array.isArray(item.collectionIds) ? item.collectionIds.map((id: string) => folderTag(folders.get(id))) : []),
    ];
    const fields: ExtraField[] = [];
    for (const field of Array.isArray(item.fields) ? item.fields : []) {
      // 0 text, 1 hidden, 2 boolean, 3 linked (points at another field; nothing to keep).
      if (field?.type === 3) continue;
      const type: FieldType = field?.type === 1 ? "concealed" : "text";
      fields.push({ label: s(field?.name), value: s(field?.value), type });
    }
    if (Array.isArray(item.attachments) && item.attachments.length > 0) warnings.add("attachments_not_imported", title);
    const passwordHistory: PasswordHistoryEntry[] = (Array.isArray(item.passwordHistory) ? item.passwordHistory : [])
      .filter((h: Json) => typeof h?.password === "string")
      .map((h: Json) => ({ value: h.password, replacedAt: Date.parse(h.lastUsedDate) || 0 }));
    const base = { title, notes: s(item.notes), tags, favorite: item.favorite === true, fields, passwordHistory };
    switch (item.type) {
      case 1: {
        const login = item.login ?? {};
        const passkeys = bitwardenPasskeys(login.fido2Credentials, warnings, title);
        const data = buildLogin(
          {
            ...base,
            username: s(login.username),
            password: s(login.password),
            totp: s(login.totp),
            urls: (Array.isArray(login.uris) ? login.uris : []).map((u: Json) => s(u?.uri)),
            passkeys,
          },
          warnings,
        );
        items.push({ data });
        break;
      }
      case 2:
        items.push({ data: buildNote(base) });
        break;
      case 3: {
        const card = item.card ?? {};
        items.push({
          data: buildCard({
            ...base,
            cardholder: s(card.cardholderName),
            number: s(card.number),
            code: s(card.code),
            brand: s(card.brand),
            expMonth: s(card.expMonth),
            expYear: s(card.expYear),
          }),
        });
        break;
      }
      case 4: {
        const id = item.identity ?? {};
        items.push({
          data: buildIdentity({
            ...base,
            identity: {
              title: s(id.title),
              first_name: s(id.firstName),
              middle_name: s(id.middleName),
              last_name: s(id.lastName),
              company: s(id.company),
              email: s(id.email),
              phone: s(id.phone),
              username: s(id.username),
              address: [id.address1, id.address2, id.address3].map(s).filter(Boolean).join("\n"),
              city: s(id.city),
              state: s(id.state),
              postal_code: s(id.postalCode),
              country: s(id.country),
              ssn: s(id.ssn),
              passport_number: s(id.passportNumber),
              license_number: s(id.licenseNumber),
            },
          }),
        });
        break;
      }
      case 5: {
        const key = item.sshKey ?? {};
        warnings.add("converted_to_other", title);
        items.push({
          data: buildOther({
            ...base,
            fields: [
              { label: "Private key", value: s(key.privateKey), type: "concealed" },
              { label: "Public key", value: s(key.publicKey) },
              { label: "Fingerprint", value: s(key.keyFingerprint) },
              ...fields,
            ],
          }),
        });
        break;
      }
      default:
        warnings.add("converted_to_other", title);
        items.push({ data: buildOther({ ...base, notes: appendNotes(base.notes, [JSON.stringify(item, null, 2)]) }) });
    }
  }
  return { items, warnings };
}

function bitwardenPasskeys(raw: Json, warnings: WarningCollector, title: string): Passkey[] {
  if (!Array.isArray(raw) || raw.length === 0) return [];
  const passkeys: Passkey[] = [];
  for (const credential of raw) {
    const usable =
      s(credential?.keyType || "public-key") === "public-key" &&
      s(credential?.keyAlgorithm || "ECDSA") === "ECDSA" &&
      s(credential?.keyCurve || "P-256") === "P-256";
    const passkey = usable
      ? makePasskey({
          credentialId: bitwardenCredentialId(s(credential.credentialId)),
          privateKey: toBase64url(s(credential.keyValue)),
          rpId: clean(credential.rpId),
          rpName: s(credential.rpName),
          userHandle: s(credential.userHandle),
          userName: s(credential.userName),
          userDisplayName: s(credential.userDisplayName),
          signCount: Number(credential.counter) || 0,
          createdAt: Date.parse(s(credential.creationDate)),
        })
      : undefined;
    if (passkey) passkeys.push(passkey);
    else warnings.add("passkeys_not_exported", title);
  }
  if (passkeys.length > 0) warnings.add("passkeys_imported", title, passkeys.length);
  return passkeys;
}
