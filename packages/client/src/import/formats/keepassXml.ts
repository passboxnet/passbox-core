/**
 * KeePass 2 XML export (KeePass 2.x "KeePass XML (2.x)", KeePassXC "XML").
 * The file is unencrypted. Groups become tags, the recycle bin is skipped,
 * custom strings become fields, history entries become the password
 * history and KeePassXC passkeys (KPEX_PASSKEY_*) are imported.
 */
import type { Passkey, PasswordHistoryEntry } from "../../items";
import { buildLogin, clean, type ExtraField } from "../build";
import { ImportError, type ImportedItem, WarningCollector } from "../types";
import { child, children, childText, parseXml, type XmlElement, XmlError } from "../xml";
import { makePasskey, pemToBase64url, toBase64url } from "./passkeys";

const STANDARD = new Set(["Title", "UserName", "Password", "URL", "Notes"]);
const TOTP_KEYS = ["otp", "TimeOtp-Secret-Base32", "TOTP Seed"];
const OTP_SETTINGS = new Set([
  "TOTP Settings",
  "TimeOtp-Length",
  "TimeOtp-Period",
  "TimeOtp-Algorithm",
  "TimeOtp-Secret",
  "TimeOtp-Secret-Hex",
  "TimeOtp-Secret-Base64",
]);
const PASSKEY_PREFIX = "KPEX_PASSKEY_";

export function isKeePassXml(text: string): boolean {
  return /<KeePassFile[\s>]/.test(text.slice(0, 4096));
}

function strings(entry: XmlElement): Map<string, { value: string; protected: boolean }> {
  const map = new Map<string, { value: string; protected: boolean }>();
  for (const item of children(entry, "String")) {
    const key = childText(item, "Key");
    const valueElement = child(item, "Value");
    if (!key) continue;
    map.set(key, {
      value: valueElement?.text ?? "",
      protected: valueElement?.attributes.Protected === "True" || valueElement?.attributes.ProtectInMemory === "True",
    });
  }
  return map;
}

export function parseKeePassXml(text: string): { items: ImportedItem[]; warnings: WarningCollector } {
  let doc: XmlElement;
  try {
    doc = parseXml(text);
  } catch (error) {
    throw new ImportError(
      "invalid_file",
      `The KeePass XML file could not be read: ${error instanceof XmlError ? error.message : String(error)}`,
    );
  }
  if (doc.name !== "KeePassFile") throw new ImportError("invalid_file", "This is not a KeePass XML file.");
  const meta = child(doc, "Meta");
  const recycleBin = meta && childText(meta, "RecycleBinEnabled") !== "False" ? childText(meta, "RecycleBinUUID") : "";
  const root = child(doc, "Root");
  const warnings = new WarningCollector();
  const items: ImportedItem[] = [];
  // The top group is the database itself; its name is not a folder.
  for (const top of root ? children(root, "Group") : []) walk(top, [], true);

  function walk(group: XmlElement, path: string[], isTop: boolean) {
    const uuid = childText(group, "UUID");
    const name = childText(group, "Name").trim();
    const inBin = recycleBin !== "" && uuid === recycleBin && recycleBin !== "AAAAAAAAAAAAAAAAAAAAAA==";
    const groupPath = isTop || !name ? path : [...path, name];
    for (const entry of children(group, "Entry")) {
      if (inBin) {
        warnings.add("trashed_skipped", strings(entry).get("Title")?.value ?? "");
        continue;
      }
      const item = convertEntry(entry, groupPath, warnings);
      if (item) items.push({ data: item });
    }
    for (const sub of children(group, "Group")) {
      if (inBin) {
        countBin(sub);
        continue;
      }
      walk(sub, groupPath, false);
    }
  }

  function countBin(group: XmlElement) {
    for (const entry of children(group, "Entry"))
      warnings.add("trashed_skipped", strings(entry).get("Title")?.value ?? "");
    for (const sub of children(group, "Group")) countBin(sub);
  }

  return { items, warnings };
}

function convertEntry(entry: XmlElement, groupPath: string[], warnings: WarningCollector) {
  const values = strings(entry);
  const get = (key: string) => values.get(key)?.value ?? "";
  const title = get("Title");
  let totp: string | undefined;
  for (const key of TOTP_KEYS) {
    if (!totp && clean(get(key))) totp = get(key);
  }
  const fields: ExtraField[] = [];
  const passkeyValues = new Map<string, string>();
  for (const [key, { value, protected: isProtected }] of values) {
    if (STANDARD.has(key) || TOTP_KEYS.includes(key) || OTP_SETTINGS.has(key)) continue;
    if (key.startsWith(PASSKEY_PREFIX)) {
      passkeyValues.set(key.slice(PASSKEY_PREFIX.length), value);
      continue;
    }
    fields.push({ label: key, value, type: isProtected ? "concealed" : "text" });
  }
  const passkeys: Passkey[] = [];
  if (passkeyValues.size > 0) {
    const passkey = makePasskey({
      credentialId: toBase64url(passkeyValues.get("CREDENTIAL_ID") ?? ""),
      privateKey: pemToBase64url(passkeyValues.get("PRIVATE_KEY_PEM") ?? ""),
      rpId: clean(passkeyValues.get("RELYING_PARTY")),
      userHandle: passkeyValues.get("USER_HANDLE") ?? "",
      userName: passkeyValues.get("USERNAME") ?? "",
    });
    if (passkey) {
      passkeys.push(passkey);
      warnings.add("passkeys_imported", title);
    } else {
      warnings.add("passkeys_not_exported", title);
      for (const [key, value] of passkeyValues) fields.push({ label: PASSKEY_PREFIX + key, value, type: "concealed" });
    }
  }
  if (children(entry, "Binary").length > 0) warnings.add("attachments_not_imported", title);
  const tags = [groupPath.length > 0 ? groupPath.join("/") : undefined, ...childText(entry, "Tags").split(/[;,]/)];
  const password = get("Password");
  const history: PasswordHistoryEntry[] = [];
  const historyElement = child(entry, "History");
  for (const old of historyElement ? children(historyElement, "Entry") : []) {
    const value = strings(old).get("Password")?.value ?? "";
    const times = child(old, "Times");
    const when = Date.parse(times ? childText(times, "LastModificationTime") : "") || 0;
    if (value && value !== password && !history.some((h) => h.value === value))
      history.push({ value, replacedAt: when });
  }
  history.sort((a, b) => b.replacedAt - a.replacedAt);
  return buildLogin(
    {
      title,
      username: get("UserName"),
      password,
      urls: [get("URL")],
      notes: get("Notes"),
      totp,
      tags,
      fields,
      passkeys,
      passwordHistory: history.slice(0, 20),
    },
    warnings,
  );
}
