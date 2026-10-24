/**
 * Proton Pass JSON export (`Proton Pass/data.json`, usually inside a ZIP).
 * Passkeys are exported in Proton's own format and cannot be imported.
 */
import { strFromU8, unzipSync } from "fflate";
import type { FieldType } from "../../items";
import { buildCard, buildIdentity, buildLogin, buildNote, buildOther, clean, type ExtraField } from "../build";
import { ImportError, type ImportedItem, WarningCollector } from "../types";

// biome-ignore lint/suspicious/noExplicitAny: external JSON is checked field by field
type Json = any;

const s = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");

const IDENTITY_EXTRAS: Record<string, string> = {
  secondPhoneNumber: "Second phone",
  workPhoneNumber: "Work phone",
  workEmail: "Work email",
  personalWebsite: "Personal website",
  xHandle: "X",
  linkedin: "LinkedIn",
  facebook: "Facebook",
  instagram: "Instagram",
  reddit: "Reddit",
  yahoo: "Yahoo",
  floor: "Floor",
  county: "County",
};

export function isProtonPassJson(value: Json): boolean {
  return typeof value === "object" && value !== null && typeof value.vaults === "object" && "userId" in value;
}

/** Reads data.json from a Proton Pass ZIP export. */
export function readProtonPassZip(bytes: Uint8Array): Json {
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(bytes, { filter: (file) => file.name.endsWith("data.json") });
  } catch {
    throw new ImportError("invalid_file", "The ZIP file could not be opened.");
  }
  const [data] = Object.values(files);
  if (!data) throw new ImportError("invalid_file", "The ZIP file does not contain a Proton Pass data.json.");
  try {
    return JSON.parse(strFromU8(data));
  } catch {
    throw new ImportError("invalid_file", "The Proton Pass file is damaged.");
  }
}

function extraFields(list: Json): ExtraField[] {
  return (Array.isArray(list) ? list : []).map((field: Json) => {
    const type: FieldType = field?.type === "hidden" ? "concealed" : field?.type === "totp" ? "totp" : "text";
    const value =
      field?.type === "totp"
        ? s(field?.data?.totpUri)
        : field?.type === "timestamp"
          ? s(field?.data?.timestamp)
          : s(field?.data?.content);
    return { label: s(field?.fieldName), value, type };
  });
}

function sections(content: Json): ExtraField[] {
  const out: ExtraField[] = [];
  for (const section of Array.isArray(content?.sections) ? content.sections : []) {
    out.push(...extraFields(section?.sectionFields));
  }
  for (const section of Array.isArray(content?.extraSections) ? content.extraSections : []) {
    out.push(...extraFields(section?.sectionFields));
  }
  return out;
}

export function parseProtonPassJson(value: Json): { items: ImportedItem[]; warnings: WarningCollector } {
  if (value.encrypted === true) {
    throw new ImportError(
      "encrypted_export",
      "This Proton Pass export is encrypted with PGP. Export again without encryption.",
    );
  }
  const warnings = new WarningCollector();
  const items: ImportedItem[] = [];
  for (const vault of Object.values(value.vaults ?? {}) as Json[]) {
    const vaultName = clean(vault?.name);
    for (const item of Array.isArray(vault?.items) ? vault.items : []) {
      const data = item?.data;
      if (!data) continue;
      const title = s(data.metadata?.name);
      if (item.state === 2) {
        warnings.add("trashed_skipped", title);
        continue;
      }
      if (Array.isArray(item.files) && item.files.length > 0) warnings.add("attachments_not_imported", title);
      const content = data.content ?? {};
      const base = {
        title,
        notes: s(data.metadata?.note),
        favorite: item.pinned === true,
        fields: extraFields(data.extraFields),
      };
      let built: ReturnType<typeof buildNote>;
      switch (data.type) {
        case "login":
        case "alias": {
          const email = clean(content.itemEmail) ?? clean(item.aliasEmail);
          const username = clean(content.itemUsername) ?? clean(content.username);
          if (Array.isArray(content.passkeys) && content.passkeys.length > 0)
            warnings.add("passkeys_not_exported", title);
          const fields = [...base.fields];
          if (email && username && email !== username) fields.unshift({ label: "Email", value: email, type: "email" });
          built = buildLogin(
            {
              ...base,
              fields,
              username: username ?? email,
              password: s(content.password),
              urls: Array.isArray(content.urls) ? content.urls.map(s) : [],
              totp: s(content.totpUri),
              tags: data.type === "alias" ? ["Alias"] : [],
            },
            warnings,
          );
          break;
        }
        case "note":
          built = buildNote(base);
          break;
        case "creditCard":
          built = buildCard({
            ...base,
            cardholder: s(content.cardholderName),
            number: s(content.number),
            code: s(content.verificationNumber),
            expiry: s(content.expirationDate),
            pin: s(content.pin),
          });
          break;
        case "identity":
          built = buildIdentity({
            ...base,
            fields: [
              ...base.fields,
              ...extraFields(content.extraPersonalDetails),
              ...extraFields(content.extraAddressDetails),
              ...extraFields(content.extraContactDetails),
              ...extraFields(content.extraWorkDetails),
              ...sections(content),
              ...Object.entries(IDENTITY_EXTRAS)
                .filter(([k]) => clean(content[k]))
                .map(([k, label]) => ({ label, value: s(content[k]) })),
            ],
            identity: {
              full_name: s(content.fullName),
              first_name: s(content.firstName),
              middle_name: s(content.middleName),
              last_name: s(content.lastName),
              birth_date: s(content.birthdate),
              gender: s(content.gender),
              email: s(content.email),
              phone: s(content.phoneNumber),
              company: s(content.company) || s(content.organization),
              job_title: s(content.jobTitle),
              address: s(content.streetAddress),
              postal_code: s(content.zipOrPostalCode),
              city: s(content.city),
              state: s(content.stateOrProvince),
              country: s(content.countryOrRegion),
              website: s(content.website),
              ssn: s(content.socialSecurityNumber),
              passport_number: s(content.passportNumber),
              license_number: s(content.licenseNumber),
            },
          });
          break;
        case "wifi":
          built = buildOther({
            ...base,
            tags: ["Wi-Fi"],
            fields: [
              { label: "Network name", value: s(content.ssid) },
              { label: "Password", value: s(content.password), type: "concealed" },
              ...base.fields,
              ...sections(content),
            ],
          });
          break;
        case "sshKey":
          warnings.add("converted_to_other", title);
          built = buildOther({
            ...base,
            tags: ["SSH key"],
            fields: [
              { label: "Private key", value: s(content.privateKey), type: "concealed" },
              { label: "Public key", value: s(content.publicKey) },
              { label: "Fingerprint", value: s(content.fingerprint) },
              ...base.fields,
              ...sections(content),
            ],
          });
          break;
        default:
          built = buildOther({ ...base, fields: [...base.fields, ...sections(content)] });
      }
      items.push(vaultName ? { data: built, sourceVault: vaultName } : { data: built });
    }
  }
  return { items, warnings };
}
