/**
 * Parsers for the CSV exports of browsers and password managers. Each one
 * reads records keyed by header name. Columns a parser does not know are
 * kept as text fields, so no data is lost.
 */
import type { ItemData } from "../../items";
import {
  appendNotes,
  buildCard,
  buildIdentity,
  buildLogin,
  buildNote,
  clean,
  type ExtraField,
  folderTag,
  isEmptyItem,
  isTrue,
} from "../build";
import { type CsvTable, toRecords } from "../csv";
import type { ImportedItem, ImportFormat } from "../types";
import { WarningCollector } from "../types";

type Row = Record<string, string>;

export interface CsvFormat {
  id: ImportFormat;
  /** Whether the (trimmed, lower-cased) headers belong to this format. */
  matches(headers: readonly string[]): boolean;
  parse(rows: Row[], warnings: WarningCollector): ImportedItem[];
}

const lower = (headers: readonly string[]) => headers.map((h) => h.trim().toLowerCase());
const hasAll = (headers: readonly string[], required: readonly string[]) => {
  const set = new Set(lower(headers));
  return required.every((h) => set.has(h));
};
const startsWith = (headers: readonly string[], prefix: readonly string[]) => {
  const l = lower(headers);
  return prefix.every((h, i) => l[i] === h);
};

/** Case-insensitive access to a record. */
function getter(row: Row) {
  const map = new Map<string, string>();
  for (const [key, value] of Object.entries(row)) {
    const k = key.trim().toLowerCase();
    if (!map.has(k)) map.set(k, value);
  }
  return (name: string) => map.get(name.toLowerCase()) ?? "";
}

/** Values of columns not listed in `known`, as text fields. */
function leftovers(row: Row, known: readonly string[]): ExtraField[] {
  const k = new Set(known.map((h) => h.toLowerCase()));
  return Object.entries(row)
    .filter(([header, value]) => header.trim() !== "" && !k.has(header.trim().toLowerCase()) && value.trim() !== "")
    .map(([header, value]) => ({ label: header.trim(), value }));
}

function keep(items: ImportedItem[], data: ItemData, warnings: WarningCollector, sourceVault?: string) {
  if (isEmptyItem(data)) {
    warnings.add("empty_skipped", "");
    return;
  }
  items.push(sourceVault ? { data, sourceVault } : { data });
}

// --- Browsers ------------------------------------------------------------------

/** Chrome, Edge, Brave, Opera, Vivaldi: name,url,username,password[,note]. */
export const chromeCsv: CsvFormat = {
  id: "chrome-csv",
  matches: (h) => hasAll(h, ["name", "url", "username", "password"]) && lower(h).length <= 6,
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    const known = ["name", "url", "username", "password", "note"];
    for (const row of rows) {
      const get = getter(row);
      const data = buildLogin(
        {
          title: get("name"),
          urls: [get("url")],
          username: get("username"),
          password: get("password"),
          notes: get("note"),
          fields: leftovers(row, known),
        },
        warnings,
      );
      keep(items, data, warnings);
    }
    return items;
  },
};

/** Firefox: url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged. */
export const firefoxCsv: CsvFormat = {
  id: "firefox-csv",
  matches: (h) => hasAll(h, ["url", "username", "password", "httprealm", "formactionorigin"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    // Sync bookkeeping without meaning in Passbox.
    const known = [
      "url",
      "username",
      "password",
      "httpRealm",
      "formActionOrigin",
      "guid",
      "timeCreated",
      "timeLastUsed",
      "timePasswordChanged",
    ];
    for (const row of rows) {
      const get = getter(row);
      const url = get("url");
      // Firefox stores logins from Chrome-style imports under "chrome://FirefoxAccounts" and similar.
      if (/^chrome:\/\//i.test(url)) continue;
      const fields: ExtraField[] = [];
      const realm = clean(get("httpRealm"));
      if (realm) fields.push({ label: "HTTP realm", value: realm });
      const form = clean(get("formActionOrigin"));
      if (form && form !== url && form !== ".") fields.push({ label: "Form address", value: form, type: "url" });
      fields.push(...leftovers(row, known));
      const data = buildLogin({ urls: [url], username: get("username"), password: get("password"), fields }, warnings);
      keep(items, data, warnings);
    }
    return items;
  },
};

/** Safari and the Apple Passwords app: Title,URL,Username,Password,Notes,OTPAuth. */
export const safariCsv: CsvFormat = {
  id: "safari-csv",
  matches: (h) => hasAll(h, ["title", "url", "username", "password", "otpauth"]) && !hasAll(h, ["favorite"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    const known = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"];
    for (const row of rows) {
      const get = getter(row);
      const data = buildLogin(
        {
          title: get("Title"),
          urls: [get("URL")],
          username: get("Username"),
          password: get("Password"),
          notes: get("Notes"),
          totp: get("OTPAuth"),
          fields: leftovers(row, known),
        },
        warnings,
      );
      keep(items, data, warnings);
    }
    return items;
  },
};

// --- Password managers -----------------------------------------------------------

/** "name: value" lines of Bitwarden's `fields` column. */
function bitwardenFields(value: string): ExtraField[] {
  return value
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line) => {
      const i = line.indexOf(": ");
      return i === -1 ? { label: "Field", value: line } : { label: line.slice(0, i), value: line.slice(i + 2) };
    });
}

/**
 * Bitwarden: folder,favorite,type,name,notes,fields,reprompt,login_uri,
 * login_username,login_password,login_totp (organization exports have
 * `collections` instead of `folder`).
 */
export const bitwardenCsv: CsvFormat = {
  id: "bitwarden-csv",
  matches: (h) => hasAll(h, ["type", "name", "login_uri", "login_username", "login_password"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    const known = [
      "folder",
      "collections",
      "favorite",
      "type",
      "name",
      "notes",
      "fields",
      "reprompt",
      "login_uri",
      "login_username",
      "login_password",
      "login_totp",
      "login_fido2Credentials",
    ];
    for (const row of rows) {
      const get = getter(row);
      const tags = [folderTag(get("folder")), ...get("collections").split(",").map(folderTag)];
      const base = {
        title: get("name"),
        notes: get("notes"),
        tags,
        favorite: isTrue(get("favorite")),
        fields: [...bitwardenFields(get("fields")), ...leftovers(row, known)],
      };
      const type = get("type").trim().toLowerCase();
      const data =
        type === "note"
          ? buildNote(base)
          : buildLogin(
              {
                ...base,
                urls: get("login_uri").split(/,|\r?\n/),
                username: get("login_username"),
                password: get("login_password"),
                totp: get("login_totp"),
              },
              warnings,
            );
      if (clean(get("login_fido2Credentials"))) warnings.add("passkeys_not_exported", data.title);
      keep(items, data, warnings);
    }
    return items;
  },
};

const ONEPASSWORD_CATEGORIES = new Set([
  "login",
  "password",
  "secure note",
  "credit card",
  "identity",
  "server",
  "database",
  "software license",
  "wireless router",
  "email account",
  "api credential",
  "bank account",
]);

/**
 * 1Password 8: Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes.
 * Also reads 1Password 7 CSV files with a Type column.
 */
export const onePasswordCsv: CsvFormat = {
  id: "1password-csv",
  matches: (h) =>
    hasAll(h, ["title", "url", "username", "password"]) &&
    (hasAll(h, ["otpauth", "favorite"]) || hasAll(h, ["archived"]) || hasAll(h, ["tags", "notes"])),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    const known = ["Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Archived", "Tags", "Notes", "Type"];
    for (const row of rows) {
      const get = getter(row);
      const tags = get("Tags")
        .split(/[;,]/)
        .map((t) => t.trim());
      if (isTrue(get("Archived"))) tags.push("Archived");
      const type = clean(get("Type"));
      const fields = leftovers(row, known);
      if (type && !ONEPASSWORD_CATEGORIES.has(type.toLowerCase())) tags.push(folderTag(type) ?? "");
      const input = {
        title: get("Title"),
        urls: [get("Url")],
        username: get("Username"),
        password: get("Password"),
        totp: get("OTPAuth"),
        notes: get("Notes"),
        favorite: isTrue(get("Favorite")),
        tags,
        fields,
      };
      const isNote = type?.toLowerCase() === "secure note" && !clean(input.password) && !clean(input.username);
      keep(items, isNote ? buildNote(input) : buildLogin(input, warnings), warnings);
    }
    return items;
  },
};

/**
 * KeePassXC: Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created.
 * KeePass 2: Account,Login Name,Password,Web Site,Comments (and the
 * Title,User Name,Password,URL,Notes variant of the generic CSV export).
 */
export const keepassCsv: CsvFormat = {
  id: "keepass-csv",
  matches: (h) =>
    (hasAll(h, ["group", "title", "username", "password", "url"]) && startsWith(h, ["group"])) ||
    hasAll(h, ["account", "login name", "password", "web site"]) ||
    hasAll(h, ["title", "user name", "password", "url"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    const known = [
      "Group",
      "Title",
      "Username",
      "User Name",
      "Password",
      "URL",
      "Notes",
      "TOTP",
      "Icon",
      "Last Modified",
      "Created",
      "Account",
      "Login Name",
      "Web Site",
      "Comments",
    ];
    for (const row of rows) {
      const get = getter(row);
      const group = keepassGroup(get("Group"));
      const data = buildLogin(
        {
          title: get("Title") || get("Account"),
          username: get("Username") || get("User Name") || get("Login Name"),
          password: get("Password"),
          urls: [get("URL") || get("Web Site")],
          notes: get("Notes") || get("Comments"),
          totp: get("TOTP"),
          tags: [group],
          fields: leftovers(row, known),
        },
        warnings,
      );
      if (/^(recycle bin|papierkorb)(\/|$)/i.test(group ?? "")) {
        warnings.add("trashed_skipped", data.title);
        continue;
      }
      keep(items, data, warnings);
    }
    return items;
  },
};

/** Drops KeePass's root group name ("Root", "Passwords", the database name stays). */
function keepassGroup(value: string): string | undefined {
  const tag = folderTag(value);
  if (!tag) return undefined;
  const parts = tag.split("/");
  if (parts.length > 1 && /^(root|passwords|passwörter)$/i.test(parts[0] as string)) parts.shift();
  else if (parts.length === 1 && /^(root|passwords|passwörter)$/i.test(parts[0] as string)) return undefined;
  return parts.join("/");
}

/** LastPass: url,username,password,totp,extra,name,grouping,fav. */
export const lastPassCsv: CsvFormat = {
  id: "lastpass-csv",
  matches: (h) => hasAll(h, ["url", "username", "password", "extra", "name", "grouping"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    const known = ["url", "username", "password", "totp", "extra", "name", "grouping", "fav"];
    for (const row of rows) {
      const get = getter(row);
      const base = {
        title: get("name"),
        tags: [folderTag(get("grouping"))],
        favorite: isTrue(get("fav")),
        fields: leftovers(row, known),
      };
      const extra = get("extra");
      if (get("url").trim() === "http://sn") {
        keep(items, lastPassNote(base, extra), warnings);
        continue;
      }
      const data = buildLogin(
        {
          ...base,
          urls: [get("url")],
          username: get("username"),
          password: get("password"),
          totp: get("totp"),
          notes: extra,
        },
        warnings,
      );
      keep(items, data, warnings);
    }
    return items;
  },
};

/** LastPass secure notes. Credit cards and addresses become cards and identities. */
function lastPassNote(
  base: { title: string; tags: (string | undefined)[]; favorite: boolean; fields: ExtraField[] },
  extra: string,
) {
  const lines = extra.split(/\r?\n/);
  const type = /^NoteType:(.*)$/.exec(lines[0] ?? "")?.[1]?.trim();
  if (!type) return buildNote({ ...base, notes: extra });
  const values = new Map<string, string>();
  let notes = "";
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i] as string;
    if (line.startsWith("Notes:")) {
      notes = [line.slice(6), ...lines.slice(i + 1)].join("\n");
      break;
    }
    const sep = line.indexOf(":");
    if (sep > 0) values.set(line.slice(0, sep), line.slice(sep + 1));
  }
  const take = (key: string) => {
    const value = values.get(key);
    values.delete(key);
    return value;
  };
  const rest = (): ExtraField[] =>
    [...values.entries()].filter(([k]) => k !== "Language").map(([label, value]) => ({ label, value }));
  if (type === "Credit Card") {
    const exp = take("Expiration Date")?.split(",");
    const months = [
      "january",
      "february",
      "march",
      "april",
      "may",
      "june",
      "july",
      "august",
      "september",
      "october",
      "november",
      "december",
    ];
    const monthIndex = months.indexOf((exp?.[0] ?? "").trim().toLowerCase());
    const card = {
      ...base,
      cardholder: take("Name on Card"),
      number: take("Number"),
      code: take("Security Code"),
      brand: take("Type"),
      expMonth: monthIndex >= 0 ? String(monthIndex + 1) : exp?.[0],
      expYear: exp?.[1],
      notes,
    };
    take("Start Date");
    return buildCard({ ...card, fields: [...base.fields, ...rest()] });
  }
  if (type === "Address") {
    const identity = {
      title: take("Title"),
      first_name: take("First Name"),
      middle_name: take("Middle Name"),
      last_name: take("Last Name"),
      company: take("Company"),
      address: [take("Address 1"), take("Address 2"), take("Address 3")].filter(Boolean).join("\n"),
      city: take("City / Town"),
      state: take("State") ?? take("County"),
      postal_code: take("Zip / Postal Code"),
      country: take("Country"),
      email: take("Email Address"),
      phone: take("Phone"),
      mobile: take("Mobile Phone"),
      username: take("Username"),
      birth_date: take("Birthday"),
      gender: take("Gender"),
    };
    return buildIdentity({ ...base, identity, notes, fields: [...base.fields, ...rest()] });
  }
  return buildNote({ ...base, notes: appendNotes(notes, [`Type: ${type}`]), fields: [...base.fields, ...rest()] });
}

/**
 * Dashlane credentials.csv: username,username2,username3,title,password,note,url,category,otpSecret|otpUrl.
 * Also reads securenotes.csv (title,note), payments.csv and personalInfo.csv.
 */
export const dashlaneCsv: CsvFormat = {
  id: "dashlane-csv",
  matches: (h) =>
    hasAll(h, ["username", "username2", "title", "password", "url"]) ||
    hasAll(h, ["account_holder", "cc_number", "expiration_month"]) ||
    hasAll(h, ["first_name", "last_name", "item_name", "address"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    for (const row of rows) {
      const get = getter(row);
      if ("cc_number" in lowerKeys(row)) {
        const known = [
          "type",
          "account_name",
          "account_holder",
          "cc_number",
          "code",
          "expiration_month",
          "expiration_year",
          "note",
        ];
        const isCard = get("type").toLowerCase().includes("card") || !!clean(get("cc_number"));
        if (isCard) {
          keep(
            items,
            buildCard({
              title: get("account_name"),
              cardholder: get("account_holder"),
              number: get("cc_number"),
              code: get("code"),
              expMonth: get("expiration_month"),
              expYear: get("expiration_year"),
              notes: get("note"),
              fields: leftovers(row, known),
            }),
            warnings,
          );
        } else {
          keep(
            items,
            buildNote({
              title: get("account_name"),
              notes: get("note"),
              fields: leftovers(row, ["account_name", "note"]),
            }),
            warnings,
          );
        }
        continue;
      }
      if ("item_name" in lowerKeys(row)) {
        const known = [
          "item_name",
          "title",
          "first_name",
          "middle_name",
          "last_name",
          "login",
          "date_of_birth",
          "email",
          "phone_number",
          "address",
          "zip",
          "city",
          "state",
          "country",
          "job_title",
          "url",
        ];
        keep(
          items,
          buildIdentity({
            title: get("item_name"),
            identity: {
              title: get("title"),
              first_name: get("first_name"),
              middle_name: get("middle_name"),
              last_name: get("last_name"),
              username: get("login"),
              birth_date: get("date_of_birth"),
              email: get("email"),
              phone: get("phone_number"),
              address: get("address"),
              postal_code: get("zip"),
              city: get("city"),
              state: get("state"),
              country: get("country"),
              job_title: get("job_title"),
              website: get("url"),
            },
            fields: leftovers(row, known),
          }),
          warnings,
        );
        continue;
      }
      const known = [
        "username",
        "username2",
        "username3",
        "title",
        "password",
        "note",
        "url",
        "category",
        "otpSecret",
        "otpUrl",
      ];
      const fields: ExtraField[] = [
        { label: "Alternative username", value: get("username2") },
        { label: "Alternative username", value: get("username3") },
        ...leftovers(row, known),
      ];
      const data = buildLogin(
        {
          title: get("title"),
          username: get("username"),
          password: get("password"),
          urls: [get("url")],
          notes: get("note"),
          totp: get("otpUrl") || get("otpSecret"),
          tags: [folderTag(get("category"))],
          fields,
        },
        warnings,
      );
      keep(items, data, warnings);
    }
    return items;
  },
};

/** Dashlane securenotes.csv: title,note (also category). */
export const dashlaneNotesCsv: CsvFormat = {
  id: "dashlane-csv",
  matches: (h) => lower(h).length <= 3 && hasAll(h, ["title", "note"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    for (const row of rows) {
      const get = getter(row);
      keep(
        items,
        buildNote({
          title: get("title"),
          notes: get("note"),
          tags: [folderTag(get("category"))],
          fields: leftovers(row, ["title", "note", "category"]),
        }),
        warnings,
      );
    }
    return items;
  },
};

function lowerKeys(row: Row): Record<string, true> {
  return Object.fromEntries(Object.keys(row).map((k) => [k.trim().toLowerCase(), true]));
}

/** Proton Pass: type,name,url,email,username,password,note,totp,createTime,modifyTime,vault. */
export const protonPassCsv: CsvFormat = {
  id: "protonpass-csv",
  matches: (h) => hasAll(h, ["type", "name", "url", "email", "username", "password", "note", "totp", "vault"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    const known = [
      "type",
      "name",
      "url",
      "email",
      "username",
      "password",
      "note",
      "totp",
      "createTime",
      "modifyTime",
      "vault",
    ];
    for (const row of rows) {
      const get = getter(row);
      const type = get("type").trim().toLowerCase();
      const vault = clean(get("vault"));
      const email = clean(get("email"));
      const username = clean(get("username"));
      const fields: ExtraField[] = [];
      if (email && username && email !== username) fields.push({ label: "Email", value: email, type: "email" });
      fields.push(...leftovers(row, known));
      const base = { title: get("name"), notes: get("note"), fields };
      let data: ItemData;
      if (type === "note") data = buildNote(base);
      else
        data = buildLogin(
          {
            ...base,
            urls: get("url").split(/,\s*/),
            username: username ?? email,
            password: get("password"),
            totp: get("totp"),
          },
          warnings,
        );
      if (type === "alias") data.tags.push("Alias");
      keep(items, data, warnings, vault);
    }
    return items;
  },
};

// --- Passbolt -----------------------------------------------------------------------

/**
 * Passbolt exports CSV in the column layout of other managers. Of these,
 * csv-kdbx (Title,Username,URL,Password,Notes,Group,TOTP), csv-1password
 * (Title,Username,Url,Password,Notes,Type — Type holds the folder) and
 * csv-bitwarden (name,login_username,login_uri,login_password,notes,folder,login_totp)
 * use a column order of their own; csv-lastpass, csv-chromium, csv-mozilla
 * and csv-safari match the original layouts and parse the same way.
 */
export const passboltCsv: CsvFormat = {
  id: "passbolt-csv",
  matches: (h) =>
    startsWith(h, ["title", "username", "url", "password", "notes", "group"]) ||
    (startsWith(h, ["title", "username", "url", "password", "notes", "type"]) && lower(h).length === 6) ||
    startsWith(h, ["name", "login_username", "login_uri", "login_password", "notes", "folder"]),
  parse(rows, warnings) {
    const items: ImportedItem[] = [];
    const known = [
      "Title",
      "name",
      "Username",
      "login_username",
      "URL",
      "login_uri",
      "Password",
      "login_password",
      "Notes",
      "Group",
      "Type",
      "folder",
      "TOTP",
      "login_totp",
    ];
    for (const row of rows) {
      const get = getter(row);
      const data = buildLogin(
        {
          title: get("Title") || get("name"),
          username: get("Username") || get("login_username"),
          urls: [get("URL") || get("login_uri")],
          password: get("Password") || get("login_password"),
          notes: get("Notes"),
          totp: get("TOTP") || get("login_totp"),
          tags: [folderTag(get("Group") || get("Type") || get("folder"))],
          fields: leftovers(row, known),
        },
        warnings,
      );
      keep(items, data, warnings);
    }
    return items;
  },
};

/** Every CSV layout, most specific first. */
export const CSV_FORMATS: readonly CsvFormat[] = [
  passboltCsv,
  protonPassCsv,
  bitwardenCsv,
  firefoxCsv,
  onePasswordCsv,
  safariCsv,
  keepassCsv,
  lastPassCsv,
  dashlaneCsv,
  chromeCsv,
  dashlaneNotesCsv,
];

/** For the formats the user picks explicitly: which layouts belong to them. */
export const CSV_FORMATS_BY_ID: Partial<Record<ImportFormat, readonly CsvFormat[]>> = {
  "chrome-csv": [chromeCsv],
  "firefox-csv": [firefoxCsv],
  "safari-csv": [safariCsv],
  "bitwarden-csv": [bitwardenCsv],
  "1password-csv": [onePasswordCsv],
  "keepass-csv": [keepassCsv],
  "lastpass-csv": [lastPassCsv],
  "dashlane-csv": [dashlaneCsv, dashlaneNotesCsv],
  "protonpass-csv": [protonPassCsv],
  "passbolt-csv": [
    passboltCsv,
    lastPassCsv,
    chromeCsv,
    firefoxCsv,
    safariCsv,
    bitwardenCsv,
    onePasswordCsv,
    keepassCsv,
    dashlaneCsv,
  ],
};

/** Finds the CSV layout of a table. */
export function detectCsvFormat(
  headers: readonly string[],
  candidates: readonly CsvFormat[] = CSV_FORMATS,
): CsvFormat | undefined {
  return candidates.find((format) => format.matches(headers));
}

export function parseCsvWith(
  format: CsvFormat,
  table: CsvTable,
  warnings = new WarningCollector(),
): { items: ImportedItem[]; warnings: WarningCollector } {
  return { items: format.parse(toRecords(table), warnings), warnings };
}
