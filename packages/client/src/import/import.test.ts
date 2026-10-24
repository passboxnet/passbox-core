import { readFileSync } from "node:fs";
import { join } from "node:path";
import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { FIELD, fieldValue, type ItemData, newItemData } from "../items";
import { formatExpiry, normalizeTotp, normalizeUrl } from "./build";
import { parseCsv, writeCsv } from "./csv";
import {
  decodeText,
  detectColumns,
  detectFormat,
  findDuplicates,
  ImportError,
  type ImportFile,
  type ImportResult,
  mappingProblem,
  mergeItem,
  parseImport,
  previewCsv,
} from "./index";
import { parseXml } from "./xml";

const fixtures = join(__dirname, "fixtures");
const read = (name: string) => new Uint8Array(readFileSync(join(fixtures, name)));
const file = (name: string): ImportFile => ({ name, bytes: read(name) });
const zip = (name: string, entries: Record<string, Uint8Array>): ImportFile => ({ name, bytes: zipSync(entries) });

function byTitle(result: ImportResult, title: string): ItemData {
  const item = result.items.find((i) => i.data.title === title)?.data;
  if (!item) throw new Error(`no item "${title}" in ${result.items.map((i) => i.data.title).join(", ")}`);
  return item;
}
const get = (item: ItemData, id: string) => fieldValue(item, id);
const extra = (item: ItemData, label: string) => item.fields.find((f) => f.label === label);
const warning = (result: ImportResult, code: string) => result.warnings.find((w) => w.code === code);

describe("CSV reader", () => {
  it("handles quotes, embedded delimiters, line breaks, CRLF and a BOM", () => {
    expect(parseCsv('﻿a,b,c\r\n"1,2","say ""hi""","x\ny"\r\n\r\nlast,,\n')).toEqual([
      ["a", "b", "c"],
      ["1,2", 'say "hi"', "x\ny"],
      ["last", "", ""],
    ]);
  });

  it("detects semicolon and tab delimiters", () => {
    expect(parseCsv("a;b\n1;2")).toEqual([
      ["a", "b"],
      ["1", "2"],
    ]);
    expect(parseCsv("a\tb\n1\t2")).toEqual([
      ["a", "b"],
      ["1", "2"],
    ]);
  });

  it("round-trips through the writer", () => {
    const rows = [
      ["name", "password"],
      ["x", ' "quoted", with\r\nbreak '],
    ];
    expect(parseCsv(writeCsv(rows))).toEqual(rows);
  });

  it("falls back to Windows-1252 for non-UTF-8 files", () => {
    expect(decodeText(new Uint8Array([0x47, 0x72, 0xfc, 0xdf, 0x65]))).toBe("Grüße");
    expect(decodeText(new TextEncoder().encode("Grüße"))).toBe("Grüße");
  });
});

describe("XML reader", () => {
  it("parses entities, CDATA and attributes and ignores the doctype", () => {
    const root = parseXml(
      '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><a k="1 &amp; 2"><b>&lt;&#65;&#x42;&gt;</b><c><![CDATA[<raw>&e;]]></c><d/></a>',
    );
    expect(root.attributes.k).toBe("1 & 2");
    expect(root.children.map((c) => c.name)).toEqual(["b", "c", "d"]);
    expect(root.children[0]?.text).toBe("<AB>");
    expect(root.children[1]?.text).toBe("<raw>&e;");
  });

  it("rejects malformed documents", () => {
    expect(() => parseXml("<a><b></a>")).toThrow();
    expect(() => parseXml("<a>")).toThrow();
  });
});

describe("helpers", () => {
  it("normalizes URLs", () => {
    expect(normalizeUrl("example.com")).toBe("https://example.com");
    expect(normalizeUrl("db01.example.internal:5432")).toBe("https://db01.example.internal:5432");
    expect(normalizeUrl("androidapp://com.example")).toBe("androidapp://com.example");
    expect(normalizeUrl("  ")).toBeUndefined();
    expect(normalizeUrl("not a url")).toBe("not a url");
  });

  it("normalizes one-time password secrets", () => {
    expect(normalizeTotp("jbsw y3dp ehpk 3pxp")).toBe("JBSWY3DPEHPK3PXP");
    expect(normalizeTotp("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP")).toBe("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP");
    expect(normalizeTotp("key=JBSWY3DPEHPK3PXP&step=30")).toBe("JBSWY3DPEHPK3PXP");
    expect(normalizeTotp("123456")).toBeUndefined();
    expect(normalizeTotp("otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=1")).toBeUndefined();
  });

  it("formats expiry dates", () => {
    expect(formatExpiry("2029-03")).toBe("03/2029");
    expect(formatExpiry("3/29")).toBe("03/2029");
    expect(formatExpiry(undefined, "7", "2027")).toBe("07/2027");
    expect(formatExpiry("11/2028")).toBe("11/2028");
  });
});

describe("format detection", () => {
  it.each([
    ["chrome.csv", "chrome-csv"],
    ["firefox.csv", "firefox-csv"],
    ["safari.csv", "safari-csv"],
    ["bitwarden.csv", "bitwarden-csv"],
    ["bitwarden.json", "bitwarden-json"],
    ["1password.csv", "1password-csv"],
    ["keepassxc.csv", "keepass-csv"],
    ["keepass2.csv", "keepass-csv"],
    ["keepass2.xml", "keepass-xml"],
    ["lastpass.csv", "lastpass-csv"],
    ["dashlane-credentials.csv", "dashlane-csv"],
    ["protonpass.csv", "protonpass-csv"],
    ["passbolt-kdbx.csv", "passbolt-csv"],
    ["passbolt-1password.csv", "passbolt-csv"],
    ["passbolt-bitwarden.csv", "passbolt-csv"],
    // Passbolt's LastPass layout is LastPass's own.
    ["passbolt-lastpass.csv", "lastpass-csv"],
    ["generic-de-excel.csv", "generic-csv"],
  ])("%s is %s", (name, format) => {
    expect(detectFormat(file(name))).toBe(format);
  });

  it("detects ZIP exports by their content", () => {
    expect(
      detectFormat(
        zip("export.1pux", { "export.data": read("1password-export.data.json"), "export.attributes": strToU8("{}") }),
      ),
    ).toBe("1password-1pux");
    expect(detectFormat(zip("proton.zip", { "Proton Pass/data.json": read("protonpass-data.json") }))).toBe(
      "protonpass-json",
    );
    expect(detectFormat(zip("dashlane.zip", { "credentials.csv": read("dashlane-credentials.csv") }))).toBe(
      "dashlane-zip",
    );
  });

  it("rejects unknown files", () => {
    expect(detectFormat({ name: "x.json", bytes: strToU8('{"hello":1}') })).toBeUndefined();
    expect(() => parseImport({ name: "x.txt", bytes: strToU8("just text") })).toThrow(ImportError);
  });
});

describe("browser exports", () => {
  it("imports Chrome/Edge CSV", () => {
    const result = parseImport(file("chrome.csv"));
    expect(result.items).toHaveLength(3);
    const login = byTitle(result, "example.com");
    expect(login.category).toBe("login");
    expect(get(login, FIELD.username)).toBe("alice@example.com");
    expect(get(login, FIELD.password)).toBe("Correct-Horse-7");
    expect(get(login, FIELD.url)).toBe("https://www.example.com/login");
    expect(get(byTitle(result, "Intranet"), FIELD.password)).toBe('pa,ss"word');
    expect(byTitle(result, "Intranet").notes).toBe("VPN required");
    expect(byTitle(result, "shop.example.net").notes).toBe("Line one\nLine two");
    expect(warning(result, "empty_skipped")?.count).toBe(1);
  });

  it("imports Firefox CSV and keeps the HTTP realm", () => {
    const result = parseImport(file("firefox.csv"));
    expect(result.items.map((i) => i.data.title)).toEqual(["accounts.example.com", "router.example.lan"]);
    const router = byTitle(result, "router.example.lan");
    expect(extra(router, "HTTP realm")?.value).toBe("Router Login");
    // Sync bookkeeping (guid, times) is not kept as fields.
    expect(router.fields.some((f) => f.label === "guid")).toBe(false);
  });

  it("imports Safari / Apple Passwords CSV with one-time passwords", () => {
    const result = parseImport(file("safari.csv"));
    const login = byTitle(result, "example.com (alice)");
    expect(get(login, FIELD.totp)).toMatch(/^otpauth:\/\/totp\//);
    expect(byTitle(result, "Bank").notes).toBe("Kundennummer 123");
  });
});

describe("Bitwarden", () => {
  it("imports JSON with folders, fields, cards, identities, history and passkeys", () => {
    const result = parseImport(file("bitwarden.json"));
    expect(result.items).toHaveLength(5);
    const login = byTitle(result, "Code hosting");
    expect(login.tags).toEqual(["Work"]);
    expect(login.favorite).toBe(true);
    expect(get(login, FIELD.totp)).toContain("otpauth://totp/");
    expect(login.fields.filter((f) => f.type === "url").map((f) => f.value)).toEqual([
      "https://code.example.com/login",
      "https://code.example.com/sso",
      "androidapp://com.example.code",
    ]);
    expect(extra(login, "Recovery code")).toMatchObject({ value: "abcd-efgh-ijkl", type: "concealed" });
    expect(extra(login, "Team")).toMatchObject({ value: "Platform", type: "text" });
    expect(login.passwordHistory?.[0]?.value).toBe("Old-GitHub-Pass");
    const [passkey] = login.passkeys ?? [];
    expect(passkey).toMatchObject({
      rpId: "code.example.com",
      userName: "kim@example.com",
      signCount: 7,
      algorithm: -7,
    });
    // GUID credential IDs are the 16 raw bytes.
    expect(Buffer.from(passkey?.credentialId ?? "", "base64url").toString("hex")).toBe(
      "4d5b6f721c2a4e0b9c337f1e2d3c4b5a",
    );
    expect(warning(result, "passkeys_imported")?.count).toBe(1);

    expect(byTitle(result, "Server room")).toMatchObject({
      category: "note",
      notes: "Door code 0815",
      tags: ["Work/Servers"],
    });
    const card = byTitle(result, "Corporate card");
    expect(card.category).toBe("card");
    expect(get(card, FIELD.cardNumber)).toBe("4111111111111111");
    expect(get(card, FIELD.cardExpiry)).toBe("03/2029");
    expect(get(card, FIELD.cardCode)).toBe("123");
    const identity = byTitle(result, "Kim (personal)");
    expect(identity.category).toBe("identity");
    expect(get(identity, "first_name")).toBe("Kim");
    expect(get(identity, "passport_number")).toBe("C01X00T47");
    expect(byTitle(result, "Deploy key").category).toBe("other");
    expect(warning(result, "trashed_skipped")?.examples).toEqual(["Deleted login"]);
  });

  it("refuses encrypted JSON exports with a clear error", () => {
    const bytes = strToU8(JSON.stringify({ encrypted: true, passwordProtected: true, items: [] }));
    expect(() => parseImport({ name: "bw.json", bytes })).toThrow(
      expect.objectContaining({ code: "encrypted_export" }),
    );
  });

  it("imports CSV with multiple URIs, custom fields and notes", () => {
    const result = parseImport(file("bitwarden.csv"));
    const gitlab = byTitle(result, "GitLab");
    expect(gitlab).toMatchObject({ favorite: true, tags: ["Work"], notes: "Team account" });
    expect(get(gitlab, FIELD.totp)).toBe("JBSWY3DPEHPK3PXP");
    expect(gitlab.fields.filter((f) => f.type === "url")).toHaveLength(2);
    expect(extra(gitlab, "PIN")?.value).toBe("1234");
    expect(get(byTitle(result, "Forum"), FIELD.url)).toBe("https://forum.example.org");
    expect(byTitle(result, "Wi-Fi at home")).toMatchObject({ category: "note", tags: ["Personal"] });
  });
});

describe("1Password", () => {
  const onePux = () =>
    zip("1PasswordExport.1pux", {
      "export.attributes": strToU8('{"version":3,"description":"1Password Unencrypted Export","createdAt":1710000000}'),
      "export.data": read("1password-export.data.json"),
      "files/": new Uint8Array(),
    });

  it("imports 1PUX logins, cards, notes, identities and other categories", () => {
    const result = parseImport(onePux());
    expect(result.format).toBe("1password-1pux");
    expect(result.items).toHaveLength(6);
    const shop = byTitle(result, "Example Shop");
    expect(result.items.find((i) => i.data === shop)?.sourceVault).toBe("Private");
    expect(shop).toMatchObject({ favorite: true, tags: ["Shopping", "Family"], notes: "Shared with family" });
    expect(get(shop, FIELD.username)).toBe("mia@example.com");
    expect(get(shop, FIELD.password)).toBe("1pux-Pass-1");
    expect(get(shop, FIELD.totp)).toContain("otpauth://totp/Shop");
    expect(get(shop, FIELD.url)).toBe("https://shop.example.com/login");
    expect(shop.fields.filter((f) => f.type === "url").map((f) => f.value)).toEqual([
      "https://shop.example.com/login",
      "https://checkout.example.com",
    ]);
    expect(extra(shop, "security answer")).toMatchObject({ value: "Blue", type: "concealed" });
    expect(extra(shop, "member since")?.value).toBe("2020-01-01");
    expect(extra(shop, "country")?.value).toBe("DE");
    expect(shop.passwordHistory).toEqual([{ value: "1pux-Old-Pass", replacedAt: 1690000000000 }]);

    const card = byTitle(result, "Family Mastercard");
    expect(get(card, FIELD.cardNumber)).toBe("5555555555554444");
    expect(get(card, FIELD.cardExpiry)).toBe("11/2028");
    expect(get(card, FIELD.cardCode)).toBe("321");
    expect(extra(card, "Brand")?.value).toBe("mc");
    expect(extra(card, "PIN")?.value).toBe("2468");

    expect(byTitle(result, "Wi-Fi notes")).toMatchObject({ category: "note", tags: ["Archived"] });
    const identity = byTitle(result, "Mia");
    expect(get(identity, "first_name")).toBe("Mia");
    expect(get(identity, "address")).toBe("Beispielweg 3\n80331 München\nde");
    expect(get(identity, "birth_date")).toBe("1990-01-01");
    const nas = byTitle(result, "Home NAS");
    expect(nas.category).toBe("other");
    expect(nas.tags).toContain("Server");
    expect(extra(nas, "password")).toMatchObject({ value: "Nas-Pass-1", type: "concealed" });
    const router = byTitle(result, "Router admin");
    expect(get(router, FIELD.password)).toBe("Router-Pass-55");
    expect(result.items.find((i) => i.data === router)?.sourceVault).toBe("Shared");
  });

  it("imports 1Password CSV", () => {
    const result = parseImport(file("1password.csv"));
    const mail = byTitle(result, "Example Mail");
    expect(mail).toMatchObject({ favorite: true, tags: ["Work", "Email"], notes: "Primary mailbox" });
    expect(get(mail, FIELD.totp)).toContain("otpauth://");
    expect(byTitle(result, "Old Forum").tags).toEqual(["Archived"]);
  });

  it("reports a damaged 1PUX file", () => {
    expect(() =>
      parseImport({ name: "x.1pux", bytes: zipSync({ "other.txt": strToU8("x") }) }, { format: "1password-1pux" }),
    ).toThrow(ImportError);
  });
});

describe("KeePass", () => {
  it("imports KeePassXC CSV with groups and skips the recycle bin", () => {
    const result = parseImport(file("keepassxc.csv"));
    expect(result.items.map((i) => i.data.title)).toEqual(["Example Cloud", "db01"]);
    expect(byTitle(result, "Example Cloud").tags).toEqual([]);
    expect(byTitle(result, "db01").tags).toEqual(["Work/Servers"]);
    expect(get(byTitle(result, "db01"), FIELD.url)).toBe("https://db01.example.internal:5432");
    expect(get(byTitle(result, "Example Cloud"), FIELD.totp)).toContain("otpauth://totp/Cloud");
    expect(warning(result, "trashed_skipped")?.count).toBe(1);
  });

  it("imports KeePass 2 CSV", () => {
    const result = parseImport(file("keepass2.csv"));
    const shop = byTitle(result, "Example Shop");
    expect(get(shop, FIELD.username)).toBe("frank");
    expect(shop.notes).toBe("Customer no. 5");
    expect(get(byTitle(result, "Router"), FIELD.url)).toBe("https://192.168.0.1");
  });

  it("imports KeePass 2 XML with groups, tags, custom strings, history, TOTP and passkeys", () => {
    const result = parseImport(file("keepass2.xml"));
    expect(result.items).toHaveLength(3);
    const mail = byTitle(result, "Mail & Calendar");
    expect(get(mail, FIELD.password)).toBe(" Kp-Xml-<Pass> ");
    expect(mail.notes).toBe("Line 1\nLine 2");
    expect(mail.tags).toEqual(["admin", "prod"]);
    expect(get(mail, FIELD.totp)).toContain("otpauth://totp/Mail");
    expect(extra(mail, "Recovery PIN")).toMatchObject({ value: "9876", type: "concealed" });
    expect(extra(mail, "Department")).toMatchObject({ value: "IT", type: "text" });
    expect(mail.passwordHistory?.[0]?.value).toBe("Old-Mail-Pass");
    expect(warning(result, "attachments_not_imported")?.examples).toEqual(["Mail & Calendar"]);

    const passkeyItem = byTitle(result, "Passkey demo");
    expect(passkeyItem.tags).toEqual(["Web"]);
    expect(passkeyItem.passkeys?.[0]).toMatchObject({
      rpId: "passkeys.example.com",
      userName: "leo",
      userHandle: "bGVvLWhhbmRsZQ",
    });
    expect(passkeyItem.passkeys?.[0]?.privateKey).toMatch(/^MIGHAgEAMBMG[A-Za-z0-9_-]+$/);
    expect(passkeyItem.fields.some((f) => f.label.startsWith("KPEX"))).toBe(false);

    const books = byTitle(result, "Book shop");
    expect(books.tags).toEqual(["Web/Shops"]);
    expect(get(books, FIELD.password)).toBe("Cd<a>ta");
    expect(get(books, FIELD.totp)).toBe("JBSWY3DPEHPK3PXP");
    expect(warning(result, "trashed_skipped")?.examples).toEqual(["Old entry"]);
  });
});

describe("Passbolt", () => {
  it.each(["passbolt-kdbx.csv", "passbolt-1password.csv", "passbolt-lastpass.csv", "passbolt-bitwarden.csv"])(
    "imports %s with folders as tags",
    (name) => {
      const result = parseImport(file(name), { format: "passbolt-csv" });
      expect(result.items).toHaveLength(2);
      const jenkins = byTitle(result, "Jenkins");
      expect(get(jenkins, FIELD.username)).toBe("ci");
      expect(get(jenkins, FIELD.url)).toBe("https://ci.example.com");
      expect(get(jenkins, FIELD.password)).toMatch(/^Pb-/);
      expect(jenkins.notes).toBe("Build server");
      expect(jenkins.tags).toEqual(["Engineering/CI"]);
      if (!name.includes("1password")) expect(get(jenkins, FIELD.totp)).toBeTruthy();
      expect(byTitle(result, "Wiki").tags).toEqual([]);
    },
  );

  it("also reads Passbolt's Chrome, Firefox and Safari layouts when Passbolt is chosen", () => {
    expect(parseImport(file("chrome.csv"), { format: "passbolt-csv" }).items).toHaveLength(3);
    expect(parseImport(file("safari.csv"), { format: "passbolt-csv" }).items).toHaveLength(2);
  });
});

describe("LastPass", () => {
  it("imports logins, secure notes, cards and addresses", () => {
    const result = parseImport(file("lastpass.csv"));
    const login = byTitle(result, "Example Login");
    expect(login).toMatchObject({ favorite: true, tags: ["Work/Tools"], notes: "Shared with team" });
    expect(get(login, FIELD.totp)).toBe("JBSWY3DPEHPK3PXP");
    const card = byTitle(result, "Company Visa");
    expect(card.category).toBe("card");
    expect(get(card, FIELD.cardholder)).toBe("Grace Example");
    expect(get(card, FIELD.cardExpiry)).toBe("03/2029");
    expect(card.notes).toBe("Company card");
    expect(byTitle(result, "Office door")).toMatchObject({ category: "note", notes: "Door code is 4711" });
    const address = byTitle(result, "Home address");
    expect(address.category).toBe("identity");
    expect(get(address, "city")).toBe("Berlin");
    expect(get(address, "address")).toBe("Musterstraße 1");
  });
});

describe("Dashlane", () => {
  it("imports credentials.csv", () => {
    const result = parseImport(file("dashlane-credentials.csv"));
    const social = byTitle(result, "Example Social");
    expect(get(social, FIELD.totp)).toContain("otpauth://");
    expect(social.tags).toEqual(["Social"]);
    expect(extra(social, "Alternative username")?.value).toBe("henry");
  });

  it("imports the ZIP export with notes and payment cards", () => {
    const result = parseImport(
      zip("dashlane.zip", {
        "credentials.csv": read("dashlane-credentials.csv"),
        "securenotes.csv": read("dashlane-securenotes.csv"),
        "payments.csv": read("dashlane-payments.csv"),
      }),
    );
    expect(result.format).toBe("dashlane-zip");
    expect(result.items).toHaveLength(4);
    expect(get(byTitle(result, "Henry's Visa"), FIELD.cardExpiry)).toBe("07/2027");
    expect(byTitle(result, "Locker")).toMatchObject({ category: "note", notes: "Code 2580" });
  });
});

describe("Proton Pass", () => {
  it("imports the JSON export (ZIP) with vaults, extra fields, cards and identities", () => {
    const result = parseImport(
      zip("Proton Pass_export.zip", { "Proton Pass/data.json": read("protonpass-data.json") }),
    );
    expect(result.items).toHaveLength(3);
    const mail = byTitle(result, "Example Mail");
    expect(mail.favorite).toBe(true);
    expect(get(mail, FIELD.username)).toBe("noah");
    expect(extra(mail, "Email")?.value).toBe("noah@example.com");
    expect(extra(mail, "Backup code")?.type).toBe("concealed");
    expect(extra(mail, "Second factor")?.type).toBe("totp");
    expect(mail.fields.filter((f) => f.type === "url")).toHaveLength(2);
    expect(warning(result, "passkeys_not_exported")?.examples).toEqual(["Example Mail"]);
    expect(get(byTitle(result, "Travel card"), FIELD.cardExpiry)).toBe("01/2030");
    const identity = byTitle(result, "Noah at work");
    expect(result.items.find((i) => i.data === identity)?.sourceVault).toBe("Work");
    expect(get(identity, "job_title")).toBe("Sales Manager");
    expect(extra(identity, "Work phone")?.value).toBe("+49 30 111");
    expect(warning(result, "trashed_skipped")?.count).toBe(1);
  });

  it("imports the CSV export", () => {
    const result = parseImport(file("protonpass.csv"));
    expect(result.items).toHaveLength(3);
    expect(result.items[0]?.sourceVault).toBe("Work");
    expect(get(byTitle(result, "Newsletter alias"), FIELD.username)).toBe("news.ivy@alias.example");
    expect(byTitle(result, "Server notes").category).toBe("note");
  });
});

describe("generic CSV", () => {
  it("suggests a column mapping from German headers", () => {
    const { table, mapping, total } = previewCsv(file("generic-de-excel.csv"));
    expect(total).toBe(3);
    expect(table.headers[2]).toBe("Kennwort");
    expect(mapping).toEqual(["title", "username", "password", "url", "notes", "folder", "field"]);
  });

  it("suggests mappings from English headers", () => {
    expect(
      detectColumns(["Account Name", "E-Mail", "Password", "Website", "2FA", "Comments", "Favorite", "PIN"]),
    ).toEqual(["title", "username", "password", "url", "totp", "notes", "favorite", "secret"]);
    expect(detectColumns(["Name", "User", "Email", "Pass"])).toEqual(["title", "username", "email", "password"]);
  });

  it("imports with the suggested or a manual mapping", () => {
    const result = parseImport(file("generic-de-excel.csv"));
    const crm = byTitle(result, "CRM");
    expect(get(crm, FIELD.password)).toBe("Grüße-2024!");
    expect(get(crm, FIELD.url)).toBe("https://crm.example.com");
    expect(crm.tags).toEqual(["Vertrieb"]);
    expect(extra(crm, "Kostenstelle")?.value).toBe("4711");
    expect(get(byTitle(result, "Reisekosten"), FIELD.password)).toBe("Pass;wort");
    expect(byTitle(result, "Notiz ohne Login")).toMatchObject({ category: "note", notes: "Schlüssel liegt im Büro" });

    const manual = parseImport(file("generic-de-excel.csv"), {
      format: "generic-csv",
      mapping: ["title", "skip", "password", "skip", "skip", "skip", "secret"],
    });
    const item = manual.items.find((i) => i.data.title === "CRM")?.data as ItemData;
    expect(get(item, FIELD.username)).toBeUndefined();
    expect(extra(item, "Kostenstelle")?.type).toBe("concealed");
  });

  it("validates mappings", () => {
    expect(mappingProblem(["skip", "field"])).toBe("no_columns");
    expect(mappingProblem(["password", "password"])).toBe("duplicate_target");
    expect(mappingProblem(["title", "password"])).toBeUndefined();
  });
});

describe("duplicates", () => {
  const existing = (() => {
    const item = newItemData("login", "Example");
    item.fields = item.fields.map((f) =>
      f.id === FIELD.url
        ? { ...f, value: "https://example.com/" }
        : f.id === FIELD.username
          ? { ...f, value: "Alice@Example.com" }
          : f,
    );
    item.tags = ["Old"];
    item.notes = "Existing note";
    return { id: "existing-1", data: item };
  })();

  it("matches the same host and username, ignoring case, www. and paths", () => {
    const result = parseImport(file("chrome.csv"));
    const matches = findDuplicates(result.items, [existing]);
    expect(matches).toEqual([{ index: 0, existingId: "existing-1" }]);
    expect(findDuplicates(result.items, [{ ...existing, data: { ...existing.data, trashedAt: 1 } }])).toEqual([]);
  });

  it("merges an update into the existing item", () => {
    const imported = byTitle(parseImport(file("chrome.csv")), "example.com");
    imported.tags = ["New"];
    imported.notes = "Imported note";
    imported.fields.push({ id: "custom_1", label: "PIN", type: "concealed", value: "1234" });
    const merged = mergeItem(existing.data, imported);
    expect(get(merged, FIELD.password)).toBe("Correct-Horse-7");
    expect(get(merged, FIELD.username)).toBe("alice@example.com");
    expect(merged.title).toBe("Example");
    expect(merged.tags).toEqual(["Old", "New"]);
    expect(merged.notes).toBe("Existing note\n\nImported note");
    expect(extra(merged, "PIN")?.value).toBe("1234");
  });
});

describe("item data", () => {
  it("every imported item has unique field IDs and valid categories", () => {
    const files = [
      "chrome.csv",
      "bitwarden.json",
      "keepass2.xml",
      "lastpass.csv",
      "generic-de-excel.csv",
      "protonpass.csv",
    ];
    for (const name of files) {
      for (const { data } of parseImport(file(name)).items) {
        const ids = data.fields.map((f) => f.id);
        expect(new Set(ids).size, `${name}: ${data.title}`).toBe(ids.length);
        expect(data.v).toBe(1);
        expect(data.title).not.toBe("");
      }
    }
  });
});
