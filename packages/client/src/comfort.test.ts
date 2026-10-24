import { describe, expect, it } from "vitest";
import {
  CATEGORIES,
  categoryName,
  FIELD,
  newItemData,
  parseItemData,
  serializeItemData,
  templateFields,
  wifiQrPayload,
} from "./items";
import { shareLinkUrl, shareSnapshot } from "./shareLinks";

describe("item types", () => {
  it("keeps categories and formats from newer versions", () => {
    const json = JSON.stringify({
      v: 1,
      category: "spaceship",
      title: "Enterprise",
      fields: [{ id: "d", label: "Launch", type: "text", value: "2263-01-01", format: "date" }],
    });
    const data = parseItemData(json);
    expect(data.category).toBe("other");
    expect(categoryName(data)).toBe("spaceship");
    expect(data.fields[0]?.format).toBe("date");
    // Edits on a copy keep it.
    const edited = { ...data, title: "NCC-1701" };
    const back = JSON.parse(serializeItemData(edited));
    expect(back.category).toBe("spaceship");
    expect(back.title).toBe("NCC-1701");
    expect(back.fields[0].format).toBe("date");
    // Choosing a known category replaces it.
    expect(JSON.parse(serializeItemData({ ...data, category: "note" })).category).toBe("note");
  });

  it("reads every known category and the archive and attachments", () => {
    for (const category of CATEGORIES) {
      const data = parseItemData(JSON.stringify(newItemData(category, "x")));
      expect(data.category).toBe(category);
      expect(categoryName(data)).toBe(category);
    }
    const data = parseItemData(
      JSON.stringify({
        v: 1,
        category: "document",
        archivedAt: 5,
        attachments: [{ id: "f", name: "a.pdf", type: "application/pdf", size: 3, key: "k", createdAt: 1 }, { id: 1 }],
      }),
    );
    expect(data.archivedAt).toBe(5);
    expect(data.attachments).toEqual([
      { id: "f", name: "a.pdf", type: "application/pdf", size: 3, key: "k", createdAt: 1 },
    ]);
  });

  it("has the same templates as the Rust client", () => {
    expect(templateFields("sshKey").map((f) => [f.id, f.type, f.format])).toEqual([
      ["private_key", "concealed", "multiline"],
      ["public_key", "text", "multiline"],
      ["fingerprint", "text", undefined],
      ["passphrase", "concealed", undefined],
    ]);
    expect(templateFields("passport").filter((f) => f.format === "date")).toHaveLength(3);
    expect(templateFields("login")[0]).toEqual({ id: "username", label: "Username", type: "text", value: "" });
  });

  it("builds Wi-Fi QR codes like the Rust client", () => {
    const wifi = newItemData("wifi", "Home");
    expect(wifiQrPayload(wifi)).toBeUndefined();
    const set = (id: string, value: string) => {
      wifi.fields = wifi.fields.map((f) => (f.id === id ? { ...f, value } : f));
    };
    set(FIELD.wifiSsid, "My;Net");
    set(FIELD.password, 'p:a"ss\\');
    expect(wifiQrPayload(wifi)).toBe('WIFI:T:WPA;S:My\\;Net;P:p\\:a\\"ss\\\\;;');
    set(FIELD.password, "");
    expect(wifiQrPayload(wifi)).toBe("WIFI:T:nopass;S:My\\;Net;;");
  });
});

describe("share links", () => {
  it("puts the key in the fragment only", () => {
    expect(shareLinkUrl("https://pb.example.com/", "abc", "KEY")).toBe("https://pb.example.com/s/abc#KEY");
  });

  it("snapshots without one-time password secrets", () => {
    const login = newItemData("login", "GitHub");
    login.fields = login.fields.map((f) => ({ ...f, value: f.id === FIELD.totp ? "otpauth://x" : `${f.id}-value` }));
    login.passwordHistory = [{ value: "old", replacedAt: 1 }];
    const snapshot = shareSnapshot({ data: login });
    expect(snapshot.fields.map((f) => f.label)).toEqual(["Username", "Password", "Website"]);
    expect(JSON.stringify(snapshot)).not.toContain("old");
    expect(shareSnapshot({ data: login }, { fieldIds: [FIELD.password] }).fields).toHaveLength(1);
  });
});
