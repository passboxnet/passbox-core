import { describe, expect, it } from "vitest";
import { FIELD, fieldValue, newItemData, parseItemData, parseVaultMeta } from "./items";

describe("item data", () => {
  it("creates login templates with well-known fields", () => {
    const item = newItemData("login", "GitHub");
    expect(item.fields.map((f) => f.id)).toEqual([FIELD.username, FIELD.password, FIELD.url, FIELD.totp]);
    expect(fieldValue(item, FIELD.username)).toBeUndefined();
  });

  it("round-trips through JSON", () => {
    const item = newItemData("card", "Visa");
    item.tags = ["finance"];
    expect(parseItemData(JSON.stringify(item))).toEqual(item);
  });

  it("sanitizes unexpected input", () => {
    const parsed = parseItemData(
      JSON.stringify({
        v: 1,
        category: "spaceship",
        title: 42,
        fields: [{ id: "a", value: "x", type: "weird" }, { id: 1 }, null],
        tags: ["ok", 3],
      }),
    );
    expect(parsed.category).toBe("other");
    expect(parsed.title).toBe("");
    expect(parsed.fields).toEqual([{ id: "a", label: "a", type: "text", value: "x" }]);
    expect(parsed.tags).toEqual(["ok"]);
  });

  it("keeps valid passkeys and drops malformed ones", () => {
    const passkey = {
      credentialId: "AAECAw",
      rpId: "example.com",
      rpName: "Example",
      userHandle: "dXNlcg",
      userName: "alice",
      userDisplayName: "Alice",
      privateKey: "MIGHAgEA",
      algorithm: -7,
      signCount: 3,
      createdAt: 1700000000000,
    };
    const item = {
      ...newItemData("login", "Example"),
      passkeys: [passkey, { rpId: "x" }, { ...passkey, userHandle: "!" }],
    };
    const parsed = parseItemData(JSON.stringify(item));
    expect(parsed.passkeys).toEqual([passkey]);
    expect(parseItemData(JSON.stringify(parsed))).toEqual(parsed);
    expect("passkeys" in parseItemData(JSON.stringify(newItemData("login")))).toBe(false);
  });

  it("rejects unknown versions", () => {
    expect(() => parseItemData(JSON.stringify({ v: 2 }))).toThrow(/version/);
  });

  it("defaults vault names", () => {
    expect(parseVaultMeta("{}").name).toBe("Vault");
    expect(parseVaultMeta('{"name":"Work"}').name).toBe("Work");
  });
});
