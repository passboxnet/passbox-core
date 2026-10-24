import { describe, expect, it } from "vitest";
import { FIELD, newItemData } from "./items";
import { analyzeVault, estimateStrength } from "./security";

describe("estimateStrength", () => {
  it.each([
    ["", 0],
    ["password", 0],
    ["Passwort!", 0],
    ["summer2024", 1],
    ["aaaaaaaaaaaa", 0],
    ["Tr0ub4dor&3x", 3],
    ["correct-horse-battery-staple", 4],
    ["9x$Lq!2vR#pW7zK@", 4],
  ])("rates %j as score %i", (password, score) => {
    expect(estimateStrength(password).score).toBe(score);
  });
});

function login(id: string, password: string, url = "https://example.com", totp = "") {
  const data = newItemData("login", id);
  data.fields = data.fields.map((f) =>
    f.id === FIELD.password
      ? { ...f, value: password }
      : f.id === FIELD.url
        ? { ...f, value: url }
        : f.id === FIELD.totp
          ? { ...f, value: totp }
          : f,
  );
  return { id, data };
}

describe("analyzeVault", () => {
  it("finds weak, reused and insecure logins", () => {
    const health = analyzeVault([
      login("a", "123456"),
      login("b", "x9$Lq!2vR#pW7zK@"),
      login("c", "x9$Lq!2vR#pW7zK@", "http://intranet.local"),
      login("d", "G7#kP2!mQ9$wX4&z", "https://bank.example", "JBSWY3DPEHPK3PXP"),
      { id: "note", data: newItemData("note", "note") },
    ]);
    expect(health.analyzed).toBe(4);
    expect(health.weak).toEqual(["a"]);
    expect(health.reused).toEqual([["b", "c"]]);
    expect(health.insecureUrls).toEqual(["c"]);
    expect(health.withoutTotp).toEqual(["a", "b", "c"]);
    expect(health.score).toBe(25);
  });

  it("scores an empty vault as healthy", () => {
    expect(analyzeVault([]).score).toBe(100);
  });
});
