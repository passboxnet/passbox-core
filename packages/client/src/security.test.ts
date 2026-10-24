import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { FIELD, newItemData } from "./items";
import { analyzeVault, breachCount, estimateStrength } from "./security";

beforeAll(async () => {
  const require = createRequire(import.meta.url);
  const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
  await core.default({ module_or_path: await readFile(wasmPath) });
});

describe("estimateStrength", () => {
  // Same cases as crates/client/src/security.rs.
  it.each([
    ["", 0],
    ["password", 0],
    ["Passwort!", 0],
    ["Sommer2024!", 1],
    ["aaaaaaaaaaaa", 0],
    ["Tr0ub4dor&3", 2],
    ["correct-horse-battery-staple", 4],
    ["9x$Lq!2vR#pW7zK@", 4],
  ])("rates %j as score %i", (password, score) => {
    expect(estimateStrength(core, password).score).toBe(score);
  });

  it("explains weak passwords and gates master passwords", () => {
    const weak = estimateStrength(core, "Sommer2024!");
    expect(weak.label).toBe("Weak");
    expect(weak.warning).toBe("recent_year");
    expect(weak.acceptableMasterPassword).toBe(false);
    expect(estimateStrength(core, "erika.mustermann", ["erika.mustermann@example.com"]).score).toBeLessThanOrEqual(1);
    expect(estimateStrength(core, "correct-horse-battery-staple").acceptableMasterPassword).toBe(true);
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
    const trashed = login("e", "123456", "http://x");
    trashed.data.trashedAt = 1;
    const health = analyzeVault(core, [
      login("a", "123456"),
      login("b", "x9$Lq!2vR#pW7zK@"),
      login("c", "x9$Lq!2vR#pW7zK@", "http://intranet.local"),
      login("d", "G7#kP2!mQ9$wX4&z", "https://bank.example", "JBSWY3DPEHPK3PXP"),
      { id: "note", data: newItemData("note", "note") },
      trashed,
    ]);
    expect(health.analyzed).toBe(4);
    expect(health.weak).toEqual(["a"]);
    expect(health.reused).toEqual([["b", "c"]]);
    expect(health.insecureUrls).toEqual(["c"]);
    expect(health.withoutTotp).toEqual(["a", "b", "c"]);
    expect(health.secure).toBe(1);
    expect(health.score).toBe(25);
  });

  it("scores an empty vault as healthy", () => {
    expect(analyzeVault(core, []).score).toBe(100);
  });
});

describe("breachCount", () => {
  it("sends only the hash prefix and reads the matching suffix", async () => {
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    const fetch = vi.fn(async (url: RequestInfo | URL) => {
      expect(String(url)).toBe("https://api.pwnedpasswords.com/range/5BAA6");
      return new Response("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n");
    });
    expect(await breachCount("password", fetch)).toBe(9545824);
    expect(await breachCount("", fetch)).toBe(0);
  });

  it("returns 0 when the suffix is not listed", async () => {
    const fetch = vi.fn(async () => new Response("0018A45C4D1DEF81644B54AB7F969B88D65:1\n"));
    expect(await breachCount("unlikely-to-be-breached-9x$Lq", fetch)).toBe(0);
  });
});
