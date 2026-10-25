import { describe, expect, it } from "vitest";
import { AiGateway } from "./gateway";
import { classify, IMPORT_TARGETS, profileColumn, redactColumns, suggestMapping } from "./importMapping";
import { recordingProvider } from "./providers";
import type { AiSettings } from "./settings";
import type { ModelLocation } from "./types";

const settings = (location: ModelLocation, features: AiSettings["features"] = ["import-mapping"]): AiSettings => ({
  enabled: true,
  provider: { location, endpoint: "http://localhost:11434/v1", model: "llama3.2" },
  features,
});

/** Every cell is distinctive, so a leak of any part is visible. */
const table = {
  headers: ["Bezeichnung", "Anmeldung", "Geheim", "Webadresse2", "Zweitfaktor", "Kundennr"],
  rows: [
    [
      "Bank of Ada",
      "ada.lovelace@example.org",
      "Tr0ub4dor&3xyzQ!",
      "https://bank.example.org/login",
      "JBSWY3DPEHPK3PXP",
      "4711081",
    ],
    [
      "Mail",
      "charles.babbage@example.org",
      "Zq8#mW2$vK9!pL4x",
      "https://mail.example.org",
      "otpauth://totp/Mail?secret=GEZDGNBVGY3TQOJQ",
      "4711082",
    ],
  ],
};
const current = ["title", "field", "field", "field", "field", "field"];
const unknown = [1, 2, 3, 4, 5];

function expectNoCellSent(sent: string) {
  expect(sent.length).toBeGreaterThan(0);
  for (const row of table.rows) {
    for (const cell of row) {
      expect(sent, `cell ${cell} was sent`).not.toContain(cell);
      for (const part of cell.split(/[@/.?=:]/)) {
        if (part.length >= 8) expect(sent, `part ${part} of ${cell} was sent`).not.toContain(part);
      }
    }
  }
}

describe("classify and profile", () => {
  it("recognizes value patterns", () => {
    expect(classify("https://example.com")).toBe("url");
    expect(classify("ada@example.com")).toBe("email");
    expect(classify("example.com")).toBe("domain");
    expect(classify("otpauth://totp/x")).toBe("otpauth");
    expect(classify("JBSWY3DPEHPK3PXP")).toBe("base32");
    expect(classify("123456")).toBe("digits");
    expect(classify("+49 30 1234567")).toBe("phone");
    expect(classify("24.12.2025")).toBe("date");
    expect(classify("ja")).toBe("boolean");
    expect(classify("x7#Kq9!vLm2@pZ")).toBe("random-string");
    expect(classify("LoginPassword")).toBe("text");
    expect(classify("6f1c2a8e-3b4d-4e5f-9a0b-1c2d3e4f5a6b")).toBe("uuid");
  });

  it("profiles shares, digit lengths and distinctness without values", () => {
    const p = profileColumn(["123456", "654321", "", "111111"]);
    expect(p).toEqual({
      filled: 0.8,
      kinds: { digits: 1 },
      digitLength: 6,
      length: { min: 6, median: 6, max: 6 },
      entropy: "low",
      distinct: "unique",
    });
  });

  it("drops headers that look like values or equal a cell", () => {
    const input = redactColumns(
      {
        headers: ["github.com", "ada@example.com", "x7#Kq9!vLm2@pZ", "Kundennummer", "Notizen"],
        rows: [["a", "b", "c", "Kundennummer", "d"]],
      },
      [],
      [0, 1, 2, 3, 4],
    );
    expect(input.value.columns.map((c) => c.header)).toEqual([null, null, null, null, "Notizen"]);
    expect(input.classes).toEqual(["D1"]);
  });
});

describe("suggestMapping", () => {
  it("never sends a cell value to the provider", async () => {
    const provider = recordingProvider({
      columns: [
        { index: 1, target: "username", confidence: "high" },
        { index: 2, target: "password", confidence: "high" },
        { index: 3, target: "url", confidence: "high" },
        { index: 4, target: "totp", confidence: "medium" },
        { index: 5, target: "field", confidence: "low" },
        { index: 0, target: "notes", confidence: "high" },
      ],
    });
    const gateway = new AiGateway({ settings: settings("cloud"), provider });
    const proposal = await suggestMapping(gateway, redactColumns(table, current, unknown));
    expect(proposal.source).toBe("ai");
    expect(proposal.mapping).toEqual(["title", "username", "password", "url", "totp", "field"]);
    expect(proposal.changed.map((c) => c.index)).toEqual([1, 2, 3, 4]);
    expectNoCellSent(provider.sent());
    expect(provider.sent()).toContain("Webadresse2");
    expect(provider.requests[0]?.classes).toEqual(["D1"]);
    expect(gateway.log).toHaveLength(1);
    expect(gateway.log[0]).toMatchObject({ feature: "import-mapping", outcome: "ok", location: "cloud" });
  });

  it("does not call the provider when AI or the feature is off", async () => {
    const provider = recordingProvider({ columns: [] });
    for (const s of [
      { enabled: false, features: [] } as AiSettings,
      { ...settings("on-device"), enabled: false },
      settings("on-device", ["security-copilot"]),
    ]) {
      const proposal = await suggestMapping(
        new AiGateway({ settings: s, provider }),
        redactColumns(table, Array(6).fill("field"), [0, 1, 2, 3, 4, 5]),
      );
      expect(proposal.source).toBe("patterns");
      expect(proposal.mapping).toEqual(["field", "username", "secret", "url", "totp", "field"]);
    }
    expect(provider.requests).toHaveLength(0);
  });

  it("falls back to patterns on invalid answers and provider errors", async () => {
    for (const answer of [
      { columns: [{ index: 99, target: "url", confidence: "high" }] },
      { columns: [{ index: 3, target: "rm -rf", confidence: "high" }] },
      "nope",
      () => {
        throw new Error("connection refused");
      },
    ]) {
      const gateway = new AiGateway({
        settings: settings("self-hosted"),
        provider: recordingProvider(answer, "self-hosted"),
      });
      const proposal = await suggestMapping(gateway, redactColumns(table, Array(6).fill("field"), [3]));
      expect(proposal.source).toBe("patterns");
      expect(proposal.mapping[3]).toBe("url");
      expect(proposal.fallbackReason).toBeDefined();
      expect(gateway.log[0]?.outcome).toMatch(/invalid|failed/);
    }
  });

  it("keeps single targets unique", async () => {
    const gateway = new AiGateway({
      settings: settings("on-device"),
      provider: recordingProvider(
        {
          columns: [
            { index: 1, target: "title", confidence: "high" },
            { index: 2, target: "password", confidence: "low" },
            { index: 3, target: "password", confidence: "high" },
          ],
        },
        "on-device",
      ),
    });
    const proposal = await suggestMapping(gateway, redactColumns(table, current, unknown));
    expect(proposal.mapping.slice(0, 4)).toEqual(["title", "field", "field", "password"]);
  });

  it("lists the targets of the import", () => {
    expect(IMPORT_TARGETS.map((t) => t.id)).toContain("secret");
  });
});
