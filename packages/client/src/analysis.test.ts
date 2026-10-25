import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { ALIAS_PROVIDERS, AliasError, createAlias } from "./aliases";
import { analyzeSecurity, checkLookalike, DEFAULT_REPORT_OPTIONS, siteSupport, withDismissed } from "./analysis";
import { FIELD, newItemData } from "./items";

beforeAll(async () => {
  const require = createRequire(import.meta.url);
  const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
  await core.default({ module_or_path: await readFile(wasmPath) });
});

const NOW = 1_790_000_000_000;

function login(id: string, password: string, url: string, username = "me") {
  const data = newItemData("login", id);
  for (const field of data.fields) {
    if (field.id === FIELD.password) field.value = password;
    if (field.id === FIELD.url) field.value = url;
    if (field.id === FIELD.username) field.value = username;
  }
  return { id, createdAt: NOW - 86_400_000, data };
}

const input = { ...DEFAULT_REPORT_OPTIONS, now: NOW, userInputs: [] };

describe("analyzeSecurity", () => {
  it("scores the vault and prioritizes fixes like the Rust engine", () => {
    const report = analyzeSecurity(
      core,
      [
        login("weak", "123456", "https://shop.example"),
        login("a", "x9$Lq!2vR#pW7zK@", "https://one.example"),
        login("b", "x9$Lq!2vR#pW7zK@", "http://two.example"),
        login("gh", "G7#kP2!mQ9$wX4&z", "https://github.com"),
      ],
      { ...input, breachCounts: { weak: 100 } },
    );
    expect(report.score).toBeLessThan(60);
    expect(report.breachChecked).toBe(true);
    expect(report.fixFirst[0]).toMatchObject({ itemId: "weak", severity: "critical", fix: "change_password" });
    expect(report.reusedGroups).toEqual([["a", "b"]]);
    const kinds = (id: string) => report.findings.filter((f) => f.itemId === id).map((f) => f.kind);
    expect(kinds("b")).toEqual(expect.arrayContaining(["reused", "insecure_url"]));
    expect(kinds("gh")).toEqual(expect.arrayContaining(["missing_two_factor", "passkey_available"]));
    const twoFactor = report.findings.find((f) => f.kind === "missing_two_factor");
    expect(twoFactor?.documentationUrl).toMatch(/^https:\/\//);
    expect(report.categories).toHaveLength(16);
    expect(report.directoryDates[0]).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("honors dismissals stored in the item", () => {
    const item = login("weak", "123456", "https://shop.example");
    const dismissed = withDismissed(item.data, "weak", true);
    expect(dismissed).toMatchObject({ securityIgnore: ["weak"] });
    expect(withDismissed(dismissed ?? item.data, "weak", true)).toBeUndefined();
    const report = analyzeSecurity(core, [{ ...item, data: dismissed ?? item.data }], input);
    expect(report.findings.find((f) => f.kind === "weak")?.dismissed).toBe(true);
    expect(report.score).toBe(100);
    expect(withDismissed(dismissed ?? item.data, "weak", false)).not.toHaveProperty("securityIgnore");
  });
});

describe("checkLookalike", () => {
  it("warns about typos, homographs and confusables", () => {
    expect(checkLookalike(core, "githuh.com", ["github.com"])).toMatchObject({
      looksLike: "github.com",
      reason: "typo",
      saved: true,
    });
    expect(checkLookalike(core, "xn--pple-43d.com", ["apple.com"])?.reason).toBe("homograph");
    expect(checkLookalike(core, "www.paypa1.com", [])).toMatchObject({ looksLike: "paypal.com", saved: false });
    expect(checkLookalike(core, "gist.github.com", ["github.com"])).toBeNull();
    expect(checkLookalike(core, "example.org", ["github.com"])).toBeNull();
  });

  it("knows which sites support 2FA and passkeys", () => {
    expect(siteSupport(core, "github.com")).toMatchObject({ totp: true, securityKey: true });
    expect(siteSupport(core, "passbox-unknown.example")).toBeNull();
  });
});

describe("createAlias", () => {
  it.each([
    ["simplelogin", { alias: "x@simplelogin.com" }, "x@simplelogin.com", "Authentication", "key"],
    ["addy", { data: { email: "a@anonaddy.me" } }, "a@anonaddy.me", "Authorization", "Bearer key"],
    ["duckduckgo", { address: "quack" }, "quack@duck.com", "Authorization", "Bearer key"],
    ["firefox_relay", { full_address: "r@mozmail.com" }, "r@mozmail.com", "Authorization", "Token key"],
  ] as const)("creates %s aliases", async (provider, answer, alias, header, value) => {
    const fetch = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => Response.json(answer));
    expect(await createAlias({ provider, apiKey: " key " }, "shop.example", fetch)).toBe(alias);
    const headers = fetch.mock.calls[0]?.[1]?.headers as Record<string, string>;
    expect(headers[header]).toBe(value);
  });

  it("creates Fastmail masked emails over JMAP", async () => {
    const fetch = vi.fn(async (url: RequestInfo | URL) =>
      String(url).endsWith("/jmap/session")
        ? Response.json({
            apiUrl: "https://api.fastmail.com/jmap/api/",
            primaryAccounts: { "https://www.fastmail.com/dev/maskedemail": "u1" },
          })
        : Response.json({
            methodResponses: [["MaskedEmail/set", { created: { passbox: { email: "m@fm.com" } } }, "0"]],
          }),
    );
    expect(await createAlias({ provider: "fastmail", apiKey: "k" }, "shop.example", fetch)).toBe("m@fm.com");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("explains failures", async () => {
    const denied = vi.fn(async () => new Response("{}", { status: 401 }));
    await expect(createAlias({ provider: "addy", apiKey: "k" }, "x", denied)).rejects.toMatchObject({
      code: "unauthorized",
    });
    await expect(createAlias({ provider: "simplelogin", apiKey: "" }, "x", denied)).rejects.toBeInstanceOf(AliasError);
    await expect(
      createAlias({ provider: "simplelogin", apiKey: "k", baseUrl: "http://sl.example" }, "x", denied),
    ).rejects.toMatchObject({ code: "insecure_url" });
    expect(ALIAS_PROVIDERS).toHaveLength(5);
  });
});
