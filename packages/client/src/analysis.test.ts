import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { ALIAS_PROVIDERS, AliasError, createAlias } from "./aliases";
import {
  analyzeSecurity,
  bundledBreachCatalog,
  checkLookalike,
  DEFAULT_REPORT_OPTIONS,
  dataClassKey,
  type SecurityReport,
  siteBreachCounts,
  siteSupport,
  withDismissed,
} from "./analysis";
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
    expect(report.categories).toHaveLength(17);
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

describe("breached websites", () => {
  const breach = (name: string, domain: string, addedAt: number, dataClasses: string[], sensitive = false) => ({
    name,
    title: name,
    domain,
    breachDate: new Date(addedAt).toISOString().slice(0, 10),
    addedDate: new Date(addedAt).toISOString().replace(/\.\d{3}Z$/, "Z"),
    modifiedDate: new Date(addedAt).toISOString().replace(/\.\d{3}Z$/, "Z"),
    pwnCount: 1000,
    dataClasses,
    verified: true,
    sensitive,
  });
  const catalog = (breaches: ReturnType<typeof breach>[]) => ({
    version: "test",
    updatedAt: Math.max(...breaches.map((b) => Date.parse(b.addedDate))),
    source: "Have I Been Pwned",
    sourceUrl: "https://haveibeenpwned.com/",
    license: "CC BY 4.0",
    breaches,
  });

  it("flags logins whose password is older than the breach", () => {
    const old = {
      ...login("old", "x9$Lq!2vR#pW7zK@", "https://www.netflix.com/login"),
      createdAt: NOW - 400 * 86_400_000,
    };
    const changed = {
      ...login("changed", "G7#kP2!mQ9$wX4&z", "https://netflix.com", "other"),
      createdAt: NOW - 400 * 86_400_000,
    };
    changed.data.passwordHistory = [{ value: "before", replacedAt: NOW - 86_400_000 }];
    const report = analyzeSecurity(core, [old, changed], {
      ...input,
      siteBreaches: catalog([breach("Netflix", "netflix.com", NOW - 5 * 86_400_000, ["Email addresses", "Passwords"])]),
    });
    const finding = report.findings.find((f) => f.kind === "breached_site");
    expect(finding).toMatchObject({
      itemId: "old",
      severity: "high",
      fix: "change_password",
      breaches: ["Netflix"],
      breachNames: ["Netflix"],
      dataClasses: ["Email addresses", "Passwords"],
      documentationUrl: "https://www.netflix.com/.well-known/change-password",
    });
    expect(report.findings.some((f) => f.kind === "breached_site" && f.itemId === "changed")).toBe(false);
    expect(report.breachedSites[0]).toMatchObject({ name: "Netflix", affected: ["old"], fixed: ["changed"] });
    expect(report.breachCatalog).toMatchObject({ version: "test", bundled: false, source: "Have I Been Pwned" });
    expect(report.fixFirst.some((p) => p.kinds.includes("breached_site"))).toBe(true);
    expect(dataClassKey("Passwords")).toBe("passwords");
    expect(dataClassKey("Something new")).toBeUndefined();
  });

  it("uses the bundled snapshot without a catalogue", () => {
    const adobe = { ...login("adobe", "x9$Lq!2vR#pW7zK@", "https://adobe.com"), createdAt: 1_000_000_000_000 };
    const report = analyzeSecurity(core, [adobe], input);
    expect(report.breachCatalog.bundled).toBe(true);
    expect(report.findings.find((f) => f.kind === "breached_site")?.breachNames).toContain("Adobe");
    const bundled = bundledBreachCatalog(core);
    expect(bundled?.entries).toBeGreaterThan(500);
    expect(bundled?.version).toMatch(/^bundled-\d{4}-\d{2}-\d{2}$/);
  });

  it("counts an organization's logins per breach, without sensitive breaches", () => {
    const report = {
      breachedSites: [
        { name: "A", title: "A", sensitive: false, affected: ["1", "x"], possibly: [], fixed: ["2"] },
        { name: "S", title: "S", sensitive: true, affected: ["1"], possibly: [], fixed: [] },
        { name: "B", title: "B", sensitive: false, affected: ["x"], possibly: [], fixed: [] },
      ],
    } as unknown as SecurityReport;
    expect(siteBreachCounts(report, new Set(["1", "2"]))).toEqual([{ name: "A", title: "A", open: 1, fixed: 1 }]);
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
