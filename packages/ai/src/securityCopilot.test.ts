import { describe, expect, it } from "vitest";
import { AiGateway } from "./gateway";
import { recordingProvider } from "./providers";
import { SecretGuard } from "./redacted";
import {
  categorize,
  cleanText,
  type Findings,
  fallbackPlan,
  placeholder,
  redactFindings,
  securityPlan,
} from "./securityCopilot";
import type { AiSettings } from "./settings";

const findings: Findings = {
  analyzed: 10,
  breachChecked: true,
  sites: [
    { host: "forum.example", kinds: ["weak", "no-totp"] },
    { host: "www.gmx.de", kinds: ["reused", "no-totp"] },
    { host: "shop.example", kinds: ["reused"] },
    { kinds: ["breached"] },
  ],
};

const settings: AiSettings = {
  enabled: true,
  provider: { location: "cloud", endpoint: "https://api.example.eu/v1", model: "m", apiKeyItemId: "item" },
  features: ["security-copilot"],
};

describe("security copilot", () => {
  it("categorizes sites by rules", () => {
    expect(categorize("www.gmx.de")).toBe("email");
    expect(categorize("banking.sparkasse-koelnbonn.de")).toBe("finance");
    expect(categorize("github.com")).toBe("developer");
    expect(categorize("example.org")).toBe("other");
  });

  it("orders the rule plan by risk", () => {
    const plan = fallbackPlan(findings);
    expect(plan.source).toBe("rules");
    expect(plan.steps.map((s) => [s.kind, s.priority, s.count])).toEqual([
      ["breached", "critical", 1],
      ["reused", "critical", 2],
      ["weak", "medium", 1],
      ["no-totp", "medium", 1],
    ]);
    expect(plan.steps[1]?.sites).toEqual(["gmx.de", "shop.example"]);
    expect(plan.steps[3]?.sites).toEqual(["gmx.de"]);
    expect(fallbackPlan({ analyzed: 3, breachChecked: false, sites: [] }).steps).toEqual([]);
  });

  it("pseudonymizes domains for cloud models and restores them", async () => {
    const provider = recordingProvider({
      summary: "Zwei Konten teilen ein Passwort.",
      steps: [
        {
          kind: "reused",
          title: "Passwort für Site A ändern",
          detail: "Site A und Site B nutzen dasselbe Passwort.‮",
          sites: ["Site A", "evil.example"],
        },
        { kind: "insecure-url", title: "Invented", detail: "No such finding" },
      ],
    });
    const guard = new SecretGuard();
    guard.add("hunter2-password");
    const plan = await securityPlan(new AiGateway({ settings, provider }), findings, "de", guard);
    expect(plan.source).toBe("ai");
    const sent = provider.sent();
    expect(sent).not.toContain("gmx.de");
    expect(sent).not.toContain("shop.example");
    expect(sent).not.toContain("hunter2");
    expect(sent).toContain("Site A");
    const reused = plan.steps.find((s) => s.kind === "reused");
    expect(reused).toMatchObject({
      count: 2,
      priority: "critical",
      title: "Passwort für gmx.de ändern",
      sites: ["gmx.de"],
    });
    expect(reused?.detail).toBe("gmx.de und shop.example nutzen dasselbe Passwort.");
    expect(plan.steps.some((s) => s.kind === "insecure-url")).toBe(false);
    // Findings the model left out keep the rule step.
    expect(plan.steps.find((s) => s.kind === "breached")?.title).toBeUndefined();
  });

  it("sends domains as they are to self-hosted models, without hosts that hold a secret", () => {
    const guard = new SecretGuard();
    guard.add("shop.example");
    const { input } = redactFindings(findings, "en", "self-hosted", guard);
    expect(input.pseudonymized).toBe(false);
    expect(input.classes).toEqual(["D1", "D2"]);
    expect(input.value.sites.map((s) => s.site)).toEqual(["gmx.de", "forum.example"]);
    expect(placeholder(0)).toBe("Site A");
    expect(placeholder(26)).toBe("Site AA");
  });

  it("falls back to rules without AI or on bad answers", async () => {
    const off = await securityPlan(AiGateway.disabled(), findings, "en", new SecretGuard());
    expect(off.source).toBe("rules");
    expect(off.fallbackReason?.code).toBe("not_allowed");
    const bad = await securityPlan(
      new AiGateway({ settings, provider: recordingProvider({ steps: [{ kind: "rm" }] }) }),
      findings,
      "en",
      new SecretGuard(),
    );
    expect(bad.source).toBe("rules");
    expect(bad.fallbackReason?.code).toBe("invalid_response");
  });

  it("cleans model text", () => {
    expect(cleanText("a\u0000b\n\nc", 10)).toBe("a b c");
    expect(cleanText("abcdefghij", 5)).toBe("abcd…");
  });
});
