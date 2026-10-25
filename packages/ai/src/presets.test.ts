import { describe, expect, it } from "vitest";
import { PROVIDER_PRESETS, presetById, presetForEndpoint } from "./presets";
import { ANTHROPIC_VERSION, anthropicProvider, providerFromSettings } from "./providers";
import { seal } from "./redacted";
import { endpointProblem, parseAiSettings, providerProblem } from "./settings";
import type { AiRequest } from "./types";

/** A request as the gateway builds it. */
function request(): AiRequest {
  return {
    feature: "import-mapping",
    classes: ["D1"],
    system: "Map columns.",
    input: seal({ columns: [] }, ["D1"]),
    schema: { type: "object" },
  };
}

describe("provider presets", () => {
  it("are valid cloud endpoints with a region", () => {
    const ids = new Set<string>();
    for (const preset of PROVIDER_PRESETS) {
      expect(ids.has(preset.id)).toBe(false);
      ids.add(preset.id);
      expect(endpointProblem(preset.baseUrl, preset.location)).toBeUndefined();
      expect(["EU", "US"]).toContain(preset.jurisdiction);
      expect(preset.domain).toBeTruthy();
      if (preset.model) expect(preset.models).toContain(preset.model);
    }
    for (const id of ["mistral", "ionos", "stackit", "scaleway", "langdock"]) {
      expect(presetById(id)?.jurisdiction).toBe("EU");
    }
    expect(presetById("anthropic")?.api).toBe("anthropic");
    expect(presetForEndpoint("https://api.scaleway.ai/v1/")?.id).toBe("scaleway");
    expect(presetForEndpoint("https://example.com/v1")).toBeUndefined();
  });

  it("are kept in the settings, unknown presets are dropped", () => {
    const parsed = parseAiSettings({
      enabled: true,
      provider: {
        location: "cloud",
        endpoint: "https://api.anthropic.com/v1",
        model: "claude-opus-5-5",
        apiKeyItemId: "k",
        jurisdiction: "US",
        api: "anthropic",
        preset: "anthropic",
      },
      features: [],
    });
    expect(parsed.provider?.api).toBe("anthropic");
    expect(parsed.provider?.preset).toBe("anthropic");
    const other = parseAiSettings({
      provider: { location: "cloud", endpoint: "https://x.example/v1", model: "m", api: "weird", preset: "nope" },
    });
    expect(other.provider?.api).toBeUndefined();
    expect(other.provider?.preset).toBeUndefined();
    // A cloud preset still needs the key as a vault item.
    expect(
      providerProblem({ location: "cloud", endpoint: "https://api.mistral.ai/v1", model: "mistral-small-latest" }),
    ).toBe("key_missing");
  });
});

describe("Anthropic Messages API", () => {
  it("sends the key as x-api-key, never in the prompt, and reads text blocks", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fake = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(
        JSON.stringify({
          content: [
            { type: "thinking", thinking: "…" },
            { type: "text", text: '```json\n{"ok":true}\n```' },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    const provider = providerFromSettings(
      {
        location: "cloud",
        endpoint: "https://api.anthropic.com/v1/",
        model: "claude-opus-5-5",
        apiKeyItemId: "item",
        jurisdiction: "US",
        api: "anthropic",
      },
      "sk-ant-test",
      fake,
    );
    expect(provider.id).toBe("anthropic");
    expect(provider.jurisdiction).toBe("US");
    expect(await provider.complete(request())).toEqual({ ok: true });
    const [call] = calls;
    expect(call?.url).toBe("https://api.anthropic.com/v1/messages");
    const headers = call?.init.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("sk-ant-test");
    expect(headers["anthropic-version"]).toBe(ANTHROPIC_VERSION);
    expect(headers.authorization).toBeUndefined();
    expect(call?.init.credentials).toBe("omit");
    const body = JSON.parse(String(call?.init.body));
    expect(body.model).toBe("claude-opus-5-5");
    expect(body.system).toMatch(/^Map columns\./);
    expect(String(call?.init.body)).not.toContain("sk-ant-test");
  });

  it("refuses incomplete settings", () => {
    expect(() =>
      anthropicProvider({ baseUrl: "https://api.anthropic.com/v1", model: "m", apiKey: undefined }),
    ).toThrow();
    expect(() => anthropicProvider({ baseUrl: "http://api.anthropic.com/v1", model: "m", apiKey: "k" })).toThrow();
  });
});
