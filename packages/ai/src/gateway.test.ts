import { describe, expect, it, vi } from "vitest";
import { AiGateway, classAllowed } from "./gateway";
import { IMPORT_MAPPING, redactColumns } from "./importMapping";
import {
  openAiCompatibleProvider,
  promptApiProvider,
  providerFromSettings,
  recordingProvider,
  stripFence,
} from "./providers";
import { Redacted, SecretGuard } from "./redacted";
import { DEFAULT_AI_SETTINGS, endpointProblem, featureEnabled, parseAiSettings, providerProblem } from "./settings";

const input = () => redactColumns({ headers: ["A", "B"], rows: [["x", "y"]] }, [], [0, 1]);

describe("Redacted", () => {
  it("cannot be constructed outside the redaction layer", () => {
    const Ctor = Redacted as unknown as new (...args: unknown[]) => unknown;
    expect(() => new Ctor(Symbol("passbox.redacted"), "raw", ["D1"], false)).toThrow(/redaction layer/);
    expect(Object.isFrozen(input())).toBe(true);
  });

  it("guards match equal and contained secrets, not short ones", () => {
    const guard = new SecretGuard();
    guard.addAll(["hunter2-long", "no", undefined]);
    expect(guard.size).toBe(1);
    expect(guard.leaks("HUNTER2-LONG")).toBe(true);
    expect(guard.leaks("x hunter2-long y")).toBe(true);
    expect(guard.leaks("no")).toBe(false);
    expect(JSON.stringify({ guard })).not.toContain("hunter2");
  });
});

describe("settings", () => {
  it("are off by default and sanitized", () => {
    expect(DEFAULT_AI_SETTINGS.enabled).toBe(false);
    expect(parseAiSettings(null)).toEqual({ enabled: false, features: [] });
    expect(parseAiSettings({ enabled: "yes", features: ["import-mapping", "evil"] })).toEqual({
      enabled: false,
      features: ["import-mapping"],
    });
    const parsed = parseAiSettings({
      enabled: true,
      provider: { location: "self-hosted", endpoint: " http://gpu.lan/v1 ", model: "qwen", extra: 1 },
      features: ["import-mapping"],
    });
    expect(parsed.provider).toEqual({ location: "self-hosted", endpoint: "http://gpu.lan/v1", model: "qwen" });
    expect(featureEnabled(parsed, "import-mapping")).toBe(true);
    expect(featureEnabled(parsed, "security-copilot")).toBe(false);
  });

  it("check endpoints like the Rust gateway", () => {
    expect(endpointProblem("https://api.mistral.ai/v1", "cloud")).toBeUndefined();
    expect(endpointProblem("http://api.mistral.ai/v1", "cloud")).toBe("cloud_https");
    expect(endpointProblem("http://localhost:11434/v1", "on-device")).toBeUndefined();
    expect(endpointProblem("", "on-device")).toBeUndefined();
    expect(endpointProblem("http://192.168.1.2:11434/v1", "on-device")).toBe("on_device_local");
    expect(endpointProblem("http://192.168.1.2:11434/v1", "self-hosted")).toBeUndefined();
    expect(endpointProblem("http://[::1]:8000/v1", "self-hosted")).toBeUndefined();
    expect(endpointProblem("http://example.com/v1", "self-hosted")).toBe("http_not_local");
    expect(endpointProblem("https://u:p@example.com", "self-hosted")).toBe("credentials");
    expect(endpointProblem("ftp://example.com", "self-hosted")).toBe("scheme");
    expect(endpointProblem("", "self-hosted")).toBe("missing");
    expect(providerProblem({ location: "cloud", endpoint: "https://a.example/v1", model: "m" })).toBe("key_missing");
    expect(providerProblem({ location: "self-hosted", endpoint: "http://localhost:1/v1", model: "" })).toBe(
      "model_missing",
    );
  });
});

describe("gateway", () => {
  it("applies the data class rules", () => {
    expect(classAllowed("D1", "cloud", false)).toBe(true);
    expect(classAllowed("D2", "cloud", false)).toBe(false);
    expect(classAllowed("D2", "cloud", true)).toBe(true);
    expect(classAllowed("D3", "cloud", true)).toBe(false);
    expect(classAllowed("D3", "self-hosted", false)).toBe(true);
  });

  it("enforces the organization policy", async () => {
    const provider = recordingProvider({ columns: [] });
    const gateway = new AiGateway({
      settings: {
        enabled: true,
        provider: { location: "cloud", endpoint: "https://a.example/v1", model: "m", apiKeyItemId: "i" },
        features: ["import-mapping"],
      },
      provider,
      policy: { allowedLocations: ["on-device", "self-hosted"] },
    });
    await expect(gateway.complete(IMPORT_MAPPING, input(), (a) => a)).rejects.toMatchObject({ code: "not_allowed" });
    expect(provider.requests).toHaveLength(0);
  });

  it("logs metadata of every request, never the input", async () => {
    const entries: unknown[] = [];
    const gateway = new AiGateway({
      settings: {
        enabled: true,
        provider: { location: "on-device", endpoint: "", model: "" },
        features: ["import-mapping"],
      },
      provider: recordingProvider({ columns: [] }, "on-device"),
      onLog: (e) => entries.push(e),
    });
    await gateway.complete(IMPORT_MAPPING, input(), (a) => a);
    expect(entries).toEqual([
      expect.objectContaining({ feature: "import-mapping", provider: "recording", classes: ["D1"], outcome: "ok" }),
    ]);
    expect(JSON.stringify(entries)).not.toContain('"A"');
  });
});

describe("providers", () => {
  it("call an OpenAI-compatible endpoint with the key as a header only", async () => {
    const fetch = vi.fn(
      async (_url: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ choices: [{ message: { content: '```json\n{"columns":[]}\n```' } }] }), {
          status: 200,
        }),
    );
    const provider = openAiCompatibleProvider({
      baseUrl: "https://api.example.eu/v1/",
      model: "small",
      apiKey: "sk-test-key",
      location: "cloud",
      jurisdiction: "EU",
      fetch,
    });
    const answer = await provider.complete({
      feature: "import-mapping",
      classes: ["D1"],
      system: IMPORT_MAPPING.system,
      input: input(),
      schema: IMPORT_MAPPING.schema,
    });
    expect(answer).toEqual({ columns: [] });
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("https://api.example.eu/v1/chat/completions");
    expect((init?.headers as Record<string, string> | undefined)?.authorization).toBe("Bearer sk-test-key");
    expect(init?.credentials).toBe("omit");
    expect(String(init?.body)).not.toContain("sk-test-key");
    expect(JSON.parse(String(init?.body)).model).toBe("small");
    expect(provider.jurisdiction).toBe("EU");
  });

  it("report errors as AiError", async () => {
    const provider = openAiCompatibleProvider({
      baseUrl: "http://localhost:11434/v1",
      model: "llama3.2",
      location: "on-device",
      fetch: async () => new Response("no", { status: 500 }),
    });
    const request = {
      feature: "import-mapping" as const,
      classes: ["D1" as const],
      system: "",
      input: input(),
      schema: {},
    };
    await expect(provider.complete(request)).rejects.toMatchObject({ code: "provider" });
    expect(() => openAiCompatibleProvider({ baseUrl: "https://a.example/v1", model: "m", location: "cloud" })).toThrow(
      /API key/,
    );
  });

  it("use the browser's built-in model for on-device without endpoint", async () => {
    const prompts: string[] = [];
    const scope = {
      LanguageModel: {
        availability: async () => "available" as const,
        create: async () => ({
          prompt: async (text: string) => {
            prompts.push(text);
            return '{"columns":[]}';
          },
          destroy: () => undefined,
        }),
      },
    };
    const provider = promptApiProvider(scope);
    expect(provider.location).toBe("on-device");
    await expect(
      provider.complete({ feature: "import-mapping", classes: ["D1"], system: "", input: input(), schema: {} }),
    ).resolves.toEqual({ columns: [] });
    expect(prompts[0]).toContain('"header":"A"');
    expect(providerFromSettings({ location: "on-device", endpoint: "", model: "" }).id).toBe("browser");
    expect(() => providerFromSettings({ location: "cloud", endpoint: "https://a.example/v1", model: "m" })).toThrow();
    expect(stripFence("```\n{}\n```")).toBe("{}");
  });
});
