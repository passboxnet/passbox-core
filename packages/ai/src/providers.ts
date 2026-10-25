/**
 * Providers: an OpenAI-compatible endpoint (Ollama, vLLM, LocalAI,
 * LiteLLM, Mistral, OpenAI, …) and the browser's built-in model (Chrome
 * Prompt API). Both return parsed JSON; the feature validates it.
 */
import { endpointProblem, type ProviderSettings, providerProblem } from "./settings";
import { AiError, type AiProvider, type AiRequest, type ModelLocation } from "./types";

/** Removes a Markdown code fence some models put around JSON. */
export function stripFence(text: string): string {
  const t = text.trim();
  const fenced = t.match(/^```[a-z]*\s*([\s\S]*?)\s*```$/i);
  return fenced?.[1] ?? t;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(stripFence(text));
  } catch {
    throw new AiError("invalid_response", "the model did not answer with JSON");
  }
}

function systemPrompt(request: AiRequest): string {
  return `${request.system}\n\nAnswer with one JSON object that follows this JSON schema, nothing else:\n${JSON.stringify(request.schema)}`;
}

export interface OpenAiCompatibleOptions {
  id?: string;
  baseUrl: string;
  model: string;
  /** From a vault item; sent as the Authorization header, never in the prompt. */
  apiKey?: string | undefined;
  location: ModelLocation;
  jurisdiction?: string | undefined;
  fetch?: typeof globalThis.fetch;
}

/** `POST {baseUrl}/chat/completions` with JSON output. */
export function openAiCompatibleProvider(options: OpenAiCompatibleOptions): AiProvider {
  const problem = endpointProblem(options.baseUrl, options.location);
  if (problem || !options.baseUrl.trim()) throw new AiError("settings", `invalid endpoint (${problem ?? "missing"})`);
  if (!options.model.trim()) throw new AiError("settings", "choose a model name");
  if (options.location === "cloud" && !options.apiKey) {
    throw new AiError("settings", "a cloud provider needs an API key from a vault item");
  }
  const base = options.baseUrl.trim().replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  return {
    id: options.id ?? options.location,
    location: options.location,
    ...(options.jurisdiction ? { jurisdiction: options.jurisdiction } : {}),
    async complete(request) {
      const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
      if (options.apiKey) headers.authorization = `Bearer ${options.apiKey}`;
      let response: Response;
      try {
        response = await fetchImpl(`${base}/chat/completions`, {
          method: "POST",
          headers,
          // No cookies or other credentials of the page go to the endpoint.
          credentials: "omit",
          referrerPolicy: "no-referrer",
          ...(request.signal ? { signal: request.signal } : {}),
          body: JSON.stringify({
            model: options.model.trim(),
            temperature: 0,
            stream: false,
            response_format: { type: "json_object" },
            messages: [
              { role: "system", content: systemPrompt(request) },
              { role: "user", content: JSON.stringify(request.input.value) },
            ],
          }),
        });
      } catch (error) {
        throw new AiError(
          "provider",
          error instanceof Error && error.name === "TimeoutError"
            ? "the model did not answer in time"
            : "the model server could not be reached (is it running, and does it allow requests from this app?)",
        );
      }
      if (!response.ok) throw new AiError("provider", `the model server answered with status ${response.status}`);
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        throw new AiError("invalid_response", "the server did not answer with JSON");
      }
      const content = (body as { choices?: { message?: { content?: unknown } }[] }).choices?.[0]?.message?.content;
      if (typeof content !== "string") throw new AiError("invalid_response", "the answer has no message");
      return parseJson(content);
    },
  };
}

/** The part of Chrome's Prompt API (`LanguageModel`) Passbox uses. */
interface LanguageModelSession {
  prompt(input: string, options?: { responseConstraint?: unknown; signal?: AbortSignal }): Promise<string>;
  destroy(): void;
}
interface LanguageModelApi {
  availability(options?: unknown): Promise<"unavailable" | "downloadable" | "downloading" | "available">;
  create(options?: unknown): Promise<LanguageModelSession>;
}

function languageModel(scope: object): LanguageModelApi | undefined {
  const api = (scope as { LanguageModel?: LanguageModelApi }).LanguageModel;
  return api && typeof api.create === "function" ? api : undefined;
}

/** Whether the browser has a built-in model: "available", "downloadable", … or "unavailable". */
export async function promptApiAvailability(scope: object = globalThis): Promise<string> {
  const api = languageModel(scope);
  if (!api) return "unavailable";
  try {
    return await api.availability({ expectedInputs: [{ type: "text", languages: ["en"] }] });
  } catch {
    return "unavailable";
  }
}

/** The browser's built-in model (Chrome Prompt API): runs on this device. */
export function promptApiProvider(scope: object = globalThis): AiProvider {
  return {
    id: "browser",
    location: "on-device",
    async complete(request) {
      const api = languageModel(scope);
      if (!api) throw new AiError("provider", "this browser has no built-in model");
      const session = await api.create({
        initialPrompts: [{ role: "system", content: systemPrompt(request) }],
        ...(request.signal ? { signal: request.signal } : {}),
      });
      try {
        const text = await session.prompt(JSON.stringify(request.input.value), {
          responseConstraint: request.schema,
          ...(request.signal ? { signal: request.signal } : {}),
        });
        return parseJson(text);
      } finally {
        session.destroy();
      }
    },
  };
}

/**
 * The provider for the settings. `apiKey` is the value of the settings'
 * API key item, read from the vault by the app.
 */
export function providerFromSettings(
  settings: ProviderSettings,
  apiKey?: string,
  fetchImpl?: typeof globalThis.fetch,
): AiProvider {
  const problem = providerProblem(settings);
  if (problem) throw new AiError("settings", `the AI settings are incomplete (${problem})`);
  if (settings.location === "on-device" && !settings.endpoint.trim()) return promptApiProvider();
  return openAiCompatibleProvider({
    baseUrl: settings.endpoint,
    model: settings.model,
    apiKey,
    location: settings.location,
    jurisdiction: settings.jurisdiction,
    ...(fetchImpl ? { fetch: fetchImpl } : {}),
  });
}

/** A provider for tests that records every request and answers with `answer`. */
export function recordingProvider(
  answer: unknown | ((request: AiRequest) => unknown),
  location: ModelLocation = "cloud",
): AiProvider & { requests: AiRequest[]; sent(): string } {
  const requests: AiRequest[] = [];
  return {
    id: "recording",
    location,
    requests,
    sent: () => requests.map((r) => `${r.system}\n${JSON.stringify(r.input.value)}`).join("\n"),
    async complete(request) {
      requests.push(request);
      return typeof answer === "function" ? (answer as (r: AiRequest) => unknown)(request) : answer;
    },
  };
}
