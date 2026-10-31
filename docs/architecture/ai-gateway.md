# AI gateway: providers, redaction and what each feature sends

> **Draft.** Not reviewed by cryptographers and not audited. The settings format may still change.

This document describes the AI gateway that Passbox's own AI features use: providers, settings, redaction and what each feature sends. Agent access (`pbx mcp`) and the agent audit are a separate building block: see [ai-agents.md](ai-agents.md). `pbx scan` uses no AI and is documented in [cli.md](https://github.com/passboxnet/cli/blob/main/docs/cli.md#finding-leaked-secrets-pbx-scan).

The binding rules are in [ADR 0006: AI principles](../adr/0006-ai-principles.md): secrets never reach a model (local or remote), the only exception being the explicit per-grant `passbox_reveal` for agents; AI off by default and opt-in per feature; bring your own model, no Passbox-hosted inference; members' names and emails pseudonymised by default for a future admin assistant.

## Principles in code

- **AI is off by default and opt-in per feature.** Settings start with `enabled: false` and no features. Every feature has its own switch and states what it sends.
- **Everything works without AI.** Each feature has a deterministic result: import mapping falls back to header rules and value patterns, the security plan to rules. A model failure, an invalid answer, a timeout or a policy refusal silently uses the fallback (and the UI says so).
- **AI code gets no keys.** The gateway packages cannot depend on the core or the client:
  - `crates/ai` (`passbox-ai`): `tests/boundary.rs` fails if `Cargo.toml` names `passbox-core`, `passbox-client`, `passbox-core-wasm` or `passbox-ffi`, or if any of them is in the dependency closure of `passbox-ai` in `Cargo.lock`.
  - `packages/ai` (`@passbox/ai`): `src/boundary.test.ts` fails if `package.json` depends on `@passbox/core-wasm`, `@passbox/client` or `@passbox/api-client`, or if a source file imports them (or reaches into other packages with `../../`); `biome.json` has a `noRestrictedImports` rule for `packages/ai/**` so `pnpm lint` fails too.
- **Only the redaction layer builds model input.** `Redacted<T>` has no public constructor: a newtype with a `pub(crate)` constructor in Rust, a class with a private constructor and a module-private seal in TypeScript (which also throws at run time). Providers accept only `Redacted` input. The feature modules are the redaction layer: they take raw data and keep only what their data classes allow.
- **Secrets (D4) are not representable.** There is no data class for passwords, TOTP seeds, card numbers, private keys or hidden fields. Additionally a `SecretGuard` (memory only, per request) holds values that must never leave the device; every string a redaction function lets through is checked against it (equality ignoring case, or containment, for values of 4+ characters).
- **Your model, your key.** Providers: the browser's built-in model (Chrome Prompt API, `LanguageModel`) or a model server on `localhost` (on-device), a self-hosted OpenAI-compatible endpoint (Ollama, vLLM, LocalAI, LiteLLM), or a cloud provider with your own key: an OpenAI-compatible API (presets for Mistral, IONOS, STACKIT, Scaleway, Langdock, OpenAI) or Anthropic's native Messages API. There is no Passbox-operated inference service, also no "EU-hosted" one ([ADR 0006](../adr/0006-ai-principles.md)). Self-hosted instances get every feature.

## Components

```
feature (web: import mapping step, security check)          raw data stays here
   │  raw table / findings ──▶ redaction (packages/ai feature module) ──▶ Redacted<input>
   ▼
AiGateway ── checks: setting on? provider location allowed by the feature manifest and the
   │         organization policy? every data class declared, not forbidden, allowed at the location?
   │         logs: feature, provider, location, classes, bytes, outcome (never the input)
   ▼
AiProvider ── OpenAI-compatible HTTP (fetch / ureq) │ Chrome Prompt API │ test fakes
   ▼
JSON answer ──▶ feature validates it (schema, allowed values, local counts) ──▶ shown as plain text
```

| Piece | Rust (`crates/ai`) | TypeScript (`packages/ai`) |
| --- | --- | --- |
| Types, provider trait | `provider.rs` (`AiProvider`, `AiRequest`, `ModelLocation`, `OpenAiCompatible`, `Anthropic`, `provider_from_settings`, `HttpPost`) | `types.ts`, `providers.ts` (`openAiCompatibleProvider`, `anthropicProvider`, `promptApiProvider`, `providerFromSettings`, `recordingProvider`) |
| Provider presets | `presets.rs` (`PROVIDER_PRESETS`; a test checks it matches the TypeScript list) | `presets.ts` (`PROVIDER_PRESETS`, `presetById`, `presetForEndpoint`) |
| Redaction | `redact.rs` (`Redacted`, `DataClass`, `SecretGuard`) | `redacted.ts` |
| Gateway, settings, policy, log | `gateway.rs` | `gateway.ts`, `settings.ts` |
| Import mapping | `import_mapping.rs` | `importMapping.ts` |
| Security copilot | `security_copilot.rs` | `securityCopilot.ts` |

The web app ([passboxnet/web](https://github.com/passboxnet/web)) wires it up in `app/src/ai` (settings panel, gateway hook, security plan) and `app/src/import/MappingSuggestion.tsx`. Native clients can use `passbox-ai` later through the FFI; nothing calls it yet outside its tests.

## Settings

Stored per account **in this browser** (`localStorage`, key `passbox.ai.<accountId>`), not synced:

```json
{
  "enabled": true,
  "provider": {
    "location": "self-hosted",
    "endpoint": "http://gpu.lan:11434/v1",
    "model": "llama3.2",
    "apiKeyItemId": "…",
    "jurisdiction": "EU",
    "api": "openai",
    "preset": "ionos"
  },
  "features": ["import-mapping", "security-copilot"]
}
```

- `location` is `on-device`, `self-hosted` or `cloud`. On-device endpoints must be loopback (`localhost`, `127.0.0.0/8`, `::1`); an empty endpoint means the browser's built-in model.
- Endpoint rules (same in Rust and TypeScript): `https://` always; `http://` only for loopback, private IPv4 ranges, IPv6 unique local addresses and `.local`/`.internal`/`.lan` names, and never for cloud providers; no user name or password in the URL.
- **API keys are vault items.** Settings hold the item ID only. The app reads the item's password (or first hidden field) when it creates the provider and sends it as the `Authorization: Bearer` header. It is never part of the prompt. Requests are sent with `credentials: "omit"` and `referrerPolicy: "no-referrer"`.
- `api` is `openai` (default, `POST {endpoint}/chat/completions` with `Authorization: Bearer`) or `anthropic` (`POST {endpoint}/messages` with `x-api-key`, `anthropic-version: 2023-06-01` and, in the browser, `anthropic-dangerous-direct-browser-access: true`, which Anthropic requires for calls from a web page; the key is the user's own). `preset` names the preset the settings came from; typing another endpoint clears it.
- The endpoint must allow cross-origin requests from the web app's origin (for Ollama: `OLLAMA_ORIGINS`).

### Provider presets (cloud, your own key)

Settings → AI → "Provider" fills in endpoint, API, region and a suggested model. Base URLs come from each provider's official API documentation; model names change more often, so the suggestion is only a start (the UI says when a suggested model was not confirmed in the docs). The data classes the features send (D1 structure, D2 metadata; never D4 secrets) are the same for every provider, and the cloud confirmation names provider and region.

| Preset | API | Base URL | Region | Suggested model | Notes |
| --- | --- | --- | --- | --- | --- |
| Mistral AI | OpenAI-compatible | `https://api.mistral.ai/v1` | EU (France) | `mistral-small-latest` (not confirmed in the docs) | |
| IONOS AI Model Hub | OpenAI-compatible | `https://openai.inference.de-txl.ionos.com/v1` | EU (Germany, Berlin) | `meta-llama/Meta-Llama-3.1-8B-Instruct` | Bearer token from the IONOS DCD |
| STACKIT AI Model Serving | OpenAI-compatible | `https://api.openai-compat.model-serving.eu01.onstackit.cloud/v1` | EU (Germany, `eu01`) | none: choose a chat model from the STACKIT portal | auth token from the STACKIT portal |
| Scaleway Generative APIs | OpenAI-compatible | `https://api.scaleway.ai/v1` | EU (France, Paris) | `llama-3.3-70b-instruct` | IAM secret key |
| Langdock | OpenAI-compatible | `https://api.langdock.com/openai/eu/v1` | EU region (company in Germany) | none: models depend on the workspace | API key with the Completion API scope; requests go to the model deployment configured for the workspace; the docs name the `eu` region but give no further residency guarantee |
| OpenAI | OpenAI-compatible | `https://api.openai.com/v1` | USA | `gpt-4.1-mini` (not confirmed in the docs) | |
| Anthropic | Anthropic Messages API | `https://api.anthropic.com/v1` | USA (inference can be limited to the US; no EU option documented) | `claude-opus-5-5` (also `claude-sonnet-5-5`, `claude-haiku-5-5`) | native API, not the OpenAI compatibility layer |

Each preset has an optional `domain` (for example `ionos.de`) for a favicon. Sources: the providers' API documentation linked in `presets.ts`.
- **Opt-in disclosure:** each feature switch says what it sends; the panel shows where it goes ("Goes to your server gpu.lan:11434"); switching a feature on with a cloud provider asks for confirmation and names the host and the country or region.
- **Organization policy** (`AiPolicy`: allowed locations, forbidden data classes, required endpoint prefix) is enforced by the gateway. It is not yet delivered by the server or the extension's managed storage; that will come through the signed organization policies ([administration.md](administration.md#policies)).

## The AI log

Every request a gateway sends is recorded locally: time, feature, provider ID, location, data classes, input size in bytes and outcome (`ok`, `failed`, `invalid`). The web app keeps the last 50 entries per account in `localStorage` (`passbox.ai.log.<accountId>`) and shows them under **Settings → AI features → AI log**, with a button to clear it. The log never contains the input or the answer.

## Data flows

Data classes: **D0** the user's own input, **D1** structure (headers, value patterns, counts), **D2** metadata (titles, domains, usernames), **D3** content (notes, custom fields). D4 (secrets) does not exist in the code. The gateway allows D0 and D1 everywhere, D2 to cloud providers only pseudonymized, D3 never to the cloud.

### Smart import mapping (`import-mapping`, D1)

When a CSV file is imported as "Excel / CSV", the header rules (`detectColumns`, English and German synonyms) map what they recognize. Columns they do not recognize become extra fields; for those the mapping step offers **Suggest fields** (patterns, on this device) or, with the feature on, **Suggest with AI**. Suggestions are marked in the table ("AI suggestion" / "Suggested"), can be undone, and nothing is imported until the user continues.

**Sent to the model (exactly):**

```json
{
  "targets": [{ "id": "title", "single": true, "description": "name of the entry or service" }, …],
  "columns": [
    {
      "index": 3,
      "header": "Seite2",
      "current": "field",
      "unknown": true,
      "profile": {
        "filled": 1,
        "kinds": { "url": 1 },
        "length": { "min": 23, "median": 24, "max": 24 },
        "entropy": "medium",
        "distinct": "unique"
      }
    }
  ]
}
```

- `header` is the column title, or `null` when it is empty, longer than 64 characters, looks like a value (URL, email, domain, number, date, UUID, Base32 or random string, as in a file without a header row) or equals or contains any cell value of the file.
- `profile` per column, computed over at most 2,000 rows (the web app reads at most the first 2 MB): `filled` (share of non-empty cells, in tenths), `kinds` (share per value kind, in tenths, ≥ 0.1: `otpauth`, `url`, `email`, `uuid`, `date`, `boolean`, `digits`, `phone`, `domain`, `base32`, `random-string`, `text`, `other`), `digitLength` (most common number of digits in digit columns, "6-digit number"), `length` (min, median, max characters, capped at 1,000), `entropy` (`low` < 28 bits, `medium` < 60 bits, `high`, median of the per-value Shannon estimate) and `distinct` (`constant`, `repeated`, `unique`).
- Plus the fixed system prompt and the answer schema.
- **Never:** any cell value or part of one. Unit tests in both languages send a table with distinctive values through a recording fake provider and assert that no cell (and no 8+ character part of one) appears in anything the provider received (`crates/ai/tests/gateway.rs`, `packages/ai/src/importMapping.test.ts`, and `app/src/ai/ai.test.ts` in passboxnet/web); the end-to-end test in passboxnet/web checks the real HTTP body.

**Answer:** `{ "columns": [{ "index", "target", "confidence" }] }`. An index outside the table or an unknown target makes the whole answer invalid (fallback). Only unknown columns change; single targets (title, username, email, password, url, totp, notes, folder, tags, favorite) stay unique, higher confidence wins.

**Without AI:** value patterns on this device: ≥ 80 % URLs → website, email addresses → username (or email if a username exists), `otpauth://` or Base32 → one-time password, random strings → hidden field.

### Security copilot (`security-copilot`, D1 + D2)

The security check shows **Your plan** above the findings: up to five steps, most important first (breached passwords; reused passwords, critical when an email or finance account is among them; weak passwords; plain-http websites; missing two-factor sign-in for email, finance, developer and government accounts), each with a count, a priority and up to three sites to start with. Without AI the plan comes from rules and translated texts (German and English). With the feature on, **Explain with AI** asks the model for plain-language titles and explanations.

**Sent to the model (exactly):**

```json
{
  "language": "de",
  "analyzed": 42,
  "breachChecked": true,
  "counts": { "breached": 1, "reused": 6, "weak": 3, "insecure-url": 1, "no-totp": 30 },
  "sites": [
    { "site": "Site A", "category": "email", "kinds": ["reused", "no-totp"] },
    { "site": "Site B", "category": "finance", "kinds": ["weak"] }
  ]
}
```

- `sites`: at most 15, most important first. `site` is the website's domain for on-device and self-hosted models, and a placeholder (`Site A`, `Site B`, …) for cloud providers; the mapping stays on the device and placeholders in the answer are replaced locally. `category` comes from local domain lists (email, finance, developer, government, social, shopping, other).
- Hosts are only sent when they are valid domain names and do not contain any secret of the vault (the `SecretGuard` holds all passwords, hidden fields and TOTP secrets in memory for the request).
- **Never:** passwords, usernames, item titles, notes, URLs beyond the host, item IDs.

**Answer:** `{ "summary", "steps": [{ "kind", "title", "detail", "sites" }] }`, at most five steps. Counts and priorities always come from the local analysis, never from the model; steps for kinds without findings are dropped; sites the model invents are dropped; text is shown as plain text (control and bidirectional override characters removed, length capped). Findings the model leaves out keep their rule step.

### `pbx scan`

No model, no network. See [cli.md](https://github.com/passboxnet/cli/blob/main/docs/cli.md#finding-leaked-secrets-pbx-scan).

## Threat model (AI features)

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Vault secrets reach a model | D4 has no representation; features only accept metadata types; `SecretGuard` check on every outgoing string; tests with recording providers | A secret that a user typed into a CSV header or a domain shorter than 4 characters |
| Cell values of an import reach a model | Profiles contain shares, lengths and classes only; value-like headers and headers equal to a cell are dropped | Statistical facts (for example that a column holds 6-digit numbers) are sent by design |
| Domains reveal which services a person uses | Cloud providers get placeholders; on-device and self-hosted get domains after the feature opt-in | The categories (for example "finance") and the number of sites still go to the cloud |
| Prompt injection through headers or domains | Fixed system prompts that call them data; answers are validated against allowed values; text is plain text, never HTML or a command; nothing is applied without a click | A manipulated header could still sway a suggestion the user then confirms |
| A compromised or malicious model server | Answers cannot change counts, add sites or targets outside the allowed lists; invalid answers fall back; the gateway has no vault access and no keys | A wrong but valid suggestion |
| API key leaks | Stored as a vault item; sent only as the `Authorization` header to the configured endpoint; `credentials: "omit"` | The endpoint operator sees the key (by design) |
| Settings tampering in the browser | Settings live in `localStorage` of the signed-in origin; an attacker who can write there already runs code in the vault page | Same as any script injection in the web app |

## Not built yet

Organization policy from the server and the extension's managed schema; pseudonymization of D2 for features beyond the security plan; desktop and mobile settings screens; native on-device runtimes (Apple Foundation Models, Android on-device); natural-language search, categorization, phishing detection and the admin copilot.
