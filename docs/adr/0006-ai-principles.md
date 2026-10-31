# ADR 0006: AI principles: secrets never reach a model, bring your own model

- Status: accepted
- Date: 2026-10-25

## Context

Passbox has two kinds of AI features (concept in docs/planning/ai-native.md, German):

- **AI agents** (Claude Code, Cursor, Codex, …) that use the user's secrets through `pbx mcp` and the agent broker ([ai-agents.md](../architecture/ai-agents.md)).
- **Passbox's own features** that call a model through the AI gateway, such as the import column mapping (K6) and the security copilot (K4) ([ai-gateway.md](../architecture/ai-gateway.md)).

Both are where a password manager can lose the property it exists for. A prompt, a model provider's log or an agent's context window is not a vault. The owner decided the following rules on 25.10.2026; the code enforces them where it can, and the documentation says where it cannot.

## Decision

1. **Secrets never reach a model, local or remote.** Data class D4 (passwords, other concealed field values, one-time password seeds, card numbers and security codes, private keys and passkeys) is never part of a model input. This holds for on-device and self-hosted models too: "local" is not a reason to relax it, because a local model's input can still end up in logs, caches or a plugin. In the gateway D4 is not even representable (`Redacted<T>` can only be built from D0–D3 by the redaction layer, and a secret guard rejects anything that looks like a stored secret); agent tools return metadata and effects, never values.

2. **The only exception is `passbox_reveal`, per grant and explicit.** An agent may see one value only when:
   - the user started `pbx mcp --allow-reveal` (off by default),
   - the user approved a grant for that item on another device **and** ticked "Allow revealing the value to the agent" for that grant, after a strong warning (the decision is signed in a separate format, so an approval without the tick can never be turned into one with it),
   - the vault is personal, or the organization's signed policy has `allowAgentReveal` (default **false**; enforced by the approving app's core, the broker and the server), and
   - the server accepted the `reveal` agent event before the broker hands out the value (fail closed). Every reveal is its own audit event (`agent_reveal`).

   Passbox's own features have no such exception.

3. **AI is off by default and opt-in per feature.** Nothing calls a model until the user switches AI on and then switches on each feature separately; a feature that would send data to a cloud provider asks first and names the provider and region. Every feature works without a model (deterministic fallback). Organizations can restrict locations and data classes by policy.

4. **Bring your own model; no Passbox-hosted inference for now.** Passbox does not run or resell inference, also not "EU-hosted" inference. Users choose the browser's built-in model, a model on their own machine or server (Ollama, vLLM, LocalAI, LiteLLM), or a cloud provider with their own API key, stored as a vault item. Presets fill in the endpoint and show the region: Mistral (France), IONOS AI Model Hub (Germany), STACKIT (Germany), Scaleway (France), Langdock (Germany, EU region), OpenAI (USA) and Anthropic (USA, native Messages API). The data-class rules (D2 metadata, D3 content) apply to every provider in the same way. Self-hosting keeps every option.

5. **Members' personal data is pseudonymised by default for a future admin assistant (K9).** When an admin assistant summarises an organization's audit log or reports, names, email addresses and account IDs of members are replaced with stable pseudonyms ("Member 7") before they reach a model and mapped back on the device. Sending real names needs an explicit setting per organization, which is off by default. Secrets and item contents are never part of it (rule 1).

## Consequences

- Features that would need secrets in a prompt (for example "let the model log in for me") are not built; agents use secrets through `passbox_run` and `passbox_inject`, where values go into a process or a file and output is redacted.
- `passbox_reveal` exists because some tasks really need the value (pasting into a web form the agent drives, debugging a connection string). Its risk is honest: once revealed, the value is in the agent's context and its provider's systems and cannot be taken back. The approval dialog says so; organizations can forbid it.
- Without hosted inference there is no Passbox AI bill, no data processing agreement for inference and no lock-in; users without a model of their own simply do not get the AI enhancements. Offering hosted inference later needs a new ADR.
- The pseudonymisation rule shapes K9 before it is built: the redaction layer gets a pseudonym map for members, as the security copilot already does for websites ("Site A").
- The rules are in the code and the tests: the gateway's boundary tests (no dependency on the core or the client), the secret guard, the broker's tests for reveal without the tick, with the tick, and with an organization policy, the server tests for `agent_reveal_not_allowed`, and the policy tests for the `allow_agent_reveal` default.

## References

- [docs/architecture/ai-gateway.md](../architecture/ai-gateway.md): data classes and flows of Passbox's own features.
- [docs/architecture/ai-agents.md](../architecture/ai-agents.md): `pbx mcp`, grants, `passbox_reveal` and the threat model.
- [docs/architecture/administration.md](../architecture/administration.md): the `allowAgentReveal` policy rule.
