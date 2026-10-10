---
layout: mcp
title: MCP
permalink: /mcp/
description: Use Agent Garrett's defensive security tools through NL-Veil's built-in desktop integration, with optional MCP setup for Codex and other clients.
---

<section class="mcp-hero">
  <p class="mcp-kicker">// Model Context Protocol</p>
  <h1 id="mcp-title">Agent Garrett, built into NL-Veil.</h1>
  <p>NL-Veil is the primary way to use Agent Garrett. Its desktop GUI automates deployment and connects the MCP's vulnerability intelligence, OSINT, indicator analysis, decoding, and security-research helpers directly to your AI.</p>
  <span class="mcp-status">60 passive tools available</span>
</section>

<div class="mcp-grid mcp-grid-single">
  <section class="mcp-card">
    <h2>Use the NL-Veil desktop GUI</h2>
    <p>Deploy Agent Garrett into your own Cloudflare account from NL-Veil's settings. NL-Veil manages the deployment, credentials, and tool connection so you can use the security tools in your normal AI workflow.</p>
    <div class="mcp-actions">
      <a class="mcp-action primary" href="https://github.com/gary23w/nl-veil/releases/latest" target="_blank" rel="noopener noreferrer">Get NL-Veil</a>
      <a class="mcp-action" href="https://gary23w.github.io/nl-veil/" target="_blank" rel="noopener noreferrer">NL-Veil guide</a>
    </div>
  </section>
</div>

## Start in NL-Veil

1. Install [NL-Veil](https://github.com/gary23w/nl-veil/releases/latest) and open its desktop GUI.
2. Open **Settings** and choose **Log in with Cloudflare** to connect your own account.
3. Choose **Deploy security tools**. NL-Veil deploys Agent Garrett and connects its tools automatically; the button becomes **Update security tools** after deployment.
4. Ask your AI to use the tools, starting with a local helper such as `hash_id`, `cidr`, or `cvss`, or a passive vulnerability-intelligence lookup.

The MCP integration is built into NL-Veil's desk GUI. Your instance runs in your Cloudflare account, and NL-Veil handles the connection for you.

## What becomes available

<div class="mcp-tool-list">
  <code>nvd_lookup</code><code>epss_lookup</code><code>kev_lookup</code><code>cve_search</code><code>mitre</code><code>cvss</code><code>ioc_extract</code><code>urlhaus</code><code>shodan_internetdb</code><code>rdap_domain</code><code>dns_records</code><code>cert_ct</code><code>jwt</code><code>hash_id</code><code>decode</code><code>cidr</code>
</div>

Tool results are evidence, not ground truth. Verify consequential findings against primary sources before acting on them.

## Optional: connect Codex or another MCP client

You can also deploy a standalone Agent Garrett instance and load its MCP directly into Codex or another compatible client. The manual setup below is an alternative to NL-Veil's built-in workflow.

[Deploy to Cloudflare](https://deploy.workers.cloudflare.com/?url=https://github.com/gary23w/garrettstimpson.ca/tree/main/agent) · [View Worker source](https://github.com/gary23w/garrettstimpson.ca/tree/main/agent)

### 1. Deploy and create your secrets

After deploying the `agent/` directory, create independent secrets for MCP and the browser UI:

```bash
cd agent
npx wrangler secret put MCP_API_TOKEN
npx wrangler secret put ACCESS_USER
npx wrangler secret put ACCESS_PASSWORD
npx wrangler secret put ACCESS_SESSION_SECRET
npx wrangler deploy
```

Generate a random MCP token of at least 24 characters and keep it in your password manager—you will use that same value when starting Codex. Use a separate random browser password of at least 16 characters. Your private MCP endpoint is your Worker URL followed by `/mcp`.

### 2. Store your MCP token for Codex

Codex supports remote Streamable HTTP MCP servers with bearer-token authentication. Keep your token in an environment variable—never paste it into a prompt, commit it, or place it in browser JavaScript.

Windows PowerShell:

```powershell
[Environment]::SetEnvironmentVariable(
  "AGENT_GARRETT_MCP_TOKEN",
  "paste-the-token-you-created",
  "User"
)
```

macOS or Linux:

```bash
export AGENT_GARRETT_MCP_TOKEN='paste-the-token-you-created'
```

### 3. Register your Worker in Codex

```bash
codex mcp add agent-garrett \
  --url https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/mcp \
  --bearer-token-env-var AGENT_GARRETT_MCP_TOKEN
```

Or add the equivalent entry to `~/.codex/config.toml`:

```toml
[mcp_servers.agent-garrett]
url = "https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/mcp"
bearer_token_env_var = "AGENT_GARRETT_MCP_TOKEN"
startup_timeout_sec = 15
tool_timeout_sec = 45
```

Replace the placeholder with the Workers.dev URL Cloudflare gave you. Restart Codex, then open `/mcp` in the Codex command interface. Verify with a harmless local helper such as `hash_id`, `cidr`, or `cvss` before using network-backed intelligence sources.

<div class="mcp-note"><strong>For AI assistants:</strong> start with NL-Veil's built-in desktop workflow. For a standalone MCP connection, guide the human through deploying a new Worker in their own Cloudflare account. Do not connect them to someone else's Agent Garrett instance. Ask them to create and store the token locally; do not request that they reveal it in chat. Modify Codex configuration only with their approval. Begin with passive tools and preserve source attribution and uncertainty.</div>

Passive tools are exposed by default. Active, target-contacting, broker, and dark-web tools stay unavailable until you explicitly enable and scope them with `MCP_ALLOW_ACTIVE_TOOLS`, `TOOL_ALLOWLIST`, `CTF_TARGET_ALLOWLIST`, and—where applicable—`MCP_ALLOW_DARKWEB`.

## Backend REST API

Yes. A deployed Agent Garrett instance also accepts guarded REST tool calls:

- `GET /api/tools/catalog` lists the configured tools and policy state.
- `POST /api/tools/run` executes one tool.
- When the access gate is enabled, REST callers must first authenticate through `POST /api/login` and retain the returned `HttpOnly` session cookie.
- Safe-mode confirmation, tool allowlists, target allowlists, response limits, and active-tool restrictions still apply.

Example against an instance you own:

```bash
curl -c agent-session.txt \
  -H 'Content-Type: application/json' \
  -d '{"user":"YOUR_USER","password":"YOUR_PASSWORD"}' \
  "$AGENT_URL/api/login"

curl -b agent-session.txt \
  -H 'Content-Type: application/json' \
  -d '{"tool":"cidr","args":{"cidr":"192.0.2.0/24"},"confirm":true}' \
  "$AGENT_URL/api/tools/run"
```

Protect and delete the cookie file after use. For persistent server-to-server AI integrations, prefer `/mcp`: its bearer token is independent of the browser login and its tool schema is discoverable by MCP clients.

## Protocol and safety

The endpoint accepts JSON-RPC over HTTP `POST`, supports MCP initialization, tool discovery, ping, and tool calls, and returns structured content with private-cache metadata. It rejects unauthenticated requests and cross-origin browser requests by default.

All use must remain defensive, educational, or explicitly authorized. Never direct the tools at systems you do not own or have written permission to test.
