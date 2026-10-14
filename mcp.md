---
layout: mcp
title: MCP
permalink: /mcp/
description: Connect Agent Garrett security tools to NL-Veil or another MCP client with your Cloudflare instance and one API key.
---

<section class="mcp-hero">
  <p class="mcp-kicker">// Model Context Protocol</p>
  <h1 id="mcp-title">Give your AI a security toolbelt.</h1>
  <p>Sign in with Cloudflare, activate Trial or Agent, and deploy your connection from one simple dashboard.</p>
  <div class="mcp-actions"><a class="mcp-action primary" href="https://agent.garrettstimpson.ca">Open Agent Garrett →</a></div>
</section>

## 1. Sign in and choose a plan

[Continue with Cloudflare](https://agent.garrettstimpson.ca). Your Cloudflare account is your Garrett account, and you authorize deployment to the Cloudflare account you choose.

- **Trial:** 3 days free with a credit card required. Automatically renews at **CAD $4.99/month** unless cancelled before the trial ends.
- **Agent:** **CAD $4.99/month**, starting immediately.

Manage your card, invoices, or cancellation from Billing in the dashboard. Cloudflare usage is billed separately by Cloudflare.

## 2. Deploy your instance and create a key

Choose an authorized Cloudflare account and deploy an instance. In API keys, select that instance and create a key. Copy it when it appears; the full key is shown only once.

Your Cloudflare Worker connects to the private Garrett security service. An active Trial or Agent subscription is required to use the tools. Expired subscriptions and revoked keys stop working for deployed instances too.

## 3. Connect NL-Veil or another MCP client

In your existing MCP connection, enter:

| Setting | Value |
| --- | --- |
| Transport | HTTP / Streamable HTTP |
| URL | Copy the MCP URL from your dashboard |
| Authentication | Bearer token |
| Token | Paste your Garrett API key |

If your client uses custom headers, add `Authorization: Bearer YOUR_GARRETT_API_KEY`. Keep the key out of URLs, public configuration, and chat messages. The dashboard includes a copyable JSON configuration.

Agent Garrett source is maintained in a private repository. Public source downloads and the old one-click repository deployment are no longer available here.

Passive security-research tools are available by default. Active tools require explicit operator policy and authorized targets.
