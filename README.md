# Garrett Stimpson — Security Research

In-the-wild exploit analysis, CVE breakdowns, and offensive security research.
10+ years in the industry. All research published for educational and defensive purposes.

**[garrettstimpson.ca](https://garrettstimpson.ca)**

---

## What's in this repo

- **`/` (Jekyll site)** — the blog: dark terminal theme, matrix rain, responsive nav, post cards, tags, full-text search, reading progress, code-copy, share buttons, Giscus comments, RSS, and an Open Graph card.
- **`/agent`** — **Agent Garrett**, a Cloudflare Worker with a terminal chat UI, stateless HTTP MCP endpoint, evidence-aware routing, **83 tools**, and optional broker-backed Tor/RE tooling.
- **`llms.txt`** — a RAG corpus of every post, rebuilt daily by GitHub Actions.

---

## Deploy the Research Agent

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/gary23w/garrettstimpson.ca/tree/main/agent)

The button (and the Git-connected "Workers Builds" flow) reads `agent/wrangler.toml` + `agent/package.json`. After deploy, the agent serves a chat UI at `/`.

### Agent configuration (all optional)

Set these as Cloudflare Worker **Variables/Secrets** (dashboard → Settings → Variables) or in `agent/wrangler.toml`:

| Var | Purpose |
|-----|---------|
| `LLMS_URL` | Corpus URL (defaults to this repo's raw `llms.txt`) |
| `SITE_NAME` | Display name in the chat UI |
| `ACCESS_PASSWORD` | Locks the browser UI/API behind a login. Must be a random 16+ character secret when enabled; blank with blank `ACCESS_USER` leaves it open. |
| `ACCESS_USER` | Optional login username |
| `ACCESS_SESSION_SECRET` | Independent random secret used with one-day, server-revocable login sessions (recommended) |
| `MCP_API_TOKEN` | Independent random 24+ character bearer secret enabling `POST /mcp` |
| `GITHUB_TOKEN` | Read-only PAT — enables `github_osint` code search (anonymous is impossible) and raises GitHub rate limits |
| `HIBP_API_KEY` | Enables HaveIBeenPwned results in `breach_check` (XposedOrNot works without it) |
| `GOOGLE_CSE_KEY` + `GOOGLE_CSE_CX`, or `BING_API_KEY` | Reliable `web_search` (keyless SearXNG/DuckDuckGo/Wikipedia fallback otherwise) |
| `TOOL_BROKER_URL` + `TOOL_BROKER_TOKEN` | Optional Tor/Python broker for live `.onion` crawling + Sherlock/Holehe/radare2/capa/yara (see `broker/`) |
| `CTF_SAFE_MODE`, `TOOL_ALLOWLIST`, `CTF_TARGET_ALLOWLIST` | Tool and target policy. Active/target-contacting calls should be explicitly allowlisted and scoped. |
| `AGENT_ALLOW_ACTIVE_TOOLS` | Off by default. Allows model-driven active calls only when both tool and target allowlists are present. |
| `MCP_ALLOW_ACTIVE_TOOLS`, `MCP_ALLOW_DARKWEB` | Off by default. Separately opt active/dark-web tools into MCP after allowlisting. |
| `VT_API_KEY` / `MALWAREBAZAAR_API_KEY` | Richer `hash_lookup` (Cymru MHR works keyless) |
| `ABUSECH_API_KEY` | Enables `urlhaus` (abuse.ch now requires a free Auth-Key) |
| `DISCLOSURE_*` / `RESEND_API_KEY` / `MAILGUN_*` | Optional, off-by-default human-confirmed disclosure sending |

### Tool execution safety

Agentic chat automatically runs only passive, public-data lookups. Target-contacting, file-download, dark-web, custom, and broker tools require an explicit operator action and confirmation; safe-mode tool/target scope is checked independently of that confirmation. Autonomous active calls remain off unless `AGENT_ALLOW_ACTIVE_TOOLS=true` and both the tool and target are allowlisted. Tool results are treated as untrusted evidence and the answer cites its evidence ledger.

**Tool families (83 in-worker):**
- **intel** — nvd_lookup, epss_lookup, kev_lookup, kev_recent, circl_cve, cve_search, cve_poc (public exploits), mitre (ATT&CK), cvss
- **OSINT** — rdap_ip/domain, dns_lookup, dns_records, cert_ct, crtsh_subs, ip_geo, asn_info, shodan_internetdb, greynoise, reverse_dns, tor_exit, wayback, archive_urls, crypto_addr
- **people** — username_enum, github_user, gravatar, email_recon, email_permutations, breach_check, pwned_password
- **recon** — http_headers, tech_fingerprint, origin_ip, subdomain_takeover, subdomains, typosquat, email_security (SPF/DMARC), bucket_finder, cors_check, crawl (links+secrets), favicon_hash, disclosure_draft, jwt, cidr, hash_id, encode, timestamp
- **dark-web** — stealer_check (HudsonRock infostealer logs), leakcheck, paste_search, onion_search, onion_fetch
- **malware** — file_analyze, hash_lookup (Cymru/VT/MalwareBazaar), decode (recursive), ioc_extract, dork
- **image** — image_osint (EXIF/GPS + reverse-image links)
- **broker (optional, real Tor + binaries)** — onion_fetch/onion_search over Tor, sherlock, holehe, re_analyze (radare2/capa), ole_macros, yara_scan, exif

Responsible disclosure: `disclosure_draft` composes an attributable blue-team email to a domain's security contact; an optional, off-by-default, human-confirmed send path (`/api/send-disclosure`) uses your own verified provider (never anonymous).

### MCP for Codex and other clients

`POST /mcp` is a stateless Streamable HTTP MCP server. It uses a bearer token separate from browser login, rejects browser cross-origin requests by default, and exposes only passive tools unless the MCP active-tool flags and normal allowlists opt in more.

```powershell
cd agent
npx wrangler secret put MCP_API_TOKEN
```

Then add the deployed endpoint in Codex Settings → MCP servers, or use the equivalent configuration:

```toml
[mcp_servers.agent_garrett]
url = "https://your-worker.workers.dev/mcp"
bearer_token_env_var = "AGENT_GARRETT_MCP_TOKEN"
```

Set `AGENT_GARRETT_MCP_TOKEN` in the environment that starts Codex. MCP does not reuse or reveal the browser password.

---

## Site configuration

In `_config.yml`:

- **Comments (Giscus):** enable GitHub **Discussions** on the repo, install the [giscus app](https://giscus.app), then paste the generated `repo_id` and `category_id` into the `giscus:` block. Comments render under each post once both are set.
- **Agent link:** set `agent_url` to your deployed worker URL to show an "Agent" nav link + a home hero CTA.
- **Analytics:** paste a Cloudflare Web Analytics token into `cf_analytics_token`.

---

## How the corpus works

```
_posts/*.md  ──► build_llms.py ──► llms.txt   (GitHub Action, daily)
                                       │
                                       ▼
                          Cloudflare Worker (agent/)
                          ├── fetches llms.txt (cached 1h)
                          ├── BM25 / optional Vectorize retrieval
                          └── streams answers via Workers AI
```

`llms.txt` is a structured `<DOCUMENT>`-delimited format — chunk by document for embeddings, or inject as context as-is. The whole pattern is generic: any site with an `llms.txt` can reuse `agent/`.

---

## Stack

- **Site**: Jekyll + Minima (dark) on GitHub Pages, custom cybersecurity CSS
- **Agent**: Cloudflare Worker + Workers AI (GLM 4.7 Flash default with a current allowlisted model picker), neuron-db WASM memory, evidence-aware tool routing
- **Corpus**: regenerated daily from `_posts/` via GitHub Actions

---

*All research and tooling is for educational and defensive purposes.*
