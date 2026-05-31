# Garrett Stimpson — Security Research

In-the-wild exploit analysis, CVE breakdowns, and offensive security research.
10+ years in the industry. All research published for educational and defensive purposes.

**[garrettstimpson.ca](https://garrettstimpson.ca)**

---

## What's in this repo

- **`/` (Jekyll site)** — the blog: dark terminal theme, matrix rain, responsive nav, post cards, tags, full-text search, reading progress, code-copy, share buttons, Giscus comments, RSS, and an Open Graph card.
- **`/agent`** — **Agent Garrett**, a Cloudflare Worker (Workers AI, free tier) with a terminal chat UI *and* an autonomous, multi-round OSINT engine — **68 in-worker tools** the AI selects via an agentic tool-router, plus broker-backed Tor/RE tools.
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
| `ACCESS_PASSWORD` | Locks the whole agent behind a login. Setting this **or** `ACCESS_USER` arms the gate; blank = open. (For secrecy use `wrangler secret put ACCESS_PASSWORD`.) |
| `ACCESS_USER` | Optional login username |
| `GITHUB_TOKEN` | Read-only PAT — enables `github_osint` code search (anonymous is impossible) and raises GitHub rate limits |
| `HIBP_API_KEY` | Enables HaveIBeenPwned results in `breach_check` (XposedOrNot works without it) |
| `GOOGLE_CSE_KEY` + `GOOGLE_CSE_CX`, or `BING_API_KEY` | Reliable `web_search` (keyless SearXNG/DuckDuckGo/Wikipedia fallback otherwise) |
| `TOOL_BROKER_URL` + `TOOL_BROKER_TOKEN` | Optional Tor/Python broker for live `.onion` crawling + Sherlock/Holehe/radare2/capa/yara (see `broker/`) |
| `VT_API_KEY` / `MALWAREBAZAAR_API_KEY` | Richer `hash_lookup` (Cymru MHR works keyless) |
| `ABUSECH_API_KEY` | Enables `urlhaus` (abuse.ch now requires a free Auth-Key) |
| `DISCLOSURE_*` / `RESEND_API_KEY` / `MAILGUN_*` | Optional, off-by-default human-confirmed disclosure sending |

### Autonomous OSINT

Two ways tools run: (1) **autonomous flows** — name an email / domain / @handle / person name / IP / CVE / image URL / crypto address / .onion / file hash and the agent auto-detects the entity, picks the right *intent* (person, dark-web, malware, origin, tech, breach, full), runs a multi-round sweep that **pivots on what it finds** (leaked git/commit emails, repo & blog domains, discovered profile handles, sample URLs → analyzed, hashes → reputation), computes an exposure-risk score, and writes a formal Markdown report (copy/download). A red **stop** button cancels long runs. (2) **agentic chat** — for any other request, an LLM tool-router selects from the full catalogue using each tool's when-to-use description and chains on findings, showing 🔧 chips as it works.

**Tool families (68 in-worker):**
- **intel** — nvd_lookup, epss_lookup, kev_lookup, kev_recent, circl_cve, cve_search, cve_poc (public exploits), mitre (ATT&CK), cvss
- **OSINT** — rdap_ip/domain, dns_lookup, dns_records, cert_ct, crtsh_subs, ip_geo, asn_info, shodan_internetdb, greynoise, reverse_dns, tor_exit, wayback, archive_urls, crypto_addr
- **people** — username_enum, github_user, gravatar, email_recon, email_permutations, breach_check, pwned_password
- **recon** — http_headers, tech_fingerprint, origin_ip, subdomain_takeover, subdomains, typosquat, email_security (SPF/DMARC), bucket_finder, cors_check, crawl (links+secrets), favicon_hash, disclosure_draft, jwt, cidr, hash_id, encode, timestamp
- **dark-web** — stealer_check (HudsonRock infostealer logs), leakcheck, paste_search, onion_search, onion_fetch
- **malware** — file_analyze, hash_lookup (Cymru/VT/MalwareBazaar), decode (recursive), ioc_extract, dork
- **image** — image_osint (EXIF/GPS + reverse-image links)
- **broker (optional, real Tor + binaries)** — onion_fetch/onion_search over Tor, sherlock, holehe, re_analyze (radare2/capa), ole_macros, yara_scan, exif

Responsible disclosure: `disclosure_draft` composes an attributable blue-team email to a domain's security contact; an optional, off-by-default, human-confirmed send path (`/api/send-disclosure`) uses your own verified provider (never anonymous).

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
- **Agent**: Cloudflare Worker + Workers AI (`@cf/meta/llama-3.1-8b-instruct`), single-file `agent/src/index.js`
- **Corpus**: regenerated daily from `_posts/` via GitHub Actions

---

*All research and tooling is for educational and defensive purposes.*
