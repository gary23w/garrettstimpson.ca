# Garrett Stimpson — Security Research

In-the-wild exploit analysis, CVE breakdowns, and offensive security research.
10+ years in the industry. All research published for educational and defensive purposes.

**[garrettstimpson.ca](https://garrettstimpson.ca)**

---

## What's in this repo

- **`/` (Jekyll site)** — the blog: dark terminal theme, matrix rain, responsive nav, post cards, tags, full-text search, reading progress, code-copy, share buttons, Giscus comments, RSS, and an Open Graph card.
- **`/agent`** — **Agent Garrett**, a Cloudflare Worker (Workers AI, free tier) with a terminal chat UI *and* an autonomous, multi-round OSINT engine (44 passive tools).
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
| `TOOL_BROKER_URL` | Optional Tor/Python broker for live `.onion` crawling + heavy tools |

### Autonomous OSINT

Name an **email / domain / @handle / IP / CVE / image URL / crypto address / .onion** in chat and the agent auto-detects the entity, runs a two-round tool sweep (pivoting on what it finds — leaked git emails, repo domains, etc.), computes an exposure-risk score, and writes a formal Markdown report you can copy or download. A red **stop** button cancels long runs.

**Tool families (44):** intel (NVD/EPSS/KEV/CIRCL/cve_search) · OSINT (RDAP, DNS, cert-transparency, IP geo/ASN, Shodan InternetDB, GreyNoise, reverse DNS, tor_exit, crypto_addr, dns_records) · people (username enumeration, GitHub profile, gravatar, email recon, breach_check, pwned_password, email_permutations) · recon (HTTP headers, tech fingerprint, origin IP behind Cloudflare, subdomain takeover, typosquat, email_security/SPF-DMARC, bucket_finder, cors_check) · dark-web (onion_search, onion_fetch via free gateways) · image (EXIF/GPS + reverse-image links) · search/fetch.

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
