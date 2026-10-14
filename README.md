# Garrett Stimpson — Security Research

In-the-wild exploit analysis, CVE breakdowns, and offensive security research.
10+ years in the industry. All research published for educational and defensive purposes.

**[garrettstimpson.ca](https://garrettstimpson.ca)**

---

## What's in this repo

- **`/` (Jekyll site)** — the blog: dark terminal theme, matrix rain, responsive nav, post cards, tags, full-text search, reading progress, code-copy, share buttons, Giscus comments, RSS, and an Open Graph card.
- **Agent Garrett** — the subscription security service has moved to a separate private repository. Sign in at [agent.garrettstimpson.ca](https://agent.garrettstimpson.ca).
- **`llms.txt`** — a RAG corpus of every post, rebuilt daily by GitHub Actions.

---

## Agent Garrett

Agent Garrett is maintained in the private `gary23w/garrett` repository. Its source and broker are not distributed from this public blog repository.

Use [the Garrett dashboard](https://agent.garrettstimpson.ca) to sign in with Cloudflare, activate a card-required 3-day trial or Agent at CAD $4.99/month, deploy your Cloudflare connection, and manage API keys. The trial automatically renews monthly unless cancelled.

## Site configuration

In `_config.yml`:

- **Comments (Giscus):** enable GitHub **Discussions** on the repo, install the [giscus app](https://giscus.app), then paste the generated `repo_id` and `category_id` into the `giscus:` block. Comments render under each post once both are set.
- **Agent link:** set `agent_url` to your deployed worker URL to show an "Agent" nav link + a home hero CTA.
- **Google Analytics 4:** set `google_analytics` to the web stream's `G-` measurement ID (Google Analytics → Admin → Data streams → select the web stream). The Google tag loads on every page in production; development builds do not send Analytics events.
- **Cloudflare Web Analytics (optional):** paste a beacon token into `cf_analytics_token`.

---

## How the corpus works

```
_posts/*.md  ──► build_llms.py ──► llms.txt   (GitHub Action, daily)
                                       │
                                       ▼
                          Agent Garrett private service
                          ├── fetches llms.txt (cached 1h)
                          ├── BM25 / optional Vectorize retrieval
                          └── streams answers via Workers AI
```

`llms.txt` is a structured `<DOCUMENT>`-delimited format — chunk by document for embeddings, or inject as context as-is. The corpus remains public; the Agent Garrett service is maintained separately.

---

## Stack

- **Site**: Jekyll + Minima (dark) on GitHub Pages, custom cybersecurity CSS
- **Agent**: Cloudflare Worker + Workers AI (GLM 4.7 Flash default with a current allowlisted model picker), neuron-db WASM memory, evidence-aware tool routing
- **Corpus**: regenerated daily from `_posts/` via GitHub Actions

---

*All research and tooling is for educational and defensive purposes.*
