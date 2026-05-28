# Garrett Stimpson — Security Research

In-the-wild exploit analysis, CVE breakdowns, and offensive security research.
10+ years in the industry. All research published for educational and defensive purposes.

**[garrettstimpson.ca](https://garrettstimpson.ca)**

---

## Deploy Research Agent

This repo ships a [`llms.txt`](./llms.txt) corpus of every post — full content, CVE metadata, and tags — automatically rebuilt daily by GitHub Actions.

The **Research Agent** is a Cloudflare Worker that loads the corpus and lets you query it via a terminal-style chat UI, powered by **Workers AI (free tier — no API key required)**.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/gary23w/garrettstimpson.ca/tree/main/agent)

> **Adapt it for your own site** — change `LLMS_URL` and `SITE_NAME` in `agent/wrangler.toml` after deploying.
> Any site with an `llms.txt` works.

---

## How It Works

```
_posts/*.md  ──► build_llms.py  ──► llms.txt
                  (GitHub Action,        │
                   runs daily)           ▼
                              Cloudflare Worker
                              ├── fetches llms.txt (cached 1h)
                              ├── streams answers via Workers AI
                              └── terminal chat UI at /
```

The pattern is generic. If your site has an `llms.txt`:

1. Fork or deploy the `agent/` directory
2. Set `LLMS_URL` to your corpus URL
3. Get a streaming chat agent backed by your own content — no OpenAI account, no monthly bill

---

## Corpus Format

`llms.txt` uses a structured plain-text format optimised for RAG retrieval and fine-tuning:

```
<DOCUMENT id="001" type="security-research-post">
<FRONTMATTER>
TITLE      : CVE-2026-31431: Copy Fail
DATE       : 2026-05-27
CVE        : CVE-2026-31431
WORD_COUNT : 3847
EXCERPT    : ...
</FRONTMATTER>
<BODY>
...full post content...
</BODY>
</DOCUMENT>
```

Chunk by `<DOCUMENT>` for embedding pipelines. Use as-is for context injection.

---

## Stack

- **Site**: Jekyll + Minima (dark) hosted on GitHub Pages
- **Theme**: Custom cybersecurity CSS — matrix rain, neon green, terminal aesthetic
- **Agent**: Cloudflare Worker + Workers AI (`@cf/meta/llama-3.1-8b-instruct`)
- **Corpus**: Auto-regenerated daily from `_posts/` via GitHub Actions

---

*All research is for educational and defensive purposes.*
