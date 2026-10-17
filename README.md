# Garrett Stimpson — Security Research

In-the-wild exploit analysis, CVE breakdowns, and offensive security research.
10+ years in the industry. All research published for educational and defensive purposes.

**[garrettstimpson.ca](https://garrettstimpson.ca)**

---

## What's in this repo

- **`/` (Jekyll site)** — the blog: dark terminal theme, matrix rain, responsive nav, post cards, tags, full-text search, reading progress, code-copy, share buttons, Giscus comments, RSS, and an Open Graph card.
- **Agent Garrett** — the subscription security service is linked from the site as a separate product.
- **`llms.txt`** — a RAG corpus of every post, rebuilt daily by GitHub Actions.

---

## Site configuration

In `_config.yml`:

- **Comments (Giscus):** enable GitHub **Discussions** on the repo, install the [giscus app](https://giscus.app), then paste the generated `repo_id` and `category_id` into the `giscus:` block. Comments render under each post once both are set.
- **Google Analytics 4:** set `google_analytics` to the web stream's `G-` measurement ID (Google Analytics → Admin → Data streams → select the web stream). The Google tag loads on every page in production; development builds do not send Analytics events.
- **Cloudflare Web Analytics (optional):** paste a beacon token into `cf_analytics_token`.

---

## How the corpus works

```
_posts/*.md  ──► build_llms.py ──► llms.txt   (GitHub Action, daily)
```

`llms.txt` is a structured `<DOCUMENT>`-delimited format — chunk by document for embeddings, or inject as context as-is.

---

## Stack

- **Site**: Jekyll + Minima (dark) on GitHub Pages, custom cybersecurity CSS
- **Corpus**: regenerated daily from `_posts/` via GitHub Actions

---

*All research and tooling is for educational and defensive purposes.*
