#!/usr/bin/env python3
"""
build_llms.py  —  Rebuilds llms.txt from _posts/ directory.
Run locally or via GitHub Actions.

Output format: structured plain-text corpus optimised for LLM inference
and fine-tuning data. One <DOCUMENT> block per post, full content preserved.
"""
import os, re, sys
from datetime import datetime, timezone
from pathlib import Path

SITE_URL    = "https://garrettstimpson.ca"
AUTHOR      = "Garrett Stimpson"
REPO        = "https://github.com/gary23w/garrettstimpson.ca"
POSTS_DIR   = Path(__file__).parent / "_posts"
OUTPUT_FILE = Path(__file__).parent / "llms.txt"

PERMALINK_TPL = "{site}/posts/{year}/{month}/{day}/{slug}/"


def parse_post(path: Path) -> dict | None:
    """Parse Jekyll frontmatter + body from a .md file."""
    raw = path.read_text(encoding="utf-8")

    # Split frontmatter ---...--- from body
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)", raw, re.DOTALL)
    if not m:
        return None

    fm_raw, body = m.group(1), m.group(2).strip()

    # Parse the simple YAML frontmatter we use (no anchors / complex types)
    fm: dict = {}
    for line in fm_raw.splitlines():
        kv = re.match(r'^(\w[\w_-]*):\s*(.*)$', line)
        if kv:
            key, val = kv.group(1), kv.group(2).strip()
            # Strip surrounding quotes
            val = re.sub(r'^["\']|["\']$', '', val).strip()
            # Lists like [a, b, c]
            if val.startswith('[') and val.endswith(']'):
                val = [v.strip().strip('"\'') for v in val[1:-1].split(',')]
            fm[key] = val

    # Derive permalink from filename: YYYY-MM-DD-slug.md
    stem  = path.stem                          # e.g. 2026-05-27-cve-2026-31431-...
    parts = stem.split('-', 3)
    if len(parts) < 4:
        return None
    year, month, day, slug = parts
    url = PERMALINK_TPL.format(
        site=SITE_URL, year=year, month=month, day=day, slug=slug
    )

    # Extract CVE IDs from body + tags
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d+\b', re.IGNORECASE)
    cves = sorted(set(cve_pattern.findall(raw)), key=lambda x: x.upper())

    # Rough word count
    word_count = len(re.findall(r'\b\w+\b', body))

    return {
        "filename":   path.name,
        "date":       fm.get("date", f"{year}-{month}-{day}"),
        "title":      fm.get("title", slug),
        "excerpt":    fm.get("excerpt", "").replace("\n", " ").strip(),
        "categories": fm.get("categories", []),
        "tags":       fm.get("tags", []),
        "cves":       cves,
        "url":        url,
        "word_count": word_count,
        "body":       body,
    }


def list_tags(val) -> str:
    if isinstance(val, list):
        return ", ".join(val)
    return str(val)


def build_corpus(posts_dir: Path) -> str:
    posts = sorted(
        [p for p in posts_dir.glob("*.md")],
        key=lambda p: p.name,
        reverse=True          # newest first
    )

    parsed = [parse_post(p) for p in posts]
    parsed = [p for p in parsed if p]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = []
    lines.append("=" * 80)
    lines.append("GARRETTSTIMPSON.CA — SECURITY RESEARCH CORPUS")
    lines.append("=" * 80)
    lines.append(f"GENERATED    : {now}")
    lines.append(f"AUTHOR       : {AUTHOR}")
    lines.append(f"SITE         : {SITE_URL}")
    lines.append(f"REPOSITORY   : {REPO}")
    lines.append(f"TOTAL POSTS  : {len(parsed)}")
    lines.append(f"DOMAIN       : offensive-security, vulnerability-research,")
    lines.append(f"               exploit-development, kernel-exploitation,")
    lines.append(f"               red-team, CVE-analysis, PoC-breakdown")
    lines.append("")
    lines.append("FORMAT: Each <DOCUMENT> block contains a complete research post.")
    lines.append("        Use as-is for RAG retrieval or chunk per block for fine-tuning.")
    lines.append("        CVE fields are extracted from body text automatically.")
    lines.append("=" * 80)
    lines.append("")

    for i, post in enumerate(parsed, 1):
        doc_id = f"{i:03d}"
        cats   = list_tags(post["categories"])
        tags   = list_tags(post["tags"])
        cves   = ", ".join(post["cves"]) if post["cves"] else "none"

        lines.append(f"<DOCUMENT id=\"{doc_id}\" type=\"security-research-post\">")
        lines.append(f"<FRONTMATTER>")
        lines.append(f"TITLE      : {post['title']}")
        lines.append(f"DATE       : {post['date']}")
        lines.append(f"URL        : {post['url']}")
        lines.append(f"CVE        : {cves}")
        lines.append(f"CATEGORIES : {cats}")
        lines.append(f"TAGS       : {tags}")
        lines.append(f"WORD_COUNT : {post['word_count']}")
        lines.append(f"EXCERPT    : {post['excerpt']}")
        lines.append(f"</FRONTMATTER>")
        lines.append(f"<BODY>")
        lines.append(post["body"])
        lines.append(f"</BODY>")
        lines.append(f"</DOCUMENT>")
        lines.append("")
        lines.append("-" * 80)
        lines.append("")

    lines.append("=" * 80)
    lines.append(f"END OF CORPUS — {len(parsed)} documents — {now}")
    lines.append("=" * 80)

    return "\n".join(lines)


if __name__ == "__main__":
    if not POSTS_DIR.exists():
        print(f"ERROR: _posts/ not found at {POSTS_DIR}", file=sys.stderr)
        sys.exit(1)

    corpus = build_corpus(POSTS_DIR)
    OUTPUT_FILE.write_text(corpus, encoding="utf-8")
    print(f"✓ llms.txt written — {len(corpus):,} bytes")
