#!/usr/bin/env python3
"""
build_llms.py  —  Rebuilds llms.txt and llms-full.txt from _posts/.
Run locally or via GitHub Actions.

llms.txt      : short Markdown index in the llms.txt proposal format
                (H1, summary, linked sections), pointing at llms-full.txt.
llms-full.txt : structured plain-text corpus for LLM retrieval. One
                <DOCUMENT> block per post, full content preserved.
"""
import os, re, sys
from datetime import datetime, timezone
from pathlib import Path

SITE_URL    = "https://garrettstimpson.ca"
AUTHOR      = "Garrett Stimpson"
REPO        = "https://github.com/gary23w/garrettstimpson.ca"
SITE_DESC   = ("Cybersecurity research and practical defensive guidance by Garrett Stimpson, "
               "a software engineer with 10+ years across offensive and defensive security.")
POSTS_DIR   = Path(__file__).parent / "_posts"
TOPICS_FILE = Path(__file__).parent / "_data" / "topics.yml"
OUTPUT_FILE = Path(__file__).parent / "llms.txt"
FULL_FILE   = Path(__file__).parent / "llms-full.txt"

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


def load_posts(posts_dir: Path) -> list[dict]:
    posts = sorted(
        [p for p in posts_dir.glob("*.md")],
        key=lambda p: p.name,
        reverse=True          # newest first
    )
    parsed = [parse_post(p) for p in posts]
    return [p for p in parsed if p]


def load_topics(path: Path) -> list[dict]:
    """Read slug/name/description from _data/topics.yml (flat entries only)."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"^- slug: (\S+)\r?\n  name: (.+?)\r?\n  description: (.+?)\r?$", re.M)
    return [{"slug": m[0], "name": m[1].strip(), "description": m[2].strip()}
            for m in pattern.findall(text)]


def build_index(parsed: list[dict], topics: list[dict]) -> str:
    """llms.txt: H1, blockquote summary, then linked sections."""
    lines = [f"# {AUTHOR}", "", f"> {SITE_DESC}", ""]
    lines.append("Vulnerability research, exploit breakdowns and malware analysis. "
                 f"The full text of every post is in [llms-full.txt]({SITE_URL}/llms-full.txt).")
    lines.append("")
    lines.append("## About")
    lines.append("")
    lines.append(f"- [About {AUTHOR}]({SITE_URL}/about/): background, software projects and professional profiles")
    lines.append(f"- [Research policy]({SITE_URL}/policy/): educational and defensive use, privacy and vulnerability disclosure")
    lines.append("")
    if topics:
        lines.append("## Topics")
        lines.append("")
        for t in topics:
            lines.append(f"- [{t['name']}]({SITE_URL}/topics/{t['slug']}/): {t['description']}")
        lines.append("")
    lines.append("## Posts")
    lines.append("")
    for post in parsed:
        note = f": {post['excerpt']}" if post["excerpt"] else ""
        lines.append(f"- [{post['title']}]({post['url']}){note}")
    lines.append("")
    return "\n".join(lines)


def build_corpus(parsed: list[dict]) -> str:

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

    parsed = load_posts(POSTS_DIR)
    corpus = build_corpus(parsed)
    FULL_FILE.write_text(corpus, encoding="utf-8")
    print(f"✓ llms-full.txt written — {len(corpus):,} bytes")
    index = build_index(parsed, load_topics(TOPICS_FILE))
    OUTPUT_FILE.write_text(index, encoding="utf-8")
    print(f"✓ llms.txt written — {len(index):,} bytes")
