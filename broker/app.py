"""
Agent Garrett OSINT broker — optional companion to the Cloudflare Worker.

Cloudflare Workers cannot open Tor circuits or run Python OSINT binaries. This
small service does both, and the Worker delegates to it when TOOL_BROKER_URL
(and TOOL_BROKER_TOKEN) are configured. Defensive / educational use only.

Contract (matches the Worker's runBrokerTool):
  POST /run  { "tool": "<name>", "args": {...}, "target": "...", ... }
  Auth:      Authorization: Bearer <BROKER_TOKEN>
  Returns:   { "ok": true, "tool": "<name>", "result": "<text>" }
"""
import os, re, subprocess
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import requests

BROKER_TOKEN = os.environ.get("BROKER_TOKEN", "")
TOR_PROXY = os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050")

app = FastAPI(title="Agent Garrett OSINT Broker", docs_url=None, redoc_url=None)
ONION_RE = re.compile(r"[a-z2-7]{16}\.onion|[a-z2-7]{56}\.onion", re.I)


def tor_session():
    s = requests.Session()
    s.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}
    s.headers.update({"User-Agent": "garrettstimpson-broker/1.0"})
    return s


def run_cli(cmd, timeout=180):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = p.stdout or ""
        if p.returncode != 0 and p.stderr:
            out += "\n[stderr] " + p.stderr[:1000]
        return out
    except subprocess.TimeoutExpired:
        return f"(timed out after {timeout}s)"
    except FileNotFoundError:
        return f"(tool not installed: {cmd[0]})"


def onion_fetch(url):
    if not url:
        return "onion_fetch: a .onion url is required."
    if not url.startswith("http"):
        url = "http://" + url
    host = re.sub(r"^https?://", "", url).split("/")[0]
    if not ONION_RE.search(host):
        return "onion_fetch: not a .onion host."
    try:
        r = tor_session().get(url, timeout=50)
        text = re.sub(r"<[^>]+>", " ", r.text)
        text = re.sub(r"\s+", " ", text).strip()
        links = sorted({m.group(0).lower() for m in ONION_RE.finditer(r.text)})[:20]
        out = f"onion_fetch {host} (HTTP {r.status_code}, via Tor)\n\n{text[:6000]}"
        if links:
            out += "\n\ndiscovered onion links:\n" + "\n".join(links)
        return out
    except Exception as e:
        return f"onion_fetch {host}: failed over Tor ({e})."


def onion_search(query):
    if not query:
        return "onion_search: a term is required."
    try:
        r = tor_session().get("https://ahmia.fi/search/", params={"q": query}, timeout=50)
        hits = [h for h in sorted({m.group(0).lower() for m in ONION_RE.finditer(r.text)})
                if not h.startswith("juhanurmihxlp")][:20]
        if hits:
            return f"onion_search '{query}' (Tor): {len(hits)} onion site(s)\n" + "\n".join(hits)
        return f"onion_search '{query}': no indexed results."
    except Exception as e:
        return f"onion_search '{query}': failed ({e})."


def sherlock(username):
    if not re.match(r"^[A-Za-z0-9_.\-]{1,40}$", username or ""):
        return "sherlock: a plain username is required."
    out = run_cli(["sherlock", "--timeout", "10", "--print-found", "--no-color", username], timeout=300)
    found = [l.strip() for l in out.splitlines() if "http" in l]
    return f"sherlock {username}: {len(found)} account(s) found\n" + ("\n".join(found) if found else out[:3000])


def holehe(email):
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""):
        return "holehe: a valid email is required."
    out = run_cli(["holehe", "--only-used", "--no-color", email], timeout=200)
    return f"holehe {email}:\n" + (out[:4000] if out.strip() else "(no used accounts reported)")


TOOLS = {
    "onion_fetch":  lambda a: onion_fetch(a.get("url") or a.get("onion") or a.get("target") or ""),
    "onion_search": lambda a: onion_search(a.get("query") or a.get("target") or ""),
    "sherlock":     lambda a: sherlock(a.get("username") or a.get("user") or a.get("target") or ""),
    "holehe":       lambda a: holehe(a.get("email") or a.get("target") or ""),
}


@app.get("/health")
def health():
    return {"ok": True, "tools": sorted(TOOLS.keys())}


@app.post("/run")
async def run(req: Request):
    if BROKER_TOKEN:
        if req.headers.get("authorization", "") != f"Bearer {BROKER_TOKEN}":
            raise HTTPException(status_code=401, detail="unauthorized")
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="bad json")
    tool = (body.get("tool") or "").strip().lower()
    args = body.get("args") if isinstance(body.get("args"), dict) else {}
    if tool not in TOOLS:
        return JSONResponse({"ok": False, "error": f"unknown broker tool: {tool}"}, status_code=404)
    try:
        return {"ok": True, "tool": tool, "result": TOOLS[tool](args)}
    except Exception as e:
        return JSONResponse({"ok": False, "tool": tool, "error": str(e)}, status_code=500)
