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
import os, re, time, hashlib, subprocess
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


def fetch_sample(url, max_mb=25):
    if not url or ".onion" in url:
        raise ValueError("a clearnet sample URL is required")
    path = "/tmp/sample_%d" % int(time.time() * 1000)
    with requests.get(url, stream=True, timeout=60, headers={"User-Agent": "gg-broker/1.0"}) as r:
        r.raise_for_status()
        n = 0
        with open(path, "wb") as f:
            for chunk in r.iter_content(65536):
                f.write(chunk); n += len(chunk)
                if n > max_mb * 1024 * 1024:
                    break
    return path


def re_analyze(url):
    if not url:
        return "re_analyze: a sample URL is required."
    try:
        path = fetch_sample(url)
    except Exception as e:
        return "re_analyze: download failed (%s)" % e
    out = []
    try:
        data = open(path, "rb").read()
        out.append("file: " + run_cli(["file", path], 30).strip())
        out.append("sha256: " + hashlib.sha256(data).hexdigest())
        strs = run_cli(["strings", "-n", "8", path], 60).splitlines()
        out.append("strings (first 40 of %d):\n%s" % (len(strs), "\n".join(strs[:40])))
        imp = run_cli(["r2", "-q", "-c", "ii", path], 90)
        if imp.strip():
            out.append("radare2 imports:\n" + imp[:2500])
        capa = run_cli(["capa", "-q", path], 240)
        if capa.strip() and "tool not installed" not in capa:
            out.append("capa capabilities:\n" + capa[:3000])
    finally:
        try: os.remove(path)
        except Exception: pass
    return "re_analyze %s\n" % url + "\n\n".join(out)


def ole_macros(url):
    if not url:
        return "ole_macros: an Office document URL is required."
    try:
        path = fetch_sample(url, max_mb=15)
    except Exception as e:
        return "ole_macros: download failed (%s)" % e
    try:
        out = run_cli(["olevba", "--no-color", path], 120)
    finally:
        try: os.remove(path)
        except Exception: pass
    return "ole_macros %s\n%s" % (url, out[:6000] if out.strip() else "(no macros / not an OLE/OOXML file)")


def exif(url):
    if not url:
        return "exif: a file URL is required."
    try:
        path = fetch_sample(url, max_mb=15)
    except Exception as e:
        return "exif: download failed (%s)" % e
    try:
        out = run_cli(["exiftool", path], 40)
    finally:
        try: os.remove(path)
        except Exception: pass
    return "exif %s\n%s" % (url, out[:4000])


def yara_scan(url):
    if not url:
        return "yara_scan: a sample URL is required."
    try:
        path = fetch_sample(url)
    except Exception as e:
        return "yara_scan: download failed (%s)" % e
    rules = os.environ.get("YARA_RULES", "/app/rules.yar")
    try:
        out = run_cli(["yara", "-w", "-s", rules, path], 120)
    finally:
        try: os.remove(path)
        except Exception: pass
    if not out.strip():
        return "yara_scan %s: no rule matches (ruleset: %s)." % (url, rules)
    return "yara_scan %s (ruleset: %s)\n%s" % (url, rules, out[:4000])


TOOLS = {
    "onion_fetch":  lambda a: onion_fetch(a.get("url") or a.get("onion") or a.get("target") or ""),
    "onion_search": lambda a: onion_search(a.get("query") or a.get("target") or ""),
    "sherlock":     lambda a: sherlock(a.get("username") or a.get("user") or a.get("target") or ""),
    "holehe":       lambda a: holehe(a.get("email") or a.get("target") or ""),
    "re_analyze":   lambda a: re_analyze(a.get("url") or a.get("target") or ""),
    "ole_macros":   lambda a: ole_macros(a.get("url") or a.get("target") or ""),
    "exif":         lambda a: exif(a.get("url") or a.get("target") or ""),
    "yara_scan":    lambda a: yara_scan(a.get("url") or a.get("target") or ""),
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
