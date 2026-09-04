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
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
from urllib.parse import urljoin, urlsplit, urlunsplit
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import requests
from starlette.concurrency import run_in_threadpool

BROKER_TOKEN = os.environ.get("BROKER_TOKEN", "")
TOR_PROXY = os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050")
MAX_REQUEST_BYTES = 64 * 1024
MAX_REDIRECTS = 3

app = FastAPI(title="Agent Garrett OSINT Broker", docs_url=None, redoc_url=None)
ONION_RE = re.compile(r"(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion", re.I)


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


def normalize_onion_url(value):
    raw = (value or "").strip()
    if not raw:
        raise ValueError("a .onion url is required")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlsplit(raw)
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
        raise ValueError("only plain http/https onion URLs are allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid onion port") from exc
    host = (parsed.hostname or "").lower()
    if not ONION_RE.fullmatch(host) or (port is not None and port not in (80, 443)):
        raise ValueError("not an exact .onion authority")
    authority = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))


def tor_get_onion(url, timeout=50):
    current = normalize_onion_url(url)
    scoped_host = urlsplit(current).hostname
    session = tor_session()
    for _ in range(MAX_REDIRECTS + 1):
        response = session.get(current, timeout=timeout, allow_redirects=False, stream=True)
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location")
            response.close()
            if not location:
                raise ValueError("onion redirect omitted Location")
            next_url = normalize_onion_url(urljoin(current, location))
            if urlsplit(next_url).hostname != scoped_host:
                raise ValueError("cross-host onion redirect is outside the authorized target")
            current = next_url
            continue
        return response, current
    raise ValueError("too many onion redirects")


def onion_fetch(url):
    try:
        normalized = normalize_onion_url(url)
        host = urlsplit(normalized).hostname
    except ValueError as exc:
        return f"onion_fetch: {exc}."
    try:
        r, _ = tor_get_onion(normalized)
        data = b""
        for chunk in r.iter_content(65536):
            data += chunk
            if len(data) > 1024 * 1024:
                raise ValueError("onion response exceeded 1 MiB")
        r.close()
        text_raw = data.decode(r.encoding or "utf-8", errors="replace")
        text = re.sub(r"<[^>]+>", " ", text_raw)
        text = re.sub(r"\s+", " ", text).strip()
        links = sorted({m.group(0).lower() for m in ONION_RE.finditer(text_raw)})[:20]
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
        r = tor_session().get("https://ahmia.fi/search/", params={"q": query}, timeout=50, stream=True)
        data = bytearray()
        for chunk in r.iter_content(65536):
            data.extend(chunk)
            if len(data) > 1024 * 1024:
                raise ValueError("search response exceeded 1 MiB")
        r.close()
        text = bytes(data).decode(r.encoding or "utf-8", errors="replace")
        hits = [h for h in sorted({m.group(0).lower() for m in ONION_RE.finditer(text)})
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


def public_addresses(host, port):
    addresses = []
    for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        value = item[4][0]
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError(f"sample host resolved to non-public address {value}")
        if value not in addresses:
            addresses.append(value)
    if not addresses:
        raise ValueError("sample host did not resolve")
    return addresses


def pinned_public_get(url):
    parsed = urlsplit((url or "").strip())
    allow_http = os.environ.get("BROKER_ALLOW_HTTP_SAMPLES", "").lower() in ("1", "true", "yes")
    if parsed.scheme not in (("https", "http") if allow_http else ("https",)):
        raise ValueError("sample URL must use https (set BROKER_ALLOW_HTTP_SAMPLES=true only for an isolated lab)")
    if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        raise ValueError("sample URL contains an invalid authority or fragment")
    host = parsed.hostname.lower()
    if ONION_RE.fullmatch(host):
        raise ValueError("a clearnet sample URL is required")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("invalid sample URL port") from exc
    expected_port = 443 if parsed.scheme == "https" else 80
    if port != expected_port:
        raise ValueError(f"sample URL port must be {expected_port} for {parsed.scheme}")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host_header = host
    last_error = None
    for address in public_addresses(host, port):
        conn = None
        try:
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=60, context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(host, port, timeout=60)
            # Pin the socket to the address already classified above. TLS still uses
            # the original hostname for SNI and certificate verification.
            conn._create_connection = lambda _destination, timeout=None, source_address=None, _addr=address: socket.create_connection(
                (_addr, port), timeout, source_address
            )
            conn.request("GET", path, headers={"Host": host_header, "User-Agent": "garrettstimpson-broker/2.0", "Accept-Encoding": "identity"})
            return conn, conn.getresponse()
        except Exception as exc:
            last_error = exc
            if conn:
                conn.close()
    raise ValueError(f"sample host connection failed ({last_error})")


def fetch_sample(url, max_mb=25):
    current = (url or "").strip()
    scoped_host = urlsplit(current).hostname
    limit = max_mb * 1024 * 1024
    for _ in range(MAX_REDIRECTS + 1):
        conn, response = pinned_public_get(current)
        try:
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location:
                    raise ValueError("sample redirect omitted Location")
                next_url = urljoin(current, location)
                if urlsplit(next_url).hostname != scoped_host:
                    raise ValueError("cross-host sample redirect is outside the authorized target")
                current = next_url
                continue
            if response.status >= 400:
                raise ValueError(f"sample download returned HTTP {response.status}")
            advertised = response.getheader("Content-Length")
            if advertised and int(advertised) > limit:
                raise ValueError(f"sample exceeds {max_mb} MiB limit")
            tmp = tempfile.NamedTemporaryFile(prefix="sample_", dir="/tmp", delete=False)
            path = tmp.name
            total = 0
            try:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise ValueError(f"sample exceeds {max_mb} MiB limit")
                    tmp.write(chunk)
                tmp.close()
                return path
            except Exception:
                tmp.close()
                try:
                    os.remove(path)
                except OSError:
                    pass
                raise
        finally:
            conn.close()
    raise ValueError("too many sample redirects")


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
    "reverse_analyze": lambda a: re_analyze(a.get("url") or a.get("target") or ""),
    "ole_macros":   lambda a: ole_macros(a.get("url") or a.get("target") or ""),
    "exif":         lambda a: exif(a.get("url") or a.get("target") or ""),
    "yara_scan":    lambda a: yara_scan(a.get("url") or a.get("target") or ""),
}


@app.get("/health")
def health():
    return {"ok": True, "auth_configured": len(BROKER_TOKEN) >= 24, "tools": sorted(TOOLS.keys())}


@app.post("/run")
async def run(req: Request):
    if len(BROKER_TOKEN) < 24:
        raise HTTPException(status_code=503, detail="broker authentication is not securely configured")
    supplied = req.headers.get("authorization", "")
    expected = f"Bearer {BROKER_TOKEN}"
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="unauthorized")
    advertised = req.headers.get("content-length")
    if advertised:
        try:
            if int(advertised) > MAX_REQUEST_BYTES:
                raise HTTPException(status_code=413, detail="request too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid content length")
    try:
        raw = bytearray()
        async for chunk in req.stream():
            raw.extend(chunk)
            if len(raw) > MAX_REQUEST_BYTES:
                raise HTTPException(status_code=413, detail="request too large")
        body = json.loads(bytes(raw))
        if not isinstance(body, dict):
            raise ValueError("object required")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="bad json")
    tool = (body.get("tool") or "").strip().lower()
    args = body.get("args") if isinstance(body.get("args"), dict) else {}
    if tool not in TOOLS:
        return JSONResponse({"ok": False, "error": f"unknown broker tool: {tool}"}, status_code=404)
    try:
        result = await run_in_threadpool(TOOLS[tool], args)
        return {"ok": True, "tool": tool, "result": result}
    except Exception as e:
        return JSONResponse({"ok": False, "tool": tool, "error": str(e)}, status_code=500)
