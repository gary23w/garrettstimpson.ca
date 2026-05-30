/**
 * Garrett Stimpson — Security Research Agent  v4.0
 *
 * Canonical source: garrettstimpson.ca/agent/  (this repo).
 * garrettstimpson-agent is a CF deploy-bot template clone — do NOT hand-edit it.
 *
 * Pipeline (deterministic pre-processing → single streaming LLM call):
 *   1. Semantic RAG — embed query (bge-base-en-v1.5), query Cloudflare Vectorize
 *      for the most relevant *chunks*. Falls back to in-worker BM25 over chunks
 *      when no Vectorize binding is present (keeps the one-click template working).
 *   2. Deterministic tools — regex CVE extraction → NVD lookup; web search
 *      (Brave → SearXNG → DuckDuckGo HTML fallback).
 *   3. Session memory — KV-backed conversation persistence + rolling summary of
 *      older turns. No-ops gracefully when no KV binding is present.
 *   4. Single streaming LLM call with a tight, budgeted prompt.
 *
 * Bindings (all optional — code degrades gracefully):
 *   AI        — Workers AI            (required; free tier)
 *   VECTORIZE — Vectorize index       (optional; enables semantic RAG)
 *   SESSIONS  — KV namespace          (optional; enables persistent memory)
 */

const MODEL        = '@cf/meta/llama-3.1-8b-instruct';
const EMBED_MODEL   = '@cf/baai/bge-base-en-v1.5'; // 768-dim
const EMBED_DIM     = 768;

// Retrieval
const TOP_K         = 5;     // chunks injected per query
const CHUNK_CHARS   = 1000;  // target chunk size
const CHUNK_OVERLAP = 150;   // overlap between chunks
const CORPUS_CHARS  = 3800;  // hard cap on total corpus text in prompt
const TOOL_CHARS    = 2600;  // hard cap on tool-result text in prompt

// History / memory
const HIST_MSGS     = 6;     // verbatim turns carried into the prompt
const KEEP_TURNS    = 4;     // turns kept verbatim in a stored session
const SUMMARY_AT    = 10;    // summarise once a session exceeds this many turns
const SESSION_TTL   = 60 * 60 * 24 * 30; // 30 days

const CORPUS_TTL    = 3600;  // corpus cache TTL (seconds)
const RAW_LLMS      = 'https://raw.githubusercontent.com/gary23w/garrettstimpson.ca/main/llms.txt';

// ── Corpus parsing + chunking ──────────────────────────────────────────────────

function parseCorpus(raw) {
  const docs = [];
  const re = /<DOCUMENT[^>]*>([\s\S]*?)<\/DOCUMENT>/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    const block = m[1];
    const fm    = (/<FRONTMATTER>([\s\S]*?)<\/FRONTMATTER>/.exec(block) || [])[1] || '';
    const body  = (/<BODY>([\s\S]*?)<\/BODY>/.exec(block)               || [])[1] || '';
    const title = (/TITLE\s*:\s*(.+)/.exec(fm)  || [])[1]?.trim() || '';
    const url   = (/URL\s*:\s*(.+)/.exec(fm)    || [])[1]?.trim() || '';
    const cves  = (/CVE\s*:\s*(.+)/.exec(fm)    || [])[1]?.trim() || '';
    const tags  = (/TAGS\s*:\s*(.+)/.exec(fm)   || [])[1]?.trim() || '';
    docs.push({ title, url, cves, tags, frontmatter: fm, body, full: fm + '\n' + body });
  }
  return docs;
}

// Split a doc body into overlapping chunks on paragraph boundaries.
function chunkDoc(doc, idx) {
  const text = doc.body.trim();
  const chunks = [];
  if (!text) return chunks;
  const paras = text.split(/\n\s*\n/);
  let buf = '';
  const flush = () => {
    const t = buf.trim();
    if (t) chunks.push(t);
    buf = '';
  };
  for (const p of paras) {
    if ((buf + '\n\n' + p).length > CHUNK_CHARS && buf) {
      flush();
      // carry overlap from the tail of the previous chunk
      const prev = chunks[chunks.length - 1] || '';
      buf = prev.slice(-CHUNK_OVERLAP);
    }
    buf += (buf ? '\n\n' : '') + p;
    // a single huge paragraph — hard-split it
    while (buf.length > CHUNK_CHARS * 1.5) {
      chunks.push(buf.slice(0, CHUNK_CHARS).trim());
      buf = buf.slice(CHUNK_CHARS - CHUNK_OVERLAP);
    }
  }
  flush();
  return chunks.map((text, i) => ({
    id:    `${idx}-${i}`,
    title: doc.title,
    url:   doc.url,
    cves:  doc.cves,
    text,
  }));
}

function chunkAll(docs) {
  const out = [];
  docs.forEach((d, i) => out.push(...chunkDoc(d, i)));
  return out;
}

// ── BM25 (fallback retrieval over chunks) ──────────────────────────────────────

function tok(text) {
  return text.toLowerCase().replace(/[^a-z0-9\-\.]/g, ' ').split(/\s+/).filter(t => t.length > 1);
}

function bm25Chunks(chunks, query, k) {
  if (!chunks.length) return [];
  const qToks  = tok(query);
  const avgLen = chunks.reduce((s, c) => s + tok(c.text).length, 0) / chunks.length;
  const k1 = 1.5, b = 0.75;
  return chunks
    .map(c => {
      const tokens = tok(c.title + ' ' + c.cves + ' ' + c.text);
      const len = tokens.length || 1;
      const tf = {};
      tokens.forEach(t => (tf[t] = (tf[t] || 0) + 1));
      let score = 0;
      for (const qt of qToks) {
        const f = tf[qt] || 0;
        if (f > 0) score += (f * (k1 + 1)) / (f + k1 * (1 - b + b * (len / avgLen)));
        if (c.title.toLowerCase().includes(qt)) score += 3;
        if (/^cve-\d+-\d+$/.test(qt) && c.cves.toLowerCase().includes(qt)) score += 30;
      }
      return { c, score };
    })
    .sort((a, b) => b.score - a.score)
    .filter(x => x.score > 0)
    .slice(0, k)
    .map(x => ({ ...x.c, score: +x.score.toFixed(3) }));
}

function formatChunk(c) {
  return `### ${c.title}${c.cves && c.cves !== 'none' ? ` (${c.cves})` : ''}\n${c.url}\n${c.text}`;
}

// ── Embeddings + Vectorize ──────────────────────────────────────────────────────

async function embedTexts(env, texts) {
  const resp = await env.AI.run(EMBED_MODEL, { text: texts });
  return resp.data; // array of EMBED_DIM-length float arrays
}

// Semantic retrieval via Vectorize. Returns chunk objects with scores, or null
// if Vectorize is unavailable / errors (caller falls back to BM25).
async function vectorRetrieve(env, query, k) {
  if (!env.VECTORIZE) return null;
  try {
    const [vec] = await embedTexts(env, [query]);
    const res = await env.VECTORIZE.query(vec, { topK: k, returnMetadata: 'all' });
    return (res.matches || []).map(m => ({
      id:    m.id,
      title: m.metadata?.title || '',
      url:   m.metadata?.url   || '',
      cves:  m.metadata?.cves  || '',
      text:  m.metadata?.text  || '',
      score: +(m.score ?? 0).toFixed(3),
    })).filter(c => c.text);
  } catch (e) {
    return null;
  }
}

// Rebuild the Vectorize index from llms.txt. Returns a small report.
async function reindex(env) {
  if (!env.VECTORIZE) throw new Error('VECTORIZE binding not configured');
  const raw   = await fetchCorpusRaw(env);
  const docs  = parseCorpus(raw);
  const chunks = chunkAll(docs);
  let upserted = 0;
  // Embed + upsert in batches (Workers AI accepts arrays; keep batches modest).
  const BATCH = 50;
  for (let i = 0; i < chunks.length; i += BATCH) {
    const slice = chunks.slice(i, i + BATCH);
    const vecs  = await embedTexts(env, slice.map(c => c.text));
    const rows  = slice.map((c, j) => ({
      id: c.id,
      values: vecs[j],
      metadata: {
        title: c.title.slice(0, 200),
        url:   c.url,
        cves:  c.cves.slice(0, 200),
        // Vectorize metadata has size limits — cap stored chunk text.
        text:  c.text.slice(0, 2800),
      },
    }));
    await env.VECTORIZE.upsert(rows);
    upserted += rows.length;
  }
  return { docs: docs.length, chunks: chunks.length, upserted };
}

// ── Corpus cache (raw text + parsed/chunked fallback) ───────────────────────────

async function fetchCorpusRaw(env) {
  // Always prefer raw.githubusercontent — fetching garrettstimpson.ca from a CF
  // Worker triggers a CF-to-CF SSL loop (HTTP 526). Try a couple of fallbacks.
  const candidates = [
    RAW_LLMS,
    (env.LLMS_URL || '').replace(/^https?:\/\/garrettstimpson\.ca/, 'https://raw.githubusercontent.com/gary23w/garrettstimpson.ca/main'),
    env.LLMS_URL || '',
  ].filter(Boolean);
  let lastErr = 'no corpus URL';
  for (const u of candidates) {
    try {
      const r = await fetch(u, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) { lastErr = `HTTP ${r.status} from ${u}`; continue; }
      const txt = await r.text();
      if (txt.includes('<DOCUMENT')) return txt;
      lastErr = `no <DOCUMENT> blocks in ${u}`;
    } catch (e) { lastErr = `${e.message} (${u})`; }
  }
  throw new Error(`Corpus fetch failed: ${lastErr}`);
}

async function getChunks(env) {
  const cache = caches.default;
  const cKey  = new Request('https://corpus-cache/chunks-v4');
  const cached = await cache.match(cKey);
  if (cached) { try { return JSON.parse(await cached.text()); } catch {} }
  const docs   = parseCorpus(await fetchCorpusRaw(env));
  const chunks = chunkAll(docs);
  await cache.put(cKey, new Response(JSON.stringify(chunks), {
    headers: { 'Cache-Control': `max-age=${CORPUS_TTL}`, 'Content-Type': 'application/json' },
  }));
  return chunks;
}

// ── Session memory (KV) ─────────────────────────────────────────────────────────

async function loadSession(env, id) {
  if (!env.SESSIONS || !id) return null;
  try { return (await env.SESSIONS.get(`sess:${id}`, 'json')) || { id, summary: '', turns: [] }; }
  catch { return { id, summary: '', turns: [] }; }
}

async function saveSession(env, sess) {
  if (!env.SESSIONS || !sess?.id) return;
  sess.updated = Date.now();
  try {
    await env.SESSIONS.put(`sess:${sess.id}`, JSON.stringify(sess), { expirationTtl: SESSION_TTL });
    // maintain a lightweight index of session ids
    const idx = (await env.SESSIONS.get('sess:index', 'json')) || [];
    if (!idx.includes(sess.id)) {
      idx.unshift(sess.id);
      await env.SESSIONS.put('sess:index', JSON.stringify(idx.slice(0, 100)), { expirationTtl: SESSION_TTL });
    }
  } catch {}
}

// Compress older turns into a rolling summary once the session grows large.
async function summariseSession(env, sess) {
  if (sess.turns.length <= SUMMARY_AT) return sess;
  const keep = sess.turns.slice(-KEEP_TURNS);
  const old  = sess.turns.slice(0, -KEEP_TURNS);
  const transcript = old.map(t => `${t.role}: ${t.content}`).join('\n').slice(0, 6000);
  try {
    const resp = await env.AI.run(MODEL, {
      messages: [
        { role: 'system', content: 'Compress this security-research conversation into terse notes. Preserve every CVE ID, product/version, technique name, and the user\'s goals. Output notes only.' },
        { role: 'user', content: (sess.summary ? `Existing notes:\n${sess.summary}\n\nNew turns:\n` : '') + transcript },
      ],
      max_tokens: 320,
      stream: false,
    });
    const note = (resp.response || '').trim();
    if (note) { sess.summary = note; sess.turns = keep; }
  } catch {}
  return sess;
}

// ── Query analysis ──────────────────────────────────────────────────────────────

const SEARCH_TRIGGERS = [
  'latest', 'recent', 'new ', 'current', 'today', 'this week',
  'in the wild', 'active exploit', 'patch', 'advisory', 'poc', 'proof of concept',
  'github', 'shodan', 'search', 'find', 'look up', 'cve-',
];

function analyseQuery(query) {
  const q = query.toLowerCase();
  const cveIds = [...new Set((query.match(/CVE-\d{4}-\d+/gi) || []).map(c => c.toUpperCase()))];
  const wantSearch = SEARCH_TRIGGERS.some(t => q.includes(t)) || cveIds.length > 0;
  return { cveIds, wantSearch };
}

// ── Tools ───────────────────────────────────────────────────────────────────────

const FETCH_ALLOWLIST = [
  'github.com', 'raw.githubusercontent.com', 'nvd.nist.gov', 'cve.org',
  'exploit-db.com', 'www.exploit-db.com', 'microsoft.com', 'msrc.microsoft.com',
  'kernel.org', 'lore.kernel.org', 'ubuntu.com', 'usn.ubuntu.com',
  'redhat.com', 'access.redhat.com', 'cisco.com', 'tools.cisco.com',
  'nginx.org', 'nginx.com', 'postgresql.org', 'openssh.com', 'www.openssh.com',
  'debian.org', 'security.debian.org',
];

async function nvdLookup(cveId) {
  try {
    const r = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(8000) }
    );
    const data = await r.json();
    const vuln = data?.vulnerabilities?.[0]?.cve;
    if (!vuln) return `NVD: no entry found for ${cveId}.`;
    const desc  = vuln.descriptions?.find(d => d.lang === 'en')?.value || 'No description.';
    const cvss  = vuln.metrics?.cvssMetricV31?.[0]?.cvssData || vuln.metrics?.cvssMetricV30?.[0]?.cvssData;
    const score = cvss ? `CVSS ${cvss.baseScore} (${cvss.baseSeverity}) — ${cvss.vectorString}` : 'No CVSS score';
    const cwes  = (vuln.weaknesses || []).flatMap(w => w.description.map(d => d.value)).join(', ') || 'none';
    const refs  = (vuln.references || []).slice(0, 4).map(x => x.url).join('\n');
    return `${cveId} | ${score}\nCWE: ${cwes}\n${desc}\n\nRefs:\n${refs}`;
  } catch (e) {
    return `NVD lookup failed: ${e.message}`;
  }
}

function ddgParse(html) {
  // Parse DuckDuckGo HTML endpoint result anchors.
  const out = [];
  const re = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g;
  let m;
  while ((m = re.exec(html)) !== null && out.length < 6) {
    let url = m[1];
    const dec = /uddg=([^&]+)/.exec(url);
    if (dec) { try { url = decodeURIComponent(dec[1]); } catch {} }
    const title = m[2].replace(/<[^>]+>/g, '').trim();
    if (title) out.push({ title, url, content: '' });
  }
  return out;
}

async function webSearch(query, braveKey) {
  // 1. Brave (when key set)
  if (braveKey) {
    try {
      const r = await fetch(
        `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=6&search_lang=en`,
        { headers: { 'X-Subscription-Token': braveKey, 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000) }
      );
      const data = await r.json();
      const results = (data?.web?.results || []).slice(0, 6);
      if (results.length) {
        return { provider: 'Brave', results: results.map(x => ({ title: x.title, url: x.url, content: x.description || '' })) };
      }
    } catch (_) {}
  }
  // 2. SearXNG public instances (JSON)
  const SEARX = ['https://searx.be', 'https://search.disroot.org', 'https://priv.au'];
  for (const host of SEARX) {
    try {
      const r = await fetch(`${host}/search?q=${encodeURIComponent(query)}&format=json&categories=general`,
        { headers: { 'Accept': 'application/json', 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(7000) });
      if (!r.ok) continue;
      const data = await r.json();
      const results = (data.results || []).slice(0, 6);
      if (results.length) {
        return { provider: 'SearXNG', results: results.map(x => ({ title: x.title, url: x.url, content: (x.content || '').slice(0, 300) })) };
      }
    } catch (_) { continue; }
  }
  // 3. DuckDuckGo HTML fallback (no key, usually reachable from CF)
  for (const host of ['https://html.duckduckgo.com/html/', 'https://lite.duckduckgo.com/lite/']) {
    try {
      const r = await fetch(`${host}?q=${encodeURIComponent(query)}`,
        { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, signal: AbortSignal.timeout(8000) });
      if (!r.ok) continue;
      const results = ddgParse(await r.text());
      if (results.length) return { provider: 'DuckDuckGo', results };
    } catch (_) { continue; }
  }
  return null;
}

function formatSearch(s) {
  return `[${s.provider}]\n\n` + s.results.map((x, i) => `[${i + 1}] ${x.title}\n${x.url}\n${x.content || ''}`).join('\n\n');
}

async function fetchUrl(url) {
  let hostname;
  try { hostname = new URL(url).hostname; } catch { return `Invalid URL: ${url}`; }
  if (!FETCH_ALLOWLIST.some(d => hostname === d || hostname.endsWith('.' + d)))
    return `fetch_url: ${hostname} not in security domain allowlist.`;
  try {
    const r = await fetch(url, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(8000) });
    const text = await r.text();
    return text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 5000);
  } catch (e) { return `fetch failed: ${e.message}`; }
}

// ── Prompt assembly ─────────────────────────────────────────────────────────────

const PERSONA = [
  'You are the AI research assistant for the security-research blog "{SITE}".',
  'You are software, not a person — never invent a human name, biography, job title, or persona for yourself. If asked who you are, say you are this site\'s research assistant.',
  'Ground every claim in the CORPUS and LIVE TOOL RESULTS provided below.',
  'Never fabricate CVE IDs, CVSS scores, affected versions, patch dates, or PoC URLs. If the answer is not in the corpus or tool results, say so plainly.',
  'Answer with technical precision. Cite the post title/URL when you draw from the corpus.',
].join(' ');

function buildSystemPrompt(env, { summary, chunks, toolContext }) {
  const persona = PERSONA.replace('{SITE}', env.SITE_NAME || 'Garrett Stimpson Security Research');
  let corpusText = '';
  if (chunks.length) {
    let budget = CORPUS_CHARS;
    const parts = [];
    for (const c of chunks) {
      const block = formatChunk(c);
      if (budget - block.length < 0) break;
      parts.push(block); budget -= block.length;
    }
    corpusText = `CORPUS (top ${parts.length} chunks by relevance):\n${parts.join('\n\n---\n\n')}`;
  }
  const toolSection = toolContext.length ? `LIVE TOOL RESULTS:\n${toolContext.join('\n\n').slice(0, TOOL_CHARS)}` : '';
  const memSection  = summary ? `CONVERSATION MEMORY (summary of earlier turns):\n${summary}` : '';
  return [persona, memSection, toolSection, corpusText].filter(Boolean).join('\n\n');
}

// ── UI ──────────────────────────────────────────────────────────────────────────

function terminalUI(siteName) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${siteName} — Research Agent</title>
<style>
:root{--green:#00ff41;--blue:#00d4ff;--bg:#000;--panel:#0a0e0a;--border:#1a1a1a;--muted:#444;--warn:#ffb347;--err:#ff5555;}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--bg);color:var(--green);font-family:'JetBrains Mono',Menlo,monospace;font-size:13px;}
#app{display:flex;flex-direction:column;height:100vh;max-width:980px;margin:0 auto;padding:12px;}
header{border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:10px;}
.h-row{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;}
.h-title{font-size:11px;color:var(--muted);letter-spacing:.15em;text-transform:uppercase;}
.h-model{color:var(--blue);font-size:10px;margin-top:3px;}
.h-meta{font-size:10px;color:var(--muted);margin-top:2px;}
.btns{display:flex;gap:6px;flex-shrink:0;}
.btn{background:transparent;border:1px solid var(--border);color:var(--muted);font:inherit;font-size:10px;padding:3px 8px;cursor:pointer;border-radius:2px;}
.btn:hover{color:var(--green);border-color:var(--green);}
.btn.on{color:var(--blue);border-color:var(--blue);}
#settings{display:none;border:1px solid var(--border);border-radius:3px;padding:10px;margin-bottom:10px;background:var(--panel);font-size:11px;}
#settings.show{display:block;}
#settings label{display:flex;align-items:center;gap:8px;margin:5px 0;color:#bbb;}
#settings input[type=range]{flex:1;}
#settings input[type=text],#settings input[type=password]{flex:1;background:#000;border:1px solid var(--border);color:var(--green);font:inherit;padding:2px 6px;}
.set-val{color:var(--blue);min-width:34px;text-align:right;}
#main{flex:1;display:flex;gap:10px;min-height:0;}
#log{flex:1;overflow-y:auto;padding:4px 0;display:flex;flex-direction:column;gap:10px;}
#debug{display:none;width:320px;flex-shrink:0;overflow-y:auto;border-left:1px solid var(--border);padding-left:10px;font-size:10.5px;color:var(--blue);}
#debug.show{display:block;}
#debug .dh{color:var(--muted);text-transform:uppercase;letter-spacing:.1em;font-size:9px;margin:8px 0 3px;}
#debug .de{white-space:pre-wrap;word-break:break-word;line-height:1.5;border-left:2px solid var(--border);padding-left:6px;margin-bottom:4px;opacity:.9;}
.msg{line-height:1.65;white-space:pre-wrap;word-break:break-word;}
.msg.user::before{content:'> ';color:var(--green);}
.msg.user{color:#ccc;}
.msg.agent{color:var(--green);}
.msg.system{color:var(--muted);font-size:11px;font-style:italic;}
#input-row{display:flex;gap:8px;margin-top:10px;border-top:1px solid var(--border);padding-top:10px;}
#inp{flex:1;background:transparent;border:none;outline:none;color:var(--green);font:inherit;caret-color:var(--green);}
#inp::placeholder{color:var(--muted);}
#prompt{color:var(--green);flex-shrink:0;}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
</head>
<body>
<div id="app">
  <header>
    <div class="h-row">
      <div>
        <div class="h-title">${siteName}</div>
        <div class="h-model" id="modeline">llama-3.1-8b · workers ai · loading…</div>
        <div class="h-meta" id="status">initialising…</div>
      </div>
      <div class="btns">
        <button class="btn" id="btn-new" title="Start a new conversation">+ new</button>
        <button class="btn" id="btn-set" title="Settings">settings</button>
        <button class="btn" id="btn-dbg" title="Toggle debug pane">debug</button>
      </div>
    </div>
  </header>

  <div id="settings">
    <label><input type="checkbox" id="s-search" checked> web search (NVD + Brave/SearXNG/DuckDuckGo)</label>
    <label>temperature <input type="range" id="s-temp" min="0" max="1" step="0.1" value="0.3"><span class="set-val" id="s-temp-v">0.3</span></label>
    <label>top-K chunks <input type="range" id="s-topk" min="1" max="10" step="1" value="5"><span class="set-val" id="s-topk-v">5</span></label>
    <label><input type="checkbox" id="s-debug"> show debug pane by default</label>
    <label>brave api key (optional, stored in your browser) <input type="password" id="s-brave" placeholder="leave blank to skip"></label>
    <div style="color:var(--muted);margin-top:6px;font-size:10px;">Settings persist locally. Session id: <span id="s-sid"></span></div>
  </div>

  <div id="main">
    <div id="log"></div>
    <div id="debug"><div class="dh">debug log</div></div>
  </div>

  <div id="input-row">
    <span id="prompt">&gt;_</span>
    <input id="inp" autocomplete="off" autocorrect="off" spellcheck="false"
           placeholder="ask about a CVE, exploit, technique…" autofocus>
  </div>
</div>
<script>
var log=document.getElementById('log'), inp=document.getElementById('inp'), stat=document.getElementById('status'),
    modeline=document.getElementById('modeline'), dbgPane=document.getElementById('debug'),
    settings=document.getElementById('settings');
var MAX_HIST=6, busy=false;

// ---- settings persistence (localStorage) ----
function loadSettings(){
  var s={};
  try{ s=JSON.parse(localStorage.getItem('gsa_settings')||'{}'); }catch(e){}
  return s;
}
function saveSettings(){
  var s={search:el('s-search').checked, temp:el('s-temp').value, topk:el('s-topk').value,
         debug:el('s-debug').checked, brave:el('s-brave').value};
  try{ localStorage.setItem('gsa_settings', JSON.stringify(s)); }catch(e){}
}
function el(id){return document.getElementById(id);}

// ---- session id ----
function sid(){
  var id=null;
  try{ id=localStorage.getItem('gsa_sid'); }catch(e){}
  if(!id){ id='s_'+Math.random().toString(36).slice(2)+Date.now().toString(36);
    try{ localStorage.setItem('gsa_sid', id); }catch(e){} }
  return id;
}
var SID=sid();

function ts(){ return new Date().toLocaleTimeString(); }
function addMsg(role,text){
  var d=document.createElement('div'); d.className='msg '+role; d.textContent=text;
  log.appendChild(d); log.scrollTop=log.scrollHeight; return d;
}
function appendTo(el,chunk){ el.textContent+=chunk; log.scrollTop=log.scrollHeight; }
function dbg(head,body){
  if(head){ var h=document.createElement('div'); h.className='dh'; h.textContent=ts()+' · '+head; dbgPane.appendChild(h); }
  if(body){ var e=document.createElement('div'); e.className='de'; e.textContent=body; dbgPane.appendChild(e); }
  dbgPane.scrollTop=dbgPane.scrollHeight;
}

// ---- wire up controls ----
el('btn-set').onclick=function(){ settings.classList.toggle('show'); };
el('btn-dbg').onclick=function(){ var on=dbgPane.classList.toggle('show'); el('btn-dbg').classList.toggle('on',on); };
el('btn-new').onclick=function(){
  if(busy) return;
  try{ localStorage.removeItem('gsa_sid'); }catch(e){}
  SID=sid(); el('s-sid').textContent=SID;
  log.innerHTML=''; dbgPane.innerHTML='<div class="dh">debug log</div>';
  fetch('/api/session/'+encodeURIComponent(SID),{method:'DELETE'}).catch(function(){});
  addMsg('system','New conversation started.');
};
['s-search','s-temp','s-topk','s-debug','s-brave'].forEach(function(id){
  var node=el(id); node.addEventListener('change',saveSettings); node.addEventListener('input',saveSettings);
});
el('s-temp').addEventListener('input',function(){ el('s-temp-v').textContent=el('s-temp').value; });
el('s-topk').addEventListener('input',function(){ el('s-topk-v').textContent=el('s-topk').value; });

(function applySaved(){
  var s=loadSettings();
  if('search' in s) el('s-search').checked=s.search;
  if('temp' in s){ el('s-temp').value=s.temp; el('s-temp-v').textContent=s.temp; }
  if('topk' in s){ el('s-topk').value=s.topk; el('s-topk-v').textContent=s.topk; }
  if('debug' in s) el('s-debug').checked=s.debug;
  if('brave' in s) el('s-brave').value=s.brave;
  if(s.debug){ dbgPane.classList.add('show'); el('btn-dbg').classList.add('on'); }
  el('s-sid').textContent=SID;
})();

async function init(){
  try{
    var d=await (await fetch('/api/status')).json();
    modeline.textContent='llama-3.1-8b · '+(d.retrieval||'?')+' RAG · '+(d.memory?'memory on':'memory off')+' · NVD + web search';
    stat.textContent=ts()+' · corpus: '+d.docCount+' posts / '+(d.chunkCount||0)+' chunks · '+(d.totalChars||0).toLocaleString()+' chars';
    if(d.docCount===0) stat.textContent+=' · WARNING corpus empty';
    addMsg('system','Agent online. Ask about any CVE, exploit technique, affected system, detection strategy, or PoC mechanics covered in the research.');
  }catch(e){
    stat.textContent='corpus unavailable';
    addMsg('system','Warning: status load failed — '+e.message);
  }
}

inp.addEventListener('keydown', async function(e){
  if(e.key!=='Enter'||busy||!inp.value.trim()) return;
  var q=inp.value.trim(); inp.value=''; busy=true; inp.disabled=true;
  addMsg('user',q);
  var el2=addMsg('agent',''); var full='';
  var opts={ webSearch:el('s-search').checked, temperature:parseFloat(el('s-temp').value),
             topK:parseInt(el('s-topk').value,10), brave:el('s-brave').value||'' };
  dbg('query', q+'  [search='+opts.webSearch+' temp='+opts.temperature+' topK='+opts.topK+']');
  try{
    var res=await fetch('/api/chat',{ method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ sessionId:SID, message:q, settings:opts }) });
    if(!res.ok) throw new Error('HTTP '+res.status);
    var reader=res.body.getReader(), decoder=new TextDecoder(), buf='';
    while(true){
      var r=await reader.read(); if(r.done) break;
      buf+=decoder.decode(r.value,{stream:true});
      var lines=buf.split('\\n'); buf=lines.pop();
      for(var i=0;i<lines.length;i++){
        var line=lines[i];
        if(line.indexOf('data: [DONE]')===0) continue;
        if(line.indexOf('data: DBG:')===0){
          var p=line.slice(10); var sep=p.indexOf('|');
          dbg(sep>=0?p.slice(0,sep):p, sep>=0?p.slice(sep+1):''); continue;
        }
        if(line.indexOf('data: ')!==0) continue;
        try{ var obj=JSON.parse(line.slice(6)); var t=obj.response||''; if(t){ full+=t; appendTo(el2,t);} }catch(e3){}
      }
    }
  }catch(e){ appendTo(el2,'[error] '+e.message); }
  busy=false; inp.disabled=false; inp.focus();
});

init();
</script>
</body>
</html>`;
}

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async scheduled(event, env, ctx) {
    // Daily: keep the Vectorize index fresh after llms.txt regenerates.
    if (env.VECTORIZE) { ctx.waitUntil(reindex(env).catch(() => {})); }
  },

  async fetch(request, env) {
    const url  = new URL(request.url);
    const cors = {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

    // GET /
    if (url.pathname === '/') {
      return new Response(terminalUI(env.SITE_NAME || 'Security Research'), {
        headers: { ...cors, 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // GET /api/status
    if (url.pathname === '/api/status' && request.method === 'GET') {
      try {
        const chunks = await getChunks(env);
        const docIds = new Set(chunks.map(c => c.id.split('-')[0]));
        return json({
          ok: true,
          docCount:   docIds.size,
          chunkCount: chunks.length,
          totalChars: chunks.reduce((s, c) => s + c.text.length, 0),
          retrieval:  env.VECTORIZE ? 'vectorize-semantic' : 'bm25-chunk',
          memory:     !!env.SESSIONS,
        });
      } catch (e) { return json({ ok: false, error: e.message }, 500); }
    }

    // POST /api/reindex — rebuild the Vectorize index from llms.txt
    if (url.pathname === '/api/reindex' && request.method === 'POST') {
      try { return json({ ok: true, ...(await reindex(env)) }); }
      catch (e) { return json({ ok: false, error: e.message }, 500); }
    }

    // DELETE /api/session/:id — clear a stored conversation
    if (url.pathname.startsWith('/api/session/') && request.method === 'DELETE') {
      const id = decodeURIComponent(url.pathname.split('/').pop() || '');
      if (env.SESSIONS && id) { try { await env.SESSIONS.delete(`sess:${id}`); } catch {} }
      return json({ ok: true });
    }

    // GET /api/session/:id — fetch a stored conversation
    if (url.pathname.startsWith('/api/session/') && request.method === 'GET') {
      const id = decodeURIComponent(url.pathname.split('/').pop() || '');
      const sess = await loadSession(env, id);
      return json({ ok: true, session: sess });
    }

    // POST /api/debug — show the assembled prompt without calling the chat model
    if (url.pathname === '/api/debug' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch { return new Response('Bad JSON', { status: 400, headers: cors }); }
      const q = body.message || '';
      const { cveIds, wantSearch } = analyseQuery(q);
      const toolContext = [];
      for (const cveId of cveIds.slice(0, 3)) toolContext.push(`=== NVD: ${cveId} ===\n${await nvdLookup(cveId)}`);
      let chunks = await vectorRetrieve(env, q, body.topK || TOP_K);
      const usedVectorize = chunks !== null;
      if (!chunks) chunks = bm25Chunks(await getChunks(env), q, body.topK || TOP_K);
      const sys = buildSystemPrompt(env, { summary: '', chunks, toolContext });
      return json({
        cveIds, wantSearch, usedVectorize,
        chunkCount: chunks.length,
        chunks: chunks.map(c => ({ title: c.title, score: c.score, chars: c.text.length })),
        systemChars: sys.length,
        systemPreview: sys.slice(0, 600),
      });
    }

    // POST /api/chat
    if (url.pathname === '/api/chat' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch { return new Response('Bad JSON', { status: 400, headers: cors }); }

      const opts      = body.settings || {};
      const topK      = Math.max(1, Math.min(10, opts.topK || TOP_K));
      const temp      = typeof opts.temperature === 'number' ? opts.temperature : 0.3;
      const useSearch = opts.webSearch !== false;
      const braveKey  = opts.brave || env.BRAVE_API_KEY || '';

      // Resolve conversation: server session (KV) is authoritative when present.
      let sess = await loadSession(env, body.sessionId);
      const lastUser = body.message
        || (body.messages ? [...body.messages].reverse().find(m => m.role === 'user')?.content : '') || '';
      let priorTurns;
      if (sess) {
        sess.turns.push({ role: 'user', content: lastUser });
        priorTurns = sess.turns.slice(-HIST_MSGS);
      } else {
        const msgs = (body.messages || []).slice(-HIST_MSGS);
        priorTurns = lastUser && !msgs.length ? [{ role: 'user', content: lastUser }] : msgs;
      }

      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const enc    = new TextEncoder();
      const send   = d => writer.write(enc.encode('data: ' + d + '\n\n'));
      const dbg    = (h, b) => send('DBG:' + h + (b !== undefined ? '|' + String(b).slice(0, 400) : ''));

      (async () => {
        const t0 = Date.now();
        try {
          const { cveIds, wantSearch } = analyseQuery(lastUser);
          const toolContext = [];

          // NVD lookups
          for (const cveId of cveIds.slice(0, 3)) {
            dbg('lookup_nvd', cveId);
            const result = await nvdLookup(cveId);
            dbg('nvd result', result.slice(0, 160));
            toolContext.push(`=== NVD: ${cveId} ===\n${result}`);
          }

          // Web search
          if (useSearch && wantSearch) {
            const q = cveIds.length ? `${cveIds[0]} exploit PoC advisory` : lastUser;
            dbg('search_web', q);
            const s = await webSearch(q, braveKey);
            if (s) { dbg('search result', s.provider + ': ' + s.results.length + ' hits'); toolContext.push(`=== Web Search ===\n${formatSearch(s)}`); }
            else {
              dbg('search result', 'all providers unavailable');
              toolContext.push('=== Search Unavailable ===\nAll web search providers failed. Do NOT fabricate CVE IDs, CVSS scores, affected versions, PoC URLs, or patch dates. If the corpus does not contain the answer, say so clearly.');
            }
          }

          // Retrieval — Vectorize semantic, BM25 fallback
          let chunks = await vectorRetrieve(env, lastUser, topK);
          const usedVectorize = chunks !== null;
          if (!chunks) chunks = bm25Chunks(await getChunks(env), lastUser, topK);
          dbg('retrieval', (usedVectorize ? 'vectorize' : 'bm25') + ' · ' + chunks.length + ' chunks · ' +
              chunks.map(c => (c.title || '?').slice(0, 24) + '(' + (c.score ?? '') + ')').join(', '));

          // Build prompt
          const sysPrompt = buildSystemPrompt(env, { summary: sess?.summary || '', chunks, toolContext });
          const messages = [
            { role: 'system', content: sysPrompt },
            ...priorTurns.filter(m => (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim()),
          ];
          dbg('prompt', 'sys=' + sysPrompt.length + 'ch · msgs=' + messages.length + ' · ' + (Date.now() - t0) + 'ms prep');

          // Stream
          const stream = await env.AI.run(MODEL, { messages, stream: true, max_tokens: 1024, temperature: temp });
          const reader = stream.getReader();
          const dec = new TextDecoder();
          let buf = '', full = '';
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += dec.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop();
            for (const line of lines) {
              if (line.startsWith('data: [DONE]')) continue;
              if (!line.startsWith('data: ')) continue;
              try {
                const obj = JSON.parse(line.slice(6));
                const t = obj.response || obj.choices?.[0]?.delta?.content || '';
                if (t) { full += t; send(JSON.stringify({ response: t })); }
              } catch {}
            }
          }
          dbg('done', (Date.now() - t0) + 'ms · ' + full.length + ' chars');

          // Persist + summarise
          if (sess && full.trim()) {
            sess.turns.push({ role: 'assistant', content: full });
            sess = await summariseSession(env, sess);
            await saveSession(env, sess);
          }
          send('[DONE]');
        } catch (e) {
          send(JSON.stringify({ response: `\n[Error: ${e.message}]` }));
          send('[DONE]');
        } finally {
          await writer.close();
        }
      })();

      return new Response(readable, {
        headers: { ...cors, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no' },
      });
    }

    return new Response('Not found', { status: 404, headers: cors });
  },
};
