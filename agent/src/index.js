/**
 * Agent Garrett — Security Research Agent  v4.1
 *
 * Canonical source: garrettstimpson.ca/agent/  (this repo).
 * garrettstimpson-agent is a CF deploy-bot template clone — do NOT hand-edit it.
 *
 * Pipeline (deterministic pre-processing → single streaming LLM call):
 *   1. Semantic RAG — embed query (bge-base-en-v1.5), query Cloudflare Vectorize
 *      for the most relevant *chunks*. Falls back to in-worker BM25 over chunks
 *      when no Vectorize binding is present (keeps the one-click template working).
 *   2. Deterministic tools — regex CVE extraction → NVD + EPSS lookup; passive
 *      RDAP IP-ownership lookup (no scanning); web search (Brave → SearXNG → DuckDuckGo).
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
const RAW_LLMS      = 'https://raw.githubusercontent.com/gary23w/garrettstimpson.ca/refs/heads/main/llms.txt';

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
  // Public IPv4 addresses only — used for passive RDAP ownership lookup, never scanning.
  const ips = [...new Set((query.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])
    .filter(ip => ip.split('.').every(o => +o >= 0 && +o <= 255))
    .filter(ip => !/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(ip)))];
  const wantSearch = SEARCH_TRIGGERS.some(t => q.includes(t)) || cveIds.length > 0;
  return { cveIds, ips, wantSearch };
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

// EPSS — exploitation-probability score (FIRST.org). Read-only intel enrichment.
async function epssLookup(cveId) {
  try {
    const r = await fetch(`https://api.first.org/data/v1/epss?cve=${cveId}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(7000) });
    const d = (await r.json())?.data?.[0];
    if (!d) return null;
    const pct = (parseFloat(d.epss) * 100).toFixed(2);
    const prc = (parseFloat(d.percentile) * 100).toFixed(1);
    return `EPSS: ${pct}% chance of exploitation in next 30d (percentile ${prc}%)`;
  } catch { return null; }
}

// Passive IP ownership lookup via RDAP (registration data only — NOT a port
// scan). Defensive OSINT: who owns an address, ASN, country, abuse contact.
async function ipLookup(ip) {
  try {
    const r = await fetch(`https://rdap.org/ip/${ip}`,
      { headers: { 'Accept': 'application/rdap+json', 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return `RDAP: no registration data for ${ip} (HTTP ${r.status}).`;
    const d = await r.json();
    const range = d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : (d.handle || '');
    const org = (d.entities || []).map(e => {
      const v = e.vcardArray?.[1] || [];
      const fn = v.find(x => x[0] === 'fn')?.[3];
      return fn ? `${fn} (${(e.roles || []).join('/')})` : null;
    }).filter(Boolean).slice(0, 3).join('; ');
    const remarks = (d.remarks || []).flatMap(x => x.description || []).join(' ').slice(0, 200);
    return `RDAP ${ip} | name: ${d.name || '?'} | range: ${range} | country: ${d.country || '?'}\norg: ${org || '?'}${remarks ? '\nremarks: ' + remarks : ''}`;
  } catch (e) { return `RDAP lookup failed for ${ip}: ${e.message}`; }
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
  'Your name is Agent Garrett, the AI research assistant for the security-research blog "{SITE}".',
  'You are software. "Agent Garrett" is your assistant name only — do not claim to be a human, and do not fabricate a biography, employer, certifications, or personal history for yourself.',
  'Ground every claim in the CORPUS and LIVE TOOL RESULTS provided below.',
  'Never fabricate CVE IDs, CVSS scores, EPSS scores, affected versions, patch dates, or PoC URLs. If the answer is not in the corpus or tool results, say so plainly.',
  'Use clear markdown: ## headings, **bold** for key terms, `code` for identifiers/commands, fenced ```code blocks```, and bullet lists where helpful.',
  'Answer with technical precision. Cite the post title/URL when you draw from the corpus.',
].join(' ');

function buildSystemPrompt(env, { summary, chunks, toolContext, clientMemory }) {
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
  const memParts = [];
  if (summary)      memParts.push(`Summary of earlier turns:\n${summary}`);
  if (clientMemory) memParts.push(`Relevant prior research/notes:\n${String(clientMemory).slice(0, 1500)}`);
  const memSection = memParts.length ? `MEMORY:\n${memParts.join('\n\n')}` : '';
  return [persona, memSection, toolSection, corpusText].filter(Boolean).join('\n\n');
}

// ── UI ──────────────────────────────────────────────────────────────────────────

function terminalUI(siteName) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Garrett — ${siteName}</title>
<style>
:root{--green:#00ff41;--blue:#00d4ff;--bg:#000;--panel:#0a0e0a;--border:#1a1a1a;--muted:#444;--warn:#ffb347;--err:#ff5555;}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--bg);color:var(--green);font-family:'JetBrains Mono',Menlo,monospace;font-size:13px;}
/* themed scrollbars */
*{scrollbar-width:thin;scrollbar-color:#0f5a26 #050805;}
::-webkit-scrollbar{width:8px;height:8px;}
::-webkit-scrollbar-track{background:#050805;}
::-webkit-scrollbar-thumb{background:#0a3d1a;border:1px solid #0f5a26;border-radius:2px;}
::-webkit-scrollbar-thumb:hover{background:#0f5a26;}
#app{display:flex;flex-direction:column;height:100vh;max-width:980px;margin:0 auto;padding:12px;}
header{border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:10px;}
.h-row{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;}
.h-title{font-size:13px;color:var(--green);letter-spacing:.12em;text-transform:uppercase;font-weight:700;}
.h-sub{font-size:10px;color:var(--muted);letter-spacing:.12em;}
.h-model{color:var(--blue);font-size:10px;margin-top:3px;}
.h-meta{font-size:10px;color:var(--muted);margin-top:2px;}
.btns{display:flex;gap:6px;flex-shrink:0;}
.btn{background:transparent;border:1px solid var(--border);color:var(--muted);font:inherit;font-size:10px;padding:3px 8px;cursor:pointer;border-radius:2px;}
.btn:hover{color:var(--green);border-color:var(--green);}
.btn.on{color:var(--blue);border-color:var(--blue);}
#chatbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:10px;}
.chat-tab{display:flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:2px;padding:3px 7px;font-size:10px;color:var(--muted);cursor:pointer;max-width:220px;}
.chat-tab:hover{border-color:var(--green);}
.chat-tab.active{color:var(--green);border-color:var(--green);}
.chat-tab .ct-title{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:170px;}
.chat-tab .ct-del{color:var(--muted);font-weight:700;}
.chat-tab .ct-del:hover{color:var(--err);}
.chat-count{font-size:9px;color:var(--muted);margin-left:4px;}
#settings{display:none;border:1px solid var(--border);border-radius:3px;padding:10px;margin-bottom:10px;background:var(--panel);font-size:11px;}
#settings.show{display:block;}
#settings label{display:flex;align-items:center;gap:8px;margin:5px 0;color:#bbb;}
#settings input[type=range]{flex:1;}
#settings input[type=text],#settings input[type=password]{flex:1;background:#000;border:1px solid var(--border);color:var(--green);font:inherit;padding:2px 6px;}
.set-val{color:var(--blue);min-width:34px;text-align:right;}
#main{flex:1;display:flex;gap:10px;min-height:0;}
#log{flex:1;overflow-y:auto;padding:4px 6px 4px 0;display:flex;flex-direction:column;gap:10px;}
#debug{display:none;width:320px;flex-shrink:0;overflow-y:auto;border-left:1px solid var(--border);padding-left:10px;font-size:10.5px;color:var(--blue);}
#debug.show{display:block;}
#debug .dh{color:var(--muted);text-transform:uppercase;letter-spacing:.1em;font-size:9px;margin:8px 0 3px;}
#debug .de{white-space:pre-wrap;word-break:break-word;line-height:1.5;border-left:2px solid var(--border);padding-left:6px;margin-bottom:4px;opacity:.9;}
.msg{line-height:1.65;word-break:break-word;}
.msg.user{white-space:pre-wrap;color:#ccc;}
.msg.user::before{content:'> ';color:var(--green);}
.msg.agent{color:var(--green);}
.msg.system{color:var(--muted);font-size:11px;font-style:italic;}
.msg.agent.streaming{white-space:pre-wrap;}
/* markdown rendering inside agent messages */
.msg.agent h2,.msg.agent h3,.msg.agent h4{color:var(--blue);font-size:13px;margin:8px 0 4px;border-bottom:1px solid var(--border);padding-bottom:2px;}
.msg.agent p{margin:6px 0;}
.msg.agent ul,.msg.agent ol{margin:6px 0 6px 20px;}
.msg.agent li{margin:2px 0;}
.msg.agent code{background:#0a140a;color:var(--blue);padding:1px 5px;border-radius:2px;font-size:12px;}
.msg.agent pre{background:#070b07;border:1px solid var(--border);border-left:2px solid var(--green);padding:8px 10px;overflow-x:auto;margin:8px 0;border-radius:2px;}
.msg.agent pre code{background:none;color:var(--green);padding:0;}
.msg.agent a{color:var(--blue);text-decoration:underline;}
.msg.agent strong{color:#7fffb0;}
#input-row{display:flex;gap:8px;margin-top:10px;border-top:1px solid var(--border);padding-top:10px;}
#inp{flex:1;background:transparent;border:none;outline:none;color:var(--green);font:inherit;caret-color:var(--green);}
#inp::placeholder{color:var(--muted);}
#prompt{color:var(--green);flex-shrink:0;}
#jobs{display:none;border:1px solid var(--border);border-radius:3px;padding:10px;margin-bottom:10px;background:var(--panel);font-size:11px;}
#jobs.show{display:block;}
#jobs .row{display:flex;gap:8px;align-items:center;margin:5px 0;flex-wrap:wrap;}
#jobs input[type=text],#jobs select{background:#000;border:1px solid var(--border);color:var(--green);font:inherit;padding:3px 6px;}
#jobs input#j-obj{flex:1;min-width:240px;}
#jobs .jbtn{border:1px solid var(--green);color:var(--green);background:transparent;font:inherit;font-size:10px;padding:3px 10px;cursor:pointer;border-radius:2px;}
#jobs .jbtn:hover{background:#0a2a12;}
#j-tasks{margin-top:8px;display:flex;flex-direction:column;gap:3px;}
.jtask{display:flex;gap:8px;align-items:center;font-size:10.5px;color:#bbb;}
.jbadge{font-size:9px;padding:1px 6px;border-radius:2px;border:1px solid var(--border);}
.jbadge.queued{color:var(--muted);}
.jbadge.running{color:var(--blue);border-color:var(--blue);}
.jbadge.done{color:var(--green);border-color:var(--green);}
.jbadge.failed{color:var(--err);border-color:var(--err);}
#j-saved{margin-top:8px;color:var(--muted);font-size:10px;}
#j-saved .sjob{display:flex;gap:8px;align-items:center;margin:2px 0;}
#j-saved .sj-del{color:var(--muted);cursor:pointer;font-weight:700;}
#j-saved .sj-del:hover{color:var(--err);}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
</head>
<body>
<div id="app">
  <header>
    <div class="h-row">
      <div>
        <div class="h-title">Agent Garrett</div>
        <div class="h-sub">${siteName}</div>
        <div class="h-model" id="modeline">llama-3.1-8b · workers ai · loading…</div>
        <div class="h-meta" id="status">initialising…</div>
      </div>
      <div class="btns">
        <button class="btn" id="btn-new" title="Start a new conversation (max 3)">+ new</button>
        <button class="btn" id="btn-set" title="Settings">settings</button>
        <button class="btn" id="btn-dbg" title="Toggle debug pane">debug</button>
        <button class="btn" id="btn-job" title="Agent mode — jobs &amp; swarms">agent</button>
      </div>
    </div>
  </header>

  <div id="chatbar"><span class="chat-count" id="chatcount"></span></div>

  <div id="settings">
    <label><input type="checkbox" id="s-search" checked> web search (NVD + EPSS + RDAP + Brave/SearXNG/DuckDuckGo)</label>
    <label>temperature <input type="range" id="s-temp" min="0" max="1" step="0.1" value="0.3"><span class="set-val" id="s-temp-v">0.3</span></label>
    <label>top-K chunks <input type="range" id="s-topk" min="1" max="10" step="1" value="5"><span class="set-val" id="s-topk-v">5</span></label>
    <label><input type="checkbox" id="s-debug"> show debug pane by default</label>
    <label>brave api key (optional, stored in your browser) <input type="password" id="s-brave" placeholder="leave blank to skip"></label>
    <div style="color:var(--muted);margin-top:6px;font-size:10px;">Settings &amp; chats are saved in this browser. Up to 3 conversations are kept.</div>
  </div>

  <div id="jobs">
    <div style="color:var(--muted);margin-bottom:6px;">AGENT MODE — give Agent Garrett a job. It plans linked sub-tasks, runs them as a swarm, and writes a synthesized report into the current chat.</div>
    <div class="row">
      <input id="j-obj" type="text" placeholder="objective — e.g. profile CVE-2026-2005, or recon 8.8.8.8">
      <select id="j-tpl">
        <option value="cve">CVE profile</option>
        <option value="infra">Infra recon (passive)</option>
        <option value="malware">Malware/actor brief</option>
        <option value="free">Free-form</option>
      </select>
      <button class="jbtn" id="j-run">run swarm</button>
    </div>
    <div class="row">
      schedule:
      <select id="j-sched">
        <option value="0">off</option>
        <option value="900000">every 15m</option>
        <option value="3600000">hourly</option>
        <option value="21600000">every 6h</option>
        <option value="86400000">daily</option>
      </select>
      <button class="jbtn" id="j-save">save scheduled job</button>
      <span style="color:var(--muted);font-size:9px;">(runs while this tab is open)</span>
    </div>
    <div id="j-tasks"></div>
    <div id="j-saved"></div>
  </div>

  <div id="main">
    <div id="log"></div>
    <div id="debug"><div class="dh">debug log</div></div>
  </div>

  <div id="input-row">
    <span id="prompt">&gt;_</span>
    <input id="inp" autocomplete="off" autocorrect="off" spellcheck="false"
           placeholder="ask Agent Garrett about a CVE, exploit, technique, IP…" autofocus>
  </div>
</div>
<script>
var MAX_CHATS=3, MAX_HIST=6, busy=false;
function el(id){return document.getElementById(id);}
var log=el('log'), inp=el('inp'), stat=el('status'), modeline=el('modeline'),
    dbgPane=el('debug'), settings=el('settings'), chatbar=el('chatbar');
function ts(){ return new Date().toLocaleTimeString(); }

// ---------- safe markdown renderer (escape-first, fixed tag whitelist) ----------
function renderMarkdown(src){
  var BT=String.fromCharCode(96);
  var blocks=[];
  src=src.replace(new RegExp(BT+BT+BT+'([^]*?)'+BT+BT+BT,'g'),function(m,code){
    blocks.push(code.replace(/^[a-zA-Z0-9]*\\n/,'')); return '\\u0000CB'+(blocks.length-1)+'\\u0000';
  });
  function esc(t){ return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  src=esc(src);
  src=src.replace(new RegExp(BT+'([^'+BT+']+)'+BT,'g'),'<code>$1</code>');
  src=src.replace(/\\*\\*([^*]+)\\*\\*/g,'<strong>$1</strong>');
  src=src.replace(/\\[([^\\]]+)\\]\\((https?:\\/\\/[^)\\s"'<>]+)\\)/g,'<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  var lines=src.split('\\n'), out=[], inList=null;
  function closeList(){ if(inList){ out.push('</'+inList+'>'); inList=null; } }
  for(var i=0;i<lines.length;i++){
    var ln=lines[i];
    if(/^\\u0000CB\\d+\\u0000$/.test(ln.trim())){ closeList(); out.push(ln.trim()); continue; }
    var h=ln.match(/^(#{1,4})\\s+(.*)$/);
    if(h){ closeList(); var lvl=Math.min(h[1].length+1,6); out.push('<h'+lvl+'>'+h[2]+'</h'+lvl+'>'); continue; }
    var ul=ln.match(/^\\s*[-*]\\s+(.*)$/);
    var ol=ln.match(/^\\s*\\d+\\.\\s+(.*)$/);
    if(ul){ if(inList!=='ul'){ closeList(); out.push('<ul>'); inList='ul'; } out.push('<li>'+ul[1]+'</li>'); continue; }
    if(ol){ if(inList!=='ol'){ closeList(); out.push('<ol>'); inList='ol'; } out.push('<li>'+ol[1]+'</li>'); continue; }
    if(ln.trim()===''){ closeList(); continue; }
    closeList(); out.push('<p>'+ln+'</p>');
  }
  closeList();
  var html=out.join('\\n');
  html=html.replace(/\\u0000CB(\\d+)\\u0000/g,function(m,idx){ return '<pre><code>'+esc(blocks[+idx]||'')+'</code></pre>'; });
  return html;
}

// ---------- settings persistence ----------
function loadSettings(){ try{ return JSON.parse(localStorage.getItem('gsa_settings')||'{}'); }catch(e){ return {}; } }
function saveSettings(){
  try{ localStorage.setItem('gsa_settings', JSON.stringify({
    search:el('s-search').checked, temp:el('s-temp').value, topk:el('s-topk').value,
    debug:el('s-debug').checked, brave:el('s-brave').value })); }catch(e){}
}

// ---------- chats (memory on by default, max 3) ----------
function newId(){ return 's_'+Math.random().toString(36).slice(2)+Date.now().toString(36); }
function loadChats(){ try{ return JSON.parse(localStorage.getItem('gsa_chats')||'[]'); }catch(e){ return []; } }
function saveChats(c){ try{ localStorage.setItem('gsa_chats', JSON.stringify(c)); }catch(e){} }
function getActiveId(){ try{ return localStorage.getItem('gsa_active'); }catch(e){ return null; } }
function setActiveId(id){ try{ localStorage.setItem('gsa_active', id); }catch(e){} }

var chats=loadChats();
function active(){
  var id=getActiveId();
  var c=chats.filter(function(x){return x.id===id;})[0];
  if(!c){ c=chats[0]; if(c) setActiveId(c.id); }
  if(!c){ c={id:newId(), title:'new chat', msgs:[]}; chats.unshift(c); setActiveId(c.id); saveChats(chats); }
  return c;
}

function renderChats(){
  var id=active().id;
  while(chatbar.firstChild) chatbar.removeChild(chatbar.firstChild);
  chats.forEach(function(c){
    var tab=document.createElement('div'); tab.className='chat-tab'+(c.id===id?' active':'');
    var t=document.createElement('span'); t.className='ct-title'; t.textContent=c.title||'new chat';
    var x=document.createElement('span'); x.className='ct-del'; x.textContent='×'; x.title='Delete chat';
    tab.appendChild(t); tab.appendChild(x);
    tab.onclick=function(ev){ if(ev.target===x){ deleteChat(c.id); return; } switchChat(c.id); };
    chatbar.appendChild(tab);
  });
  var cnt=document.createElement('span'); cnt.className='chat-count'; cnt.id='chatcount';
  cnt.textContent=chats.length+'/'+MAX_CHATS+' chats';
  chatbar.appendChild(cnt);
}

function renderLog(c){
  while(log.firstChild) log.removeChild(log.firstChild);
  if(!c.msgs.length){ addMsg('system','Agent Garrett online. Ask about any CVE, exploit technique, affected system, IP ownership, or PoC mechanics in the research.'); return; }
  c.msgs.forEach(function(m){
    if(m.role==='user') addMsg('user',m.content);
    else{ var d=addMsg('agent',''); d.innerHTML=renderMarkdown(m.content); }
  });
}

function switchChat(id){ if(busy) return; setActiveId(id); renderChats(); renderLog(active()); inp.focus(); }

function deleteChat(id){
  if(busy) return;
  chats=chats.filter(function(x){return x.id!==id;});
  saveChats(chats);
  fetch('/api/session/'+encodeURIComponent(id),{method:'DELETE'}).catch(function(){});
  if(getActiveId()===id){ setActiveId(chats[0]?chats[0].id:null); }
  renderChats(); renderLog(active());
}

function newChat(){
  if(busy) return;
  if(chats.length>=MAX_CHATS){
    chatbar.style.outline='1px solid var(--warn)';
    setTimeout(function(){ chatbar.style.outline=''; }, 1200);
    addMsg('system','You have '+MAX_CHATS+' saved chats — the maximum. Delete one (× on a chat tab above) before starting a new conversation.');
    return;
  }
  var c={id:newId(), title:'new chat', msgs:[]}; chats.unshift(c); setActiveId(c.id); saveChats(chats);
  renderChats(); renderLog(c); inp.focus();
}

// ---------- message rendering ----------
function addMsg(role,text){
  var d=document.createElement('div'); d.className='msg '+role; d.textContent=text;
  log.appendChild(d); log.scrollTop=log.scrollHeight; return d;
}
function dbg(head,body){
  if(head){ var h=document.createElement('div'); h.className='dh'; h.textContent=ts()+' · '+head; dbgPane.appendChild(h); }
  if(body){ var e=document.createElement('div'); e.className='de'; e.textContent=body; dbgPane.appendChild(e); }
  dbgPane.scrollTop=dbgPane.scrollHeight;
}

// ---------- controls ----------
el('btn-set').onclick=function(){ settings.classList.toggle('show'); };
el('btn-dbg').onclick=function(){ var on=dbgPane.classList.toggle('show'); el('btn-dbg').classList.toggle('on',on); };
el('btn-new').onclick=newChat;
['s-search','s-temp','s-topk','s-debug','s-brave'].forEach(function(id){
  var n=el(id); n.addEventListener('change',saveSettings); n.addEventListener('input',saveSettings);
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
})();

async function init(){
  renderChats(); renderLog(active());
  try{
    var d=await (await fetch('/api/status')).json();
    modeline.textContent='llama-3.1-8b · '+(d.retrieval||'?')+' RAG · memory on · NVD+EPSS+RDAP+web';
    stat.textContent=ts()+' · corpus: '+d.docCount+' posts / '+(d.chunkCount||0)+' chunks · '+(d.totalChars||0).toLocaleString()+' chars'+(d.memory?' · KV sync':'');
    if(d.docCount===0) stat.textContent+=' · WARNING corpus empty';
  }catch(e){ stat.textContent='status unavailable — '+e.message; }
}

inp.addEventListener('keydown', async function(e){
  if(e.key!=='Enter'||busy||!inp.value.trim()) return;
  var q=inp.value.trim(); inp.value=''; busy=true; inp.disabled=true;
  var c=active();
  if(!c.msgs.length){ c.title=q.slice(0,40); }
  c.msgs.push({role:'user',content:q}); saveChats(chats); renderChats();
  addMsg('user',q);
  var el2=addMsg('agent',''); el2.className='msg agent streaming'; var full='';
  var opts={ webSearch:el('s-search').checked, temperature:parseFloat(el('s-temp').value),
             topK:parseInt(el('s-topk').value,10), brave:el('s-brave').value||'' };
  dbg('query', q+'  [search='+opts.webSearch+' temp='+opts.temperature+' topK='+opts.topK+']');
  try{
    var res=await fetch('/api/chat',{ method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ sessionId:c.id, message:q, messages:c.msgs.slice(-MAX_HIST), memory:MEM.retrieve(q,4), settings:opts }) });
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
        try{ var obj=JSON.parse(line.slice(6)); var t=obj.response||''; if(t){ full+=t; el2.textContent+=t; log.scrollTop=log.scrollHeight; } }catch(e3){}
      }
    }
  }catch(e){ full=(full||'')+'\\n[error] '+e.message; el2.textContent=full; }
  el2.className='msg agent';
  if(full.trim()){ el2.innerHTML=renderMarkdown(full); c.msgs.push({role:'assistant',content:full}); saveChats(chats); MEM.add(q+' \u2192 '+full.slice(0,500),'finding'); }
  busy=false; inp.disabled=false; inp.focus();
});


// ============ JS-controlled memory bank (browser-first) ============
var MEM=(function(){
  var KEY='gsa_memory', CAP=80;
  function load(){ try{ return JSON.parse(localStorage.getItem(KEY)||'[]'); }catch(e){ return []; } }
  function save(a){ try{ localStorage.setItem(KEY, JSON.stringify(a)); }catch(e){} }
  function toks(t){ return (t||'').toLowerCase().replace(/[^a-z0-9\\-\\.]/g,' ').split(/\\s+/).filter(function(x){return x.length>2;}); }
  function rank(a, query, n){
    var q=toks(query), now=Date.now(), set={};
    q.forEach(function(w){ set[w]=1; });
    return a.map(function(e){
      var overlap=0;
      if(q.length){ toks(e.text).forEach(function(w){ if(set[w]) overlap++; }); }
      var ageDays=(now-(e.ts||0))/86400000, recency=1/(1+ageDays);
      return { e:e, score: overlap*2 + recency + (e.hits||0)*0.2 + (e.kind==='finding'?0.5:0) };
    }).sort(function(x,y){ return y.score-x.score; }).slice(0,n).map(function(x){ return x.e; });
  }
  function add(text, kind){
    if(!text||!text.trim()) return;
    var a=load();
    a.push({ id:'m_'+Date.now().toString(36)+Math.random().toString(36).slice(2,6),
             text:text.slice(0,800), kind:kind||'note', ts:Date.now(), hits:0 });
    if(a.length>CAP) a=rank(a,'',CAP);   // compact: drop lowest-scoring
    save(a);
  }
  function retrieve(query, n){
    var a=load(); if(!a.length) return '';
    var top=rank(a, query, n||4), ids={};
    top.forEach(function(e){ ids[e.id]=1; });
    a.forEach(function(e){ if(ids[e.id]) e.hits=(e.hits||0)+1; });
    save(a);
    return top.map(function(e){ return '- '+e.text; }).join('\\n');
  }
  return { add:add, retrieve:retrieve, all:load, clear:function(){ save([]); } };
})();

// ============ Agent planning + scheduled jobs ============
var AGENT=(function(){
  var JKEY='gsa_jobs';
  function loadJobs(){ try{ return JSON.parse(localStorage.getItem(JKEY)||'[]'); }catch(e){ return []; } }
  function saveJobs(a){ try{ localStorage.setItem(JKEY, JSON.stringify(a)); }catch(e){} }
  function plan(objective, template){
    var cve=(objective.match(/CVE-\\d{4}-\\d+/i)||[''])[0].toUpperCase();
    var ip=(objective.match(/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/)||[''])[0];
    if(template==='cve'){
      var b=cve||objective;
      return [
        {id:'t1', title:'Severity & CVSS',       prompt:'Summarize severity, CVSS vector/score, and CWE for '+b+'.'},
        {id:'t2', title:'Exploitation status',   prompt:'Is '+b+' exploited in the wild? Give EPSS, KEV status, and any active-exploitation evidence.'},
        {id:'t3', title:'Affected versions & fix',prompt:'List affected products/versions and patched versions or mitigations for '+b+'.', dep:['t1']},
        {id:'t4', title:'PoC availability',       prompt:'Is there a public PoC/exploit for '+b+'? Describe the mechanism at a high level for defensive purposes.'},
        {id:'t5', title:'Detection & mitigation', prompt:'Provide detection guidance (logs, signatures, hunts) and mitigations for '+b+'.', dep:['t2','t3']}
      ];
    }
    if(template==='infra'){
      var t=ip||objective;
      return [
        {id:'t1', title:'Ownership / ASN (RDAP)', prompt:'Who owns '+t+'? Give RDAP ownership, ASN, country, and abuse contact. Passive registration data only.'},
        {id:'t2', title:'Known associations',      prompt:'Summarize anything in the research corpus or public sources associated with '+t+'. Passive OSINT only, no scanning.'},
        {id:'t3', title:'Relevant services/CVEs',  prompt:'What services or CVEs are commonly relevant to infrastructure like '+t+' per the research? Defensive framing.', dep:['t1']}
      ];
    }
    if(template==='malware'){
      return [
        {id:'t1', title:'Overview',   prompt:'Give a concise overview of '+objective+' (family, purpose, platform) from the research.'},
        {id:'t2', title:'TTPs / MITRE',prompt:'List key TTPs and MITRE ATT&CK techniques for '+objective+'.'},
        {id:'t3', title:'IOCs',        prompt:'List notable research IOCs (hashes, domains, paths) for '+objective+', clearly labeled as research indicators.'},
        {id:'t4', title:'Detection',   prompt:'Provide detection and mitigation guidance for '+objective+'.', dep:['t1','t2']}
      ];
    }
    return [{id:'t1', title:'Research', prompt:objective}];
  }
  return { plan:plan, loadJobs:loadJobs, saveJobs:saveJobs };
})();

// ============ Swarm runner (browser orchestration) ============
function curOpts(){
  return { webSearch:el('s-search').checked, temperature:parseFloat(el('s-temp').value),
           topK:parseInt(el('s-topk').value,10), brave:el('s-brave').value||'' };
}
async function callTask(objective, context){
  var res=await fetch('/api/task',{ method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ objective:objective, context:context||'', memory:MEM.retrieve(objective,4), settings:curOpts() }) });
  if(!res.ok) throw new Error('HTTP '+res.status);
  var d=await res.json(); if(!d.ok) throw new Error(d.error||'task failed');
  return d.text||'';
}
function jtasksRender(tasks){
  var box=el('j-tasks'); box.innerHTML='';
  tasks.concat([{id:'synth',title:'Synthesis'}]).forEach(function(t){
    var row=document.createElement('div'); row.className='jtask'; row.id='jt-'+t.id;
    var b=document.createElement('span'); b.className='jbadge queued'; b.textContent='queued';
    var n=document.createElement('span'); n.textContent=t.title;
    row.appendChild(b); row.appendChild(n); box.appendChild(row);
  });
}
function jstatus(id, state){
  var row=el('jt-'+id); if(!row) return;
  var b=row.querySelector('.jbadge'); if(b){ b.className='jbadge '+state; b.textContent=state; }
}
async function runSwarmToChat(objective, template){
  if(busy||!objective.trim()) return;
  busy=true; inp.disabled=true;
  var c=active();
  addMsg('system','Agent job started: '+objective+'  ['+template+']');
  var tasks=AGENT.plan(objective, template);
  jtasksRender(tasks);
  dbg('agent job', objective+' ['+template+'] '+tasks.length+' tasks');
  var done={}, results={}, pending=tasks.slice(), CONC=3;
  try{
    while(pending.length){
      var ready=pending.filter(function(t){ return (t.dep||[]).every(function(d){ return done[d]; }); });
      if(!ready.length) ready=[pending[0]];
      var batch=ready.slice(0,CONC);
      await Promise.all(batch.map(async function(t){
        jstatus(t.id,'running'); dbg('task running', t.title);
        try{
          var ctx=(t.dep||[]).map(function(d){ return '['+d+'] '+(results[d]||''); }).join('\\n\\n').slice(0,2000);
          var out=await callTask(t.prompt, ctx);
          results[t.id]=out; done[t.id]=true;
          MEM.add('['+(template||'job')+'] '+t.title+': '+out.slice(0,500),'finding');
          jstatus(t.id,'done');
        }catch(e){ done[t.id]=true; results[t.id]='(failed: '+e.message+')'; jstatus(t.id,'failed'); dbg('task failed', t.title+' '+e.message); }
      }));
      pending=pending.filter(function(t){ return !done[t.id]; });
    }
    jstatus('synth','running');
    var combined=tasks.map(function(t){ return '## '+t.title+'\\n'+(results[t.id]||''); }).join('\\n\\n');
    var report;
    try{ report=await callTask('Synthesize these findings about "'+objective+'" into one clear markdown report: a short summary line at the top, then a section per finding. Do not invent anything beyond the findings.', combined); }
    catch(e){ report='# '+objective+'\\n\\n'+combined; }
    jstatus('synth','done');
    MEM.add('REPORT '+objective+': '+report.slice(0,600),'finding');
    var d=addMsg('agent',''); d.innerHTML=renderMarkdown(report);
    c.msgs.push({role:'assistant',content:report}); if(c.msgs.length===1) c.title='[job] '+objective.slice(0,34); saveChats(chats); renderChats();
  }catch(e){ addMsg('system','Agent job error: '+e.message); }
  busy=false; inp.disabled=false; inp.focus();
}

// ============ Scheduler (browser-side; runs while tab open) ============
function renderSaved(){
  var box=el('j-saved'); if(!box) return; box.innerHTML='';
  var jobs=AGENT.loadJobs();
  if(!jobs.length){ box.textContent='No scheduled jobs.'; return; }
  jobs.forEach(function(j,idx){
    var row=document.createElement('div'); row.className='sjob';
    var mins=Math.round(j.schedule/60000);
    var label=document.createElement('span'); label.textContent='every '+mins+'m · '+j.template+' · '+j.objective;
    var del=document.createElement('span'); del.className='sj-del'; del.textContent='x'; del.title='Delete scheduled job';
    del.onclick=function(){ var a=AGENT.loadJobs(); a.splice(idx,1); AGENT.saveJobs(a); renderSaved(); };
    row.appendChild(del); row.appendChild(label); box.appendChild(row);
  });
}
function startScheduler(){
  setInterval(async function(){
    if(busy) return;
    var jobs=AGENT.loadJobs(), now=Date.now(), changed=false;
    for(var k=0;k<jobs.length;k++){
      var j=jobs[k];
      if(j.schedule && (!j.lastRun || now-j.lastRun>=j.schedule)){
        j.lastRun=now; AGENT.saveJobs(jobs); changed=true;
        await runSwarmToChat(j.objective, j.template);
        break;
      }
    }
    if(changed) renderSaved();
  }, 60000);
}

// ============ Agent-panel wiring ============
el('btn-job').onclick=function(){ var on=el('jobs').classList.toggle('show'); el('btn-job').classList.toggle('on',on); };
el('j-run').onclick=function(){ runSwarmToChat(el('j-obj').value.trim(), el('j-tpl').value); };
el('j-save').onclick=function(){
  var obj=el('j-obj').value.trim(), sched=parseInt(el('j-sched').value,10);
  if(!obj){ addMsg('system','Enter an objective before saving a scheduled job.'); return; }
  if(!sched){ addMsg('system','Pick a schedule interval (not "off") to save a recurring job.'); return; }
  var a=AGENT.loadJobs(); a.push({ objective:obj, template:el('j-tpl').value, schedule:sched, lastRun:0 }); AGENT.saveJobs(a);
  renderSaved(); addMsg('system','Scheduled job saved. It will run while this tab is open.');
};
renderSaved();
startScheduler();


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
      const { cveIds, ips, wantSearch } = analyseQuery(q);
      const toolContext = [];
      for (const cveId of cveIds.slice(0, 3)) {
        const epss = await epssLookup(cveId);
        toolContext.push(`=== NVD: ${cveId} ===\n${await nvdLookup(cveId)}${epss ? '\n' + epss : ''}`);
      }
      for (const ip of (ips || []).slice(0, 2)) toolContext.push(`=== IP RDAP: ${ip} ===\n${await ipLookup(ip)}`);
      let chunks = await vectorRetrieve(env, q, body.topK || TOP_K);
      const usedVectorize = chunks !== null;
      if (!chunks) chunks = bm25Chunks(await getChunks(env), q, body.topK || TOP_K);
      const sys = buildSystemPrompt(env, { summary: '', chunks, toolContext });
      return json({
        cveIds, ips, wantSearch, usedVectorize,
        chunkCount: chunks.length,
        chunks: chunks.map(c => ({ title: c.title, score: c.score, chars: c.text.length })),
        systemChars: sys.length,
        systemPreview: sys.slice(0, 600),
      });
    }

    // POST /api/task — non-streaming single task (browser agent/swarm mode)
    if (url.pathname === '/api/task' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch { return new Response('Bad JSON', { status: 400, headers: cors }); }
      const opts      = body.settings || {};
      const topK      = Math.max(1, Math.min(10, opts.topK || TOP_K));
      const temp      = typeof opts.temperature === 'number' ? opts.temperature : 0.3;
      const useSearch = opts.webSearch !== false;
      const braveKey  = opts.brave || env.BRAVE_API_KEY || '';
      const objective = (body.objective || body.message || '').toString();
      const context   = (body.context || '').toString();
      const clientMemory = typeof body.memory === 'string' ? body.memory : '';
      try {
        const { cveIds, ips, wantSearch } = analyseQuery(objective + ' ' + context);
        const toolContext = [];
        for (const cveId of cveIds.slice(0, 3)) {
          const epss = await epssLookup(cveId);
          toolContext.push(`=== NVD: ${cveId} ===\n${await nvdLookup(cveId)}${epss ? '\n' + epss : ''}`);
        }
        for (const ip of (ips || []).slice(0, 2)) toolContext.push(`=== IP RDAP: ${ip} ===\n${await ipLookup(ip)}`);
        if (useSearch && wantSearch) {
          const s = await webSearch(cveIds.length ? `${cveIds[0]} exploit PoC advisory` : objective, braveKey);
          toolContext.push(s ? `=== Web Search ===\n${formatSearch(s)}` : '=== Search Unavailable ===\nDo NOT fabricate details; rely on corpus or state what is unknown.');
        }
        let chunks = await vectorRetrieve(env, objective, topK);
        const usedVectorize = chunks !== null;
        if (!chunks) chunks = bm25Chunks(await getChunks(env), objective, topK);
        const sysPrompt = buildSystemPrompt(env, { summary: '', chunks, toolContext, clientMemory });
        const userContent = context ? `${objective}\n\nContext from earlier steps:\n${context.slice(0, 2500)}` : objective;
        const r = await env.AI.run(MODEL, {
          messages: [{ role: 'system', content: sysPrompt }, { role: 'user', content: userContent }],
          stream: false, max_tokens: 1024, temperature: temp,
        });
        return json({ ok: true, text: (r.response || '').trim(), meta: { cveIds, ips, usedVectorize, chunkCount: chunks.length } });
      } catch (e) { return json({ ok: false, error: e.message }, 500); }
    }

    // POST /api/chat
    if (url.pathname === '/api/chat' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch { return new Response('Bad JSON', { status: 400, headers: cors }); }

      const opts      = body.settings || {};
      const topK      = Math.max(1, Math.min(10, opts.topK || TOP_K));
      const temp      = typeof opts.temperature === 'number' ? opts.temperature : 0.3;
      const useSearch = opts.webSearch !== false;
      const braveKey  = opts.brave || env.BRAVE_API_KEY || '';
      const clientMemory = typeof body.memory === 'string' ? body.memory : '';

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
          const { cveIds, ips, wantSearch } = analyseQuery(lastUser);
          const toolContext = [];

          // NVD + EPSS lookups
          for (const cveId of cveIds.slice(0, 3)) {
            dbg('lookup_nvd', cveId);
            const result = await nvdLookup(cveId);
            const epss = await epssLookup(cveId);
            dbg('nvd result', result.slice(0, 160));
            if (epss) dbg('epss', epss);
            toolContext.push(`=== NVD: ${cveId} ===\n${result}${epss ? '\n' + epss : ''}`);
          }

          // Passive IP ownership lookup (RDAP) — registration data only, no scanning
          for (const ip of (ips || []).slice(0, 2)) {
            dbg('ip_rdap', ip);
            const result = await ipLookup(ip);
            dbg('rdap result', result.slice(0, 160));
            toolContext.push(`=== IP RDAP: ${ip} ===\n${result}`);
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
          const sysPrompt = buildSystemPrompt(env, { summary: sess?.summary || '', chunks, toolContext, clientMemory });
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
