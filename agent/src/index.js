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
const TOOL_RUN_TIMEOUT_MS = 15000;

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
  // Domains / URLs — for passive RDAP registration lookup (never scanning).
  const domSet = new Set();
  (query.match(/https?:\/\/([^\/\s)]+)/gi) || []).forEach(u => { try { domSet.add(new URL(u).hostname.toLowerCase()); } catch (_) {} });
  (query.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi) || []).forEach(d => domSet.add(d.toLowerCase()));
  const BAD = /\.(md|txt|js|json|png|jpe?g|gif|svg|webp|exe|dll|so|sh|py|c|go|rs|html?|css|yml|yaml|toml|pdf|zip)$/i;
  const domains = [...domSet]
    .filter(d => !/^\d+\.\d+\.\d+\.\d+$/.test(d))
    .filter(d => !BAD.test(d))
    .filter(d => d !== 'garrettstimpson.ca' && !d.endsWith('.garrettstimpson.ca'))
    .slice(0, 2);
  const wantSearch = SEARCH_TRIGGERS.some(t => q.includes(t)) || cveIds.length > 0 || domains.length > 0;
  return { cveIds, ips, domains, wantSearch };
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

// Passive domain registration lookup via RDAP (no scanning). Returns real
// registrar/dates/nameservers, or an explicit UNKNOWN so the model won't invent.
async function domainLookup(domain) {
  try {
    const r = await fetch(`https://rdap.org/domain/${domain}`,
      { headers: { 'Accept': 'application/rdap+json', 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return `RDAP: no registration data returned for ${domain} (HTTP ${r.status}). Ownership is UNKNOWN — do not invent it.`;
    const d = await r.json();
    const events = (d.events || []).map(e => `${e.eventAction}: ${e.eventDate}`).join(', ');
    const ns = (d.nameservers || []).map(n => n.ldhName).filter(Boolean).slice(0, 4).join(', ');
    const reg = (d.entities || []).find(e => (e.roles || []).includes('registrar'));
    const regName = reg ? (reg.vcardArray?.[1]?.find(x => x[0] === 'fn')?.[3] || reg.handle || '') : '';
    const status = (d.status || []).join(', ');
    return `RDAP domain ${domain} | registrar: ${regName || '?'} | status: ${status || '?'}\nevents: ${events || '?'}\nnameservers: ${ns || '?'}`;
  } catch (e) { return `RDAP domain lookup failed for ${domain}: ${e.message}. Ownership is UNKNOWN — do not invent it.`; }
}

// Passive DNS resolution via DNS-over-HTTPS (Cloudflare). Read-only, no scanning.
async function dnsLookup(domain) {
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
  const out = [];
  for (const t of types) {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${t}`,
        { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
      const d = await r.json();
      const ans = (d.Answer || []).map(a => a.data).filter(Boolean).slice(0, 5);
      if (ans.length) out.push(`${t}: ${ans.join(', ')}`);
    } catch (_) {}
  }
  return out.length ? `DNS ${domain}\n${out.join('\n')}` : `DNS ${domain}: no records resolved. Treat as UNKNOWN — do not invent records.`;
}

// Passive TLS certificate transparency via crt.sh. Reveals known subdomains/SANs
// from public CT logs (read-only OSINT, not a scan).
async function certLookup(domain) {
  try {
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`,  // crt.sh is flaky
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return `crt.sh: no certificate data for ${domain} (HTTP ${r.status}).`;
    const data = await r.json();
    const names = [...new Set(data.flatMap(x => (x.name_value || '').split('\n')))].filter(Boolean).slice(0, 12);
    const issuers = [...new Set(data.map(x => x.issuer_name).filter(Boolean))].slice(0, 3);
    return `Certificate Transparency (crt.sh) ${domain}\nnames/SANs: ${names.join(', ') || 'none'}\nissuers: ${issuers.join('; ') || '?'}`;
  } catch (e) { return `crt.sh lookup failed for ${domain}: ${e.message}.`; }
}

// CISA Known Exploited Vulnerabilities catalog (cached). Authoritative "is this
// actively exploited" signal.
async function kevSet(env) {
  const cache = caches.default, key = new Request('https://kev-cache/v1');
  const c = await cache.match(key);
  if (c) { try { return new Set(await c.json()); } catch {} }
  try {
    const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(12000) });
    const d = await r.json();
    const ids = (d.vulnerabilities || []).map(v => v.cveID).filter(Boolean);
    await cache.put(key, new Response(JSON.stringify(ids), { headers: { 'Cache-Control': 'max-age=21600', 'Content-Type': 'application/json' } }));
    return new Set(ids);
  } catch { return null; }
}
async function kevLookup(env, cveId) {
  const set = await kevSet(env);
  if (!set) return null;
  return set.has(cveId) ? 'CISA KEV: LISTED — known exploited in the wild' : 'CISA KEV: not listed';
}

// Combined intel helpers (run leaf tools in parallel).
async function cveIntel(env, cveId) {
  const [nvd, epss, kev] = await Promise.all([nvdLookup(cveId), epssLookup(cveId), kevLookup(env, cveId)]);
  return `${nvd}${epss ? '\n' + epss : ''}${kev ? '\n' + kev : ''}`;
}
async function domainIntel(domain) {
  const [rd, dns, ct, wb, us] = await Promise.all([domainLookup(domain), dnsLookup(domain), certLookup(domain), wayback(domain), urlscanSearch(domain)]);
  return `${rd}\n${dns}\n${ct}\n${wb}\n${us}`;
}

// Shodan InternetDB — pre-collected open ports / CVEs / hostnames for an IP.
// Passive: Shodan already scanned the internet; we do NOT touch the target.
async function shodanInternetDB(ip) {
  try {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`,
      { headers: { 'Accept': 'application/json', 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(8000) });
    if (r.status === 404) return `Shodan InternetDB ${ip}: not previously observed (no data). UNKNOWN — do not invent.`;
    if (!r.ok) return `Shodan InternetDB ${ip}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    const ports = (d.ports || []).join(', ') || 'none';
    const vulns = (d.vulns || []).slice(0, 14).join(', ') || 'none';
    const host = (d.hostnames || []).slice(0, 4).join(', ') || 'none';
    const tags = (d.tags || []).join(', ') || 'none';
    return `Shodan InternetDB ${ip} (passive, pre-collected — no live scan)\nopen ports: ${ports}\nhostnames: ${host}\ntags: ${tags}\nknown CVEs: ${vulns}`;
  } catch (e) { return `Shodan InternetDB ${ip}: lookup failed (${e.message}).`; }
}

// Reverse DNS (PTR) via DoH. Passive.
async function reverseDns(ip) {
  try {
    const arpa = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${arpa}&type=PTR`,
      { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
    const d = await r.json();
    const ptr = (d.Answer || []).map(a => a.data).filter(Boolean).slice(0, 4);
    return ptr.length ? `Reverse DNS ${ip}: ${ptr.join(', ')}` : `Reverse DNS ${ip}: no PTR record.`;
  } catch (e) { return `Reverse DNS ${ip}: lookup failed (${e.message}).`; }
}

// HTTP security-header inspection. Contacts the target with a single benign GET,
// so it is gated behind /api/tools/run (confirm + scope) — not auto-invoked.
async function httpHeaders(url) {
  let u; try { u = new URL(url); } catch { return `Invalid URL: ${url}`; }
  if (!/^https?:$/.test(u.protocol)) return `Unsupported protocol: ${url}`;
  try {
    const r = await fetch(u.toString(),
      { method: 'GET', redirect: 'manual', headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(8000) });
    const keys = ['server', 'content-type', 'strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'set-cookie'];
    const out = keys.map(k => { const v = r.headers.get(k); return v ? `${k}: ${v.slice(0, 180)}` : null; }).filter(Boolean);
    return `HTTP ${r.status} ${u.hostname}\n${out.join('\n') || '(no notable security headers present)'}`;
  } catch (e) { return `HTTP headers ${url}: fetch failed (${e.message}).`; }
}

// Combined passive IP intel (RDAP + reverse DNS + Shodan InternetDB).
async function ipIntel(env, ip) {
  const [rd, rev, sh, geo, asn] = await Promise.all([ipLookup(ip), reverseDns(ip), shodanInternetDB(ip), ipGeo(ip), asnInfo(ip)]);
  return `${rd}\n${rev}\n${geo}\n${asn}\n${sh}`;
}

// ── OSINT tool suite (all passive, keyless public sources) ────────────────────

// IP geolocation + ASN/org (ipwho.is)
async function ipGeo(ip) {
  try {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,isp,org,as,reverse,query`, { signal: AbortSignal.timeout(7000) });
    const d = await r.json();
    if (d.status !== 'success') return `Geo ${ip}: ${d.message || 'no data'}.`;
    return `Geo ${ip}: ${[d.city, d.regionName, d.country].filter(Boolean).join(', ')}\nASN: ${d.as || '?'} | ISP: ${d.isp || '?'} | Org: ${d.org || '?'}${d.reverse ? ' | PTR: ' + d.reverse : ''}`;
  } catch (e) { return `Geo ${ip}: lookup failed (${e.message}).`; }
}

// BGP/ASN prefix + holder (bgpview.io). Accepts an IP or an AS number.
async function asnInfo(target) {
  const t = String(target || '').trim().replace(/^as/i, '');
  const isAsn = /^\d+$/.test(t);
  const url = isAsn ? `https://api.bgpview.io/asn/${t}` : `https://api.bgpview.io/ip/${target}`;
  try {
    const r = await fetch(url, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000) });
    const d = (await r.json()).data || {};
    if (isAsn) return `ASN AS${t}: ${d.name || '?'} — ${d.description_short || ''} (${d.country_code || '?'})`;
    const pfx = (d.prefixes || []).slice(0, 1).map(p => `${p.prefix} ${p.name || ''}`).join('; ');
    const asns = (d.prefixes || []).map(p => p.asn && `AS${p.asn.asn} ${p.asn.name || ''}`).filter(Boolean).slice(0, 2).join('; ');
    return `BGP ${target}: prefix ${pfx || '?'}\noriginating ASN: ${asns || '?'}`;
  } catch (e) { return `ASN/BGP ${target}: lookup failed (${e.message}).`; }
}

// Wayback Machine — latest snapshot + recent archived URLs (archive.org)
async function wayback(url) {
  try {
    const a = await (await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(url)}`, { signal: AbortSignal.timeout(8000) })).json();
    const snap = a && a.archived_snapshots && a.archived_snapshots.closest;
    let cdx = '';
    try {
      const host = String(url).replace(/^https?:\/\//, '').split('/')[0];
      const rows = await (await fetch(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(host)}*&output=json&limit=5&collapse=urlkey`, { signal: AbortSignal.timeout(8000) })).json();
      cdx = Array.isArray(rows) && rows.length > 1 ? rows.slice(1, 5).map(x => x[2]).join('\n') : '';
    } catch {}
    return `Wayback ${url}\nlatest snapshot: ${snap ? `${snap.timestamp} ${snap.url}` : 'none'}${cdx ? `\narchived URLs:\n${cdx}` : ''}`;
  } catch (e) { return `Wayback ${url}: lookup failed (${e.message}).`; }
}

// urlscan.io — public scan history for a domain (passive: others' prior scans)
async function urlscanSearch(domain) {
  try {
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5`, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(9000) });
    if (!r.ok) return `urlscan ${domain}: search failed (HTTP ${r.status}).`;
    const d = await r.json();
    const res = (d.results || []).slice(0, 5).map(x => `${(x.task && x.task.time || '').slice(0, 10)} ${(x.page && x.page.url) || (x.task && x.task.url) || ''} -> ${(x.page && x.page.ip) || '?'} (${(x.page && x.page.server) || '?'})`);
    return `urlscan.io ${domain}: ${d.total || 0} public scans\n${res.join('\n') || 'no recent results'}`;
  } catch (e) { return `urlscan ${domain}: lookup failed (${e.message}).`; }
}

// abuse.ch URLhaus — malware-URL records for a host/IP/domain
async function urlhausLookup(env, host) {
  const key = String((env && (env.ABUSECH_API_KEY || env.URLHAUS_API_KEY)) || '');
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (key) headers['Auth-Key'] = key;
  try {
    const r = await fetch('https://urlhaus-api.abuse.ch/v1/host/', { method: 'POST', headers, body: `host=${encodeURIComponent(host)}`, signal: AbortSignal.timeout(8000) });
    if (r.status === 401) return key ? `URLhaus ${host}: Auth-Key rejected (401).` : `URLhaus ${host}: skipped — abuse.ch now needs a free Auth-Key (set ABUSECH_API_KEY).`;
    if (!r.ok) return `URLhaus ${host}: unavailable (HTTP ${r.status}).`;
    const d = await r.json();
    if (d.query_status === 'no_results') return `URLhaus ${host}: no malware URLs on record.`;
    if (d.query_status !== 'ok') return `URLhaus ${host}: ${d.query_status}.`;
    const urls = (d.urls || []).slice(0, 5).map(u => `${u.url_status} ${u.threat || ''} ${u.url}`);
    return `URLhaus ${host}: ${d.url_count || urls.length} known malware URLs\n${urls.join('\n')}`;
  } catch (e) { return `URLhaus ${host}: lookup failed (${e.message}).`; }
}

// GitHub public code search (anonymous — rate-limited, no token)
async function githubOsint(env, query) {
  const token = String((env && env.GITHUB_TOKEN) || '');
  if (!token) return `GitHub code search "${query}": GitHub's code-search API requires authentication (anonymous always returns 401). Set GITHUB_TOKEN (a read-only PAT) on deploy to enable this tool.`;
  try {
    const r = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=5`, { headers: { 'Accept': 'application/vnd.github+json', 'Authorization': `Bearer ${token}`, 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(9000) });
    if (r.status === 401) return `GitHub code search "${query}": token rejected (401) — check GITHUB_TOKEN.`;
    if (r.status === 403) return `GitHub code search "${query}": rate-limited (403). Retry later.`;
    if (!r.ok) return `GitHub code search "${query}": search failed (HTTP ${r.status}).`;
    const d = await r.json();
    const items = (d.items || []).slice(0, 5).map(x => `${x.repository && x.repository.full_name}/${x.path}  ${x.html_url || ''}`);
    return `GitHub code search "${query}": ${d.total_count || 0} hits\n${items.join('\n') || 'none'}`;
  } catch (e) { return `GitHub code search "${query}": lookup failed (${e.message}).`; }
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

async function webSearch(query, braveKey, env) {
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
  // 1b. Google Programmable Search (if GOOGLE_CSE_KEY + GOOGLE_CSE_CX set)
  if (env && env.GOOGLE_CSE_KEY && env.GOOGLE_CSE_CX) {
    try {
      const r = await fetch(`https://www.googleapis.com/customsearch/v1?key=${env.GOOGLE_CSE_KEY}&cx=${env.GOOGLE_CSE_CX}&num=6&q=${encodeURIComponent(query)}`,
        { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000) });
      if (r.ok) { const d = await r.json(); const results = (d.items || []).slice(0, 6).map(x => ({ title: x.title, url: x.link, content: x.snippet || '' })); if (results.length) return { provider: 'Google', results }; }
    } catch (_) {}
  }
  // 1c. Bing Web Search (if BING_API_KEY set)
  if (env && env.BING_API_KEY) {
    try {
      const r = await fetch(`https://api.bing.microsoft.com/v7.0/search?count=6&q=${encodeURIComponent(query)}`,
        { headers: { 'Ocp-Apim-Subscription-Key': env.BING_API_KEY, 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000) });
      if (r.ok) { const d = await r.json(); const results = ((d.webPages && d.webPages.value) || []).slice(0, 6).map(x => ({ title: x.name, url: x.url, content: x.snippet || '' })); if (results.length) return { provider: 'Bing', results }; }
    } catch (_) {}
  }
  // 2. SearXNG public instances (JSON)
  const SEARX = ['https://searx.be', 'https://search.disroot.org', 'https://priv.au', 'https://searx.tiekoetter.com', 'https://search.bus-hit.me', 'https://baresearch.org'];
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
  // 4. DuckDuckGo Instant Answer (JSON, keyless — usually reachable from CF datacenters)
  try {
    const r = await fetch(`https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&no_redirect=1&t=gsa`,
      { headers: { 'Accept': 'application/json', 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(7000) });
    if (r.ok) {
      const d = await r.json();
      const results = [];
      if (d.AbstractText) results.push({ title: d.Heading || query, url: d.AbstractURL || '', content: d.AbstractText });
      (d.RelatedTopics || []).forEach(t => { if (t && t.Text && t.FirstURL) results.push({ title: (t.Text || '').slice(0, 80), url: t.FirstURL, content: t.Text }); });
      if (results.length) return { provider: 'DuckDuckGo IA', results: results.slice(0, 6) };
    }
  } catch (_) {}
  // 5. Wikipedia opensearch (keyless last resort)
  try {
    const r = await fetch(`https://en.wikipedia.org/w/api.php?action=opensearch&limit=5&format=json&search=${encodeURIComponent(query)}`,
      { headers: { 'Accept': 'application/json', 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(7000) });
    if (r.ok) {
      const d = await r.json();
      const titles = d[1] || [], descs = d[2] || [], urls = d[3] || [];
      const results = titles.map((t, i) => ({ title: t, url: urls[i] || '', content: descs[i] || '' }));
      if (results.length) return { provider: 'Wikipedia', results };
    }
  } catch (_) {}
  return null;
}

function formatSearch(s) {
  return `[${s.provider}]\n\n` + s.results.map((x, i) => `[${i + 1}] ${x.title}\n${x.url}\n${x.content || ''}`).join('\n\n');
}

function isPrivateHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) return true;
  if (h === '::1') return true;
  if (h.indexOf(':') >= 0 && (h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80'))) return true;  // IPv6 ULA/link-local only
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;      // link-local incl. cloud metadata 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a >= 224) return true;                     // multicast / reserved
  }
  return false;
}

// fetch_url — CTF open mode: any public http(s) host; SSRF guard blocks internal targets.
async function fetchUrl(url) {
  let u;
  try { u = new URL(url); } catch { return `Invalid URL: ${url}`; }
  if (!/^https?:$/.test(u.protocol)) return `fetch_url: only http/https URLs are allowed.`;
  if (isPrivateHost(u.hostname)) return `fetch_url: ${u.hostname} is a private/internal address — blocked by SSRF guard.`;
  try {
    const r = await fetch(u.toString(), { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, redirect: 'follow', signal: AbortSignal.timeout(10000) });
    const ct = r.headers.get('content-type') || '';
    const raw = await r.text();
    const body = /html|xml/i.test(ct)
      ? raw.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
      : raw.trim();
    return `fetch_url ${u.hostname} (HTTP ${r.status}, ${ct || 'unknown type'})\n\n${body.slice(0, 6000)}`;
  } catch (e) { return `fetch_url ${u.hostname}: fetch failed (${e.message}).`; }
}

// ── CTF safe-mode tool wiring ─────────────────────────────────────────────────

const BUILTIN_TOOL_SPECS = [
  { name: 'nvd_lookup', category: 'intel', passive: true, description: 'NVD CVE metadata lookup' },
  { name: 'epss_lookup', category: 'intel', passive: true, description: 'FIRST.org EPSS lookup' },
  { name: 'kev_lookup', category: 'intel', passive: true, description: 'CISA KEV status lookup' },
  { name: 'rdap_ip', category: 'osint', passive: true, description: 'RDAP IP registration lookup' },
  { name: 'rdap_domain', category: 'osint', passive: true, description: 'RDAP domain registration lookup' },
  { name: 'dns_lookup', category: 'osint', passive: true, description: 'DNS over HTTPS lookup' },
  { name: 'cert_ct', category: 'osint', passive: true, description: 'Certificate transparency lookup' },
  { name: 'web_search', category: 'search', passive: true, description: 'Brave/SearXNG/DuckDuckGo search' },
  { name: 'fetch_url', category: 'fetch', passive: true, description: 'Allowlisted source fetch and text extraction' },
  { name: 'shodan_internetdb', category: 'osint', passive: true, description: 'Shodan InternetDB — pre-collected open ports/CVEs/hostnames (no live scan)' },
  { name: 'reverse_dns', category: 'osint', passive: true, description: 'Reverse DNS (PTR) lookup via DoH' },
  { name: 'http_headers', category: 'recon', passive: false, description: 'Fetch a URL and report security-relevant HTTP headers (contacts target)' },
  { name: 'ip_geo', category: 'osint', passive: true, description: 'IP geolocation + ASN/org (ipwho.is)' },
  { name: 'asn_info', category: 'osint', passive: true, description: 'BGP/ASN prefix + holder (bgpview.io); accepts IP or ASN' },
  { name: 'wayback', category: 'osint', passive: true, description: 'Wayback Machine snapshots + archived URLs (archive.org)' },
  { name: 'urlscan', category: 'osint', passive: true, description: 'urlscan.io public scan history for a domain' },
  { name: 'urlhaus', category: 'osint', passive: true, description: 'abuse.ch URLhaus malware-URL lookup by host' },
  { name: 'github_osint', category: 'osint', passive: true, description: 'GitHub public code search (anonymous, rate-limited)' },
  { name: 'crtsh_subs', category: 'osint', passive: true, description: 'crt.sh certificate-transparency subdomain enumeration' },
  { name: 'circl_cve', category: 'intel', passive: true, description: 'CIRCL keyless CVE detail (CVSS, summary, refs)' },
  { name: 'greynoise', category: 'osint', passive: true, description: 'GreyNoise community — is an IP a known internet scanner' },
  { name: 'wellknown', category: 'recon', passive: true, description: 'Fetch /.well-known/security.txt + /robots.txt for a host' },
  { name: 'username_enum', category: 'people', passive: true, description: 'Username presence across GitHub/GitLab/Keybase/HN/Reddit' },
  { name: 'github_user', category: 'people', passive: true, description: 'GitHub public user profile (name/company/location/links)' },
  { name: 'gravatar', category: 'people', passive: true, description: 'Gravatar profile + avatar existence by email (sha256)' },
  { name: 'email_recon', category: 'people', passive: true, description: 'Email format + MX (DoH) + gravatar presence' },
  { name: 'breach_check', category: 'people', passive: true, description: 'Email breach exposure (XposedOrNot keyless; HIBP if HIBP_API_KEY set)' },
  { name: 'tech_fingerprint', category: 'recon', passive: false, description: 'Fetch site and fingerprint CMS/framework/server (Discourse, WordPress, ...) — contacts target' },
  { name: 'origin_ip', category: 'recon', passive: true, description: 'Find possible origin IP behind Cloudflare via passive subdomain DNS probing' },
  { name: 'image_osint', category: 'osint', passive: true, description: 'Image OSINT: hash, type, EXIF (camera/GPS/timestamp) + reverse-image-search links' },
  { name: 'onion_search', category: 'darkweb', passive: true, description: 'Dark-web exposure: Ahmia onion index (+ Tor broker if TOOL_BROKER_URL set)' },
  { name: 'email_security', category: 'recon', passive: true, description: 'SPF / DMARC / MX / DNSSEC posture for a domain (spoofability check)' },
  { name: 'typosquat', category: 'recon', passive: true, description: 'Generate lookalike domains and flag registered ones (phishing / brand abuse)' },
  { name: 'crypto_addr', category: 'osint', passive: true, description: 'BTC/ETH address balance + transaction activity (threat-intel)' },
  { name: 'dns_records', category: 'osint', passive: true, description: 'Full DNS record dump (A/AAAA/MX/NS/TXT/CAA/SOA) via DoH' },
  { name: 'tor_exit', category: 'osint', passive: true, description: 'Is an IP a known Tor relay / exit node (onionoo)' },
  { name: 'pwned_password', category: 'people', passive: true, description: 'Check a password against Have I Been Pwned (k-anonymity; only a hash prefix is sent)' },
  { name: 'cve_search', category: 'intel', passive: true, description: 'Search NVD for CVEs by product/keyword (top results with CVSS)' },
  { name: 'cve_poc', category: 'intel', passive: true, description: 'Public PoC/exploit repos for a CVE (PoC-in-GitHub, by stars)' },
  { name: 'kev_recent', category: 'intel', passive: true, description: 'Latest CISA Known-Exploited-Vulnerabilities additions (what is exploited now)' },
  { name: 'mitre', category: 'intel', passive: true, description: 'MITRE ATT&CK technique lookup by id (T1059, T1059.001)' },
  { name: 'bucket_finder', category: 'recon', passive: false, description: 'Check S3/GCS/Azure for an exposed storage bucket by name (contacts providers)' },
  { name: 'email_permutations', category: 'people', passive: true, description: 'Generate likely email addresses from a name + domain (MX-checked, not verified)' },
  { name: 'cors_check', category: 'recon', passive: false, description: 'Test a URL for permissive/misconfigured CORS (Origin reflection)' },
  { name: 'subdomain_takeover', category: 'recon', passive: false, description: 'Detect dangling CNAMEs to deprovisioned services (subdomain takeover risk)' },
  { name: 'onion_fetch', category: 'darkweb', passive: true, description: 'Fetch .onion content over clearnet via free tor2web gateways (no Tor needed)' },
  { name: 'stealer_check', category: 'darkweb', passive: true, description: 'Infostealer / stealer-log exposure for email/username/domain (HudsonRock, keyless)' },
  { name: 'leakcheck', category: 'darkweb', passive: true, description: 'Public breach-index record count + exposed data types (LeakCheck, keyless)' },
  { name: 'paste_search', category: 'darkweb', passive: true, description: 'Search public paste dumps (psbdmp) for an email/domain/keyword' },
  { name: 'dork', category: 'search', passive: true, description: 'Generate + run Google dorks for a domain/email/name (recon)' },
  { name: 'phish_check', category: 'recon', passive: false, description: 'Phishing verdict for a URL: domain age, URLhaus, lure keywords, login form, redirects' },
  { name: 'archive_urls', category: 'osint', passive: true, description: 'Wayback historical URLs/endpoints for a domain (forgotten paths)' },
  { name: 'favicon_hash', category: 'recon', passive: false, description: 'Shodan/FOFA favicon-hash pivot — find other servers sharing a site favicon' },
  { name: 'crawl', category: 'recon', passive: false, description: 'Crawl a website: extract & follow links/files, download linked text files, scan for exposed secrets' },
  { name: 'subdomains', category: 'recon', passive: true, description: 'DNS-brute common subdomains (DoH) — complements crt.sh' },
  { name: 'vuln_scan', category: 'recon', passive: false, description: 'Passive vuln indication: detect software versions -> candidate CVEs (NVD) + Shodan CVE tags (no active exploitation)' },
  { name: 'keybase', category: 'people', passive: true, description: 'Keybase cryptographically-VERIFIED identity: proven Twitter/GitHub/Reddit/web links, PGP key, crypto addresses' },
  { name: 'devto_user', category: 'people', passive: true, description: 'Dev.to profile (real name, location, linked GitHub/Twitter/site) — corroborates identity' },
  { name: 'people_search', category: 'people', passive: true, description: 'Generate analyst deep-links for a NAME (people-search, public records, obituary/FindAGrave, court, dorks) — no auto-scrape' },
  { name: 'edgar', category: 'people', passive: true, description: 'SEC EDGAR full-text search; finds a person/company in insider filings (Form 3/4/5 name individuals)' },
  { name: 'opencorporates', category: 'people', passive: true, description: 'OpenCorporates officer/directorship search (needs OPENCORPORATES_API_TOKEN; else returns the manual link)' },
  { name: 'phone_osint', category: 'people', passive: true, description: 'Phone: country/NANP region + line-type/reverse-lookup deep links (no auto-scrape)' },
  { name: 'holehe', category: 'people', passive: false, description: 'Map an EMAIL to accounts registered across 100+ sites (via broker holehe)' },
  { name: 'exposure_search', category: 'people', passive: true, description: 'UNIFIED breach/darknet exposure for any selector (email/username/domain) — aggregates HudsonRock stealer logs + LeakCheck + breach DBs + paste into one verdict, exposure timeline, and cross-source pivots' },
  { name: 'jwt', category: 'recon', passive: true, description: 'Decode/inspect a JWT (claims, alg:none, expiry) — no verification' },
  { name: 'cidr', category: 'recon', passive: true, description: 'IPv4 CIDR math: network/broadcast/mask/range/host count' },
  { name: 'hash_id', category: 'malware', passive: true, description: 'Identify likely hash type by format (MD5/SHA/NTLM/bcrypt/...)' },
  { name: 'encode', category: 'malware', passive: true, description: 'Encode text to base64 / hex / url / rot13' },
  { name: 'timestamp', category: 'recon', passive: true, description: 'Decode unix epoch or UUID (v1 -> embedded time + MAC)' },
  { name: 'disclosure_draft', category: 'recon', passive: true, description: 'Find a domain security contact (security.txt/abuse) and DRAFT a responsible-disclosure email (does not send)' },
  { name: 'hash_lookup', category: 'malware', passive: true, description: 'File-hash reputation (Team Cymru MHR keyless; VirusTotal/MalwareBazaar if keys set)' },
  { name: 'file_analyze', category: 'malware', passive: true, description: 'Static triage of a sample URL: type, hashes, strings, IOCs, suspicious API flags' },
  { name: 'decode', category: 'malware', passive: true, description: 'Recursive multi-layer decode (base64/hex/url/gzip) + refang + IOCs' },
  { name: 'ioc_extract', category: 'malware', passive: true, description: 'Extract + defang all IOCs (IP/domain/URL/email/hash/CVE/crypto) from pasted text' },
  { name: 'cvss', category: 'intel', passive: true, description: 'CVSS v3.1 base-score calculator from a vector string' },
  { name: 'unshorten', category: 'recon', passive: true, description: 'Trace a shortened/redirecting URL to its real destination (phishing analysis)' },
];

function parseCsvSet(value) {
  return new Set(
    String(value || '')
      .split(',')
      .map(v => v.trim().toLowerCase())
      .filter(Boolean)
  );
}

function parseCustomTools(env) {
  const fromCsv = String(env.CUSTOM_TOOL_NAMES || '')
    .split(',')
    .map(v => v.trim().toLowerCase())
    .filter(Boolean);
  let fromJson = [];
  try {
    if (env.CUSTOM_TOOL_NAMES_JSON) {
      fromJson = JSON.parse(env.CUSTOM_TOOL_NAMES_JSON)
        .map(v => String(v).trim().toLowerCase())
        .filter(Boolean);
    }
  } catch {}
  return [...new Set([...fromCsv, ...fromJson])];
}

function isTruthy(v, fallback = false) {
  if (v === undefined || v === null || v === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

function normalizeTarget(target) {
  const t = String(target || '').trim().toLowerCase();
  if (!t) return '';
  try { return new URL(t).hostname.toLowerCase(); }
  catch { return t.replace(/^https?:\/\//, '').split('/')[0].trim(); }
}

function matchTarget(target, rule) {
  if (!target || !rule) return false;
  if (rule.startsWith('*.')) return target === rule.slice(2) || target.endsWith('.' + rule.slice(2));
  return target === rule;
}

function getToolPolicy(env) {
  const safeMode = isTruthy(env.CTF_SAFE_MODE, true);
  const requireConfirm = isTruthy(env.CTF_REQUIRE_CONFIRM, true);
  const toolAllowlist = parseCsvSet(env.TOOL_ALLOWLIST);
  const targetAllowlist = parseCsvSet(env.CTF_TARGET_ALLOWLIST);
  return { safeMode, requireConfirm, toolAllowlist, targetAllowlist };
}

function isBuiltinTool(name) {
  return BUILTIN_TOOL_SPECS.some(t => t.name === name);
}

function toolCatalog(env) {
  const custom = parseCustomTools(env).map(name => ({
    name,
    category: 'custom',
    passive: false,
    description: 'Custom tool wiring entry (execution delegated to broker if configured)',
  }));
  return [...BUILTIN_TOOL_SPECS, ...custom];
}

async function runBuiltinTool(env, name, args = {}) {
  if (name === 'nvd_lookup')   return nvdLookup(String(args.cveId || args.cve || '').toUpperCase());
  if (name === 'epss_lookup')  return epssLookup(String(args.cveId || args.cve || '').toUpperCase());
  if (name === 'kev_lookup')   return kevLookup(env, String(args.cveId || args.cve || '').toUpperCase());
  if (name === 'rdap_ip')      return ipLookup(String(args.ip || ''));
  if (name === 'rdap_domain')  return domainLookup(String(args.domain || ''));
  if (name === 'dns_lookup')   return dnsLookup(String(args.domain || ''));
  if (name === 'cert_ct')      return certLookup(String(args.domain || ''));
  if (name === 'web_search')   return formatSearch(await webSearch(String(args.query || ''), String(args.braveKey || ''), env) || { provider: 'none', results: [] });
  if (name === 'fetch_url')    return fetchUrl(String(args.url || ''));
  if (name === 'shodan_internetdb') return shodanInternetDB(String(args.ip || ''));
  if (name === 'reverse_dns')  return reverseDns(String(args.ip || ''));
  if (name === 'http_headers') return httpHeaders(String(args.url || args.target || ''));
  if (name === 'ip_geo')       return ipGeo(String(args.ip || ''));
  if (name === 'asn_info')     return asnInfo(String(args.target || args.ip || args.asn || ''));
  if (name === 'wayback')      return wayback(String(args.url || args.domain || ''));
  if (name === 'urlscan')      return urlscanSearch(String(args.domain || ''));
  if (name === 'urlhaus')      return urlhausLookup(env, String(args.host || args.domain || args.ip || ''));
  if (name === 'github_osint') return githubOsint(env, String(args.query || ''));
  if (name === 'crtsh_subs')   return crtshSubs(String(args.domain || args.target || ''));
  if (name === 'circl_cve')    return circlCve(String(args.cveId || args.cve || ''));
  if (name === 'greynoise')    return greynoise(String(args.ip || args.target || ''));
  if (name === 'wellknown')    return wellKnown(String(args.target || args.domain || args.host || ''));
  if (name === 'username_enum') return usernameEnum(String(args.username || args.user || args.target || ''));
  if (name === 'github_user')  return githubUser(env, String(args.username || args.user || args.target || ''));
  if (name === 'gravatar')     return gravatarLookup(String(args.email || args.target || ''));
  if (name === 'email_recon')  return emailRecon(String(args.email || args.target || ''));
  if (name === 'breach_check') return breachCheck(env, String(args.email || args.target || ''));
  if (name === 'tech_fingerprint') return techFingerprint(String(args.url || args.target || args.domain || ''));
  if (name === 'origin_ip')    return originIp(String(args.domain || args.target || ''));
  if (name === 'image_osint')  return imageOsint(String(args.url || args.image || args.target || ''));
  if (name === 'onion_search') return onionSearch(env, String(args.query || args.target || args.domain || args.email || ''));
  if (name === 'email_security') return emailSecurity(String(args.domain || args.target || ''));
  if (name === 'typosquat')    return typosquat(String(args.domain || args.target || ''));
  if (name === 'crypto_addr')  return cryptoAddr(String(args.address || args.addr || args.target || ''));
  if (name === 'dns_records')  return dnsRecords(String(args.domain || args.target || ''));
  if (name === 'tor_exit')     return torExit(String(args.ip || args.target || ''));
  if (name === 'pwned_password') return pwnedPassword(String(args.password || args.pw || args.target || ''));
  if (name === 'cve_search')   return cveSearch(String(args.query || args.keyword || args.target || ''));
  if (name === 'cve_poc')      return cvePoc(String(args.cveId || args.cve || args.target || ''));
  if (name === 'kev_recent')   return kevRecent(String(args.count || args.target || ''));
  if (name === 'mitre')        return mitreLookup(String(args.technique || args.target || args.id || ''));
  if (name === 'bucket_finder') return bucketFinder(String(args.name || args.target || args.domain || ''));
  if (name === 'email_permutations') return emailPermutations(String(args.input || args.name || args.target || ''));
  if (name === 'cors_check')   return corsCheck(String(args.url || args.target || ''));
  if (name === 'subdomain_takeover') return subdomainTakeover(String(args.domain || args.target || ''));
  if (name === 'onion_fetch')  return onionFetch(env, String(args.url || args.onion || args.target || ''));
  if (name === 'stealer_check') return stealerCheck(String(args.target || args.email || args.username || args.domain || ''));
  if (name === 'leakcheck')    return leakCheck(String(args.target || args.email || args.username || ''));
  if (name === 'paste_search') return pasteSearch(String(args.target || args.term || args.query || ''));
  if (name === 'dork')         return dorkTool(env, String(args.target || args.query || ''));
  if (name === 'phish_check')  return phishCheck(String(args.url || args.target || ''));
  if (name === 'archive_urls') return archiveUrls(String(args.domain || args.target || ''));
  if (name === 'favicon_hash') return faviconHash(String(args.url || args.target || ''));
  if (name === 'crawl')        return crawl(String(args.url || args.target || ''));
  if (name === 'subdomains')   return subdomains(String(args.domain || args.target || ''));
  if (name === 'vuln_scan')    return vulnScan(String(args.target || args.url || args.domain || ''));
  if (name === 'keybase')      return keybaseLookup(String(args.username || args.user || args.target || ''));
  if (name === 'devto_user')   return devtoUser(String(args.username || args.user || args.target || ''));
  if (name === 'people_search') return peopleSearch(String(args.name || args.target || args.query || ''));
  if (name === 'edgar')        return secEdgar(String(args.name || args.target || args.query || ''));
  if (name === 'opencorporates') return openCorporates(env, String(args.name || args.target || args.query || ''));
  if (name === 'phone_osint')  return phoneOsint(String(args.phone || args.number || args.target || ''));
  if (name === 'holehe')       { try { const out = await runBrokerTool(env, { tool:'holehe', args:{ email:String(args.email||args.target||'') }, target:String(args.email||args.target||''), requestedAt:new Date().toISOString() }); return typeof out==='string'?out:JSON.stringify(out,null,2); } catch(e){ return `holehe ${String(args.email||args.target||'')}: requires TOOL_BROKER_URL (the broker runs holehe to map an email to registered accounts). ${e.message}`; } }
  if (name === 'exposure_search') return exposureSearch(env, String(args.selector || args.target || args.email || args.username || args.domain || ''));
  if (name === 'jwt')          return jwtDecode(String(args.token || args.target || args.input || ''));
  if (name === 'cidr')         return cidrTool(String(args.input || args.cidr || args.target || ''));
  if (name === 'hash_id')      return hashId(String(args.hash || args.target || args.input || ''));
  if (name === 'encode')       return encodeTool(String(args.input || args.text || args.target || ''));
  if (name === 'timestamp')    return timestampDecode(String(args.input || args.target || ''));
  if (name === 'disclosure_draft') return disclosureDraft(env, String(args.target || args.domain || ''));
  if (name === 'hash_lookup')  return hashLookup(env, String(args.hash || args.target || ''));
  if (name === 'file_analyze') return fileAnalyze(String(args.url || args.target || ''));
  if (name === 'decode')       return decodeTool(String(args.input || args.text || args.target || ''));
  if (name === 'ioc_extract')  return iocExtract(String(args.text || args.input || args.target || ''));
  if (name === 'cvss')         return cvssCalc(String(args.vector || args.target || ''));
  if (name === 'unshorten')    return unshorten(String(args.url || args.target || ''));
  throw new Error(`Unknown builtin tool: ${name}`);
}

// Cache-API wrapper for builtin tool results (10-min TTL) — speeds the agentic loop
// and OSINT fan-out, and reduces upstream API rate-limit pressure.
async function runBuiltinCached(env, tool, args) {
  let cache; try { cache = caches.default; } catch (e) { cache = null; }
  const key = 'https://toolcache.local/' + tool + '?a=' + encodeURIComponent(JSON.stringify(args || {})).slice(0, 800);
  if (cache) { try { const hit = await cache.match(key); if (hit) return await hit.text(); } catch (e) {} }
  const v = String(await runBuiltinTool(env, tool, args));
  if (cache) { try { await cache.put(key, new Response(v, { headers: { 'Cache-Control': 'max-age=600' } })); } catch (e) {} }
  return v;
}

async function runBrokerTool(env, payload) {
  const broker = String(env.TOOL_BROKER_URL || '').trim();
  if (!broker) {
    throw new Error('TOOL_BROKER_URL is not configured. Tool is wired but cannot execute yet.');
  }
  const r = await fetch(broker, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(env.TOOL_BROKER_TOKEN ? { Authorization: `Bearer ${env.TOOL_BROKER_TOKEN}` } : {}),
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(TOOL_RUN_TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`Broker error ${r.status}`);
  const out = await r.json();
  return out;
}

function validateToolAccess(policy, toolName, target, confirmed) {
  // CTF: a checked confirm box is the human-verification gate — it unlocks any tool/target.
  if (confirmed) return { ok: true };
  if (policy.safeMode && policy.toolAllowlist.size && !policy.toolAllowlist.has(toolName)) {
    return { ok: false, status: 403, error: `Tool ${toolName} is not allowlisted in TOOL_ALLOWLIST.` };
  }
  if (policy.safeMode && policy.targetAllowlist.size && target) {
    const allowed = [...policy.targetAllowlist].some(rule => matchTarget(target, rule));
    if (!allowed) {
      return { ok: false, status: 403, error: `Target ${target} is out of scope. Add it to CTF_TARGET_ALLOWLIST.` };
    }
  }
  return { ok: true };
}

async function sha256hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// crt.sh — subdomain/host enumeration via certificate transparency (passive).
async function crtshSubs(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!d) return 'crtsh_subs: a domain is required.';
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(d)}&output=json`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(7000) });
    if (!r.ok) return `crt.sh ${d}: lookup failed (HTTP ${r.status}).`;
    const rows = await r.json();
    const set = new Set();
    for (const row of rows) {
      String(row.name_value || '').split(/\n+/).forEach(n => {
        n = n.trim().toLowerCase().replace(/^\*\./, '');
        if (n && n.endsWith(d) && !n.includes(' ')) set.add(n);
      });
    }
    const subs = [...set].sort();
    if (!subs.length) return `crt.sh ${d}: no certificates / subdomains found. UNKNOWN — do not invent.`;
    return `crt.sh ${d}: ${subs.length} unique names (CT logs, passive)\n` + subs.slice(0, 60).join('\n') + (subs.length > 60 ? `\n…(+${subs.length - 60} more)` : '');
  } catch (e) { return `crt.sh ${d}: lookup failed (${e.message}).`; }
}

// CIRCL CVE — keyless CVE detail (CVSS, summary, references).
async function circlCve(cve) {
  const id = String(cve || '').trim().toUpperCase();
  if (!/^CVE-\d{4}-\d+$/.test(id)) return 'circl_cve: a CVE id like CVE-2024-1234 is required.';
  try {
    const r = await fetch(`https://cve.circl.lu/api/cve/${id}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(9000) });
    if (!r.ok) return `CIRCL ${id}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    const cna = (d.containers && d.containers.cna) || {};
    if (!d || (!d.summary && !d.cvss && !d.containers && !d.id)) return `CIRCL ${id}: no record. UNKNOWN — do not invent.`;
    const summary = d.summary
      || (cna.descriptions && cna.descriptions[0] && cna.descriptions[0].value)
      || 'no summary';
    let cvss = d.cvss != null ? d.cvss : '?';
    if (cvss === '?' && Array.isArray(cna.metrics)) {
      for (const mtc of cna.metrics) {
        const cv = mtc.cvssV4_0 || mtc.cvssV3_1 || mtc.cvssV3_0 || mtc.cvssV2_0;
        if (cv && cv.baseScore != null) { cvss = `${cv.baseScore}${cv.baseSeverity ? ' (' + cv.baseSeverity + ')' : ''}`; break; }
      }
    }
    let refs = (d.references || []).map(x => typeof x === 'string' ? x : x.url);
    if (!refs.length && Array.isArray(cna.references)) refs = cna.references.map(x => x.url);
    refs = refs.filter(Boolean).slice(0, 6);
    return `CIRCL ${id}\nCVSS: ${cvss}\n${summary}\n${refs.length ? 'refs:\n' + refs.join('\n') : ''}`.trim();
  } catch (e) { return `CIRCL ${id}: lookup failed (${e.message}).`; }
}

// GreyNoise community — is this IP a known internet scanner? (keyless, passive)
async function greynoise(ip) {
  const v = String(ip || '').trim();
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'greynoise: a public IPv4 is required.';
  try {
    const r = await fetch(`https://api.greynoise.io/v3/community/${v}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000) });
    if (r.status === 404) return `GreyNoise ${v}: not observed (no scanning activity recorded). UNKNOWN — do not invent.`;
    if (!r.ok) return `GreyNoise ${v}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    return `GreyNoise ${v} (community)\nnoise: ${d.noise} | riot: ${d.riot} | classification: ${d.classification || '?'}\nname: ${d.name || '?'}${d.last_seen ? ' | last seen: ' + d.last_seen : ''}`;
  } catch (e) { return `GreyNoise ${v}: lookup failed (${e.message}).`; }
}

// .well-known recon — security.txt + robots.txt (passive fetch of a host's own files)
async function wellKnown(target) {
  const host = String(target || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!host) return 'wellknown: a domain or host is required.';
  const grab = async (path) => {
    try {
      const r = await fetch(`https://${host}${path}`, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(7000) });
      if (!r.ok) return `(${path}: HTTP ${r.status})`;
      const t = (await r.text()).trim();
      return t ? t.slice(0, 1200) : `(${path}: empty)`;
    } catch (e) { return `(${path}: ${e.message})`; }
  };
  const [sec, rob] = await Promise.all([grab('/.well-known/security.txt'), grab('/robots.txt')]);
  return `well-known ${host}\n=== /.well-known/security.txt ===\n${sec}\n\n=== /robots.txt ===\n${rob}`;
}

// Username enumeration across keyless JSON endpoints (passive presence check).
async function usernameEnum(username) {
  const u = String(username || '').trim().replace(/^@/, '');
  if (!u || /[^A-Za-z0-9_.\-]/.test(u)) return 'username_enum: a plain username (letters/digits/_-.) is required.';
  if (/^(him|her|them|it|they|he|she|his|hers|their|theirs|this|that|someone|somebody|anyone|anybody|everyone|person|people|user|target|subject|guy|me|you|us)$/i.test(u)) return `username_enum: "${u}" is a pronoun/placeholder, not a real username — resolve it to the actual handle first.`;
  const sites = [
    { name: 'GitHub',     api: `https://api.github.com/users/${u}`,                           profile: `https://github.com/${u}`,                 test: r => r.ok },
    { name: 'GitLab',     api: `https://gitlab.com/api/v4/users?username=${u}`,               profile: `https://gitlab.com/${u}`,                 test: async r => r.ok && (await r.json()).length > 0 },
    { name: 'Keybase',    api: `https://keybase.io/_/api/1.0/user/lookup.json?username=${u}`, profile: `https://keybase.io/${u}`,                  test: async r => { if (!r.ok) return false; const j = await r.json(); return !!(j && j.status && j.status.code === 0); } },
    { name: 'HackerNews', api: `https://hacker-news.firebaseio.com/v0/user/${u}.json`,        profile: `https://news.ycombinator.com/user?id=${u}`, test: async r => r.ok && (await r.text()).trim() !== 'null' },
    { name: 'Reddit',     api: `https://www.reddit.com/user/${u}/about.json`,                 profile: `https://www.reddit.com/user/${u}`,        test: r => r.ok },
    { name: 'Dev.to',     api: `https://dev.to/api/users/by_username?url=${u}`,               profile: `https://dev.to/${u}`,                     test: r => r.ok },
    { name: 'npm',        api: `https://registry.npmjs.org/-/user/org.couchdb.user:${u}`,     profile: `https://www.npmjs.com/~${u}`,             test: async r => r.ok && !!(await r.json()).name },
    { name: 'PyPI',       api: `https://pypi.org/user/${u}/`,                                 profile: `https://pypi.org/user/${u}/`,             test: r => r.ok },
    { name: 'DockerHub',  api: `https://hub.docker.com/v2/users/${u}/`,                       profile: `https://hub.docker.com/u/${u}`,           test: r => r.ok },
    { name: 'Codeberg',   api: `https://codeberg.org/api/v1/users/${u}`,                      profile: `https://codeberg.org/${u}`,               test: r => r.ok },
    { name: 'Mastodon',   api: `https://mastodon.social/.well-known/webfinger?resource=acct:${u}@mastodon.social`, profile: `https://mastodon.social/@${u}`, test: r => r.ok },
    { name: 'Lobsters',   api: `https://lobste.rs/u/${u}.json`,                               profile: `https://lobste.rs/u/${u}`,                test: r => r.ok },
  ];
  const out = await Promise.all(sites.map(async s => {
    try {
      const r = await fetch(s.api, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000) });
      let found = false;
      try { found = await s.test(r); } catch { found = false; }
      const tag = found ? 'FOUND' : (r.status === 403 || r.status === 429 ? 'BLOCK' : (r.status >= 500 ? 'err  ' : 'none '));
      return `${tag}  ${s.name.padEnd(11)} ${found ? s.profile : '(' + (r.status === 403 || r.status === 429 ? 'datacenter-blocked HTTP ' + r.status : 'no account, HTTP ' + r.status) + ')'}`;
    } catch (e) { return `err    ${s.name.padEnd(11)} (${e.message})`; }
  }));
  return `username_enum "${u}" (passive presence check)\n${out.join('\n')}`;
}

// GitHub public user profile (keyless, rate-limited).
async function githubUser(env, username) {
  const u = String(username || '').trim().replace(/^@/, '');
  if (!u) return 'github_user: a username is required.';
  const token = String((env && env.GITHUB_TOKEN) || '');
  const headers = { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/vnd.github+json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  try {
    const r = await fetch(`https://api.github.com/users/${u}`, { headers, signal: AbortSignal.timeout(8000) });
    if (r.status === 404) return `GitHub user ${u}: not found. UNKNOWN — do not invent.`;
    if (r.status === 403) return `GitHub user ${u}: rate-limited (403). Set GITHUB_TOKEN to raise limits.`;
    if (!r.ok) return `GitHub user ${u}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    let extra = '';
    // Pivot fuel 1: commit author emails leaked via public push events.
    try {
      const ev = await fetch(`https://api.github.com/users/${u}/events/public?per_page=50`, { headers, signal: AbortSignal.timeout(8000) });
      if (ev.ok) {
        const evs = await ev.json();
        const emails = new Set();
        (evs || []).forEach(e => { if (e.payload && Array.isArray(e.payload.commits)) e.payload.commits.forEach(co => { const em = co.author && co.author.email; if (em && !/noreply|users\.noreply\.github/i.test(em)) emails.add(em); }); });
        if (emails.size) extra += `\ncommit emails (from public events): ${[...emails].slice(0, 6).join(', ')}`;
      }
    } catch {}
    // Pivot fuel 2: recent repos + their homepage domains.
    try {
      const rp = await fetch(`https://api.github.com/users/${u}/repos?per_page=12&sort=updated`, { headers, signal: AbortSignal.timeout(8000) });
      if (rp.ok) {
        const repos = await rp.json();
        const names = (repos || []).map(x => x.name).filter(Boolean);
        const homes = [...new Set((repos || []).map(x => x.homepage).filter(h => h && /^https?:\/\//i.test(h)))];
        const langs = [...new Set((repos || []).map(x => x.language).filter(Boolean))];
        if (names.length) extra += `\ntop repos: ${names.slice(0, 10).join(', ')}`;
        if (langs.length) extra += `\nlanguages: ${langs.slice(0, 8).join(', ')}`;
        if (homes.length) extra += `\nrepo homepages: ${homes.slice(0, 5).join(', ')}`;
      }
    } catch {}
    return `GitHub @${d.login}\nname: ${d.name || '?'} | company: ${d.company || '?'} | location: ${d.location || '?'}\nblog: ${d.blog || '?'} | email: ${d.email || '?'} | twitter: ${d.twitter_username || '?'}\npublic repos: ${d.public_repos} | followers: ${d.followers} | created: ${d.created_at}\nbio: ${d.bio || '(none)'}${extra}`;
  } catch (e) { return `GitHub user ${u}: lookup failed (${e.message}).`; }
}

// Gravatar by email (sha256) — avatar existence + public profile (keyless).
async function gravatarLookup(email) {
  const e = String(email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) return 'gravatar: a valid email is required.';
  const h = await sha256hex(e);
  let has = false, prof = '';
  try { const av = await fetch(`https://gravatar.com/avatar/${h}?d=404`, { signal: AbortSignal.timeout(7000) }); has = av.ok; } catch {}
  try {
    const r = await fetch(`https://api.gravatar.com/v3/profiles/${h}`, { headers: { 'Accept': 'application/json', 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(7000) });
    if (r.ok) {
      const d = await r.json();
      if (!d || d.error) throw new Error('no profile');
      prof = `name: ${d.display_name || '?'} | location: ${d.location || '?'} | job: ${d.job_title || '?'} | company: ${d.company || '?'}`;
      if (d.description) prof += `\nbio: ${d.description}`;
      if (Array.isArray(d.verified_accounts) && d.verified_accounts.length) prof += `\naccounts: ` + d.verified_accounts.map(a => `${a.service_label}:${a.url}`).join(', ');
    }
  } catch {}
  return `Gravatar ${e}\nsha256: ${h}\navatar: ${has ? 'EXISTS' : 'none'}${prof ? '\n' + prof : '\nprofile: none/private'}`;
}

// ── People-OSINT depth: identity correlation, records, phone/email enrichment ──

// Keybase — cryptographically VERIFIED cross-account identity links (proofs), PGP, crypto addrs.
async function keybaseLookup(u) {
  const v = String(u || '').trim().replace(/^@/, '');
  if (!v || /[^A-Za-z0-9_.\-]/.test(v)) return 'keybase: a username/handle is required.';
  async function look(qs) {
    const r = await fetch(`https://keybase.io/_/api/1.0/user/lookup.json?${qs}&fields=proofs_summary,profile,basics,cryptocurrency_addresses,public_keys`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(9000) });
    if (!r.ok) return null;
    const d = await r.json();
    const them = d.them;
    if (Array.isArray(them)) return them.find(Boolean) || null;
    return them || null;
  }
  let them = null;
  try { them = await look('usernames=' + encodeURIComponent(v)); } catch (e) { return `keybase ${v}: lookup failed (${e.message}).`; }
  if (!them) { try { them = await look('twitter=' + encodeURIComponent(v)); } catch (e) {} }
  if (!them) { try { them = await look('github=' + encodeURIComponent(v)); } catch (e) {} }
  if (!them) return `keybase ${v}: no Keybase identity found (Keybase proofs are cryptographically verified, so absence is common and NOT exonerating).`;
  const prof = them.profile || {}, basics = them.basics || {};
  const proofs = ((them.proofs_summary || {}).all) || [];
  const lines = [`keybase @${basics.username || v} — CRYPTOGRAPHICALLY VERIFIED identity links`];
  if (prof.full_name || prof.location || prof.bio) lines.push(`name: ${prof.full_name || '?'} | location: ${prof.location || '?'}${prof.bio ? ' | bio: ' + prof.bio : ''}`);
  if (proofs.length) { lines.push('proven accounts:'); proofs.forEach(p => lines.push(`  ${p.proof_type}: ${p.nametag}  ${p.service_url || p.human_url || ''}`)); }
  const cc = them.cryptocurrency_addresses || {};
  Object.keys(cc).forEach(k => { (cc[k] || []).forEach(a => lines.push(`  ${k}: ${a.address || a}`)); });
  const fp = ((them.public_keys || {}).primary || {}).key_fingerprint || (them.public_keys || {}).eldest_key_fingerprint;
  if (fp) lines.push(`pgp: ${String(fp).toUpperCase()}`);
  if (!proofs.length && !Object.keys(cc).length) lines.push('(identity exists but no public proofs/keys)');
  return lines.join('\n');
}

// Dev.to profile — real name, location, linked GitHub/Twitter/site (strong corroboration).
async function devtoUser(u) {
  const v = String(u || '').trim().replace(/^@/, '');
  if (!v || /[^A-Za-z0-9_.\-]/.test(v)) return 'devto_user: a username is required.';
  try {
    const r = await fetch(`https://dev.to/api/users/by_username?url=${encodeURIComponent(v)}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000) });
    if (r.status === 404) return `devto_user ${v}: no Dev.to account.`;
    if (!r.ok) return `devto_user ${v}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    const links = [];
    if (d.github_username) links.push('github:' + d.github_username);
    if (d.twitter_username) links.push('twitter:' + d.twitter_username);
    if (d.website_url) links.push('site:' + d.website_url);
    return `devto_user @${d.username} (https://dev.to/${d.username})\nname: ${d.name || '?'} | location: ${d.location || '?'} | joined: ${d.joined_at || '?'}\nbio: ${d.summary || '(none)'}${links.length ? '\nlinked: ' + links.join(', ') : ''}`;
  } catch (e) { return `devto_user ${v}: lookup failed (${e.message}).`; }
}

// People search — analyst DEEP LINKS only (no auto-scrape). Covers social, people-search,
// genealogy/vital records, court records, and Google dorks for a human to review.
function peopleSearch(input) {
  const parts = String(input || '').split('|').map(s => s.trim());
  const name = parts[0], loc = parts[1] || '';
  if (!name || name.length < 2) return 'people_search: a person NAME is required (optionally "Name | City/Region").';
  const toks = name.split(/\s+/);
  const first = toks[0], last = toks[toks.length - 1];
  const q = encodeURIComponent(name), ql = encodeURIComponent(name + (loc ? ' ' + loc : ''));
  const nm = name.toLowerCase().replace(/[^a-z ]/g, '').trim().replace(/\s+/g, '-');
  const L = (t, u) => `  ${t}: ${u}`;
  const out = [`people_search "${name}"${loc ? ' (' + loc + ')' : ''} — analyst deep links (open only what you need; same-name hits are often DIFFERENT people)`];
  out.push('social:');
  out.push(L('LinkedIn', `https://www.google.com/search?q=site:linkedin.com/in+${q}`));
  out.push(L('Twitter/X', `https://x.com/search?q=${q}&f=user`));
  out.push(L('Facebook', `https://www.facebook.com/search/people/?q=${q}`));
  out.push(L('Instagram', `https://www.google.com/search?q=site:instagram.com+${q}`));
  out.push('people-search / public records:');
  out.push(L('TruePeopleSearch', `https://www.truepeoplesearch.com/results?name=${q}`));
  out.push(L('FastPeopleSearch', `https://www.fastpeoplesearch.com/name/${nm}`));
  out.push(L('ThatsThem', `https://thatsthem.com/name/${nm}`));
  out.push(L('Radaris', `https://radaris.com/p/${encodeURIComponent(first)}/${encodeURIComponent(last)}/`));
  out.push('genealogy / vital records (relatives, ancestry):');
  out.push(L('FamilySearch', `https://www.familysearch.org/search/record/results?q.givenName=${encodeURIComponent(first)}&q.surname=${encodeURIComponent(last)}`));
  out.push(L('FindAGrave', `https://www.findagrave.com/memorial/search?firstname=${encodeURIComponent(first)}&lastname=${encodeURIComponent(last)}`));
  out.push(L('Legacy obituaries', `https://www.legacy.com/search?query=${q}`));
  out.push('court / legal:');
  out.push(L('CanLII (CA)', `https://www.canlii.org/en/#search/text=${q}`));
  out.push(L('CourtListener (US)', `https://www.courtlistener.com/?q=${q}`));
  out.push('dorks:');
  out.push(L('contact dork', `https://www.google.com/search?q=${ql}+(email+OR+phone+OR+contact)`));
  out.push(L('resume/CV dork', `https://www.google.com/search?q=${ql}+(resume+OR+cv+OR+filetype:pdf)`));
  out.push('NOTE: these are human-review links to public portals. The agent does NOT auto-harvest relatives, addresses, or genealogy. Verify each hit is actually the same person before relying on it.');
  return out.join('\n');
}

// SEC EDGAR full-text search — find a person/company in insider filings (Form 3/4/5 name individuals).
async function secEdgar(name) {
  const v = String(name || '').trim();
  if (!v || v.length < 2) return 'edgar: a person or company name is required.';
  try {
    const r = await fetch(`https://efts.sec.gov/LATEST/search-index?q=%22${encodeURIComponent(v)}%22&forms=3,4,5`,
      { headers: { 'User-Agent': 'garrettstimpson-agent research (defensive OSINT)', 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return `edgar ${v}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    const h = d.hits || {};
    const total = ((h.total || {}).value) || 0;
    if (!total) return `edgar "${v}": no SEC insider (Form 3/4/5) filings naming this entity.`;
    const rows = (h.hits || []).slice(0, 8).map(it => {
      const s = it._source || {};
      const nm = (s.display_names || []).join('; ');
      const cik = (s.ciks || [])[0] || '';
      return `  ${s.file_date || '?'} ${(s.root_forms || [s.form]).join('/')} — ${nm}${cik ? '  https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=' + cik : ''}`;
    });
    return `edgar "${v}" — SEC insider filings (Form 3/4/5 name individuals): ${total} hit(s)\n${rows.join('\n')}\nbrowse: https://www.sec.gov/cgi-bin/browse-edgar?company=${encodeURIComponent(v)}&CIK=&type=&action=getcompany`;
  } catch (e) { return `edgar ${v}: lookup failed (${e.message}).`; }
}

// OpenCorporates — officer/directorship records (free API now needs a token; degrade to the link).
async function openCorporates(env, name) {
  const v = String(name || '').trim();
  if (!v || v.length < 2) return 'opencorporates: a name is required.';
  const ui = `https://opencorporates.com/officers?q=${encodeURIComponent(v)}`;
  const tok = String(env.OPENCORPORATES_API_TOKEN || '').trim();
  if (!tok) return `opencorporates: the free API now requires a token. Set OPENCORPORATES_API_TOKEN to enable officer/directorship search. Manual: ${ui}`;
  try {
    const r = await fetch(`https://api.opencorporates.com/v0.4/officers/search?q=${encodeURIComponent(v)}&api_token=${encodeURIComponent(tok)}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return `opencorporates ${v}: HTTP ${r.status}. Manual: ${ui}`;
    const d = await r.json();
    const offs = (((d.results || {}).officers) || []).slice(0, 8).map(o => {
      const x = o.officer || o;
      return `  ${x.name} — ${x.position || 'officer'} @ ${(x.company || {}).name || '?'} (${(x.company || {}).jurisdiction_code || '?'})`;
    });
    const tot = ((d.results || {}).total_count) || offs.length;
    return offs.length ? `opencorporates "${v}": ${tot} officer record(s)\n${offs.join('\n')}\nUI: ${ui}` : `opencorporates "${v}": no officer records. UI: ${ui}`;
  } catch (e) { return `opencorporates ${v}: ${e.message}. Manual: ${ui}`; }
}

// Phone OSINT — country/NANP region + line-type/reverse-lookup deep links (no auto-scrape).
function phoneOsint(input) {
  const raw = String(input || '').trim();
  const d = raw.replace(/[^\d+]/g, '').replace(/^\+/, '');
  if (d.length < 7) return 'phone_osint: provide a number in international format (e.g. +14165551234).';
  const CC = [['1', 'North America (US/Canada — NANP)'], ['44', 'United Kingdom'], ['61', 'Australia'], ['91', 'India'], ['49', 'Germany'], ['33', 'France'], ['81', 'Japan'], ['86', 'China'], ['7', 'Russia/Kazakhstan'], ['55', 'Brazil'], ['52', 'Mexico'], ['34', 'Spain'], ['39', 'Italy'], ['31', 'Netherlands'], ['46', 'Sweden'], ['41', 'Switzerland'], ['971', 'UAE'], ['972', 'Israel'], ['234', 'Nigeria'], ['27', 'South Africa'], ['82', 'South Korea'], ['65', 'Singapore'], ['63', 'Philippines'], ['62', 'Indonesia'], ['90', 'Turkey'], ['380', 'Ukraine'], ['48', 'Poland'], ['351', 'Portugal'], ['353', 'Ireland'], ['64', 'New Zealand']];
  let cc = '', country = 'unknown';
  for (const [c, n] of CC.sort((a, b) => b[0].length - a[0].length)) { if (d.startsWith(c)) { cc = c; country = n; break; } }
  const lines = [`phone_osint ${raw}`, `normalized: +${d} | digits: ${d.length}`, `country code: ${cc ? '+' + cc + ' — ' + country : 'unknown (include the country code, e.g. +1)'}`];
  if (cc === '1') { lines.push(`NANP area code: ${d.slice(1, 4)} (geographic region varies — confirm via lookup)`); }
  const q = encodeURIComponent(raw), dd = encodeURIComponent(d);
  lines.push('lookups (human-review):');
  lines.push(`  carrier/line-type: https://www.google.com/search?q=%2B${dd}+carrier`);
  lines.push(`  Truecaller: https://www.truecaller.com/search/${cc === '1' ? 'us' : 'intl'}/${dd}`);
  lines.push(`  Sync.me: https://sync.me/search/?number=${dd}`);
  lines.push(`  WhitePages: https://www.whitepages.com/phone/${dd}`);
  lines.push(`  leak/breach context: https://www.google.com/search?q=${q}+(leak+OR+breach+OR+pastebin)`);
  lines.push('NOTE: carrier/line-type/owner require the linked services; the agent does not auto-scrape them.');
  return lines.join('\n');
}

// Email recon — format + MX (DoH) + gravatar presence (passive).
async function emailRecon(email) {
  const e = String(email || '').trim().toLowerCase();
  const m = e.match(/^[^@\s]+@([^@\s]+\.[^@\s]+)$/);
  if (!m) return `email_recon: ${email} is not a valid email.`;
  const dom = m[1];
  const disposable = /(mailinator|guerrilla|10minutemail|tempmail|temp-mail|throwaway|yopmail|trashmail|getnada|maildrop|dispostable|fakeinbox|sharklasers|mohmal|emailondeck|moakt|mailnesia|tempr\.email|33mail|spamgourmet|guerrillamail)/i.test(dom);
  let mx = 'UNKNOWN';
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${dom}&type=MX`, { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
    const d = await r.json();
    const recs = (d.Answer || []).map(a => a.data).filter(Boolean);
    mx = recs.length ? recs.join(', ') : 'none (no MX — may not receive mail)';
  } catch (ex) { mx = `lookup failed (${ex.message})`; }
  const grav = await gravatarLookup(e);
  return `email_recon ${e}\ndomain: ${dom}\ndisposable: ${disposable ? 'YES (throwaway provider)' : 'no'}\nMX: ${mx}\n--- gravatar ---\n${grav}`;
}

// ── Defensive OSINT tools ────────────────────────────────────────────────────

function isCloudflareIp(ip) {
  const m = String(ip || '').match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); if (!m) return false;
  const a = +m[1], b = +m[2];
  if (a === 104 && b >= 16 && b <= 31) return true;
  if (a === 172 && b >= 64 && b <= 71) return true;
  if (a === 162 && (b === 158 || b === 159)) return true;
  if (a === 173 && b === 245) return true;
  if (a === 141 && b === 101) return true;
  if (a === 108 && b === 162) return true;
  if (a === 188 && b === 114) return true;
  if (a === 190 && b === 93) return true;
  if (a === 198 && b === 41) return true;
  if (a === 131 && b === 0) return true;
  if (a === 103 && (b === 21 || b === 22 || b === 31)) return true;
  if (a === 197 && b === 234) return true;
  return false;
}

// Email breach exposure — XposedOrNot (keyless) + HaveIBeenPwned (if HIBP_API_KEY set).
async function breachCheck(env, email) {
  const e = String(email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) return 'breach_check: a valid email is required.';
  const out = [];
  try {
    const r = await fetch(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(e)}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) });
    if (r.status === 404) out.push('XposedOrNot: no known breaches for this email.');
    else if (r.ok) {
      const d = await r.json();
      const eb = (d.ExposedBreaches && d.ExposedBreaches.breaches_details) || [];
      if (!eb.length) out.push('XposedOrNot: no known breaches.');
      else {
        const risk = d.BreachMetrics && d.BreachMetrics.risk && d.BreachMetrics.risk[0];
        const classes = new Set();
        eb.forEach(b => String(b.xposed_data || '').split(';').forEach(c => { const t = c.trim(); if (t) classes.add(t); }));
        const named = eb.slice(0, 8).map(b => b.breach + (b.xposed_date ? ' (' + b.xposed_date + ')' : ''));
        let line = `XposedOrNot: ${eb.length} breach(es)` + (risk ? ` | risk: ${risk.risk_label} (${risk.risk_score}/100)` : '');
        line += `\nexposed data types: ${[...classes].slice(0, 14).join(', ') || 'unknown'}`;
        line += `\nbreaches: ${named.join(', ')}${eb.length > 8 ? ', +' + (eb.length - 8) + ' more' : ''}`;
        out.push(line);
      }
    } else out.push(`XposedOrNot: lookup failed (HTTP ${r.status}).`);
  } catch (ex) { out.push(`XposedOrNot: lookup failed (${ex.message}).`); }
  const hibpKey = String((env && env.HIBP_API_KEY) || '');
  if (hibpKey) {
    try {
      const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(e)}?truncateResponse=true`,
        { headers: { 'hibp-api-key': hibpKey, 'User-Agent': 'garrettstimpson-agent', 'Accept': 'application/json' }, signal: AbortSignal.timeout(9000) });
      if (r.status === 404) out.push('HIBP: no breaches found.');
      else if (r.ok) { const d = await r.json(); out.push(`HIBP: ${d.length} breach(es) — ${d.map(x => x.Name).join(', ')}`); }
      else out.push(`HIBP: lookup failed (HTTP ${r.status}).`);
    } catch (ex) { out.push(`HIBP: lookup failed (${ex.message}).`); }
  } else out.push('HIBP: skipped (set HIBP_API_KEY on deploy to enable).');
  return `breach_check ${e}\n` + out.join('\n');
}

// Web tech fingerprint — fetch the site and detect CMS/framework/server. Contacts target.
async function techFingerprint(target) {
  const t = String(target || '').trim();
  let u; try { u = new URL(/^https?:\/\//.test(t) ? t : 'https://' + t); } catch { return 'tech_fingerprint: a domain or URL is required.'; }
  if (isPrivateHost(u.hostname)) return `tech_fingerprint: ${u.hostname} is private/internal — blocked.`;
  try {
    const r = await fetch(u.toString(), { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, redirect: 'follow', signal: AbortSignal.timeout(10000) });
    const html = await r.text();
    const h = (n) => r.headers.get(n) || '';
    const hits = [];
    const sig = [
      ['WordPress', /wp-content\/|wp-includes\/|<meta name="generator" content="WordPress/i],
      ['Drupal', /Drupal\.settings|\/sites\/default\/files\/|content="Drupal/i],
      ['Joomla', /\/media\/jui\/|content="Joomla/i],
      ['Ghost', /content="Ghost \d|ghost-url/i],
      ['Shopify', /cdn\.shopify\.com|Shopify\.theme/i],
      ['MediaWiki', /content="MediaWiki/i],
      ['Next.js', /\/_next\/static\//i],
      ['React', /data-reactroot|__REACT_DEVTOOLS/i],
      ['Vue', /__VUE__|data-v-[0-9a-f]{8}/i],
      ['Cloudflare', /cf-ray/i],
    ];
    const gen = (html.match(/<meta name="generator" content="([^"]+)"/i) || [])[1];
    sig.forEach(([name, re]) => { if (re.test(html) || re.test(h('server'))) hits.push(name); });
    let discourse = /content="Discourse|data-discourse-setup|id="data-discourse|discourse-application|DiscourseAjax/i.test(html);
    if (!discourse) {
      try {
        const sj = await fetch(u.origin + '/site.json', { headers: { 'Accept': 'application/json', 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(6000) });
        if (sj.ok) { const j = await sj.json(); if (j && (j.categories || j.default_archetype || j.post_action_types || j.groups)) discourse = true; }
      } catch {}
    }
    if (discourse && hits.indexOf('Discourse') < 0) hits.push('Discourse');
    const title = ((html.match(/<title[^>]*>([^<]{0,140})<\/title>/i) || [])[1] || '').trim();
    return `tech_fingerprint ${u.hostname} (HTTP ${r.status})\n` +
      `server: ${h('server') || '?'} | x-powered-by: ${h('x-powered-by') || '?'} | via: ${h('via') || '?'}\n` +
      `generator: ${gen || '?'}\n` +
      `title: ${title || '?'}\n` +
      `detected: ${[...new Set(hits)].join(', ') || 'no known signatures'}` +
      (discourse ? '\nDiscourse: CONFIRMED (forum platform)' : '');
  } catch (e) { return `tech_fingerprint ${u.hostname}: fetch failed (${e.message}).`; }
}

// Origin-IP discovery behind Cloudflare — passive DoH probing of common non-fronted hosts.
async function originIp(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!d) return 'origin_ip: a domain is required.';
  const parts = d.split('.');
  const root = parts.length > 2 ? parts.slice(-2).join('.') : d;
  const aRecords = async (host) => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
        { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
      const j = await r.json();
      return (j.Answer || []).filter(x => x.type === 1).map(x => x.data);
    } catch { return []; }
  };
  const main = await aRecords(d);
  const fronted = main.some(isCloudflareIp);
  const subs = ['direct', 'origin', 'origin-www', 'cpanel', 'webdisk', 'webmail', 'mail', 'ftp', 'dev', 'staging', 'test', 'vpn', 'remote', 'server', 'web', 'blog', 'api', 'admin', 'portal'];
  const targets = subs.map(s => s + '.' + root);
  targets.push(d.startsWith('www.') ? d.slice(4) : 'www.' + d);
  const seen = {}, leaks = [];
  await Promise.all(targets.map(async (host) => {
    const recs = await aRecords(host);
    recs.forEach(ip => { if (!isCloudflareIp(ip) && !seen[ip]) { seen[ip] = 1; leaks.push(`${host} -> ${ip}`); } });
  }));
  let res = `origin_ip ${d}\nfront A records: ${main.join(', ') || 'none'}${fronted ? '  (Cloudflare-fronted)' : ''}`;
  if (leaks.length) res += `\nPOSSIBLE ORIGIN / non-Cloudflare IPs (verify before trusting):\n${leaks.join('\n')}`;
  else if (fronted) res += `\nNo origin leaked via common subdomains. Origin is UNKNOWN — do not guess. (Pivot via crt.sh historical certs or paid passive-DNS.)`;
  else res += `\nDomain does not appear Cloudflare-fronted; the A records above are likely the real origin.`;
  return res;
}

async function sha256hexBytes(bytes) {
  const b = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}

// Minimal EXIF reader for JPEG (camera, timestamps, GPS). Returns {} or {error}.
function readExifBytes(bytes) {
  try {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (dv.getUint16(0) !== 0xFFD8) return { error: 'not a JPEG (EXIF read skipped)' };
    let off = 2, app1 = -1;
    while (off < dv.byteLength - 1) {
      if (dv.getUint8(off) !== 0xFF) break;
      const marker = dv.getUint8(off + 1), size = dv.getUint16(off + 2);
      if (marker === 0xE1) { app1 = off + 4; break; }
      if (marker === 0xDA) break;
      off += 2 + size;
    }
    if (app1 < 0) return { error: 'no EXIF/APP1 segment' };
    if (String.fromCharCode(dv.getUint8(app1), dv.getUint8(app1 + 1), dv.getUint8(app1 + 2), dv.getUint8(app1 + 3)) !== 'Exif') return { error: 'no Exif header' };
    const tiff = app1 + 6;
    const le = String.fromCharCode(dv.getUint8(tiff), dv.getUint8(tiff + 1)) === 'II';
    const u16 = o => dv.getUint16(o, le), u32 = o => dv.getUint32(o, le);
    const TYPE_SZ = { 1:1, 2:1, 3:2, 4:4, 5:8, 7:1, 9:4, 10:8 };
    const rat = o => u32(o) / (u32(o + 4) || 1);
    function readIFD(ifdOff) {
      const out = {}; const n = u16(ifdOff); let p = ifdOff + 2;
      for (let i = 0; i < n; i++, p += 12) {
        const tag = u16(p), type = u16(p + 2), cnt = u32(p + 4);
        const valOff = (TYPE_SZ[type] || 1) * cnt <= 4 ? p + 8 : tiff + u32(p + 8);
        out[tag] = { type, cnt, valOff };
      }
      return out;
    }
    const str = e => { let s = ''; for (let i = 0; i < e.cnt; i++) { const c = dv.getUint8(e.valOff + i); if (c) s += String.fromCharCode(c); } return s.trim(); };
    const ifd0 = readIFD(tiff + u32(tiff + 4));
    const res = {};
    if (ifd0[0x010F]) res.make = str(ifd0[0x010F]);
    if (ifd0[0x0110]) res.model = str(ifd0[0x0110]);
    if (ifd0[0x0132]) res.datetime = str(ifd0[0x0132]);
    if (ifd0[0x8769]) { const ex = readIFD(tiff + u32(ifd0[0x8769].valOff)); if (ex[0x9003]) res.taken = str(ex[0x9003]); }
    if (ifd0[0x8825]) {
      const g = readIFD(tiff + u32(ifd0[0x8825].valOff));
      const dms = e => { const o = e.valOff; return rat(o) + rat(o + 8) / 60 + rat(o + 16) / 3600; };
      if (g[2] && g[4]) {
        let lat = dms(g[2]), lon = dms(g[4]);
        if (g[1] && str(g[1]) === 'S') lat = -lat;
        if (g[3] && str(g[3]) === 'W') lon = -lon;
        res.gps = { lat: +lat.toFixed(6), lon: +lon.toFixed(6) };
      }
    }
    return res;
  } catch (e) { return { error: 'EXIF parse failed (' + e.message + ')' }; }
}

// Image OSINT — hash, type, EXIF (camera/GPS/timestamp), reverse-image-search links.
async function imageOsint(url) {
  const u = String(url || '').trim();
  let parsed; try { parsed = new URL(u); } catch { return 'image_osint: a direct image URL (jpg/png/...) is required.'; }
  if (isPrivateHost(parsed.hostname)) return `image_osint: ${parsed.hostname} is private/internal — blocked.`;
  try {
    const r = await fetch(parsed.toString(), { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, redirect: 'follow', signal: AbortSignal.timeout(12000) });
    if (!r.ok) return `image_osint ${parsed.hostname}: fetch failed (HTTP ${r.status}).`;
    const ct = r.headers.get('content-type') || '';
    const bytes = new Uint8Array(await r.arrayBuffer());
    const hash = await sha256hexBytes(bytes);
    const isJpeg = /jpe?g/i.test(ct) || (bytes[0] === 0xFF && bytes[1] === 0xD8);
    const exif = isJpeg ? readExifBytes(bytes) : { error: 'EXIF only parsed for JPEG (this is ' + (ct || 'unknown') + ')' };
    const enc = encodeURIComponent(u);
    let out = `image_osint ${parsed.hostname}\ntype: ${ct || '?'} | bytes: ${bytes.length} | sha256: ${hash}`;
    if (exif && !exif.error) {
      const cam = [exif.make, exif.model].filter(Boolean).join(' ');
      if (cam) out += `\ncamera: ${cam}`;
      if (exif.taken || exif.datetime) out += `\ntaken: ${exif.taken || exif.datetime}`;
      if (exif.gps) out += `\nGPS: ${exif.gps.lat}, ${exif.gps.lon}  (map: https://maps.google.com/?q=${exif.gps.lat},${exif.gps.lon})`;
      if (!cam && !exif.gps && !exif.taken) out += `\nEXIF: present, but no camera/GPS/timestamp tags`;
    } else if (exif && exif.error) { out += `\nEXIF: ${exif.error}`; }
    out += `\nreverse-image search:\n` +
      `Google Lens: https://lens.google.com/uploadbyurl?url=${enc}\n` +
      `Yandex: https://yandex.com/images/search?rpt=imageview&url=${enc}\n` +
      `Bing: https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:${enc}\n` +
      `TinEye: https://tineye.com/search?url=${enc}`;
    return out;
  } catch (e) { return `image_osint ${parsed.hostname}: failed (${e.message}).`; }
}

// Dark-web exposure — Ahmia clearnet onion index (best-effort) + Tor broker if configured.
async function onionSearch(env, query) {
  const q = String(query || '').trim();
  if (!q) return 'onion_search: a term (email, domain, handle, keyword) is required.';
  const lines = [];
  try {
    const r = await fetch(`https://ahmia.fi/search/?q=${encodeURIComponent(q)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0', 'Accept': 'text/html' }, redirect: 'follow', signal: AbortSignal.timeout(12000) });
    if (r.ok) {
      const html = await r.text();
      const seen = {}, hits = [];
      const re = /([a-z2-7]{16}\.onion|[a-z2-7]{56}\.onion)/gi;
      let m; while ((m = re.exec(html))) { const o = m[1].toLowerCase(); if (o.indexOf('juhanurmihxlp') === 0) continue; if (!seen[o]) { seen[o] = 1; hits.push(o); } }
      lines.push(hits.length
        ? `Ahmia (clearnet onion index): ${hits.length} onion site(s) referencing "${q}":\n` + hits.slice(0, 15).map(o => o + '  (view: https://' + o + '.onion.ws)').join('\n')
        : `Ahmia: no indexed onion sites referencing "${q}" (or abuse-filtered).`);
    } else lines.push(`Ahmia: unavailable (HTTP ${r.status}). Clearnet onion gateways frequently block datacenter/Workers IPs.`);
  } catch (e) { lines.push(`Ahmia: unavailable (${e.message}).`); }
  if (String((env && env.TOOL_BROKER_URL) || '')) {
    try {
      const out = await runBrokerTool(env, { tool: 'onion_search', args: { query: q }, target: q, reason: 'darkweb exposure', requestedAt: new Date().toISOString() });
      const txt = typeof out === 'string' ? out : (out && (out.result || JSON.stringify(out)));
      if (txt) lines.push(`Broker Tor search:\n${String(txt).slice(0, 2500)}`);
    } catch (e) { lines.push(`Broker Tor search: ${e.message}`); }
  } else {
    lines.push('Live .onion crawl: not available in-worker (Cloudflare Workers cannot open Tor circuits). Set TOOL_BROKER_URL to a Tor-capable broker to enable real onion crawling.');
  }
  return `onion_search "${q}" (dark-web exposure monitoring)\n` + lines.join('\n\n') + '\n\nTip: use onion_fetch <address> to pull onion site text via a free clearnet gateway. Index references surfaced for defensive exposure assessment only.';
}

// Email-security posture — SPF / DMARC / MX / DNSSEC (spoofability assessment).
async function emailSecurity(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!d || d.indexOf('.') < 0) return 'email_security: a domain is required.';
  const doh = async (name, type) => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
        { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(7000) });
      const j = await r.json(); return j.Answer || [];
    } catch { return []; }
  };
  const clean = a => a.map(x => String(x.data || '').replace(/^"|"$/g, '').replace(/" "/g, ''));
  const root = clean(await doh(d, 'TXT'));
  const dmRec = clean(await doh('_dmarc.' + d, 'TXT'));
  const mxA = await doh(d, 'MX');
  const dk = await doh(d, 'DNSKEY');
  const spf = root.find(t => /v=spf1/i.test(t));
  const dmarc = dmRec.find(t => /v=DMARC1/i.test(t));
  const mx = mxA.filter(a => a.type === 15).map(a => a.data);
  const dnssec = dk.some(a => a.type === 48);
  const pol = (dmarc && (dmarc.match(/p=([a-z]+)/i) || [])[1]) || '';
  const gaps = [];
  if (!spf) gaps.push('No SPF record — sender domain is easier to spoof.');
  else if (/[~?]all/.test(spf)) gaps.push('SPF uses soft-fail (~all/?all) — weaker enforcement than -all.');
  if (!dmarc) gaps.push('No DMARC record — no anti-spoofing policy published.');
  else if (/p=none/i.test(dmarc)) gaps.push('DMARC p=none — monitor only; does NOT block spoofed mail.');
  if (!mx.length) gaps.push('No MX — domain does not receive mail (or is misconfigured).');
  if (!dnssec) gaps.push('DNSSEC not enabled — DNS answers are not cryptographically signed.');
  return `email_security ${d}\nSPF: ${spf || 'NONE'}\nDMARC: ${dmarc || 'NONE'}${pol ? ' (policy: ' + pol + ')' : ''}\nMX: ${mx.join(', ') || 'none'}\nDNSSEC: ${dnssec ? 'enabled' : 'not enabled'}\n` +
    (gaps.length ? `Spoofability / gaps:\n- ${gaps.join('\n- ')}` : 'Posture: SPF + enforcing DMARC + DNSSEC — strong.');
}

// Typosquat / lookalike-domain discovery (phishing & brand-abuse, passive DoH).
function typoCandidates(domain) {
  const parts = domain.split('.'); const name = parts[0]; const tld = parts.slice(1).join('.') || 'com';
  const set = new Set();
  for (let i = 0; i < name.length; i++) set.add(name.slice(0, i) + name.slice(i + 1) + '.' + tld);          // omission
  for (let i = 0; i < name.length - 1; i++) { const a = name.split(''); const t = a[i]; a[i] = a[i + 1]; a[i + 1] = t; set.add(a.join('') + '.' + tld); } // transposition
  for (let i = 0; i < name.length; i++) set.add(name.slice(0, i) + name[i] + name.slice(i) + '.' + tld);     // repetition
  const homo = { o: '0', l: '1', i: '1', e: '3', a: '4', s: '5' };
  for (let i = 0; i < name.length; i++) { const c = name[i]; if (homo[c]) set.add(name.slice(0, i) + homo[c] + name.slice(i + 1) + '.' + tld); } // homoglyph
  for (let i = 1; i < name.length; i++) set.add(name.slice(0, i) + '-' + name.slice(i) + '.' + tld);         // hyphenation
  ['com', 'net', 'org', 'co', 'io', 'app', 'xyz', 'info', 'online', 'site'].forEach(t => { if (t !== tld) set.add(name + '.' + t); }); // tld swap
  set.delete(domain);
  return [...set].slice(0, 34);
}
async function typosquat(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!d || d.split('.').length < 2) return 'typosquat: a domain (name.tld) is required.';
  const cands = typoCandidates(d);
  const live = [];
  await Promise.all(cands.map(async c => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(c)}&type=A`,
        { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
      const j = await r.json();
      const a = (j.Answer || []).filter(x => x.type === 1).map(x => x.data);
      if (a.length) live.push(`${c} -> ${a.slice(0, 2).join(', ')}`);
    } catch {}
  }));
  if (!live.length) return `typosquat ${d}: checked ${cands.length} lookalikes — none currently resolve (no active typosquats found).`;
  return `typosquat ${d}: ${live.length}/${cands.length} lookalikes are REGISTERED & resolving (possible phishing / brand abuse — investigate):\n${live.join('\n')}`;
}

// Crypto-address intel — BTC (blockchain.info) / ETH (blockchair), keyless. Threat-intel.
async function cryptoAddr(addr) {
  const a = String(addr || '').trim();
  if (/^(bc1[a-z0-9]{20,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$/.test(a)) {
    try {
      const r = await fetch(`https://blockchain.info/rawaddr/${a}?limit=0`, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(9000) });
      if (!r.ok) return `crypto_addr ${a}: BTC lookup failed (HTTP ${r.status}).`;
      const d = await r.json(); const btc = v => (Number(v) / 1e8).toFixed(8);
      return `crypto_addr ${a} (Bitcoin)\ntx count: ${d.n_tx}\ntotal received: ${btc(d.total_received)} BTC\ntotal sent: ${btc(d.total_sent)} BTC\nbalance: ${btc(d.final_balance)} BTC`;
    } catch (e) { return `crypto_addr ${a}: BTC lookup failed (${e.message}).`; }
  }
  if (/^0x[a-fA-F0-9]{40}$/.test(a)) {
    try {
      const r = await fetch(`https://api.blockchair.com/ethereum/dashboards/address/${a}`, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(9000) });
      if (!r.ok) return `crypto_addr ${a}: ETH lookup failed (HTTP ${r.status}).`;
      const d = await r.json(); const k = a.toLowerCase();
      const info = d.data && d.data[k] && d.data[k].address;
      if (!info) return `crypto_addr ${a}: no ETH data returned.`;
      const eth = v => (Number(v) / 1e18).toFixed(6);
      return `crypto_addr ${a} (Ethereum)\nbalance: ${eth(info.balance)} ETH\ntx count: ${info.transaction_count != null ? info.transaction_count : '?'}\nreceived: ${info.received != null ? eth(info.received) : '?'} ETH`;
    } catch (e) { return `crypto_addr ${a}: ETH lookup failed (${e.message}).`; }
  }
  return `crypto_addr: "${a}" is not a recognized BTC or ETH address.`;
}

async function sha1hex(s) {
  const b = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Full DNS record dump (A/AAAA/MX/NS/TXT/CAA/SOA) via DoH.
async function dnsRecords(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!d || d.indexOf('.') < 0) return 'dns_records: a domain is required.';
  const doh = async (type) => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(d)}&type=${type}`,
        { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(7000) });
      const j = await r.json(); return (j.Answer || []).map(a => a.data);
    } catch { return []; }
  };
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'SOA'];
  const res = await Promise.all(types.map(doh));
  const fmt = (label, arr) => `${label}: ${arr.length ? arr.slice(0, 8).join(' | ') : 'none'}`;
  return `dns_records ${d}\n` + types.map((t, i) => fmt(t, t === 'TXT' ? res[i].map(x => String(x).slice(0, 90)) : res[i])).join('\n');
}

// Is an IP a known Tor relay / exit node (onionoo, keyless).
async function torExit(ip) {
  const v = String(ip || '').trim();
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'tor_exit: a public IPv4 is required.';
  try {
    const r = await fetch(`https://onionoo.torproject.org/details?search=${v}&type=relay`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(9000) });
    if (!r.ok) return `tor_exit ${v}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    const relays = d.relays || [];
    if (!relays.length) return `tor_exit ${v}: not a known Tor relay.`;
    const x = relays[0]; const flags = x.flags || [];
    return `tor_exit ${v}: KNOWN TOR RELAY${flags.indexOf('Exit') >= 0 ? ' (EXIT NODE)' : ''}\nnickname: ${x.nickname || '?'} | flags: ${flags.join(', ')}\nfirst seen: ${x.first_seen || '?'} | AS: ${x.as || '?'} ${x.as_name || ''}`;
  } catch (e) { return `tor_exit ${v}: lookup failed (${e.message}).`; }
}

// Check a password against Have I Been Pwned (k-anonymity: only a 5-char hash prefix leaves).
async function pwnedPassword(pw) {
  const p = String(pw || '');
  if (!p) return 'pwned_password: provide a password to check. Only the first 5 chars of its SHA-1 hash are sent (k-anonymity).';
  try {
    const h = await sha1hex(p);
    const prefix = h.slice(0, 5), suffix = h.slice(5);
    const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Add-Padding': 'true' }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return `pwned_password: lookup failed (HTTP ${r.status}).`;
    const text = await r.text();
    const line = text.split('\n').map(l => l.trim()).find(l => l.indexOf(suffix) === 0);
    const count = line ? parseInt(line.split(':')[1], 10) : 0;
    return count > 0
      ? `pwned_password: COMPROMISED — this exact password appears in ${count.toLocaleString()} known breaches. Do NOT use it anywhere.`
      : `pwned_password: not found in the Have I Been Pwned breach corpus (absence is not proof of strength).`;
  } catch (e) { return `pwned_password: lookup failed (${e.message}).`; }
}

// Search NVD for CVEs by product/keyword.
async function cveSearch(query) {
  const q = String(query || '').trim();
  if (!q) return 'cve_search: a product or keyword is required.';
  try {
    const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(q)}&resultsPerPage=6`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(12000) });
    if (!r.ok) return `cve_search "${q}": NVD lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    const v = d.vulnerabilities || [];
    if (!v.length) return `cve_search "${q}": no CVEs found.`;
    const rows = v.slice(0, 6).map(x => {
      const c = x.cve;
      const en = (c.descriptions || []).find(z => z.lang === 'en');
      let score = '?';
      try {
        const m = c.metrics || {};
        const cv = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
        if (cv && cv.cvssData) score = cv.cvssData.baseScore + (cv.cvssData.baseSeverity ? ' ' + cv.cvssData.baseSeverity : '');
      } catch {}
      return `${c.id} [CVSS ${score}] ${(en ? en.value : '').slice(0, 150)}`;
    });
    return `cve_search "${q}": ${d.totalResults} total — top ${rows.length}:\n` + rows.join('\n');
  } catch (e) { return `cve_search "${q}": failed (${e.message}).`; }
}

// Cloud-storage exposure — check S3 / GCS / Azure for a bucket by name. Contacts providers.
async function bucketFinder(name) {
  let n = String(name || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  n = n.split('.')[0];
  if (!n || !/^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$/.test(n)) return 'bucket_finder: a bucket/name keyword is required.';
  const targets = [
    ['S3', `https://${n}.s3.amazonaws.com`],
    ['GCS', `https://storage.googleapis.com/${n}`],
    ['Azure', `https://${n}.blob.core.windows.net/?comp=list`],
  ];
  const out = await Promise.all(targets.map(async ([label, url]) => {
    try {
      const r = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(8000) });
      let verdict;
      if (r.status === 200) verdict = 'PUBLIC (listable!)';
      else if (r.status === 403) verdict = 'exists, listing denied (private)';
      else if (r.status === 404) verdict = 'not found';
      else verdict = 'HTTP ' + r.status;
      return `${label.padEnd(6)} ${verdict}  ${url}`;
    } catch (e) { return `${label.padEnd(6)} error (${e.message})`; }
  }));
  return `bucket_finder "${n}" (cloud-storage exposure)\n` + out.join('\n') + '\nNote: PUBLIC listable buckets may leak data — investigate and lock down.';
}

// Likely email addresses from a name + domain (MX-checked, NOT existence-verified).
async function emailPermutations(input) {
  let s = String(input || '').trim();
  let dom = '';
  const m = s.match(/@?([a-z0-9.\-]+\.[a-z]{2,})\s*$/i);
  if (m) { dom = m[1].toLowerCase(); s = s.slice(0, m.index).trim(); }
  s = s.replace(/@.*/, '').trim();
  const parts = s.split(/\s+/).filter(Boolean);
  if (!parts.length || !dom) return 'email_permutations: provide a name and a domain, e.g. "John Doe acme.com".';
  const f = parts[0].toLowerCase().replace(/[^a-z]/g, '');
  const l = (parts[parts.length - 1] || '').toLowerCase().replace(/[^a-z]/g, '');
  const fi = f[0] || '', li = l[0] || '';
  const users = [...new Set([f, l, f + '.' + l, f + l, fi + l, f + li, fi + '.' + l, l + '.' + f, l + f, f + '_' + l, f + '-' + l].filter(x => x && x.length > 1))];
  let mx = 'UNKNOWN';
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${dom}&type=MX`, { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
    const j = await r.json(); const recs = (j.Answer || []).map(a => a.data);
    mx = recs.length ? recs.slice(0, 3).join(', ') : 'none (domain may not receive mail)';
  } catch { mx = 'lookup failed'; }
  return `email_permutations ${parts.join(' ')} @ ${dom}\nMX: ${mx}\ncandidate addresses (NOT verified to exist — cross-check before use):\n` + users.map(u => u + '@' + dom).join('\n');
}

// CORS misconfiguration check — does the endpoint reflect an arbitrary Origin?
async function corsCheck(url) {
  let u; try { u = new URL(/^https?:\/\//i.test(url) ? url : 'https://' + url); } catch { return 'cors_check: a URL is required.'; }
  if (isPrivateHost(u.hostname)) return `cors_check: ${u.hostname} is private/internal — blocked.`;
  const evil = 'https://evil.example.com';
  try {
    const r = await fetch(u.toString(), { headers: { 'Origin': evil, 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(9000) });
    const acao = r.headers.get('access-control-allow-origin') || '';
    const acac = r.headers.get('access-control-allow-credentials') || '';
    let verdict;
    if (acao === evil && /true/i.test(acac)) verdict = 'CRITICAL: reflects an arbitrary Origin WITH credentials — cross-origin data theft is possible.';
    else if (acao === evil) verdict = 'WARNING: reflects an arbitrary Origin (no credentials).';
    else if (acao === '*' && /true/i.test(acac)) verdict = 'MISCONFIG: wildcard ACAO with credentials.';
    else if (acao === '*') verdict = 'permissive: ACAO=* (fine for public APIs, not for private data).';
    else if (acao) verdict = `ACAO=${acao} (does not reflect our test origin — looks controlled).`;
    else verdict = 'no CORS headers (same-origin only).';
    return `cors_check ${u.hostname} (HTTP ${r.status})\nAccess-Control-Allow-Origin: ${acao || '(none)'}\nAccess-Control-Allow-Credentials: ${acac || '(none)'}\nverdict: ${verdict}`;
  } catch (e) { return `cors_check ${u.hostname}: failed (${e.message}).`; }
}

// Subdomain-takeover check — dangling CNAMEs to deprovisioned services (defensive).
async function subdomainTakeover(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!d || d.indexOf('.') < 0) return 'subdomain_takeover: a domain is required.';
  const SIGS = [
    { svc: 'GitHub Pages', cname: /github\.io$/, sig: /There isn't a GitHub Pages site here|For root URLs.*must be configured/i },
    { svc: 'Heroku', cname: /herokudns\.com$|herokuapp\.com$|herokussl\.com$/, sig: /No such app|there's nothing here/i },
    { svc: 'AWS S3', cname: /s3[.-][^.]*\.amazonaws\.com$|s3\.amazonaws\.com$/, sig: /NoSuchBucket|The specified bucket does not exist/i },
    { svc: 'Azure', cname: /azurewebsites\.net$|cloudapp\.net$|trafficmanager\.net$|azureedge\.net$/, sig: /404 Web Site not found|The resource you are looking for has been removed/i },
    { svc: 'Fastly', cname: /fastly\.net$/, sig: /Fastly error: unknown domain/i },
    { svc: 'Shopify', cname: /myshopify\.com$/, sig: /Sorry, this shop is currently unavailable/i },
    { svc: 'Surge', cname: /surge\.sh$/, sig: /project not found/i },
    { svc: 'Pantheon', cname: /pantheonsite\.io$/, sig: /The gods are wise|404 error unknown site/i },
    { svc: 'Tumblr', cname: /domains\.tumblr\.com$/, sig: /Whatever you were looking for doesn't currently exist/i },
    { svc: 'Readthedocs', cname: /readthedocs\.io$/, sig: /unknown to Read the Docs/i },
    { svc: 'Wordpress', cname: /wordpress\.com$/, sig: /Do you want to register/i },
    { svc: 'Ghost', cname: /ghost\.io$/, sig: /The thing you were looking for is no longer here/i },
  ];
  const candidates = ['www', 'blog', 'dev', 'staging', 'test', 'app', 'mail', 'shop', 'docs', 'status', 'cdn', 'assets', 'api', 'support', 'help', 'portal', 'beta', 'm', 'cname', 'go'].map(s => s + '.' + d);
  const cnameLookup = async (host) => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=CNAME`,
        { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
      const j = await r.json();
      return (j.Answer || []).filter(a => a.type === 5).map(a => String(a.data).replace(/\.$/, ''));
    } catch { return []; }
  };
  const findings = [];
  await Promise.all(candidates.map(async host => {
    const cns = await cnameLookup(host);
    for (const c of cns) {
      const m = SIGS.find(x => x.cname.test(c));
      if (!m) continue;
      let danger = false, note = `points to ${m.svc} (${c})`;
      try {
        const r = await fetch('https://' + host, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(8000) });
        const t = await r.text();
        if (m.sig.test(t)) { danger = true; note = `${m.svc} takeover signature present (HTTP ${r.status}) — claimable`; }
        else note = `${m.svc} (HTTP ${r.status}, no takeover signature)`;
      } catch (e) { danger = true; note = `${m.svc} CNAME but host unreachable (${e.message}) — likely dangling/claimable`; }
      findings.push(`${danger ? 'VULNERABLE' : 'note      '} ${host} -> ${c} [${note}]`);
    }
  }));
  if (!findings.length) return `subdomain_takeover ${d}: no dangling/known-service CNAMEs found among ${candidates.length} common subdomains. (Run crtsh_subs for a wider list.)`;
  return `subdomain_takeover ${d}:\n` + findings.join('\n');
}

// Fetch .onion content over clearnet via free tor2web gateways (no Tor/broker needed).
async function onionFetch(env, onionUrl) {
  let s = String(onionUrl || '').trim().replace(/^https?:\/\//i, '');
  const m = s.match(/^([a-z2-7]{16}\.onion|[a-z2-7]{56}\.onion)(\/.*)?$/i);
  if (!m) return 'onion_fetch: provide a .onion address (v2 16-char or v3 56-char), optionally with a path.';
  const host = m[1].toLowerCase(), path = m[2] || '/';
  if (env && env.TOOL_BROKER_URL) {
    try {
      const out = await runBrokerTool(env, { tool: 'onion_fetch', args: { url: host + path }, target: host, requestedAt: new Date().toISOString() });
      const txt = typeof out === 'string' ? out : (out && (out.result || ''));
      if (txt && /HTTP \d/.test(txt)) return txt + '\n(via Tor broker)';
    } catch (e) {}
  }
  const gateways = ['onion.ws', 'onion.ly', 'onion.pet', 'onion.moe', 'onion.re'];
  for (const gw of gateways) {
    try {
      const r = await fetch(`https://${host}.${gw}${path}`,
        { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, redirect: 'follow', signal: AbortSignal.timeout(9000) });
      if (r.ok) {
        const raw = await r.text();
        const body = raw.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
        if (body.length > 40) {
          const links = [...new Set((raw.match(/[a-z2-7]{16}\.onion|[a-z2-7]{56}\.onion/gi) || []).map(x => x.toLowerCase()))].filter(o => o !== host).slice(0, 12);
          const emails = [...new Set(raw.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g) || [])].slice(0, 8);
          const btc = [...new Set(raw.match(/\b(?:bc1[a-z0-9]{20,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b/g) || [])].slice(0, 6);
          let piv = '';
          if (links.length) piv += `\n\ndiscovered onion links (${links.length}):\n` + links.join('\n');
          if (emails.length) piv += `\n\nemails on page: ` + emails.join(', ');
          if (btc.length) piv += `\n\nBTC addresses on page: ` + btc.join(', ');
          return `onion_fetch ${host} (via ${gw}, HTTP ${r.status})\n\n${body.slice(0, 4500)}${piv}`;
        }
      }
    } catch (e) {}
  }
  return `onion_fetch ${host}: no free Tor gateway could reach it right now (public gateways are unreliable / often down).\nTo view it yourself: open http://${host}${path} in the Tor Browser, or try a gateway link: https://${host}.onion.ws${path}`;
}

// File-hash reputation — Team Cymru MHR (keyless, MD5/SHA1) + optional VT / MalwareBazaar.
async function hashLookup(env, h) {
  const x = String(h || '').trim().toLowerCase();
  if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(x)) return 'hash_lookup: provide an MD5, SHA-1, or SHA-256 file hash.';
  const kind = x.length === 32 ? 'MD5' : x.length === 40 ? 'SHA-1' : 'SHA-256';
  const out = [`hash_lookup ${x} (${kind})`];
  if (x.length !== 64) {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${x}.malware.hash.cymru.com&type=TXT`,
        { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(7000) });
      const j = await r.json();
      const ans = (j.Answer || []).map(a => String(a.data).replace(/^"|"$/g, ''));
      if (ans.length) {
        const parts = ans[0].split(/\s+/);
        const seen = new Date((+parts[0]) * 1000).toISOString().slice(0, 10);
        out.push(`Team Cymru MHR: KNOWN MALWARE — last seen ${seen}, ~${parts[1]}% AV detection`);
      } else out.push('Team Cymru MHR: not in registry (unknown or clean).');
    } catch (e) { out.push(`Team Cymru MHR: lookup failed (${e.message}).`); }
  } else out.push('Team Cymru MHR: SHA-256 unsupported there — provide MD5/SHA-1 for MHR.');
  const vt = String((env && env.VT_API_KEY) || '');
  if (vt) {
    try {
      const r = await fetch(`https://www.virustotal.com/api/v3/files/${x}`, { headers: { 'x-apikey': vt }, signal: AbortSignal.timeout(9000) });
      if (r.status === 404) out.push('VirusTotal: not found.');
      else if (r.ok) {
        const a = (await r.json()).data.attributes; const s = a.last_analysis_stats || {};
        const total = (s.malicious || 0) + (s.suspicious || 0) + (s.undetected || 0) + (s.harmless || 0);
        out.push(`VirusTotal: ${s.malicious || 0}/${total} malicious | type: ${a.type_description || '?'} | names: ${(a.names || []).slice(0, 3).join(', ')}` +
          (a.popular_threat_classification ? `\nthreat label: ${a.popular_threat_classification.suggested_threat_label}` : ''));
      } else out.push(`VirusTotal: HTTP ${r.status}.`);
    } catch (e) { out.push(`VirusTotal: ${e.message}`); }
  } else out.push('VirusTotal: skipped (set VT_API_KEY for detections + threat label).');
  const mb = String((env && env.MALWAREBAZAAR_API_KEY) || '');
  if (mb) {
    try {
      const r = await fetch('https://mb-api.abuse.ch/api/v1/', { method: 'POST', headers: { 'Auth-Key': mb, 'Content-Type': 'application/x-www-form-urlencoded' }, body: `query=get_info&hash=${x}`, signal: AbortSignal.timeout(9000) });
      if (r.ok) { const d = await r.json(); if (d.query_status === 'ok' && d.data && d.data[0]) { const m = d.data[0]; out.push(`MalwareBazaar: ${m.signature || 'unknown family'} | ${m.file_type || ''} | tags: ${(m.tags || []).join(', ')}`); } else out.push('MalwareBazaar: not found.'); }
    } catch (e) { out.push(`MalwareBazaar: ${e.message}`); }
  }
  return out.join('\n');
}

// Static triage of a sample fetched by URL — type, hashes, strings, IOCs, suspicious APIs.
async function fileAnalyze(url) {
  let u; try { u = new URL(url); } catch { return 'file_analyze: a direct file URL is required.'; }
  if (isPrivateHost(u.hostname)) return `file_analyze: ${u.hostname} is private/internal — blocked.`;
  try {
    const r = await fetch(u.toString(), { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, redirect: 'follow', signal: AbortSignal.timeout(15000) });
    if (!r.ok) return `file_analyze ${u.hostname}: fetch failed (HTTP ${r.status}).`;
    let bytes = new Uint8Array(await r.arrayBuffer());
    const size = bytes.length;
    if (size > 3145728) bytes = bytes.slice(0, 3145728);
    const sha256 = await sha256hexBytes(bytes);
    const sha1 = [...new Uint8Array(await crypto.subtle.digest('SHA-1', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
    const hex = n => [...bytes.slice(0, n)].map(b => b.toString(16).padStart(2, '0')).join('');
    let ftype = 'unknown / data';
    if (bytes[0] === 0x4D && bytes[1] === 0x5A) ftype = 'PE/DOS executable (MZ)';
    else if (hex(4) === '7f454c46') ftype = 'ELF executable';
    else if (['cafebabe', 'feedface', 'feedfacf', 'cffaedfe'].includes(hex(4))) ftype = 'Mach-O executable';
    else if (hex(4) === '25504446') ftype = 'PDF document';
    else if (hex(8) === 'd0cf11e0a1b11ae1') ftype = 'OLE / legacy Office (DOC/XLS/PPT)';
    else if (bytes[0] === 0x50 && bytes[1] === 0x4B) ftype = 'ZIP / OOXML Office (DOCX/XLSX/JAR/APK)';
    else if (hex(4) === '4d534346') ftype = 'Microsoft Cabinet (CAB)';
    let cur = '', strings = [];
    for (let i = 0; i < bytes.length; i++) { const c = bytes[i]; if (c >= 32 && c < 127) cur += String.fromCharCode(c); else { if (cur.length >= 5) strings.push(cur); cur = ''; } }
    if (cur.length >= 5) strings.push(cur);
    const blob = strings.join('\n'); const low = blob.toLowerCase();
    const urls = [...new Set(blob.match(/https?:\/\/[^\s"'<>]{6,200}/g) || [])].slice(0, 12);
    const ips = [...new Set(blob.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])].slice(0, 12);
    const SUS = ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'LoadLibrary', 'GetProcAddress', 'WinExec', 'ShellExecute', 'URLDownloadToFile', 'RegSetValue', 'CryptEncrypt', 'powershell', 'cmd.exe', 'rundll32', 'schtasks', 'WScript.Shell', 'FromBase64String', 'Invoke-Expression', 'mimikatz', 'VirtualProtect', 'SetWindowsHookEx', 'IsDebuggerPresent', 'bcdedit', 'vssadmin', 'wbadmin'];
    const flags = SUS.filter(k => low.indexOf(k.toLowerCase()) >= 0);
    const notable = strings.filter(t => t.length >= 8 && t.length <= 120).slice(0, 25);
    let out = `file_analyze ${u.hostname}\nsize: ${size} bytes | type: ${ftype}\nsha256: ${sha256}\nsha1: ${sha1}`;
    if (flags.length) out += `\nsuspicious indicators (${flags.length}): ${flags.join(', ')}`;
    if (urls.length) out += `\nembedded URLs:\n${urls.join('\n')}`;
    if (ips.length) out += `\nembedded IPs: ${ips.join(', ')}`;
    if (notable.length) out += `\nnotable strings:\n${notable.join('\n')}`;
    out += `\n\n(Run hash_lookup ${sha1} for reputation; for deep RE — yara/capa/radare2 — set TOOL_BROKER_URL.)`;
    return out;
  } catch (e) { return `file_analyze ${u.hostname}: failed (${e.message}).`; }
}

// Recursive multi-layer decoder (CyberChef-style): url / base64 / hex / gzip + refang.
function gsPrintableRatio(s) {
  if (!s) return 0;
  let p = 0;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) p++; }
  return p / s.length;
}
function gsBytesToStr(b) { let o = ''; for (let i = 0; i < b.length; i++) o += String.fromCharCode(b[i]); return o; }
function gsStrToBytes(s) { const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff; return b; }
async function gsGunzip(bytes, fmt) {
  try {
    const ds = new DecompressionStream(fmt || 'gzip');
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    const ab = await new Response(stream).arrayBuffer();
    return new Uint8Array(ab);
  } catch (e) { return null; }
}
async function decodeOne(s) {
  if (/%[0-9a-fA-F]{2}/.test(s)) { try { const u = decodeURIComponent(s); if (u !== s) return { label: 'url', value: u }; } catch (e) {} }
  const compact = s.replace(/\s+/g, '');
  if (/^[A-Za-z0-9+/=]{16,}$/.test(compact) && compact.length % 4 === 0) {
    try {
      const bin = atob(compact); const bytes = gsStrToBytes(bin);
      if (bytes[0] === 0x1f && bytes[1] === 0x8b) { const g = await gsGunzip(bytes, 'gzip'); if (g) return { label: 'base64+gzip', value: gsBytesToStr(g) }; }
      if (bytes[0] === 0x78) { const g = await gsGunzip(bytes, 'deflate'); if (g) return { label: 'base64+zlib', value: gsBytesToStr(g) }; }
      if (gsPrintableRatio(bin) > 0.75) return { label: 'base64', value: bin };
    } catch (e) {}
  }
  if (/^[0-9a-fA-F]{16,}$/.test(compact) && compact.length % 2 === 0) {
    try {
      const bytes = new Uint8Array(compact.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(compact.substr(i * 2, 2), 16);
      if (bytes[0] === 0x1f && bytes[1] === 0x8b) { const g = await gsGunzip(bytes, 'gzip'); if (g) return { label: 'hex+gzip', value: gsBytesToStr(g) }; }
      const str = gsBytesToStr(bytes); if (gsPrintableRatio(str) > 0.75) return { label: 'hex', value: str };
    } catch (e) {}
  }
  return null;
}
async function decodeTool(input) {
  let s = String(input || '').trim();
  if (!s) return 'decode: paste an encoded/obfuscated string (url / base64 / hex / gzip — multi-layer).';
  const refanged = s.replace(/\[:?\/\/\]/g, '://').replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.').replace(/\[:\]/g, ':').replace(/hxxp/gi, 'http');
  const chain = [];
  let cur = refanged, layers = 0;
  if (refanged !== s) chain.push('refang -> ' + refanged.slice(0, 200));
  while (layers < 8) {
    const step = await decodeOne(cur);
    if (!step) break;
    chain.push('[' + (layers + 1) + '] ' + step.label + ' -> ' + step.value.slice(0, 400));
    cur = step.value; layers++;
  }
  if (!chain.length) return 'decode: no confident decoding (tried url / base64 / hex / gzip, multi-layer). May be plaintext or an unsupported codec.';
  const iocs = [...new Set(cur.match(/https?:\/\/[^\s"'<>]{6,200}|\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])].slice(0, 12);
  return 'decode (' + layers + ' layer' + (layers === 1 ? '' : 's') + ')\n' + chain.join('\n') + (iocs.length ? '\n\nIOCs in final output:\n' + iocs.join('\n') : '');
}

// Extract + defang IOCs from arbitrary text (logs, emails, reports).
function iocExtract(text) {
  const raw = String(text || '');
  if (!raw.trim()) return 'ioc_extract: paste text (logs, email, report) to pull IOCs from.';
  const t = raw.replace(/\[:?\/\/\]/g, '://').replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.').replace(/\[:\]/g, ':').replace(/hxxp/gi, 'http');
  const uniq = a => [...new Set(a)];
  const urls = uniq(t.match(/https?:\/\/[^\s"'<>\])]{4,}/gi) || []);
  const ipv4 = uniq((t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(ip => ip.split('.').every(o => +o <= 255)));
  const emails = uniq(t.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g) || []);
  const domains = uniq((t.match(/\b(?:[a-z0-9\-]+\.)+[a-z]{2,18}\b/gi) || []).map(d => d.toLowerCase())
    .filter(d => !/\.(png|jpe?g|gif|svg|js|css|html?|php|aspx?|exe|dll|txt|md|json|xml|zip)$/.test(d)));
  const md5 = uniq((t.match(/\b[a-f0-9]{32}\b/gi) || []).map(x => x.toLowerCase()));
  const sha1 = uniq((t.match(/\b[a-f0-9]{40}\b/gi) || []).map(x => x.toLowerCase()));
  const sha256 = uniq((t.match(/\b[a-f0-9]{64}\b/gi) || []).map(x => x.toLowerCase()));
  const cves = uniq((t.match(/CVE-\d{4}-\d+/gi) || []).map(c => c.toUpperCase()));
  const btc = uniq(t.match(/\b(?:bc1[a-z0-9]{20,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b/g) || []);
  const eth = uniq(t.match(/\b0x[a-f0-9]{40}\b/gi) || []);
  const defang = s => s.replace(/^http/i, 'hxxp').replace(/:\/\//g, '[://]').replace(/\./g, '[.]');
  const sections = [];
  const add = (label, arr, df) => { if (arr.length) sections.push(`${label} (${arr.length}):\n` + arr.slice(0, 50).map(x => df ? defang(x) : x).join('\n')); };
  add('URLs', urls, true); add('IPv4', ipv4, true); add('Domains', domains, true); add('Emails', emails, true);
  add('MD5', md5, false); add('SHA1', sha1, false); add('SHA256', sha256, false);
  add('CVEs', cves, false); add('BTC addresses', btc, false); add('ETH addresses', eth, false);
  if (!sections.length) return 'ioc_extract: no IOCs found in the provided text.';
  return 'ioc_extract — IOCs (defanged where applicable; safe to share):\n\n' + sections.join('\n\n');
}

// CVSS v3.1 base-score calculator from a vector string.
function cvssCalc(vector) {
  const v = String(vector || '').trim().toUpperCase();
  if (!/AV:[NALP]/.test(v)) return 'cvss: provide a CVSS v3.x vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  const m = {}; v.split('/').forEach(p => { const kv = p.split(':'); if (kv.length === 2) m[kv[0]] = kv[1]; });
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const scope = m.S;
  const PR = (scope === 'C' ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[m.PR];
  const imp = { H: 0.56, L: 0.22, N: 0 };
  const C = imp[m.C], I = imp[m.I], A = imp[m.A];
  if ([AV, AC, PR, UI, C, I, A].some(x => x === undefined)) return 'cvss: incomplete/invalid vector (need AV,AC,PR,UI,S,C,I,A).';
  const isc = 1 - ((1 - C) * (1 - I) * (1 - A));
  const impact = scope === 'C' ? 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc - 0.02, 15) : 6.42 * isc;
  const expl = 8.22 * AV * AC * PR * UI;
  let base;
  if (impact <= 0) base = 0;
  else if (scope === 'C') base = Math.min(1.08 * (impact + expl), 10);
  else base = Math.min(impact + expl, 10);
  base = Math.ceil(base * 10) / 10;
  const sev = base === 0 ? 'None' : base < 4 ? 'Low' : base < 7 ? 'Medium' : base < 9 ? 'High' : 'Critical';
  return `cvss ${v}\nbase score: ${base.toFixed(1)} (${sev})\nimpact sub-score: ${impact.toFixed(2)} | exploitability: ${expl.toFixed(2)}`;
}

// Trace a shortened/redirecting URL to its real destination (phishing analysis).
async function unshorten(url) {
  let u; try { u = new URL(/^https?:\/\//i.test(url) ? url : 'https://' + url); } catch { return 'unshorten: a URL is required.'; }
  if (isPrivateHost(u.hostname)) return `unshorten: ${u.hostname} is private/internal — blocked.`;
  const chain = [u.toString()]; let cur = u.toString(), hops = 0;
  try {
    while (hops < 10) {
      const r = await fetch(cur, { method: 'GET', redirect: 'manual', headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, signal: AbortSignal.timeout(9000) });
      const loc = r.headers.get('location');
      if (r.status >= 300 && r.status < 400 && loc) {
        const next = new URL(loc, cur).toString();
        chain.push(`-> [${r.status}] ${next}`);
        if (isPrivateHost(new URL(next).hostname)) { chain.push('(redirects to a private host — stopped)'); cur = next; break; }
        cur = next; hops++;
      } else { chain.push(`(final: HTTP ${r.status})`); break; }
    }
    if (hops >= 10) chain.push('(stopped: too many redirects)');
  } catch (e) { chain.push(`(error: ${e.message})`); }
  return `unshorten (${hops} redirect${hops === 1 ? '' : 's'})\n` + chain.join('\n') + `\nfinal destination: ${cur}`;
}

// Infostealer / stealer-log exposure — HudsonRock Cavalier (free, keyless). The modern dark-web dump data.
// Unified exposure search — ONE selector fanned across every keyless breach/stealer/
// leak/paste source, merged into a verdict + exposure timeline + cross-source pivots.
// Uses defender-oriented exposure APIs only; never hosts/returns raw stolen dumps.
async function exposureSearch(env, selector) {
  const t = String(selector || '').trim();
  if (!t) return 'exposure_search: a selector (email, username, or domain) is required.';
  const isEmail = /@/.test(t);
  const jobs = [
    ['HudsonRock infostealer logs', stealerCheck(t)],
    ['LeakCheck (public)', leakCheck(t)],
    ['Paste / forum mentions', pasteSearch(t)],
  ];
  if (isEmail) {
    jobs.push(['Breach databases (XposedOrNot/HIBP)', breachCheck(env, t)]);
    jobs.push(['Gravatar profile', gravatarLookup(t)]);
  }
  const settled = await Promise.all(jobs.map(async ([label, p]) => {
    try { return [label, String(await p)]; } catch (e) { return [label, '(' + e.message + ')']; }
  }));
  const combined = settled.map(([l, v]) => `### ${l}\n${v}`).join('\n\n');
  const uq = a => [...new Set(a)];
  let hits = 0;
  if (/comput(er|ers)\b|infected|stealer (log|infection)/i.test(combined) && !/no .*(stealer|infection|comput)/i.test(combined)) hits++;
  const lcm = combined.match(/(\d+)\s+(?:results?|breach(?:es)?|record|source)/i); if (lcm && +lcm[1] > 0) hits++;
  if (/exposed in \d+ breach|breaches:\s*[1-9]|\bpwned\b/i.test(combined)) hits++;
  if (/(onion site\(s\) referencing|paste|leaked)/i.test(combined) && !/no (indexed|paste|result)/i.test(combined)) hits++;
  const verdict = hits >= 2 ? 'EXPOSED (corroborated by multiple sources)' : (hits === 1 ? 'LIKELY EXPOSED (single source)' : 'NO PUBLIC EXPOSURE FOUND in keyless sources (NOT exhaustive — absence is not proof of safety)');
  const dates = uq(combined.match(/\b(?:20)\d{2}(?:-\d{2}(?:-\d{2})?)?\b/g) || []).filter(d => { const y = +d.slice(0, 4); return y >= 2007 && y <= 2026; }).sort();
  const tl = t.toLowerCase();
  const pEmails = uq((combined.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g) || []).map(x => x.toLowerCase())).filter(e => e !== tl && !/noreply|@example\.|@hudsonrock|@leakcheck/.test(e)).slice(0, 8);
  const pDomains = uq((combined.match(/\b(?:[a-z0-9\-]+\.)+[a-z]{2,}\b/ig) || []).map(x => x.toLowerCase())).filter(d => d !== tl && !/hudsonrock|leakcheck|xposedornot|gravatar|garrettstimpson|w3\.org|example\./.test(d) && !pEmails.some(e => e.endsWith('@' + d))).slice(0, 8);
  const classes = ['password', 'email', 'username', 'phone', 'ip address', 'full name', 'address', 'date of birth', 'hash'].filter(c => new RegExp(c.replace(' ', '\\s*'), 'i').test(combined));
  const out = [`exposure_search "${t}" — unified breach/darknet exposure (aggregated, defender APIs only)`, `VERDICT: ${verdict}`];
  if (classes.length) out.push(`data classes seen: ${classes.join(', ')}`);
  if (dates.length) out.push(`exposure timeline: ${dates.join(' -> ')}`);
  if (pEmails.length || pDomains.length) out.push(`cross-source PIVOTS (run exposure_search on these next): ${[].concat(pEmails, pDomains).join(', ')}`);
  out.push('', combined, '\nNOTE: aggregated from defender-oriented keyless sources (HudsonRock, LeakCheck public, XposedOrNot, paste). Not exhaustive vs. a paid breach DB; this tool reports WHETHER/WHERE a selector is exposed, never raw stolen credentials. Rotate any exposed secrets.');
  return out.join('\n');
}

async function stealerCheck(target) {
  const t = String(target || '').trim();
  if (!t) return 'stealer_check: an email, username, or domain is required.';
  let ep;
  if (/@/.test(t)) ep = 'search-by-email?email=';
  else if (t.indexOf('.') > 0 && !/\s/.test(t)) ep = 'search-by-domain?domain=';
  else ep = 'search-by-username?username=';
  try {
    const r = await fetch(`https://cavalier.hudsonrock.com/api/json/v2/osint-tools/${ep}${encodeURIComponent(t)}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(12000) });
    if (!r.ok) return `stealer_check ${t}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    const st = d.stealers || [];
    const exposed = st.length > 0 || +d.total > 0 || +d.employees > 0 || +d.users > 0 || +d.total_user_services > 0 || +d.total_corporate_services > 0 || +d.third_parties > 0;
    if (!exposed) return `stealer_check ${t}: NOT found in HudsonRock infostealer datasets (no known stealer-log exposure).`;
    let out = `stealer_check ${t} (HudsonRock — infostealer / stealer-logs)\nEXPOSED in stealer-log data.`;
    if (st.length) {
      out += '\n' + st.slice(0, 6).map(s =>
        `- compromised ${(s.date_compromised || '?').slice(0, 10)} | OS: ${s.operating_system || '?'} | host: ${s.computer_name || '?'} | corp creds: ${s.total_corporate_services != null ? s.total_corporate_services : '?'} | user creds: ${s.total_user_services != null ? s.total_user_services : '?'}`).join('\n');
    }
    const agg = [];
    ['total', 'employees', 'users', 'third_parties', 'total_stealers', 'total_corporate_services', 'total_user_services'].forEach(k => { if (d[k] != null) agg.push(`${k}: ${d[k]}`); });
    if (agg.length) out += '\n' + agg.join(' | ');
    return out;
  } catch (e) { return `stealer_check ${t}: lookup failed (${e.message}).`; }
}

// Public breach index — LeakCheck (keyless public endpoint): record count + exposed field types.
async function leakCheck(target) {
  const t = String(target || '').trim();
  if (!t) return 'leakcheck: an email or username is required.';
  try {
    const r = await fetch(`https://leakcheck.io/api/public?check=${encodeURIComponent(t)}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return `leakcheck ${t}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    if (!d.success) return `leakcheck ${t}: ${d.error || 'no result'}.`;
    if (!d.found) return `leakcheck ${t}: not found in the public breach index.`;
    const fields = (d.fields || []).join(', ');
    const srcs = (d.sources || []).slice(0, 8).map(s => (s.name || '?') + (s.date ? ' (' + s.date + ')' : ''));
    return `leakcheck ${t}: FOUND in ${d.found} breach record(s)\nexposed data types: ${fields || '?'}` + (srcs.length ? '\nsources:\n' + srcs.join('\n') : '');
  } catch (e) { return `leakcheck ${t}: lookup failed (${e.message}).`; }
}

// Public paste-dump search — psbdmp (best-effort, keyless).
async function pasteSearch(term) {
  const t = String(term || '').trim();
  if (!t) return 'paste_search: a term (email / domain / keyword) is required.';
  try {
    const r = await fetch('https://psbdmp.ws/api/v3/search/' + encodeURIComponent(t),
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0', 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return `paste_search ${t}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    const data = d.data || [];
    if (!data.length) return `paste_search ${t}: no public paste dumps found referencing the term.`;
    const rows = data.slice(0, 12).map(p => 'https://psbdmp.ws/' + (p.id || p) + (p.time ? '  (' + p.time + ')' : ''));
    return `paste_search ${t}: ${data.length} paste(s) reference the term\n${rows.join('\n')}`;
  } catch (e) { return `paste_search ${t}: lookup failed (${e.message}).`; }
}

// Google-dork generator + runner for a domain / email / name (recon).
async function dorkTool(env, target) {
  const t = String(target || '').trim();
  if (!t) return 'dork: a domain, email, or name is required.';
  let dorks;
  if (/@/.test(t)) {
    dorks = [`"${t}"`, `"${t}" (password OR leak OR dump)`, `site:pastebin.com "${t}"`, `site:github.com "${t}"`];
  } else if (/\./.test(t) && !/\s/.test(t)) {
    const d = t.replace(/^https?:\/\//, '').split('/')[0];
    dorks = [`site:${d} (confidential OR internal OR password)`, `site:pastebin.com ${d}`, `"${d}" (leak OR breach OR dump)`, `intext:"@${d}" (password OR login)`, `site:${d} ext:pdf OR ext:xls OR ext:doc`];
  } else {
    dorks = [`"${t}"`, `"${t}" (linkedin OR github OR twitter)`, `"${t}" (email OR contact OR profile)`];
  }
  const out = [`dork "${t}" — generated dorks (open in a search engine):`];
  dorks.forEach(dk => out.push('https://www.google.com/search?q=' + encodeURIComponent(dk)));
  out.push('\nlive results for the top dorks:');
  for (let i = 0; i < Math.min(2, dorks.length); i++) {
    try { const s = await webSearch(dorks[i], (env && env.BRAVE_API_KEY) || '', env); out.push(`\n# ${dorks[i]}\n` + (s ? formatSearch(s).slice(0, 1200) : '(no results)')); }
    catch (e) { out.push(`\n# ${dorks[i]}: ${e.message}`); }
  }
  return out.join('\n');
}

// Composite phishing analyzer — domain age + URLhaus + lure keywords + login form + redirects.
async function phishCheck(url) {
  let u; try { u = new URL(/^https?:\/\//i.test(url) ? url : 'https://' + url); } catch { return 'phish_check: a URL is required.'; }
  if (isPrivateHost(u.hostname)) return `phish_check: ${u.hostname} is private/internal — blocked.`;
  const host = u.hostname.toLowerCase();
  let score = 0; const signals = [];
  if (/xn--/.test(host)) { score += 22; signals.push('punycode/IDN domain (homoglyph spoofing risk)'); }
  if ((host.match(/-/g) || []).length >= 3) { score += 8; signals.push('many hyphens in hostname'); }
  if (/\d{4,}/.test(host)) { score += 5; signals.push('long digit run in hostname'); }
  const brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'bank', 'secure', 'login', 'signin', 'verify', 'update', 'account', 'wallet', 'coinbase', 'metamask', 'support'];
  const hit = brands.filter(b => host.includes(b));
  if (hit.length) { score += 12; signals.push('brand/lure keywords in host: ' + hit.join(', ')); }
  try {
    const reg = host.split('.').slice(-2).join('.');
    const rd = await domainLookup(reg);
    const m = String(rd).match(/(\d{4}-\d{2}-\d{2})/);
    if (m) { const days = (Date.now() - Date.parse(m[1])) / 86400000; if (days >= 0 && days < 90) { score += 25; signals.push(`registration date ${m[1]} (~${Math.round(days)} days old — very new)`); } }
  } catch (e) {}
  try {
    const uh = await urlhausLookup(null, host);
    if (/malware|blacklist|listed/i.test(uh) && !/no results|not (found|listed)|0 /i.test(uh)) { score += 30; signals.push('URLhaus: host associated with malware URLs'); }
  } catch (e) {}
  try {
    const r = await fetch(u.toString(), { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, redirect: 'follow', signal: AbortSignal.timeout(10000) });
    const html = await r.text();
    if (/<input[^>]+type=["']?password/i.test(html)) { score += 10; signals.push('page contains a password / login form'); }
    try { const fin = new URL(r.url).hostname.toLowerCase(); if (fin && fin !== host) { score += 8; signals.push('redirects to a different host: ' + fin); } } catch (e) {}
  } catch (e) { signals.push('page fetch failed: ' + e.message); }
  score = Math.min(100, score);
  const verdict = score >= 60 ? 'HIGH likelihood of phishing' : score >= 30 ? 'SUSPICIOUS' : score > 0 ? 'low-risk signals present' : 'no obvious phishing signals';
  return `phish_check ${host}\nverdict: ${verdict} (${score}/100)\n` + (signals.length ? signals.map(s => '- ' + s).join('\n') : '- none');
}

// Wayback historical URLs (CDX) — surfaces forgotten endpoints/paths.
async function archiveUrls(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!d) return 'archive_urls: a domain is required.';
  try {
    const r = await fetch(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(d)}*&output=json&collapse=urlkey&limit=80&filter=statuscode:200`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(15000) });
    if (!r.ok) return `archive_urls ${d}: lookup failed (HTTP ${r.status}).`;
    const rows = await r.json();
    if (Array.isArray(rows) && rows.length) rows.shift();
    const paths = [...new Set((rows || []).map(x => x[2]).filter(Boolean))].slice(0, 45);
    if (!paths.length) return `archive_urls ${d}: no archived URLs found (or archive.org unreachable from here).`;
    return `archive_urls ${d}: ${paths.length} archived URLs (historical endpoints — check for forgotten admin/API paths)\n` + paths.join('\n');
  } catch (e) { return `archive_urls ${d}: failed (${e.message}).`; }
}

// MurmurHash3 x86 32-bit (signed) — for Shodan/FOFA favicon-hash pivoting.
function mmh3_32(key) {
  const data = []; for (let i = 0; i < key.length; i++) data.push(key.charCodeAt(i) & 0xff);
  const c1 = 0xcc9e2d51, c2 = 0x1b873593, len = data.length; let h1 = 0;
  const rl = len & ~3;
  for (let i = 0; i < rl; i += 4) {
    let k1 = (data[i]) | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);
    k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2);
    h1 ^= k1; h1 = (h1 << 13) | (h1 >>> 19); h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }
  let k1 = 0;
  switch (len & 3) {
    case 3: k1 ^= data[rl + 2] << 16;
    case 2: k1 ^= data[rl + 1] << 8;
    case 1: k1 ^= data[rl]; k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2); h1 ^= k1;
  }
  h1 ^= len; h1 ^= h1 >>> 16; h1 = Math.imul(h1, 0x85ebca6b); h1 ^= h1 >>> 13; h1 = Math.imul(h1, 0xc2b2ae35); h1 ^= h1 >>> 16;
  return h1 | 0;
}
function b64encodeNL(bytes) {
  let bin = ''; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b = btoa(bin); let out = '';
  for (let i = 0; i < b.length; i += 76) out += b.slice(i, i + 76) + '\n';
  return out;
}
// Favicon hash (Shodan/FOFA pivot) — find other servers sharing a site's favicon.
async function faviconHash(url) {
  let u; try { u = new URL(/^https?:\/\//i.test(url) ? url : 'https://' + url); } catch { return 'favicon_hash: a URL or domain is required.'; }
  if (isPrivateHost(u.hostname)) return `favicon_hash: ${u.hostname} is private/internal — blocked.`;
  const favUrl = /favicon/i.test(u.pathname) ? u.toString() : u.origin + '/favicon.ico';
  try {
    const r = await fetch(favUrl, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(9000) });
    if (!r.ok) return `favicon_hash ${u.hostname}: no favicon at /favicon.ico (HTTP ${r.status}).`;
    const bytes = new Uint8Array(await r.arrayBuffer());
    if (!bytes.length) return `favicon_hash ${u.hostname}: empty favicon.`;
    const hash = mmh3_32(b64encodeNL(bytes));
    return `favicon_hash ${u.hostname}\nShodan favicon hash: ${hash}\npivot — find servers with the SAME favicon (related/phishing infra):\nShodan: https://www.shodan.io/search?query=http.favicon.hash%3A${hash}\nFOFA: https://fofa.info/result?qbase64=${encodeURIComponent(btoa('icon_hash="' + hash + '"'))}`;
  } catch (e) { return `favicon_hash ${u.hostname}: failed (${e.message}).`; }
}

// Agentic tool router — the model decides which ONE tool (if any) the request needs.
async function toolRouter(env, userMsg, already, contextSoFar) {
  // ── Deterministic gate (code, not few-shot examples) ──────────────────────
  // A tool only makes sense when the message contains a concrete ARTIFACT to act on.
  // Detecting that in code is reliable and example-free; it also kills the failure
  // where a conversational follow-up ('show me an example') routes to a random tool.
  const msg = String(userMsg || '');
  const ARTIFACT = [
    /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/,                 // email
    /\bCVE-\d{4}-\d{3,}\b/i,                                            // cve
    /\bCVSS:[0-9.]+\/[A-Z:\/]+/i,                                        // cvss vector
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/,                                     // ipv4
    /\bhttps?:\/\/[^\s]+/i,                                             // url
    /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/i,            // hash
    /\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b/i,               // onion
    /\b(?:bc1[a-z0-9]{20,}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b/, // crypto
    /\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|dev|ca|co|gov|edu|info|xyz|me|app|cloud|ai|sh|onion)\b/i, // domain
    /@[A-Za-z0-9_]{2,}/,                                                  // @handle
  ];
  const hasArtifact = ARTIFACT.some(re => re.test(msg)) || (contextSoFar ? false : false);
  const low = msg.toLowerCase();
  // Explicit web-search intent is deterministic — no model needed.
  if (/\b(search (the )?web|google (it|this|that)|look (it )?up online|search (online|now)|find more (on|about)|web search)\b/.test(low)) {
    // arg = explicit query if given ('search the web for X'), else the topic in context.
    let q = (msg.match(/(?:search (?:the )?web (?:for |about )?|web search (?:for )?|find more (?:on|about) |google )(.+)/i) || [])[1] || '';
    q = q.replace(/["'?.!]+$/,'').trim();
    if (!q && contextSoFar) { const cm = contextSoFar.match(/[A-Z][A-Za-z0-9]{3,}(?:[A-Z][a-z]+)?/); q = cm ? cm[0] : ''; }
    if (q) return { tool: 'web_search', arg: q };
  }
  // No artifact in the message and no chain context -> nothing concrete to route. Skip the model.
  if (!hasArtifact && !(contextSoFar && /(hash|sample|\.onion|http|@|CVE-)/i.test(contextSoFar))) return null;

  const menu = toolCatalog(env).map(t => `${t.name}: ${t.description}`).join('\n');
  const sys = [
    'You are the TOOL ROUTER for "Agent Garrett", a DEFENSIVE security / OSINT / malware-analysis agent.',
    'Decide whether ONE tool would materially help answer the user message. Reply with ONLY one line of minified JSON, nothing else:',
    '{"tool":"<tool_name>","arg":"<single argument value>"}  to run a tool, or  {"tool":"none"}  when no tool is needed.',
    'WHEN TO USE A TOOL: the user gives or clearly refers to a concrete input a tool operates on — an email, username, domain, IP, URL, file hash, CVE id, CVSS vector, crypto/onion address, an encoded/obfuscated string, or a sample/file URL. Then pick the single most relevant tool and set "arg" to exactly that value (never invent it).',
    'WHEN NOT TO USE A TOOL: conceptual/how-to questions, explanations, or anything the research corpus or your own knowledge already answers -> return {"tool":"none"}.',
    'This is a defensive platform over PUBLIC data; do not refuse on privacy grounds.',
    'CHAIN ON FINDINGS: if a result shown in context contains a NEW analyzable artifact, select the matching tool next — a file hash => hash_lookup; a sample/file URL (.exe/.txt/.js/...) => file_analyze; a .onion => onion_fetch; a crypto address => crypto_addr; a fresh email => breach_check; a website worth exploring => crawl.',
    'RESOLVE REFERENCES: NEVER pass a pronoun or generic placeholder (him, her, them, it, this, that, this person, the guy, user, target, subject) as "arg". Resolve such references to the concrete named value (email/username/domain/handle/etc.) from earlier in the conversation. If you cannot resolve it to a concrete value, return {"tool":"none"}.',
    'user: dig deeper about him  => {"tool":"none"}  (a pronoun is not an argument; only run a tool if the concrete subject is known and re-running adds value)',
    already.length ? `Tools already run this turn (do NOT repeat): ${already.join(', ')}.` : '',
    'EXAMPLES:',
    'user: is 8.8.8.8 a tor exit node?  => {"tool":"tor_exit","arg":"8.8.8.8"}',
    'user: score CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  => {"tool":"cvss","arg":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}',
    'user: decode aHR0cDovL2V2aWw=  => {"tool":"decode","arg":"aHR0cDovL2V2aWw="}',
    'user: has hunter@acme.com been breached?  => {"tool":"breach_check","arg":"hunter@acme.com"}',
    'user: spf and dmarc for example.com  => {"tool":"email_security","arg":"example.com"}',
    'user: is paypa1-login.com a phishing site?  => {"tool":"phish_check","arg":"paypa1-login.com"}',
    'user: reputation of hash 44d88612fea8a8f36de82e1278abb02f  => {"tool":"hash_lookup","arg":"44d88612fea8a8f36de82e1278abb02f"}',
    'user: who is behind the handle malgorithms? / verify their accounts  => {"tool":"keybase","arg":"malgorithms"}',
    'user: find background / relatives / public records on Jane Doe  => {"tool":"people_search","arg":"Jane Doe"}',
    'user: whose phone number is +14165551234?  => {"tool":"phone_osint","arg":"+14165551234"}',
    'user: is John Smith named in any SEC filings?  => {"tool":"edgar","arg":"John Smith"}',
    'user: what sites is bob@acme.com registered on?  => {"tool":"holehe","arg":"bob@acme.com"}',
    'user: what has leaked about bob@acme.com? / is this account exposed in breaches?  => {"tool":"exposure_search","arg":"bob@acme.com"}',
    'user: dev.to profile for garrettstimpson  => {"tool":"devto_user","arg":"garrettstimpson"}',
    'user: what is a heap overflow?  => {"tool":"none"}',
    'user: thanks, that helps  => {"tool":"none"}',
    'TOOLS (name: when to use):\n' + menu,
  ].filter(Boolean).join('\n');
  const u = contextSoFar ? `${userMsg}\n\n[results gathered so far — decide if a FURTHER tool is needed, else "none"]\n${contextSoFar.slice(0, 1200)}` : userMsg;
  try {
    const r = await env.AI.run(MODEL, { messages: [{ role: 'system', content: sys }, { role: 'user', content: u }], stream: false, max_tokens: 120, temperature: 0 });
    const txt = (r.response || '').trim();
    const m = txt.match(/\{[^{}]*\}/);
    if (!m) return null;
    const o = JSON.parse(m[0]);
    if (!o.tool || String(o.tool).toLowerCase() === 'none') return null;
    const arg = String(o.arg || o.argument || o.value || '').trim();
    const PRON = new Set(['him','her','them','it','they','he','she','his','hers','their','theirs','this','that','these','those','someone','somebody','anyone','anybody','everyone','person','people','the person','this person','that person','the guy','this guy','that guy','guy','user','the user','target','the target','subject','the subject','me','you','us','more','everybody']);
    const norm = arg.toLowerCase().replace(/[?.!,]+$/, '').replace(/^(the|a|an)\s+/, '');
    if (arg && PRON.has(norm)) return null;
    const tool = String(o.tool).toLowerCase().trim();
    // Grounding: for entity tools, the arg must literally appear in the message/context —
    // the model may not invent a target. Pure-compute tools (cvss/decode/encode/...) are exempt.
    const COMPUTE = new Set(['cvss','decode','encode','jwt','cidr','hash_id','timestamp','ioc_extract','cve_search','web_search','people_search','phone_osint']);
    if (arg && !COMPUTE.has(tool)) {
      const hay = (msg + ' ' + (contextSoFar || '')).toLowerCase();
      if (hay.indexOf(norm) < 0 && hay.indexOf(arg.toLowerCase()) < 0) return null;
    }
    return { tool, arg };
  } catch (e) { return null; }
}

// Website crawler — fetch a page, extract & classify links, follow interesting files, scan for secrets.
async function crawl(url) {
  let u; try { u = new URL(/^https?:\/\//i.test(url) ? url : 'https://' + url); } catch { return 'crawl: a URL is required.'; }
  if (isPrivateHost(u.hostname)) return `crawl: ${u.hostname} is private/internal — blocked.`;
  const SECRET = [
    [/AKIA[0-9A-Z]{16}/, 'AWS access key'],
    [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, 'private key'],
    [/ghp_[A-Za-z0-9]{36}/, 'GitHub token'], [/glpat-[A-Za-z0-9_-]{20}/, 'GitLab token'],
    [/xox[baprs]-[A-Za-z0-9-]{10,}/, 'Slack token'], [/AIza[0-9A-Za-z\-_]{35}/, 'Google API key'],
    [/sk_live_[0-9A-Za-z]{24,}/, 'Stripe secret key'], [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}/, 'JWT'],
    [/(?:api[_-]?key|secret|passwd|password|token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']/i, 'inline credential'],
  ];
  const scan = t => SECRET.filter(([re]) => re.test(t)).map(([, n]) => n);
  try {
    const r = await fetch(u.toString(), { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, redirect: 'follow', signal: AbortSignal.timeout(10000) });
    const html = await r.text();
    const links = new Set(); let m; const re = /(?:href|src)\s*=\s*["']([^"'#]+)["']/gi;
    while ((m = re.exec(html))) { try { links.add(new URL(m[1], u).toString()); } catch (e) {} }
    const all = [...links];
    const host = u.hostname;
    const sameHost = all.filter(l => { try { return new URL(l).hostname === host; } catch (e) { return false; } });
    const extDomains = [...new Set(all.map(l => { try { return new URL(l).hostname; } catch (e) { return ''; } }).filter(h => h && h !== host))];
    const js = all.filter(l => /\.js(\?|$)/i.test(l));
    const interesting = all.filter(l => /\.(txt|json|xml|env|ya?ml|conf|config|bak|old|sql|log|csv|ini)(\?|$)|robots\.txt|sitemap|\.well-known|\.env|\.git\/|backup|admin|login|wp-config|phpinfo/i.test(l));
    const homeSecrets = scan(html);
    const followed = [];
    const toFetch = [...new Set([...interesting, u.origin + '/robots.txt', u.origin + '/.well-known/security.txt', u.origin + '/.git/config', u.origin + '/.env'])].slice(0, 7);
    for (const f of toFetch) {
      try {
        const fr = await fetch(f, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(7000) });
        if (!fr.ok) continue;
        const txt = (await fr.text()).slice(0, 4000);
        if (!txt.trim()) continue;
        const secrets = scan(txt);
        const urls = [...new Set(txt.match(/https?:\/\/[^\s"'<>]{6,120}/g) || [])].slice(0, 4);
        followed.push(`- ${f} (HTTP ${fr.status})${secrets.length ? '  [SECRETS: ' + secrets.join(', ') + ']' : ''}${urls.length ? '\n    refs: ' + urls.join(', ') : ''}`);
      } catch (e) {}
    }
    let out = `crawl ${host} (HTTP ${r.status})\nlinks: ${all.length} total, ${sameHost.length} same-host`;
    out += `\nexternal domains: ${extDomains.slice(0, 14).join(', ') || 'none'}`;
    if (js.length) out += `\nJS files (${js.length}): ${js.slice(0, 6).join(', ')}`;
    if (homeSecrets.length) out += `\nSECRETS IN PAGE SOURCE: ${homeSecrets.join(', ')}`;
    if (interesting.length) out += `\ninteresting files (${interesting.length}):\n${interesting.slice(0, 12).join('\n')}`;
    if (followed.length) out += `\nfollowed files:\n${followed.join('\n')}`;
    return out;
  } catch (e) { return `crawl ${u.hostname}: failed (${e.message}).`; }
}

// Responsible-disclosure DRAFT — finds a domain's security contact and composes a
// blue-team notification email for a HUMAN to review and send. Never sends; never anonymous.
async function disclosureDraft(env, target) {
  const parts = String(target || '').split('|');
  const d = parts[0].trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  const finding = (parts[1] || '').trim();
  if (!d || d.indexOf('.') < 0) return 'disclosure_draft: a domain is required (optionally "domain | brief finding").';
  const contacts = [];
  try {
    const r = await fetch('https://' + d + '/.well-known/security.txt', { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(7000) });
    if (r.ok) { const t = await r.text(); (t.match(/Contact:\s*([^\s]+)/ig) || []).forEach(c => contacts.push(c.replace(/Contact:\s*/i, '').replace(/^mailto:/i, '').trim())); }
  } catch (e) {}
  try { const rd = await domainLookup(d); const em = (String(rd).match(/[a-z0-9._%+\-]*abuse[a-z0-9._%+\-]*@[a-z0-9.\-]+\.[a-z]{2,}/i) || String(rd).match(/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i) || [])[0]; if (em) contacts.push(em); } catch (e) {}
  let to = [...new Set(contacts.filter(c => /@/.test(c)))];
  if (!to.length) to = ['security@' + d, 'abuse@' + d];
  const who = String((env && env.DISCLOSURE_FROM) || '[your name / handle — set DISCLOSURE_FROM]');
  const subject = `Responsible disclosure: potential security issue on ${d}`;
  const body = `Hello,\n\nMy name is ${who} and I am reaching out in good faith about a potential security issue I observed on ${d} during passive, non-intrusive analysis (a blue-team / responsible-disclosure courtesy).\n\nObservation:\n${finding || '[describe the specific issue — e.g., missing SPF/DMARC, an exposed file, a takeover-able subdomain, weak security headers]'}\n\nNo systems were accessed or exploited; this is based only on publicly available information. Please treat it as a heads-up so your team can verify and remediate. I am happy to provide details and coordinate.\n\nRegards,\n${who}`;
  return `disclosure_draft ${d}\nsuggested recipient(s): ${to.slice(0, 3).join(', ')}\n\n--- SUBJECT ---\n${subject}\n\n--- BODY ---\n${body}\n\nNOTE: DRAFT only — Agent Garrett does not send email. Review and send from your own verified, attributable address. Responsible disclosure should never be anonymous.`;
}

// Public PoC / exploit repos for a CVE (nomi-sec PoC-in-GitHub dataset, keyless).
async function cvePoc(cve) {
  const id = String(cve || '').trim().toUpperCase();
  const m = id.match(/^CVE-(\d{4})-\d+$/);
  if (!m) return 'cve_poc: a CVE id like CVE-2021-44228 is required.';
  try {
    const r = await fetch(`https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/${m[1]}/${id}.json`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(9000) });
    if (r.status === 404) return `cve_poc ${id}: no public PoC repos indexed (PoC-in-GitHub).`;
    if (!r.ok) return `cve_poc ${id}: lookup failed (HTTP ${r.status}).`;
    const d = await r.json();
    if (!d.length) return `cve_poc ${id}: no public PoC repos found.`;
    const top = d.sort((a, b) => (b.stargazers_count || 0) - (a.stargazers_count || 0)).slice(0, 10)
      .map(x => `★${x.stargazers_count || 0}  ${x.html_url}${x.description ? '\n    ' + String(x.description).slice(0, 110) : ''}`);
    return `cve_poc ${id}: ${d.length} public PoC repo(s) on GitHub (top by stars):\n${top.join('\n')}`;
  } catch (e) { return `cve_poc ${id}: failed (${e.message}).`; }
}

// Latest CISA Known-Exploited-Vulnerabilities additions (what is being exploited now).
async function kevRecent(arg) {
  const n = Math.min(30, Math.max(1, parseInt(arg, 10) || 15));
  try {
    const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(12000) });
    if (!r.ok) return `kev_recent: CISA feed failed (HTTP ${r.status}).`;
    const d = await r.json();
    const v = (d.vulnerabilities || []).sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded))).slice(0, n);
    const rows = v.map(x => `${x.dateAdded}  ${x.cveID}  ${x.vendorProject}/${x.product} — ${String(x.vulnerabilityName || '').slice(0, 70)}${x.knownRansomwareCampaignUse === 'Known' ? '  [RANSOMWARE]' : ''}`);
    return `kev_recent: ${n} most recently added CISA KEV entries (catalog total ${d.count || v.length}):\n${rows.join('\n')}`;
  } catch (e) { return `kev_recent: failed (${e.message}).`; }
}

// MITRE ATT&CK technique lookup (by id, e.g. T1059 or T1059.001).
async function mitreLookup(tech) {
  const t = String(tech || '').trim().toUpperCase();
  const m = t.match(/^T(\d{4})(?:\.(\d{3}))?$/);
  if (!m) return 'mitre: a technique id like T1059 or T1059.001 is required.';
  const path = m[2] ? `${m[1]}/${m[2]}` : `${m[1]}`;
  try {
    const r = await fetch(`https://attack.mitre.org/techniques/T${path}/`,
      { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, signal: AbortSignal.timeout(10000) });
    if (r.status === 404) return `mitre T${path.replace('/', '.')}: technique not found.`;
    if (!r.ok) return `mitre: lookup failed (HTTP ${r.status}).`;
    const html = await r.text();
    const title = ((html.match(/<title>([^<]+)<\/title>/i) || [])[1] || '').replace(/\s*\|\s*MITRE.*/i, '').trim();
    const tactics = [...new Set((html.match(/\/tactics\/TA\d+/g) || []))].map(x => x.split('/').pop());
    let desc = '';
    const dm = html.match(/<div class="description-body">([\s\S]*?)<\/div>/i);
    if (dm) desc = dm[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 600);
    return `mitre T${path.replace('/', '.')} — ${title || '?'}\ntactics: ${tactics.join(', ') || '?'}\n${desc || '(description not parsed)'}\nref: https://attack.mitre.org/techniques/T${path}/`;
  } catch (e) { return `mitre: failed (${e.message}).`; }
}

// DNS-brute subdomain enumeration (DoH) — complements crt.sh.
async function subdomains(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!d || d.indexOf('.') < 0) return 'subdomains: a domain is required.';
  const words = ['www','mail','remote','blog','webmail','server','ns1','ns2','smtp','secure','vpn','m','shop','ftp','test','portal','ns','admin','dev','staging','api','app','cdn','cloud','git','gitlab','jenkins','jira','confluence','wiki','docs','support','help','status','dashboard','internal','intranet','owa','autodiscover','exchange','beta','demo','assets','static','img','media','db','backup','old','new','mobile','careers','jobs','store','login','sso','auth','proxy','gateway','monitor','grafana','kibana','sonar','nexus','registry','docker','prod','uat','qa','origin','direct','cpanel'];
  const live = [];
  await Promise.all(words.map(async w => {
    const host = w + '.' + d;
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
      const j = await r.json();
      const a = (j.Answer || []).filter(x => x.type === 1).map(x => x.data);
      if (a.length) live.push(`${host} -> ${a.slice(0, 2).join(', ')}`);
    } catch (e) {}
  }));
  if (!live.length) return `subdomains ${d}: none of ${words.length} common subdomains resolved (try crtsh_subs for cert-transparency names).`;
  return `subdomains ${d}: ${live.length}/${words.length} common subdomains resolve\n` + live.sort().join('\n');
}

// JWT decoder/inspector (no verification — flags alg:none, expiry).
function b64urlDecode(x) { let t = String(x || '').replace(/-/g, '+').replace(/_/g, '/'); while (t.length % 4) t += '='; try { return atob(t); } catch (e) { return ''; } }
function jwtDecode(token) {
  const t = String(token || '').trim().replace(/^Bearer\s+/i, '');
  const parts = t.split('.');
  if (parts.length < 2 || !/^[A-Za-z0-9_-]{4,}$/.test(parts[0])) return 'jwt: provide a JWT (header.payload.signature).';
  let hdr; try { hdr = JSON.parse(b64urlDecode(parts[0])); } catch (e) { return 'jwt: header is not valid base64url JSON.'; }
  let pl; try { pl = JSON.parse(b64urlDecode(parts[1])); } catch (e) { pl = { _raw: b64urlDecode(parts[1]).slice(0, 200) }; }
  const notes = [];
  if (String(hdr.alg).toLowerCase() === 'none') notes.push('alg=none — signature is NOT verified (critical if the server accepts it)');
  if (pl.exp) notes.push('expires ' + new Date(pl.exp * 1000).toISOString() + (Date.now() > pl.exp * 1000 ? '  (EXPIRED)' : ''));
  if (pl.iat) notes.push('issued ' + new Date(pl.iat * 1000).toISOString());
  if (pl.iss) notes.push('issuer: ' + pl.iss);
  return `jwt decode\nheader: ${JSON.stringify(hdr)}\nclaims: ${JSON.stringify(pl).slice(0, 1400)}\nsignature: ${parts[2] ? '(present — NOT verified; needs the signing key)' : '(none)'}` + (notes.length ? '\nnotes:\n- ' + notes.join('\n- ') : '');
}

// IPv4 CIDR math.
function cidrTool(input) {
  const m = String(input || '').trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) return 'cidr: provide an IPv4 CIDR like 192.168.1.0/24.';
  const bits = +m[2];
  if (m[1].split('.').some(o => +o > 255) || bits > 32) return 'cidr: invalid IP or prefix.';
  const ipToInt = ip => ip.split('.').reduce((a, o) => ((a << 8) + (+o)) >>> 0, 0) >>> 0;
  const intToIp = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  const ip = ipToInt(m[1]);
  const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  const net = (ip & mask) >>> 0;
  const bcast = (net | (~mask >>> 0)) >>> 0;
  const total = Math.pow(2, 32 - bits);
  const usable = bits >= 31 ? total : total - 2;
  return `cidr ${m[1]}/${bits}\nnetwork: ${intToIp(net)} | broadcast: ${intToIp(bcast)}\nmask: ${intToIp(mask)}\nrange: ${intToIp(net)} - ${intToIp(bcast)}\ntotal addresses: ${total} | usable hosts: ${usable}`;
}

// Identify likely hash type by format.
function hashId(h) {
  const x = String(h || '').trim();
  if (!x) return 'hash_id: paste a hash.';
  const out = [];
  if (/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/.test(x)) out.push('bcrypt');
  if (/^\$1\$/.test(x)) out.push('md5crypt');
  if (/^\$5\$/.test(x)) out.push('sha256crypt');
  if (/^\$6\$/.test(x)) out.push('sha512crypt');
  if (/^\$argon2/i.test(x)) out.push('argon2');
  if (/^\*[A-F0-9]{40}$/i.test(x)) out.push('MySQL 4.1+');
  if (/^[a-f0-9]{16}$/i.test(x)) out.push('MySQL323 / CRC64');
  if (/^[a-f0-9]{32}$/i.test(x)) out.push('MD5', 'NTLM', 'MD4', 'LM');
  if (/^[a-f0-9]{40}$/i.test(x)) out.push('SHA-1', 'MySQL5', 'RIPEMD-160');
  if (/^[a-f0-9]{56}$/i.test(x)) out.push('SHA-224');
  if (/^[a-f0-9]{64}$/i.test(x)) out.push('SHA-256', 'SHA3-256', 'BLAKE2s');
  if (/^[a-f0-9]{96}$/i.test(x)) out.push('SHA-384');
  if (/^[a-f0-9]{128}$/i.test(x)) out.push('SHA-512', 'SHA3-512', 'Whirlpool');
  if (!out.length) return `hash_id: no confident format match for "${x.slice(0, 24)}...".`;
  return `hash_id ${x.slice(0, 24)}${x.length > 24 ? '…' : ''}\nlength: ${x.length} | likely: ${[...new Set(out)].join(', ')}`;
}

// Encode text -> base64 / hex / url / rot13.
function encodeTool(input) {
  const s = String(input || '');
  if (!s) return 'encode: provide text to encode.';
  let b64 = ''; try { b64 = btoa(unescape(encodeURIComponent(s))); } catch (e) { b64 = '(encode failed)'; }
  let hex = ''; for (let i = 0; i < s.length; i++) hex += s.charCodeAt(i).toString(16).padStart(2, '0');
  const url = encodeURIComponent(s);
  const r13 = s.replace(/[a-z]/g, c => String.fromCharCode((c.charCodeAt(0) - 97 + 13) % 26 + 97)).replace(/[A-Z]/g, c => String.fromCharCode((c.charCodeAt(0) - 65 + 13) % 26 + 65));
  return `encode "${s.slice(0, 60)}"\nbase64: ${b64.slice(0, 300)}\nhex: ${hex.slice(0, 240)}\nurl: ${url.slice(0, 240)}\nrot13: ${r13.slice(0, 140)}`;
}

// Decode unix epoch or UUID (v1 leaks timestamp + node MAC).
function timestampDecode(input) {
  const s = String(input || '').trim();
  const u = s.match(/^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f])([0-9a-f]{3})-([0-9a-f]{4})-([0-9a-f]{12})$/i);
  if (u) {
    const ver = u[3];
    let out = `uuid ${s}\nversion: ${ver}`;
    if (ver === '1') {
      const timeLow = BigInt(parseInt(u[1], 16)), timeMid = BigInt(parseInt(u[2], 16)), timeHi = BigInt(parseInt(u[4], 16));
      const ts = (timeHi << 48n) | (timeMid << 32n) | timeLow;
      const ms = Number(ts / 10000n) - 12219292800000;
      out += `\ntimestamp: ${new Date(ms).toISOString()}`;
      out += `\nnode (MAC): ${u[6].replace(/(..)(?=.)/g, '$1:')}`;
    }
    return out;
  }
  if (/^\d{10}$/.test(s)) return `timestamp ${s} (unix seconds) = ${new Date(+s * 1000).toISOString()}`;
  if (/^\d{13}$/.test(s)) return `timestamp ${s} (unix millis) = ${new Date(+s).toISOString()}`;
  return 'timestamp: provide a unix epoch (10 or 13 digits) or a UUID.';
}

// Passive vulnerability indication: detect software/versions from banners, map to
// candidate CVEs (NVD) + Shodan's pre-collected CVE tags. NOT active exploitation.
async function vulnScan(target) {
  let u; try { u = new URL(/^https?:\/\//i.test(target) ? target : 'https://' + target); } catch { return 'vuln_scan: a domain or URL is required.'; }
  if (isPrivateHost(u.hostname)) return `vuln_scan: ${u.hostname} is private/internal — blocked.`;
  const products = new Set(); const lines = [];
  try {
    const r = await fetch(u.toString(), { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; garrettstimpson-agent/4.0)' }, redirect: 'follow', signal: AbortSignal.timeout(10000) });
    const html = await r.text(); const hd = n => r.headers.get(n) || '';
    lines.push(`fingerprint: server=${hd('server') || '?'} | x-powered-by=${hd('x-powered-by') || '?'}`);
    [hd('server'), hd('x-powered-by')].forEach(sv => { (String(sv).match(/[A-Za-z][A-Za-z0-9.\-]*\/\d+\.\d+(?:\.\d+)?/g) || []).forEach(p => products.add(p.replace('/', ' '))); });
    const gen = (html.match(/<meta name="generator" content="([^"]+)"/i) || [])[1];
    if (gen) { lines.push(`generator: ${gen}`); if (/\d/.test(gen)) products.add(gen); }
    (html.match(/([a-z][a-z0-9_]{2,20})[\-\/](\d+\.\d+\.\d+)(?:\.min)?\.js/ig) || []).slice(0, 6).forEach(js => { const m = js.match(/([a-z][a-z0-9_]{2,20})[\-\/](\d+\.\d+\.\d+)/i); if (m) products.add(m[1] + ' ' + m[2]); });
  } catch (e) { return `vuln_scan ${u.hostname}: fetch failed (${e.message}).`; }
  const plist = [...products].filter(p => /\d/.test(p)).slice(0, 3);
  if (!plist.length) lines.push('no versioned software banners exposed (server hides versions — good hardening).');
  for (const p of plist) {
    try {
      const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(p)}&resultsPerPage=5`, { headers: { 'User-Agent': 'garrettstimpson-agent/4.0' }, signal: AbortSignal.timeout(12000) });
      if (!r.ok) { lines.push(`\n${p}: NVD lookup HTTP ${r.status}`); continue; }
      const d = await r.json();
      const v = (d.vulnerabilities || []).slice(0, 5).map(x => {
        const c = x.cve; let sc = '?';
        try { const m = c.metrics || {}; const cv = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0]; if (cv && cv.cvssData) sc = cv.cvssData.baseScore + ' ' + (cv.cvssData.baseSeverity || ''); } catch (e) {}
        return `  ${c.id} [CVSS ${sc}]`;
      });
      lines.push(`\n${p} -> ${d.totalResults || 0} NVD matches (version-match CANDIDATES):\n${v.join('\n') || '  none'}`);
    } catch (e) { lines.push(`\n${p}: NVD ${e.message}`); }
  }
  try {
    const dr = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(u.hostname)}&type=A`, { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
    const j = await dr.json(); const ip = ((j.Answer || []).filter(a => a.type === 1).map(a => a.data))[0];
    if (ip) { const sh = await shodanInternetDB(ip); lines.push(`\nShodan InternetDB (${ip} — pre-scanned, real observed CVEs/ports):\n${sh}`); }
  } catch (e) {}
  return `vuln_scan ${u.hostname}\n${lines.join('\n')}\n\nNOTE: passive banner/version matching. The NVD entries are CANDIDATE CVEs for the detected software — NOT confirmed exploitable on this host (the patch level/config is unknown, and the IP may be a CDN/WAF edge). Confirming exploitability requires AUTHORIZED active testing, which Agent Garrett does not perform.`;
}

// ── Prompt assembly ─────────────────────────────────────────────────────────────

const PERSONA = [
  'Your name is Agent Garrett, the AI research assistant for the security-research blog "{SITE}".',
  'You are software. "Agent Garrett" is your assistant name only — do not claim to be a human, and do not fabricate a biography, employer, certifications, or personal history for yourself.',
  'Ground every claim in the CORPUS and LIVE TOOL RESULTS provided below.',
  'CRITICAL — never fabricate. Do not invent CVE IDs, CVSS/EPSS scores, affected versions, patch/registration dates, WHOIS or RDAP records, owner names, organizations, postal addresses, phone numbers, emails, ASNs, IP addresses, hostnames, file hashes, or URLs. If the CORPUS and LIVE TOOL RESULTS do not contain a fact, reply that you do not have it / it is UNKNOWN. Inventing any such detail is a critical failure.',
  'When a tool result says data is UNKNOWN, missing, or that a lookup returned nothing, report exactly that — never fill the gap with a plausible-looking guess.',
  'You CANNOT execute commands, shells, or live scans yourself (no dig, whois, nslookup, nmap, curl, ping, traceroute, host). If asked to run one, say plainly that you cannot run commands and instead rely on the LIVE TOOL RESULTS, or state UNKNOWN. NEVER write fake terminal/command output, invented dig/whois/nslookup results, or made-up IP addresses, nameservers, or registrars — fabricating tool or command output is a critical failure.',
  'Your purpose is defensive: help protect users and organizations, assess their exposure, and identify threats and malicious infrastructure. Frame findings for defenders.',
  'Use clear markdown: ## headings, **bold** for key terms, `code` for identifiers/commands, fenced ```code blocks```, and bullet lists where helpful.',
  'Answer with technical precision. Cite the post title/URL when you draw from the corpus.',
].join(' ');

function buildSystemPrompt(env, { summary, chunks, toolContext, clientMemory, reasoning }) {
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
    corpusText = `CORPUS (top ${parts.length} chunks by relevance — use ONLY chunks that actually match the question; ignore unrelated ones):\n${parts.join('\n\n---\n\n')} ANTI-FABRICATION (critical): only state facts that appear in the LIVE TOOL RESULTS or research context actually shown to you. NEVER fabricate or guess files, filenames, file listings, hashes, malware names/families, loaders, payloads, IOCs, CVEs, or attributions; if no tool returned such data, say it was not found or is UNKNOWN. NEVER take malware/exploit details from the research corpus and attribute them to a user-supplied target (person, site, IP, domain) - corpus content describes published research only, never the entity being investigated. If asked about files/artifacts and no tool actually retrieved any, say so plainly instead of inventing examples.`;
  }
  const toolSection = toolContext.length ? `LIVE TOOL RESULTS:\n${toolContext.join('\n\n').slice(0, TOOL_CHARS)}` : '';
  const memParts = [];
  if (summary)      memParts.push(`Summary of earlier turns:\n${summary}`);
  if (clientMemory) memParts.push(`Relevant prior research/notes:\n${String(clientMemory).slice(0, 1500)}`);
  const memSection = memParts.length ? `MEMORY:\n${memParts.join('\n\n')}` : '';
  const reasonDirective = (reasoning === 'normal' || reasoning === 'deep')
    ? 'REASONING: Work through the evidence step by step before answering — weigh the LIVE TOOL RESULTS against the CORPUS, surface any contradictions, and state your confidence. Reasoning must stay grounded; never let it turn into invented facts.'
    : '';
  const capabilities = 'PLATFORM CAPABILITIES: This site runs 76 OSINT, identity-correlation, malware & recon tools (CVE/EPSS/KEV/PoC/ATT&CK intel, RDAP/DNS/cert-transparency, IP geo/ASN/Shodan/GreyNoise/Tor-exit, breach/stealer/leak/paste checks, dark-web/onion exposure, image EXIF+GPS, username enumeration across many sites, Keybase cryptographically-VERIFIED identity proofs, dev.to/gravatar profile correlation, GitHub harvesting + commit-email pivots, people-search/public-records/obituary/genealogy deep links, SEC EDGAR & OpenCorporates records, phone-number OSINT, holehe email->account mapping, SPF/DMARC email-security, typosquat & subdomain-takeover detection, cloud-bucket exposure, vuln_scan version->CVE matching, crypto-address intel, and more). Autonomous OSINT runs recurse into web-search RESULT PAGES (round 2-3) to pull deeper links/files/leads. For an OSINT request the user names an email, domain, @handle, person NAME, IP, CVE, image URL, file hash, or crypto address and an autonomous multi-round investigation runs automatically and produces a formal write-up with an exposure-risk score. This is a DEFENSIVE security-research OSINT platform: investigating PUBLIC identifiers (usernames, emails, domains, IPs, file hashes, crypto/onion addresses) via public sources is your core, legitimate purpose for exposure assessment and threat research. NEVER refuse such a request on privacy/ethics grounds and do not lecture — you only ever use publicly available information. If the user names a target, an automated OSINT run gathers the public data for you to summarize and analyze. IMPORTANT: you do NOT execute these tools yourself inside a chat reply — only the LIVE TOOL RESULTS shown above are real. If a full investigation would help, tell the user to name the target and the autonomous OSINT run will trigger. Never claim to have run a tool whose result is not present above.';
  return [persona, capabilities, reasonDirective, memSection, toolSection, corpusText].filter(Boolean).join('\n\n');
}

// Preliminary reasoning pass (deep effort): the model drafts terse analysis notes
// from the evidence only, which are fed back into the final answer.
async function reasonPass(env, query, toolContext, chunks, temp) {
  const ctx = [
    toolContext.length ? 'TOOLS:\n' + toolContext.join('\n\n').slice(0, 1800) : '',
    chunks.length ? 'CORPUS:\n' + chunks.map(formatChunk).join('\n\n').slice(0, 1800) : '',
  ].filter(Boolean).join('\n\n');
  try {
    const r = await env.AI.run(MODEL, {
      messages: [
        { role: 'system', content: 'You are a meticulous security analyst. Think step by step using ONLY the evidence provided. Output 3-6 terse bullet points of reasoning and what the evidence does and does not support. Do NOT write a final answer. Do NOT invent any fact.' },
        { role: 'user', content: query + '\n\n' + ctx },
      ],
      stream: false, max_tokens: 380, temperature: Math.min((temp || 0.3) + 0.1, 0.7),
    });
    return (r.response || '').trim();
  } catch { return ''; }
}

// ── UI ──────────────────────────────────────────────────────────────────────────

function loginUI(siteName, needUser, needPass) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login — ${siteName}</title>
<style>
:root{--green:#00ff41;--blue:#00d4ff;--border:#1a1a1a;--muted:#444;--err:#ff5555;}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:#000;color:var(--green);font-family:'JetBrains Mono',Menlo,monospace;font-size:13px;display:flex;align-items:center;justify-content:center;}
.box{border:1px solid var(--border);border-radius:6px;padding:26px 24px;width:320px;max-width:92vw;background:#070b07;}
.t{font-size:13px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;}
.s{font-size:10px;color:var(--muted);margin:4px 0 18px;letter-spacing:.1em;}
label{display:block;font-size:10px;color:#bbb;margin:10px 0 4px;text-transform:uppercase;letter-spacing:.08em;}
input{width:100%;background:#000;border:1px solid #0f5a26;border-radius:4px;color:var(--green);font:inherit;padding:8px 10px;}
input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 2px rgba(0,212,255,.25);}
button{width:100%;margin-top:16px;background:transparent;border:1px solid var(--green);color:var(--green);font:inherit;padding:9px;border-radius:4px;cursor:pointer;letter-spacing:.1em;text-transform:uppercase;}
button:hover{background:#0a2a12;}
.err{color:var(--err);font-size:10px;margin-top:10px;min-height:12px;}
</style><link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet"></head>
<body><form class="box" id="f">
<div class="t">Agent Garrett</div><div class="s">${siteName} — restricted access</div>
${needUser ? '<label>user</label><input id="u" autocomplete="username" autofocus>' : ''}
${needPass ? ('<label>password</label><input id="p" type="password" autocomplete="current-password"' + (needUser ? '' : ' autofocus') + '>') : ''}
<button type="submit">enter</button><div class="err" id="e"></div>
</form>
<script>
document.getElementById('f').addEventListener('submit', async function(ev){
  ev.preventDefault();
  var body={}; var uel=document.getElementById('u'); var pel=document.getElementById('p');
  if(uel) body.user=uel.value; if(pel) body.password=pel.value;
  if((uel && !uel.value) || (pel && !pel.value)){ document.getElementById('e').textContent='Enter your credentials.'; return; }
  try{
    var r=await fetch('/api/login',{ method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
    if(r.ok){ location.href='/'; return; }
    document.getElementById('e').textContent='Access denied.';
  }catch(e){ document.getElementById('e').textContent='Error: '+e.message; }
});
</script></body></html>`;
}

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
#app{display:flex;flex-direction:column;height:100vh;max-width:980px;margin:0 auto;padding:12px;position:relative;z-index:1;}
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
.msg.agent.jtaskout{border-left:2px solid var(--blue);padding-left:10px;opacity:.92;font-size:12.5px;}
.msg.agent.jtaskout .jt-h{color:var(--blue);font-size:10px;text-transform:uppercase;letter-spacing:.08em;}
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
#jobs textarea#j-obj{flex:1 1 100%;width:100%;min-height:64px;resize:vertical;background:#000;border:1px solid var(--border);color:var(--green);font:inherit;padding:6px 8px;line-height:1.5;}
#j-chips{display:flex;gap:6px;flex-wrap:wrap;margin:2px 0 6px;}
.jchip{border:1px solid var(--border);color:var(--blue);background:transparent;font:inherit;font-size:10px;padding:3px 9px;cursor:pointer;border-radius:11px;}
.jchip:hover{border-color:var(--blue);background:#06121a;}
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
#wm{position:fixed;left:16px;bottom:58px;width:160px;height:160px;z-index:0;pointer-events:none;
  background:url('https://garrettstimpson.ca/assets/img/agent-garrett-logo.png') no-repeat bottom left;
  background-size:contain;opacity:.5;mix-blend-mode:screen;}
@media (max-width:640px){#wm{width:104px;height:104px;bottom:54px;opacity:.4;}}
#tools{display:none;border:1px solid var(--border);border-radius:3px;padding:10px;margin-bottom:10px;background:var(--panel);font-size:11px;}
#tools.show{display:block;}
#tools .trow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:5px 0;}
#tools input,#tools select{background:#000;border:1px solid var(--border);color:var(--green);font:inherit;padding:3px 6px;}
#tools input.t-arg{flex:1;min-width:170px;}
#tools .jbtn{border:1px solid var(--green);color:var(--green);background:transparent;font:inherit;font-size:10px;padding:3px 10px;cursor:pointer;border-radius:2px;}
#tools .jbtn:hover{background:#0a2a12;}
.tool-item{font-size:10.5px;color:#bbb;margin:2px 0;}
.tool-item .tcat{color:var(--muted);}
.tool-pill{display:inline-block;font-size:9px;border:1px solid var(--border);border-radius:8px;padding:1px 6px;margin-left:6px;}
.tool-pill.passive{color:var(--green);border-color:var(--green);}
.tool-pill.active{color:var(--warn);border-color:var(--warn);}
.t-badge{font-size:9px;padding:1px 6px;border:1px solid var(--border);border-radius:2px;color:var(--muted);}
.t-badge.safe{color:var(--green);border-color:var(--green);}
.t-out{white-space:pre-wrap;word-break:break-word;border-left:2px solid var(--blue);padding-left:8px;margin-top:6px;color:#bbb;font-size:10.5px;}
/* themed dropdowns — tools + agent + settings panels */
#tools select,#jobs select,#settings select,#s-reason{
  -webkit-appearance:none;-moz-appearance:none;appearance:none;
  background-color:#0a140a;color:var(--green);
  border:1px solid #0f5a26;border-radius:4px;
  padding:6px 28px 6px 10px;font:inherit;font-size:11px;line-height:1.4;cursor:pointer;
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'><path d='M1 1l4 4 4-4' fill='none' stroke='%2300ff41' stroke-width='1.5'/></svg>");
  background-repeat:no-repeat;background-position:right 10px center;
  transition:border-color .15s,box-shadow .15s,background-color .15s;max-width:100%;
}
#tools select:hover,#jobs select:hover,#settings select:hover,#s-reason:hover{border-color:var(--green);background-color:#0c1a0c;}
#tools select:focus,#jobs select:focus,#settings select:focus,#s-reason:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 2px rgba(0,212,255,.25);}
#tools select option,#jobs select option,#settings select option,#s-reason option{background:#050805;color:var(--green);}
#tools .trow,#jobs .row{align-items:center;}
@media (max-width:640px){
  #tools select,#jobs select,#tools input.t-arg,#jobs input[type=text]{width:100%;flex:1 1 100%;}
  #tools .trow,#jobs .row{gap:6px;}
}
@keyframes gsspin{to{transform:rotate(360deg)}}
.spinner{display:inline-block;width:11px;height:11px;border:2px solid var(--muted);border-top-color:var(--blue);border-radius:50%;animation:gsspin .7s linear infinite;vertical-align:-2px;margin-right:7px;}
@keyframes gsblink{0%,49%{opacity:1}50%,100%{opacity:0}}
.msg.agent.streaming::after{content:'\u258b';color:var(--blue);animation:gsblink 1.05s steps(1) infinite;margin-left:1px;}
.think{color:var(--muted);font-style:italic;}
.tool-chips{display:flex;flex-wrap:wrap;gap:5px;margin:0 0 6px;}
.tchip{font-size:10px;color:var(--blue);border:1px solid var(--border);border-radius:10px;padding:1px 9px;background:#06121a;}
#disclose{display:none;border:1px solid var(--border);border-radius:3px;padding:10px;margin-bottom:10px;background:var(--panel);font-size:11px;}
#disclose.show{display:block;}
#disclose .trow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:5px 0;}
#disclose input{background:#000;border:1px solid var(--border);color:var(--green);font:inherit;padding:3px 6px;}
#disclose .jbtn{cursor:pointer;border:1px solid var(--green);color:var(--green);background:transparent;font:inherit;padding:3px 10px;border-radius:2px;}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
</head>
<body>
<div id="wm" aria-hidden="true"></div>
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
        <button class="btn" id="btn-tools" title="CTF tools &amp; policy">tools</button>
        <button class="btn" id="btn-stop" title="Stop the running OSINT run" style="display:none;color:var(--err);border-color:var(--err);">stop</button>
        <button class="btn" id="btn-disclose" title="Responsible disclosure — draft &amp; (if enabled) send">disclose</button>
      </div>
    </div>
  </header>

  <div id="chatbar"><span class="chat-count" id="chatcount"></span></div>

  <div id="settings">
    <label><input type="checkbox" id="s-search" checked> web search (NVD + EPSS + RDAP + Brave/SearXNG/DuckDuckGo)</label>
    <label>temperature <input type="range" id="s-temp" min="0" max="1" step="0.1" value="0.3"><span class="set-val" id="s-temp-v">0.3</span></label>
    <label>top-K chunks <input type="range" id="s-topk" min="1" max="10" step="1" value="5"><span class="set-val" id="s-topk-v">5</span></label>
    <label>reasoning effort
      <select id="s-reason">
        <option value="off">off (fastest)</option>
        <option value="normal" selected>normal</option>
        <option value="deep">deep (2-pass)</option>
      </select>
    </label>
    <label><input type="checkbox" id="s-debug"> show debug pane by default</label>
    <label><input type="checkbox" id="s-aitools" checked> AI tool use — let the agent pick &amp; run tools to answer</label>
    <label>brave api key (optional, stored in your browser) <input type="password" id="s-brave" placeholder="leave blank to skip"></label>
    <div style="color:var(--muted);margin-top:6px;font-size:10px;">Settings &amp; chats are saved in this browser. Up to 3 conversations are kept.</div>
  </div>

  <div id="jobs">
    <div style="color:var(--muted);margin-bottom:6px;">AGENT MODE — give Agent Garrett a job. It plans linked sub-tasks, runs them as a swarm, and writes a synthesized report into the current chat. Tools (passive / read-only): NVD &middot; EPSS &middot; CISA KEV &middot; RDAP whois (IP + domain) &middot; DNS &middot; TLS / certificate-transparency &middot; web search. No active scanning or exploitation.</div>
    <div id="j-chips"></div>
    <div class="row">
      <textarea id="j-obj" rows="3" placeholder="objective — describe the job in detail, or click an example prompt above"></textarea>
    </div>
    <div class="row">
      <select id="j-tpl">
        <option value="osint">OSINT monitor (full)</option>
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

  <div id="tools">
    <div style="color:var(--muted);margin-bottom:6px;">CTF TOOLS — <span id="t-mode" class="t-badge">policy…</span> &nbsp;Passive tools run in-worker; active/custom tools require an operator broker. Runs are gated by confirm + target scope.</div>
    <div id="t-catalog" style="margin:6px 0;"></div>
    <div class="trow">
      <select id="t-tool"></select>
      <input class="t-arg" id="t-target" placeholder="arg: CVE / IP / domain / url">
      <label style="font-size:10px;color:#bbb;"><input type="checkbox" id="t-confirm"> confirm</label>
      <button class="jbtn" id="t-run">run tool</button>
    </div>
    <div id="t-result"></div>
  </div>

  <div id="disclose">
    <div style="color:var(--muted);margin-bottom:6px;">RESPONSIBLE DISCLOSURE — draft a blue-team email to a domain's published security contact. Sending is OFF unless a verified provider is configured (DISCLOSURE_SEND_ENABLED + RESEND_API_KEY/MAILGUN + DISCLOSURE_FROM_EMAIL). Attributable only — never anonymous; you confirm every send.</div>
    <div class="trow"><input class="t-arg" id="dc-domain" placeholder="domain (auto-draft from its security contact)"><button class="jbtn" id="dc-draft">draft</button></div>
    <div class="trow"><input class="t-arg" id="dc-to" placeholder="recipient (security@ / abuse@ ...)"></div>
    <div class="trow"><input class="t-arg" id="dc-subject" placeholder="subject"></div>
    <textarea id="dc-body" rows="7" placeholder="email body (review carefully)" style="width:100%;background:#000;border:1px solid var(--border);color:var(--green);font:inherit;padding:6px 8px;"></textarea>
    <div class="trow"><label style="font-size:10px;color:#bbb;"><input type="checkbox" id="dc-confirm"> I verified this is accurate and authorize sending from my address</label><button class="jbtn" id="dc-send">send</button></div>
    <div id="dc-result"></div>
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
  <div id="footer" style="text-align:center;padding:9px 0 4px;border-top:1px solid var(--border);margin-top:4px;">
    <button class="btn" id="btn-export" title="Download all your chats, memory, jobs and settings as a JSON file">&#8675; export my data (JSON)</button>
    <button class="btn" id="btn-import" title="Restore chats, memory, jobs and settings from an exported JSON file">&#8673; import</button>
    <input type="file" id="imp-file" accept="application/json" style="display:none">
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
    debug:el('s-debug').checked, brave:el('s-brave').value, reason:el('s-reason').value, aitools:(el('s-aitools')?el('s-aitools').checked:true) })); }catch(e){}
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
function addCopyBtn(elm, text){
  var b=document.createElement('button'); b.className='btn'; b.style.cssText='margin-top:5px;font-size:9px;padding:1px 7px;'; b.textContent='copy';
  b.onclick=function(){ if(navigator.clipboard){ navigator.clipboard.writeText(text).then(function(){ b.textContent='copied!'; setTimeout(function(){ b.textContent='copy'; },1200); }); } };
  elm.appendChild(b);
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
['s-search','s-temp','s-topk','s-debug','s-brave','s-reason','s-aitools'].forEach(function(id){
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
  if('aitools' in s && el('s-aitools')) el('s-aitools').checked=s.aitools;
  if('brave' in s) el('s-brave').value=s.brave;
  if('reason' in s) el('s-reason').value=s.reason;
  if(s.debug){ dbgPane.classList.add('show'); el('btn-dbg').classList.add('on'); }
})();

async function init(){
  renderChats(); renderLog(active());
  try{
    var d=await (await fetch('/api/status')).json();
    modeline.textContent='llama-3.1-8b · '+(d.retrieval||'?')+' RAG · memory on · NVD/EPSS/KEV · RDAP/DNS/CT/Shodan · web'+(d.ctfSafeMode?' · CTF safe':'');
    stat.textContent=ts()+' · corpus: '+d.docCount+' posts / '+(d.chunkCount||0)+' chunks · '+(d.totalChars||0).toLocaleString()+' chars'+(d.memory?' · KV sync':'')+(d.ctfSafeMode?' · CTF safe-mode':'');
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
  { var od=detectOsint(q, window.__lastOsint); if(od.isOsint){ window.__lastOsint={emails:od.emails,ips:od.ips,domains:od.domains,handles:od.handles,cves:od.cves,images:od.images,crypto:od.crypto,onions:od.onions,hashes:od.hashes,persons:od.persons}; try{ await runOsintFlow(q, od, c); }catch(err){ addMsg('system','OSINT run error: '+err.message); } busy=false; inp.disabled=false; inp.focus(); return; } }
  var el2=addMsg('agent',''); el2.className='msg agent streaming'; var full=''; var firstTok=true;
  el2.innerHTML='<span class="spinner"></span><span class="think">Agent Garrett is thinking…</span>'; window.__chipsEl=null;
  var opts={ webSearch:el('s-search').checked, temperature:parseFloat(el('s-temp').value),
             topK:parseInt(el('s-topk').value,10), brave:el('s-brave').value||'', reasoning:el('s-reason').value, aiTools:(el('s-aitools')?el('s-aitools').checked:true) };
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
        if(line.indexOf('data: TOOL:')===0){ var tn=line.slice(11).trim(); if(tn){ if(!window.__chipsEl){ window.__chipsEl=document.createElement('div'); window.__chipsEl.className='tool-chips'; log.insertBefore(window.__chipsEl, el2); } window.__chipsEl.insertAdjacentHTML('beforeend','<span class="tchip">&#128295; '+tn+'</span>'); } continue; }
        if(line.indexOf('data: DBG:')===0){
          var p=line.slice(10); var sep=p.indexOf('|');
          dbg(sep>=0?p.slice(0,sep):p, sep>=0?p.slice(sep+1):''); continue;
        }
        if(line.indexOf('data: ')!==0) continue;
        try{ var obj=JSON.parse(line.slice(6)); var t=obj.response||''; if(t){ if(firstTok){ el2.textContent=''; firstTok=false; } full+=t; el2.textContent+=t; log.scrollTop=log.scrollHeight; } }catch(e3){}
      }
    }
  }catch(e){ full=(full||'')+'\\n[error] '+e.message; el2.textContent=full; }
  el2.className='msg agent';
  if(full.trim()){ el2.innerHTML=renderMarkdown(full); addCopyBtn(el2, full); c.msgs.push({role:'assistant',content:full}); saveChats(chats); MEM.add(q+' \u2192 '+full.slice(0,500),'finding'); } else { el2.textContent='[no response]'; }
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
        {id:'t1', title:'Ownership / ASN (RDAP)', prompt:'Report ONLY the registration data present in the RDAP tool results for '+t+' (registrar, ASN, country, dates, nameservers, abuse contact). If the RDAP result says UNKNOWN or returned nothing, say exactly that. Do NOT invent WHOIS fields, owner names, addresses, phone numbers, or emails.'},
        {id:'t2', title:'Known associations',      prompt:'Using ONLY the corpus and web-search results provided, list anything genuinely associated with '+t+'. If nothing is found, say "no associations found in available sources." Do not speculate. Passive OSINT only, no scanning.'},
        {id:'t3', title:'Relevant services/CVEs',  prompt:'Based ONLY on the research corpus, what service or CVE classes are relevant to infrastructure like '+t+'? If the corpus has nothing specific, say so. Defensive framing.', dep:['t1']}
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
           topK:parseInt(el('s-topk').value,10), brave:el('s-brave').value||'', reasoning:el('s-reason').value, aiTools:(el('s-aitools')?el('s-aitools').checked:true) };
}
async function callTask(objective, context, grounded){
  var res=await fetch('/api/task',{ method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ objective:objective, context:context||'', memory:grounded?'':MEM.retrieve(objective,4), grounded:!!grounded, settings:curOpts() }) });
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
        addMsg('system','> running task: '+t.title);
        try{
          var ctx=(t.dep||[]).map(function(d){ return '['+d+'] '+(results[d]||''); }).join('\\n\\n').slice(0,2000);
          var out=await callTask(t.prompt, ctx);
          results[t.id]=out; done[t.id]=true;
          MEM.add('['+(template||'job')+'] '+t.title+': '+out.slice(0,500),'finding');
          jstatus(t.id,'done');
          var pd=addMsg('agent',''); pd.className='msg agent jtaskout';
          pd.innerHTML='<div class="jt-h">task done - '+t.title+'</div>'+renderMarkdown(out);
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

// ============ Autonomous OSINT (auto-detected from chat) ============
function detectOsint(q, prev){
  var text=String(q||'').trim(), low=text.toLowerCase();
  function uniq(a){ return a.filter(function(x,i){ return a.indexOf(x)===i; }); }
  var images=uniq(text.match(/https?:\\/\\/[^\\s)]+?\\.(?:jpe?g|png|gif|webp|bmp|tiff?)(?:\\?[^\\s)]*)?/ig)||[]);
  var emails=uniq(text.match(/[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}/g)||[]);
  var ips=uniq((text.match(/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/g)||[]).filter(function(ip){ return ip.split('.').every(function(o){ return +o>=0&&+o<=255; }); }));
  var cves=uniq((text.match(/CVE-\\d{4}-\\d+/ig)||[]).map(function(c){ return c.toUpperCase(); }));
  var crypto=uniq(text.match(/\\b(?:bc1[a-z0-9]{20,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,39}|0x[a-fA-F0-9]{40})\\b/g)||[]);
  var onions=uniq((text.match(/\\b[a-z2-7]{16}\\.onion\\b|\\b[a-z2-7]{56}\\.onion\\b/ig)||[]).map(function(x){ return x.toLowerCase(); }));
  var hashes=uniq((text.match(/\\b[a-f0-9]{64}\\b|\\b[a-f0-9]{40}\\b|\\b[a-f0-9]{32}\\b/ig)||[]).map(function(x){ return x.toLowerCase(); }));
  var emailDoms={}; emails.forEach(function(e){ emailDoms[e.split('@')[1].toLowerCase()]=1; });
  var imgHosts={}; images.forEach(function(x){ try{ imgHosts[new URL(x).hostname.toLowerCase()]=1; }catch(e){} });
  var domains=uniq((text.match(/\\b(?:[a-z0-9\\-]+\\.)+[a-z]{2,24}\\b/ig)||[]).map(function(d){ return d.toLowerCase(); })
    .filter(function(d){ return !/\\.(md|txt|js|json|png|jpe?g|gif|svg|webp|bmp|tiff?|exe|dll|sh|py|html?|css|ya?ml|pdf|zip)$/.test(d); })
    .filter(function(d){ return !emailDoms[d] && !imgHosts[d]; })
    .filter(function(d){ return !/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(d); }));
  var handles=uniq((text.match(/(?:^|\\s)@([A-Za-z0-9_]{2,30})/g)||[]).map(function(s){ return s.trim().replace(/^@/,''); }));
  var um=low.match(/\\b(?:username|handle|user|account|alias)\\s*[:=]?\\s*['"]?([a-z0-9_.\\-]{2,30})/);
  if(um){ handles.push(um[1]); handles=uniq(handles); }
  // Generic vocabulary is NEVER an entity/target — stops 'show me malware examples' from
  // running username/stealer/keybase on the literal word 'malware'.
  var COMMON=/^(malware|samples?|virus(es)?|trojans?|ransomware|stealers?|payloads?|exploits?|code|snippets?|examples?|corpus|research|vulnerabilit(y|ies)|cve|hash(es)?|breach(es)?|leaks?|dumps?|dark|web|darkweb|onion|tor|phishing|scans?|recon|osint|targets?|demo|poc|attacks?|threats?|actors?|campaigns?|loaders?|injectors?|shellcode|exfil|techniques?|robots|txt|packs|assets|dist|static|login|about|home|search|malicious|security|info|data|something|anything|everything|nothing|stuff|things?|new|latest|update|recent)$/;
  var TRIG=['osint','investigate','recon','reconnaissance','footprint','look up','lookup','look at','take a look','find everything','find anything','dig up','enumerate','who is','whois','background on','attribution','intel on','gather intel','profile','trace','check','scan','analyze','analyse','fingerprint','reputation','breach','pwned','leaked','leak','exposed','behind','onion','dark web','darkweb','image','photo','picture','exif','geolocate','email security','spf','dmarc','spoof','typosquat','lookalike','phishing','wallet','bitcoin','ethereum','malware','sample','hash','virus','trojan','stealer','ransomware','reverse engineer','breakdown','osin','conduct','look into','dig into','look up','run osint'];
  var hasTrigger=TRIG.some(function(t){ return low.indexOf(t)>=0; });
  var persons=uniq(text.match(/\\b[A-Z][a-z'\\-]{1,}\\s+[A-Z][a-z'\\-]{1,}(?:\\s+[A-Z][a-z'\\-]{1,})?\\b/g)||[]);
  var pnm=low.match(/(?:look into|look up|investigate|osint(?: on)?|profile(?: of)?|recon|stalk|dig into|background on|person(?: named| called)?|named|called|info on|intel on|dossier on|about|who is|who's|search for)\\s+(?:the\\s+person\\s+|the\\s+|a\\s+|an\\s+)?([a-z][a-z'\\-]+(?:\\s+[a-z][a-z'\\-]+){1,2})/);
  if(pnm){ var cnm=pnm[1].trim(); if(!/\\b(the|this|that|dark|web|domain|website|site|email|address|ip|hash|sample|malware|exploit|onion|tor|breach|leak|leaked|exposure|company|server|forum|page|guy|persons?|people|profile|account|target|username|handle|everything|anything|info|information|details|more|whatever)\\b/.test(cnm)) persons.push(cnm.replace(/\\b[a-z]/g,function(ch){ return ch.toUpperCase(); })); }
  persons=uniq(persons.filter(function(p){ return !/^(the|a|an|agent|osint|hello|hi|hey|dear|mr|ms|dr|new|good)\\b/i.test(p); }));
  // Handle only via an EXPLICIT command verb ('osint X', 'recon bob123', 'enumerate user42') —
  // never by grabbing the last word of any sentence that merely mentions a topic word.
  if(!handles.length && !emails.length){
    var hcmd=low.match(/\\b(?:osint|investigate|recon|reconnaissance|enumerate|profile|footprint|stalk|trace|look (?:up|into)|dig (?:up|into)|run osint|background on|intel on)\\s+(?:on\\s+|the\\s+|user\\s+|account\\s+|handle\\s+)?@?([a-z0-9][a-z0-9_.\\-]{2,29})\\b/);
    if(hcmd && hcmd[1].indexOf('.')<0 && !COMMON.test(hcmd[1])){ handles.push(hcmd[1]); handles=uniq(handles); }
  }
  // Drop any generic-word handles/persons that slipped through.
  handles=handles.filter(function(h){ return !COMMON.test(h); });
  persons=persons.filter(function(p){ return !COMMON.test(p.toLowerCase()) && !COMMON.test(p.toLowerCase().split(' ')[0]); });
  var personHint=/\\b(person|people|name|individual|someone|identity)\\b/.test(low);
  var refPrev=/\\b(it|its|that|this|him|her|them|he|she|his|hers|their|theirs|this (guy|man|woman|person|individual|account|user)|that (guy|man|woman|person)|the (site|website|domain|host|server|forum|page|url|ip|target|company|org|organization|image|photo|person|individual|guy))\\b/i.test(low);
  var entityCount=emails.length+ips.length+domains.length+handles.length+cves.length+images.length+crypto.length+onions.length+hashes.length+persons.length;
  var soloEntity=(entityCount===1)&&(text.split(/\\s+/).length<=2);
  if(entityCount===0 && prev && (hasTrigger||refPrev||personHint)){
    emails=(prev.emails||[]).slice(); ips=(prev.ips||[]).slice(); domains=(prev.domains||[]).slice(); handles=(prev.handles||[]).slice(); cves=(prev.cves||[]).slice(); images=(prev.images||[]).slice(); crypto=(prev.crypto||[]).slice(); onions=(prev.onions||[]).slice(); hashes=(prev.hashes||[]).slice(); persons=(prev.persons||[]).slice();
    entityCount=emails.length+ips.length+domains.length+handles.length+cves.length+images.length+crypto.length+onions.length+hashes.length+persons.length;
  }
  var intent='full';
  if(images.length || /\\b(image|photo|picture|exif|reverse image|geoloc)\\b/.test(low)) intent='image';
  else if(onions.length || /\\b(onion|dark ?web|tor network|leaked on|paste dump|stealer ?logs?|infostealer|am i (on |pwned|exposed))/.test(low)) intent='darkweb';
  else if(hashes.length || /\\b(malware|sample|virus|trojan|stealer|ransomware|payload|reverse engineer|disassemble|md5|sha1|sha256|sha-1|sha-256)\\b/.test(low)) intent='malware';
  else if(/\\b(origin|behind|real ip|true ip|bypass|unmask)\\b/.test(low)) intent='origin';
  else if(/\\b(discourse|wordpress|drupal|joomla|cms|tech stack|framework|fingerprint|built with|built on|powered by|running|is it a|is it an)\\b/.test(low)) intent='tech';
  else if(/\\b(breach|pwned|leaked|leak|exposed|hibp|compromis)\\b/.test(low)) intent='breach';
  else if(persons.length && (personHint || /\\b(look into|look up|background|investigate|profile|who is|find|search for|named|recon|dossier|osint|footprint|dig)\\b/.test(low))) intent='person';
  else if(cves.length && !domains.length && !ips.length && !emails.length && !handles.length) intent='cve';
  var hasIntent=intent!=='full';
  var actionable=hasTrigger||hasIntent||(refPrev&&!!prev);
  var strongEntity=(emails.length+handles.length+ips.length+(hashes?hashes.length:0)+(onions?onions.length:0)+(crypto?crypto.length:0)+(images?images.length:0))>0;
  var isOsint=(entityCount>0&&actionable)||soloEntity||(hasTrigger&&personHint)||strongEntity;
  var explicitSweep=/\\b(osint|investigate|reconnaissance|recon|profile|dossier|footprint|background|everything|full (report|sweep|scan)|deep dive)\\b/.test(low);
  var narrowAsk=(/\\?/.test(text)||/^(is|are|does|do|where|which|was|were|has|have|can)\\b/.test(low)) && /\\b(tor ?exit|exit node|geoloc|geolocat|located|location|who owns|reputation|malicious|blacklist|black ?listed|phish|phishing|open ports?|spf|dmarc|breached|pwned|proxy|vpn|takeover|typosquat|valid email|mx record)\\b/.test(low);
  if(narrowAsk && !explicitSweep) isOsint=false;
  return { isOsint:!!isOsint, intent:intent, emails:emails, ips:ips, domains:domains, handles:handles, cves:cves, images:images, crypto:crypto, onions:onions, hashes:hashes, persons:persons, keyword:text };
}

function osintSummary(od){
  var p=[];
  if(od.emails.length) p.push('email:'+od.emails.join(','));
  if(od.handles.length) p.push('user:'+od.handles.join(','));
  if(od.domains.length) p.push('domain:'+od.domains.join(','));
  if(od.ips.length) p.push('ip:'+od.ips.join(','));
  if(od.cves.length) p.push('cve:'+od.cves.join(','));
  if(od.images && od.images.length) p.push('image:'+od.images.length);
  if(od.crypto && od.crypto.length) p.push('crypto:'+od.crypto.join(','));
  if(od.onions && od.onions.length) p.push('onion:'+od.onions.length);
  if(od.hashes && od.hashes.length) p.push('hash:'+od.hashes.length);
  if(od.persons && od.persons.length) p.push('person:'+od.persons.join(', '));
  return p.length?p.join(' | '):'keyword search';
}
async function runOsintTool(tool, arg){
  var args={}, k=TOOL_ARGKEY[tool]||'target'; if(arg) args[k]=arg;
  try{
    var r=await fetch('/api/tools/run',{ method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ tool:tool, args:args, target:arg, confirm:true, settings:curOpts() }) });
    var d=await r.json();
    if(!d.ok) return '('+tool+' failed: '+(d.error||('HTTP '+r.status))+')';
    return typeof d.result==='string'?d.result:JSON.stringify(d.result,null,2);
  }catch(e){ return '('+tool+' error: '+e.message+')'; }
}
async function runJobs(jobs, blocks, statusEl, label){
  var done=0, queue=jobs.slice();
  async function worker(){
    while(queue.length){
      if(window.__osintAbort) return;
      var j=queue.shift();
      var out=await runOsintTool(j[1], j[2]);
      blocks.push('=== '+j[0]+' ===\\n'+out);
      done++; statusEl.textContent='OSINT: '+label+' - '+done+'/'+jobs.length+' tools...';
      dbg('osint '+j[1], (j[2]||'')+' -> '+out.slice(0,140));
    }
  }
  await Promise.all([worker(),worker(),worker(),worker()]);
}
function riskScore(text){
  var pts=0, reasons=[];
  var bm=text.match(/(\\d+)\\s+breach\\(es\\)/i);
  if(bm && (+bm[1])>0){ pts+=Math.min(30,8+(+bm[1])*2); reasons.push(bm[1]+' breach(es)'); }
  if(/this exact password appears in/i.test(text)){ pts+=20; reasons.push('password compromised'); }
  if(/PUBLIC \\(listable!\\)/i.test(text)){ pts+=25; reasons.push('public cloud bucket'); }
  if(/commit emails \\(from public events\\)/i.test(text)){ pts+=10; reasons.push('email leaked via git'); }
  if(/DMARC: NONE|p=none/i.test(text)){ pts+=10; reasons.push('weak/absent DMARC (spoofable)'); }
  if(/SPF: NONE/i.test(text)){ pts+=8; reasons.push('no SPF'); }
  if(/lookalikes are REGISTERED/i.test(text)){ pts+=12; reasons.push('active typosquats'); }
  if(/onion site\\(s\\) referencing/i.test(text)){ pts+=20; reasons.push('dark-web mentions'); }
  if(/KNOWN TOR RELAY/.test(text)){ pts+=5; reasons.push('Tor relay IP'); }
  pts=Math.min(100,pts);
  var level= pts>=60?'HIGH':(pts>=30?'MEDIUM':(pts>0?'LOW':'MINIMAL'));
  return { score:pts, level:level, reasons:reasons };
}
function harvestPivots(text, known){
  function uniq(a){ return a.filter(function(x,i){ return a.indexOf(x)===i; }); }
  var kEmails=(known.emails||[]).map(function(x){ return x.toLowerCase(); });
  var kDomains=(known.domains||[]).map(function(x){ return x.toLowerCase(); });
  var kHashes=(known.hashes||[]).map(function(x){ return x.toLowerCase(); });
  var emails=uniq((text.match(/[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}/g)||[]).map(function(x){ return x.toLowerCase(); }))
    .filter(function(e){ return kEmails.indexOf(e)<0 && !/noreply|@example\\.com|@garrettstimpson/.test(e); });
  var doms=[];
  emails.forEach(function(e){ doms.push(e.split('@')[1]); });
  (text.match(/(?:blog|repo homepages|homepage|external domains):\\s*([^\\n|]+)/ig)||[]).forEach(function(seg){
    (seg.match(/https?:\\/\\/[^\\s,|]+|\\b[a-z0-9.\\-]+\\.[a-z]{2,}\\b/ig)||[]).forEach(function(d){
      try{ d=new URL(/^https?:/i.test(d)?d:'https://'+d).hostname; }catch(e){}
      doms.push(String(d).toLowerCase());
    });
  });
  var PLAT=/(github\\.com|githubusercontent|gitlab\\.com|pypi\\.org|npmjs|ycombinator|keybase\\.io|reddit\\.com|dev\\.to|hub\\.docker|docker\\.com|codeberg\\.org|mastodon|lobste\\.rs|gravatar|twitter\\.com|x\\.com|linkedin|facebook|google\\.|archive\\.org|crt\\.sh|abuse\\.ch|shodan|greynoise|ahmia|wikipedia|duckduckgo|bing\\.com|yandex|tineye|cloudflare|w3\\.org|schema\\.org|gstatic|fonts\\.|jsdelivr|cloudfront|hudsonrock|youtube)/i;
  doms=uniq(doms.filter(function(d){ return d && /\\./.test(d) && !PLAT.test(d) && kDomains.indexOf(d)<0; }));
  var names=uniq((text.match(/\\bname:\\s*([A-Z][A-Za-z'\\-]+(?:\\s+[A-Z][A-Za-z'\\-]+){1,2})/g)||[]).map(function(x){ return x.replace(/name:\\s*/i,'').trim(); }));
  var hashes=uniq((text.match(/\\b[a-f0-9]{40}\\b|\\b[a-f0-9]{32}\\b/ig)||[]).map(function(x){ return x.toLowerCase(); })).filter(function(h){ return kHashes.indexOf(h)<0; }).slice(0,4);
  var samples=uniq(text.match(/https?:\\/\\/[^\\s"'<>\\/]+\\.[a-z]{2,}\\/[^\\s"'<>]*?\\.(?:exe|dll|bin|jar|apk|ps1|vbs|hta|scr|msi|cab|iso|7z|gz|tar)(?:\\?[^\\s"'<>]*)?/ig)||[]).slice(0,4);
  var onions=uniq((text.match(/[a-z2-7]{16}\\.onion|[a-z2-7]{56}\\.onion/ig)||[]).map(function(x){ return x.toLowerCase(); })).filter(function(o){ return o.indexOf('juhanurmihxlp')!==0; }).slice(0,3);
  var cryptos=uniq(text.match(/\\b(?:bc1[a-z0-9]{20,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,39}|0x[a-fA-F0-9]{40})\\b/g)||[]).slice(0,3);
  var phandles=[];
  var PROF=/(?:github\\.com|gitlab\\.com|twitter\\.com|x\\.com|instagram\\.com|keybase\\.io|t\\.me|dev\\.to|codeberg\\.org|mastodon\\.social|reddit\\.com\\/(?:user|u)|linkedin\\.com\\/in)\\/@?([a-z0-9_.\\-]{3,30})/ig;
  var pm; while((pm=PROF.exec(text))){ var ph=pm[1].toLowerCase(); if(!/^(login|about|home|search|explore|settings|help|signup|signin|status|share|intent|hashtag|tos|privacy|notifications|messages|orgs|sponsors|features|pricing|topics|collections|trending|marketplace|enterprise|security|blog|docs)$/.test(ph)) phandles.push(ph); }
  phandles=uniq(phandles).filter(function(h){ return (known.handles||[]).indexOf(h)<0; }).slice(0,6);
  var LEADDENY=/(google\\.|bing\\.com|duckduckgo|yandex|baidu|facebook\\.com|instagram\\.com|twitter\\.com|x\\.com|linkedin\\.com|reddit\\.com|youtube\\.|youtu\\.be|play\\.google|apps\\.apple|apkmirror|gizmodo|pinterest|tiktok|amazon\\.|ebay\\.|\\/search\\?|\\/wiki\\/%)/i;
  var rawleads=uniq((text.match(/https?:\\/\\/[^\\s"'<>\\)\\]]+/ig)||[]).map(function(u){ return u.replace(/[.,);]+$/,''); }));
  var seenH={}, leads=[];
  rawleads.forEach(function(u){ var h; try{ h=new URL(u).hostname.toLowerCase(); }catch(e){ return; } var path=u.replace(/^https?:\\/\\/[^\\/]+/i,''); if(!path||path==='/') return; if(LEADDENY.test(u)) return; if(seenH[h]) return; seenH[h]=1; leads.push(u); });
  return { emails:emails, domains:doms.slice(0,4), names:names.slice(0,2), hashes:hashes, samples:samples, onions:onions, cryptos:cryptos, phandles:phandles, leads:leads.slice(0,4) };
}

async function runOsintFlow(q, od, c){
  var FENCE=String.fromCharCode(96,96,96);
  addMsg('system','> OSINT run ('+(od.intent||'full')+') - '+osintSummary(od));
  window.__osintAbort=false; var stopBtn=el('btn-stop'); if(stopBtn){ stopBtn.style.display=''; stopBtn.textContent='stop'; }
  var jobs=[];
  function addIpFull(x){ ['ip_geo','asn_info','rdap_ip','shodan_internetdb','reverse_dns','greynoise','tor_exit'].forEach(function(t){ jobs.push([t+' '+x,t,x]); }); }
  function addDomainFull(x){ ['rdap_domain','dns_records','crtsh_subs','wellknown','tech_fingerprint','origin_ip','http_headers','urlscan','wayback','urlhaus','email_security','typosquat','bucket_finder','cors_check','subdomain_takeover','stealer_check','crawl'].forEach(function(t){ jobs.push([t+' '+x,t,(t==='http_headers'||t==='tech_fingerprint'||t==='cors_check'||t==='crawl')?('https://'+x):x]); }); }
  if(od.intent==='image'){
    (od.images||[]).forEach(function(x){ jobs.push(['image_osint '+x,'image_osint',x]); });
    if(!(od.images||[]).length) addMsg('system','OSINT(image): no image URL found - paste a direct image link (jpg/png/...).');
  } else if(od.intent==='darkweb'){
    var dterms=[]; (od.emails||[]).forEach(function(x){ dterms.push(x); }); (od.domains||[]).forEach(function(x){ dterms.push(x); }); (od.handles||[]).forEach(function(x){ dterms.push(x); });
    if(!dterms.length) dterms.push(od.keyword);
    dterms.slice(0,4).forEach(function(x){ jobs.push(['exposure_search '+x,'exposure_search',x]); jobs.push(['onion_search '+x,'onion_search',x]); });
    (od.onions||[]).forEach(function(x){ jobs.push(['onion_fetch '+x,'onion_fetch',x]); });
    (od.emails||[]).forEach(function(x){ jobs.push(['breach_check '+x,'breach_check',x]); });
  } else if(od.intent==='malware'){
    (od.hashes||[]).forEach(function(x){ jobs.push(['hash_lookup '+x,'hash_lookup',x]); });
    var furl=''; var hi=q.indexOf('http'); if(hi>=0) furl=q.slice(hi).split(' ')[0];
    if(furl) jobs.push(['file_analyze '+furl,'file_analyze',furl]);
    if(!jobs.length) addMsg('system','OSINT(malware): provide a file hash (md5/sha1/sha256) or a sample URL.');
  } else if(od.intent==='origin'){
    od.domains.forEach(function(x){ jobs.push(['origin_ip '+x,'origin_ip',x]); jobs.push(['dns_lookup '+x,'dns_lookup',x]); jobs.push(['crtsh_subs '+x,'crtsh_subs',x]); });
    od.ips.forEach(addIpFull);
  } else if(od.intent==='tech'){
    od.domains.forEach(function(x){ jobs.push(['tech_fingerprint '+x,'tech_fingerprint','https://'+x]); jobs.push(['vuln_scan '+x,'vuln_scan','https://'+x]); jobs.push(['http_headers '+x,'http_headers','https://'+x]); jobs.push(['wellknown '+x,'wellknown',x]); });
  } else if(od.intent==='breach'){
    od.emails.forEach(function(x){ jobs.push(['exposure_search '+x,'exposure_search',x]); jobs.push(['email_recon '+x,'email_recon',x]); });
    od.handles.forEach(function(x){ jobs.push(['exposure_search '+x,'exposure_search',x]); jobs.push(['username_enum '+x,'username_enum',x]); jobs.push(['github_user '+x,'github_user',x]); });
    od.domains.forEach(function(x){ jobs.push(['exposure_search '+x,'exposure_search',x]); });
  } else if(od.intent==='person'){
    (od.persons||[]).forEach(function(nm){
      var ql='"'+nm+'"';
      jobs.push(['web_search '+nm,'web_search',ql]);
      jobs.push(['web_search '+nm+' profiles','web_search',ql+' (linkedin OR github OR twitter OR facebook OR instagram OR email)']);
      (od.domains||[]).slice(0,1).forEach(function(dm){ jobs.push(['web_search '+nm+' '+dm,'web_search',ql+' '+dm]); });
      var ctx=q.toLowerCase().replace(/[",]/g,' ').split(/\\s+/).filter(function(w){ return w && w.length>1 && nm.toLowerCase().split(' ').indexOf(w)<0 && ['osint','investigate','profile','recon','stalk','who','whos','is','person','named','called','about','the','a','an','please','find','look','into','up','on','background','info','intel','dossier','search','for','of','people','dig','everything','anything'].indexOf(w)<0; }).join(' ').trim();
      if(ctx.length>2) jobs.push(['web_search '+nm+' ['+ctx+']','web_search',ql+' '+ctx]);
      jobs.push(['github code search '+nm,'github_osint',ql]);
      jobs.push(['people_search '+nm,'people_search',nm]);
      jobs.push(['edgar '+nm,'edgar',nm]);
      var p=nm.toLowerCase().replace(/[^a-z ]/g,'').split(/\\s+/).filter(Boolean);
      if(p.length>=2){ var f=p[0],l=p[p.length-1]; var cand=[f+l,f[0]+l,f+'.'+l,f+'_'+l,l+f]; cand.slice(0,5).forEach(function(u){ jobs.push(['username_enum '+u,'username_enum',u]); jobs.push(['github_user '+u,'github_user',u]); }); cand.slice(0,3).forEach(function(u){ jobs.push(['keybase '+u,'keybase',u]); jobs.push(['devto_user '+u,'devto_user',u]); }); }
    });
    (od.emails||[]).forEach(function(x){ jobs.push(['breach_check '+x,'breach_check',x]); jobs.push(['email_recon '+x,'email_recon',x]); jobs.push(['stealer_check '+x,'stealer_check',x]); });
    (od.handles||[]).forEach(function(x){ jobs.push(['username_enum '+x,'username_enum',x]); jobs.push(['github_user '+x,'github_user',x]); jobs.push(['keybase '+x,'keybase',x]); jobs.push(['devto_user '+x,'devto_user',x]); });
  } else if(od.intent==='cve'){
    od.cves.forEach(function(x){ jobs.push(['NVD '+x,'nvd_lookup',x]); jobs.push(['CVE detail '+x,'circl_cve',x]); jobs.push(['EPSS '+x,'epss_lookup',x]); jobs.push(['KEV '+x,'kev_lookup',x]); jobs.push(['PoC '+x,'cve_poc',x]); jobs.push(['web_search '+x,'web_search',x+' exploit advisory patch']); });
  } else {
    od.cves.forEach(function(x){ jobs.push(['CVE detail '+x,'circl_cve',x]); jobs.push(['KEV '+x,'kev_lookup',x]); jobs.push(['EPSS '+x,'epss_lookup',x]); jobs.push(['PoC '+x,'cve_poc',x]); });
    od.ips.forEach(addIpFull);
    od.domains.forEach(addDomainFull);
    od.emails.forEach(function(x){ jobs.push(['breach_check '+x,'breach_check',x]); jobs.push(['email_recon '+x,'email_recon',x]); jobs.push(['gravatar '+x,'gravatar',x]); jobs.push(['stealer_check '+x,'stealer_check',x]); jobs.push(['leakcheck '+x,'leakcheck',x]); });
    od.handles.forEach(function(x){ jobs.push(['username_enum '+x,'username_enum',x]); jobs.push(['github_user '+x,'github_user',x]); jobs.push(['stealer_check '+x,'stealer_check',x]); });
    (od.images||[]).forEach(function(x){ jobs.push(['image_osint '+x,'image_osint',x]); });
    (od.crypto||[]).forEach(function(x){ jobs.push(['crypto_addr '+x,'crypto_addr',x]); });
    (od.onions||[]).forEach(function(x){ jobs.push(['onion_fetch '+x,'onion_fetch',x]); });
    var sterms=[];
    (od.handles||[]).forEach(function(h){ sterms.push('"'+h+'"'); });
    (od.emails||[]).forEach(function(e){ sterms.push('"'+e+'"'); });
    (od.domains||[]).forEach(function(d){ sterms.push(d); });
    (od.ips||[]).forEach(function(i){ sterms.push('"'+i+'"'); });
    (od.cves||[]).forEach(function(cv){ sterms.push(cv+' exploit advisory'); });
    if(!sterms.length) sterms.push(q);
    sterms.slice(0,3).forEach(function(tm){ jobs.push(['web_search '+tm,'web_search',tm]); });
    var oterm=(od.emails[0]||od.domains[0]||od.handles[0]);
    if(oterm) jobs.push(['onion_search '+oterm,'onion_search',oterm]);
  }
  if(!jobs.length){ addMsg('system','OSINT: no actionable entity detected.'); return; }
  var blocks=[];
  var st1=addMsg('system','OSINT: round 1 - 0/'+Math.min(jobs.length,30)+' tools...');
  await runJobs(jobs.slice(0,30), blocks, st1, 'round 1');
  st1.textContent='OSINT: round 1 complete ('+blocks.length+' tools).';
  var pv=harvestPivots(blocks.join('\\n'), od);
  var doEntityPivot=(od.intent==='full'||od.intent==='person');
  if((doEntityPivot || (pv.leads||[]).length) && !window.__osintAbort){
    var pjobs=[];
    if(doEntityPivot){
      pv.emails.forEach(function(e){ pjobs.push(['breach_check '+e,'breach_check',e]); pjobs.push(['gravatar '+e,'gravatar',e]); pjobs.push(['email_recon '+e,'email_recon',e]); pjobs.push(['onion_search '+e,'onion_search',e]); });
      pv.domains.forEach(function(d){ pjobs.push(['tech_fingerprint '+d,'tech_fingerprint','https://'+d]); pjobs.push(['rdap_domain '+d,'rdap_domain',d]); pjobs.push(['dns_lookup '+d,'dns_lookup',d]); pjobs.push(['crtsh_subs '+d,'crtsh_subs',d]); });
      pv.names.forEach(function(nm){ pjobs.push(['web_search '+nm,'web_search','"'+nm+'"']); });
      (pv.phandles||[]).forEach(function(h){ pjobs.push(['username_enum '+h,'username_enum',h]); pjobs.push(['github_user '+h,'github_user',h]); pjobs.push(['keybase '+h,'keybase',h]); pjobs.push(['devto_user '+h,'devto_user',h]); });
      pv.domains.forEach(function(d){ pjobs.push(['crawl '+d,'crawl','https://'+d]); });
      (pv.hashes||[]).forEach(function(h){ pjobs.push(['hash_lookup '+h,'hash_lookup',h]); });
      (pv.samples||[]).forEach(function(su){ pjobs.push(['file_analyze '+su,'file_analyze',su]); });
      (pv.onions||[]).forEach(function(o){ pjobs.push(['onion_fetch '+o,'onion_fetch',o]); });
      (pv.cryptos||[]).forEach(function(c){ pjobs.push(['crypto_addr '+c,'crypto_addr',c]); });
    }
    (pv.leads||[]).forEach(function(u){ pjobs.push(['crawl '+u,'crawl',u]); });
    if(pjobs.length){
      var disc=[].concat(pv.emails,pv.domains,pv.names,pv.phandles||[],pv.hashes||[],pv.samples||[],pv.onions||[],pv.cryptos||[],pv.leads||[]).slice(0,12);
      addMsg('system','> pivot: '+disc.join(', ')+' - digging deeper ('+Math.min(pjobs.length,24)+' tools)');
      var preR2=blocks.length;
      var st2=addMsg('system','OSINT: round 2 (pivots) - 0/'+Math.min(pjobs.length,24)+' tools...');
      await runJobs(pjobs.slice(0,24), blocks, st2, 'round 2 (pivots)');
      st2.textContent='OSINT: round 2 complete.';
      if(!window.__osintAbort){
        var pv2=harvestPivots(blocks.slice(preR2).join('\\n'), od);
        var done={}; jobs.concat(pjobs).forEach(function(j){ done[j[1]+':'+String(j[2]).toLowerCase()]=1; });
        var p3=[];
        function add3(tool,arg){ var k=tool+':'+String(arg).toLowerCase(); if(arg && !done[k]){ done[k]=1; p3.push([tool+' '+arg,tool,arg]); } }
        (pv2.leads||[]).forEach(function(u){ add3('crawl',u); });
        (pv2.samples||[]).forEach(function(su){ add3('file_analyze',su); });
        (pv2.emails||[]).forEach(function(e){ add3('breach_check',e); add3('email_recon',e); });
        (pv2.phandles||[]).forEach(function(h){ add3('username_enum',h); add3('keybase',h); });
        (pv2.domains||[]).forEach(function(d){ add3('rdap_domain',d); });
        if(p3.length){
          addMsg('system','> recursion: following '+Math.min(p3.length,12)+' new lead(s) found inside fetched pages');
          var st3=addMsg('system','OSINT: round 3 (recursion) - 0/'+Math.min(p3.length,12)+' tools...');
          await runJobs(p3.slice(0,12), blocks, st3, 'round 3 (recursion)');
          st3.textContent='OSINT: round 3 complete.';
        }
      }
    } else { addMsg('system','> no new pivots surfaced from round 1.'); }
  }
  var evidence=blocks.join('\\n\\n');
  var ev=addMsg('agent',''); ev.className='msg agent jtaskout';
  ev.innerHTML='<div class="jt-h">collected evidence - '+blocks.length+' tool results</div>'+renderMarkdown(FENCE+'\\n'+evidence.slice(0,12000)+'\\n'+FENCE);
  if(window.__osintAbort){ if(stopBtn) stopBtn.style.display='none'; addMsg('system','OSINT run stopped - '+blocks.length+' partial result(s) shown above; synthesis skipped.'); return; }
  var synStatus=addMsg('system','OSINT: synthesizing write-up from '+blocks.length+' results...');
  var rs=riskScore(evidence);
  var showRisk=['full','person','breach','darkweb'].indexOf(od.intent)>=0;
  var rsLine='exposure risk (heuristic): '+rs.score+'/100 ['+rs.level+']'+(rs.reasons.length?' - '+rs.reasons.join('; '):'');
  if(showRisk) addMsg('system','> '+rsLine);
  var synth=blocks.map(function(b){ return b.slice(0,900); }).join('\\n\\n').slice(0,13500);
  if(showRisk) synth='RISK ASSESSMENT (heuristic, computed from the evidence): '+rsLine+'\\n\\n'+synth;
  var objective=(od.intent==='malware') ? ('You are writing a FORMAL MALWARE ANALYSIS report for: "'+q+'". Use ONLY the tool evidence in the context; never invent a fact not present in it; mark anything missing as UNKNOWN. Use this markdown structure:\\n## Executive Summary\\n## Sample Identification (hashes, file type, size)\\n## Reputation & Classification (Cymru MHR / VirusTotal / MalwareBazaar verdicts, malware family)\\n## Capabilities & Suspicious Indicators (notable APIs/strings and what they imply)\\n## Indicators of Compromise (URLs, IPs, hashes)\\n## MITRE ATT&CK Mapping (only techniques clearly evidenced)\\n## Detection & Mitigation\\n## Detection Rules (draft a YARA rule from the notable strings/imports, and a Sigma rule if process/registry/network indicators are evident)\\nBe precise and defensive.') : ('You are writing a FORMAL OSINT WRITE-UP for the request: "'+q+'". Use ONLY the tool evidence in the context - never invent a fact not present in it; mark anything missing as UNKNOWN. Do NOT merely restate tool output: ANALYZE it - infer the subject likely identity, connect accounts/emails/domains/repos that plausibly belong to the same person, and weigh your confidence. Use this markdown structure:\\n## Executive Summary (3-5 sentences with your assessment)\\n## Entities and Identifiers\\n## Findings (per source; note which tool produced each fact)\\n## Dark-web & Exposure (onion index, breaches, leaked/commit emails - or state none found)\\n## Pivots and Links (how discovered emails/domains/repos connect and what they reveal)\\n## Gaps and Confidence (what is UNKNOWN, reliability, plus 3-5 concrete recommended next OSINT steps)\\nBe precise, defensive in framing, and analytical.');
  if(od.intent==='person') objective='Write a FORMAL PERSON / IDENTITY OSINT report for: "'+q+'". Use ONLY the tool evidence; never invent; mark missing as UNKNOWN. CRITICAL: separate accounts/data CONFIRMED to be THIS specific person (corroborated by matching name, bio, or the user-provided context/domain) from generic same-name or same-username matches that are likely UNRELATED people — never attribute breach/stealer data or accounts to the subject unless clearly theirs. An account counts as CONFIRMED when its OWN profile, bio, or repository NAMES reference the subject name or a domain/site already tied to the subject (for example a GitHub user whose repositories include the subject website, or a profile whose bio names them) - corroborate such links explicitly and do NOT file them under unrelated. Use this markdown structure:\\n## Executive Summary (who this likely is + confidence)\\n## Confirmed Identifiers (accounts/emails/domains tied to THIS person, and why)\\n## Candidate / Unconfirmed Matches (same name/handle, possibly unrelated)\\n## Exposure (breaches / stealer logs ONLY for confirmed emails)\\n## Gaps & Recommended Next Steps\\nBe precise and label confidence honestly.';
  if(od.intent==='cve') objective='Write a FORMAL VULNERABILITY REPORT for: "'+q+'". Use ONLY the tool evidence; never invent CVSS/EPSS scores, affected versions, or dates. Use this markdown structure:\\n## Summary\\n## Severity (CVSS vector + base score, EPSS exploitation probability)\\n## Exploitation Status (CISA KEV listing, public PoC availability with links, any in-the-wild evidence)\\n## Affected & Fixed Versions\\n## Detection & Mitigation\\n## References\\nIMPORTANT: the NVD evidence often states affected/fixed versions inline (e.g. \"Versions before X, Y, Z are affected\") - extract those verbatim into Affected & Fixed Versions; only write UNKNOWN if no version string appears anywhere in the evidence.';
  if(od.intent==='darkweb') objective='Write a FORMAL DARK-WEB EXPOSURE report for: "'+q+'". Use ONLY the tool evidence; never invent; mark anything missing as UNKNOWN. Use this markdown structure:\\n## Executive Summary (overall exposure verdict)\\n## Stealer-Log / Infostealer Exposure (HudsonRock: infected hosts, dates, credential counts at risk)\\n## Breaches & Leaked Data (which breaches, exposed data classes, password exposure)\\n## Dark-Web / Onion Mentions\\n## Exposure Timeline (order breach/stealer dates oldest->newest)\\n## Cross-Selector Pivots (other emails/usernames/domains surfaced + what to search next)\\n## Risk & Remediation (passwords to rotate, accounts at risk, monitoring advice)\\nBe precise and defensive.';
  var report;
  try{ report=await callTask(objective, synth, true); }
  catch(e){ report='# OSINT write-up: '+q+'\\n\\n(synthesis failed: '+e.message+')\\n\\n'+evidence; }
  synStatus.textContent='OSINT run complete - '+blocks.length+' tool results across '+(od.intent==='full'?'2 rounds':'1 round')+'.';
  if(stopBtn) stopBtn.style.display='none';
  var d2=addMsg('agent',''); d2.innerHTML=renderMarkdown(report);
  var dl=document.createElement('button'); dl.className='btn'; dl.style.marginTop='6px'; dl.textContent='\u2913 download report (.md)';
  dl.onclick=function(){ var blob=new Blob([report],{type:'text/markdown'}); var u=URL.createObjectURL(blob); var a=document.createElement('a'); a.href=u; a.download='osint-'+(q.replace(/[^a-z0-9]+/ig,'-').replace(/^-|-$/g,'').slice(0,40)||'report')+'.md'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(u); };
  d2.appendChild(dl);
  var cp=document.createElement('button'); cp.className='btn'; cp.style.marginTop='6px'; cp.style.marginLeft='6px'; cp.textContent='copy report';
  cp.onclick=function(){ if(navigator.clipboard){ navigator.clipboard.writeText(report).then(function(){ cp.textContent='copied!'; setTimeout(function(){ cp.textContent='copy report'; },1500); }); } };
  d2.appendChild(cp);
  c.msgs.push({role:'assistant',content:report});
  if(c.msgs.length===1||(c.title||'').indexOf('[osint]')!==0) c.title='[osint] '+q.slice(0,30);
  saveChats(chats); renderChats();
  MEM.add('OSINT '+q+': '+report.slice(0,600),'finding');
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
        await (j.template==='osint' ? startOsint(j.objective) : runSwarmToChat(j.objective, j.template));
        break;
      }
    }
    if(changed) renderSaved();
  }, 60000);
}

// ============ Agent-panel wiring ============
el('btn-job').onclick=function(){ var on=el('jobs').classList.toggle('show'); el('btn-job').classList.toggle('on',on); };
el('btn-tools').onclick=function(){ var on=el('tools').classList.toggle('show'); el('btn-tools').classList.toggle('on',on); if(on) loadCatalog(); };
el('btn-disclose').onclick=function(){ var on=el('disclose').classList.toggle('show'); el('btn-disclose').classList.toggle('on',on); };
el('dc-draft').onclick=async function(){
  var dom=el('dc-domain').value.trim(); var out=el('dc-result'); if(!dom){ out.innerHTML='<div class="t-out">enter a domain to draft.</div>'; return; }
  out.innerHTML='<div class="t-out">drafting...</div>';
  try{
    var r=await fetch('/api/tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:'disclosure_draft',args:{target:dom},target:dom,confirm:true})});
    var d=await r.json(); var t=String(d.result||d.error||'');
    var rec=(t.match(/recipient\\(s\\):\\s*([^\\n,]+)/)||[])[1]||'';
    var subj=(t.match(/--- SUBJECT ---\\n([\\s\\S]*?)\\n\\n--- BODY ---/)||[])[1]||'';
    var body=(t.match(/--- BODY ---\\n([\\s\\S]*?)\\n\\nNOTE:/)||[])[1]||'';
    if(rec) el('dc-to').value=rec.trim(); if(subj) el('dc-subject').value=subj.trim(); if(body) el('dc-body').value=body.trim();
    var pre=document.createElement('div'); pre.className='t-out'; pre.textContent=t; out.innerHTML=''; out.appendChild(pre);
  }catch(e){ out.innerHTML='<div class="t-out">error: '+e.message+'</div>'; }
};
el('dc-send').onclick=async function(){
  var out=el('dc-result');
  if(!el('dc-confirm').checked){ out.innerHTML='<div class="t-out">Tick the confirmation box to authorize sending.</div>'; return; }
  var to=el('dc-to').value.trim(), subject=el('dc-subject').value.trim(), body=el('dc-body').value.trim();
  if(!to||!subject||!body){ out.innerHTML='<div class="t-out">Recipient, subject and body are required.</div>'; return; }
  out.innerHTML='<div class="t-out">sending...</div>';
  try{
    var r=await fetch('/api/send-disclosure',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to:to,subject:subject,body:body,confirm:true})});
    var d=await r.json();
    out.innerHTML='<div class="t-out">'+(d.ok?('sent via '+d.provider+' to '+d.to+(d.id?' (id '+d.id+')':'')):('NOT sent: '+(d.error||('HTTP '+r.status))))+'</div>';
  }catch(e){ out.innerHTML='<div class="t-out">error: '+e.message+'</div>'; }
};

el('btn-stop').onclick=function(){ window.__osintAbort=true; el('btn-stop').textContent='stopping...'; };
el('btn-export').onclick=function(){
  var data={ app:'Agent Garrett', exportedAt:new Date().toISOString(), schema:1,
    chats:(function(){ try{ return JSON.parse(localStorage.getItem('gsa_chats')||'[]'); }catch(e){ return chats; } })(),
    activeChat:(function(){ try{ return localStorage.getItem('gsa_active'); }catch(e){ return null; } })(),
    memory: MEM.all(), jobs: AGENT.loadJobs(),
    settings:(function(){ try{ return JSON.parse(localStorage.getItem('gsa_settings')||'{}'); }catch(e){ return {}; } })() };
  var blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  var url=URL.createObjectURL(blob); var a=document.createElement('a'); a.href=url;
  a.download='agent-garrett-export-'+new Date().toISOString().slice(0,10)+'.json';
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  addMsg('system','Exported '+data.chats.length+' chat(s), '+data.memory.length+' memory item(s), '+data.jobs.length+' job(s) to JSON.');
};
el('btn-import').onclick=function(){ el('imp-file').click(); };
el('imp-file').onchange=function(ev){
  var f=ev.target.files&&ev.target.files[0]; if(!f) return;
  var rd=new FileReader();
  rd.onload=function(){
    try{
      var data=JSON.parse(rd.result);
      if(data.chats){ try{ localStorage.setItem('gsa_chats', JSON.stringify(data.chats)); }catch(e){} }
      if(data.activeChat){ try{ localStorage.setItem('gsa_active', data.activeChat); }catch(e){} }
      if(data.settings){ try{ localStorage.setItem('gsa_settings', JSON.stringify(data.settings)); }catch(e){} }
      if(data.jobs){ try{ localStorage.setItem('gsa_jobs', JSON.stringify(data.jobs)); }catch(e){} }
      if(data.memory){ try{ localStorage.setItem('gsa_memory', JSON.stringify(data.memory)); }catch(e){} }
      addMsg('system','Imported '+((data.chats||[]).length)+' chat(s), '+((data.memory||[]).length)+' memory item(s). Reloading...');
      setTimeout(function(){ location.reload(); }, 800);
    }catch(e){ addMsg('system','Import failed: '+e.message); }
  };
  rd.readAsText(f);
};
var TOOL_ARGKEY={ nvd_lookup:'cveId', epss_lookup:'cveId', kev_lookup:'cveId', rdap_ip:'ip', rdap_domain:'domain', dns_lookup:'domain', cert_ct:'domain', shodan_internetdb:'ip', reverse_dns:'ip', http_headers:'url', web_search:'query', fetch_url:'url', ip_geo:'ip', asn_info:'target', wayback:'url', urlscan:'domain', urlhaus:'host', github_osint:'query', crtsh_subs:'domain', circl_cve:'cveId', greynoise:'ip', wellknown:'target', username_enum:'username', github_user:'username', gravatar:'email', email_recon:'email', breach_check:'email', tech_fingerprint:'url', origin_ip:'domain', image_osint:'url', onion_search:'query', email_security:'domain', typosquat:'domain', crypto_addr:'address', dns_records:'domain', tor_exit:'ip', pwned_password:'password', cve_search:'query', bucket_finder:'name', email_permutations:'input', cors_check:'url', subdomain_takeover:'domain', onion_fetch:'url', hash_lookup:'hash', file_analyze:'url', decode:'input', ioc_extract:'text', cvss:'vector', unshorten:'url', stealer_check:'target', leakcheck:'target', paste_search:'target', dork:'target', phish_check:'url', archive_urls:'domain', favicon_hash:'url', crawl:'url', disclosure_draft:'target', cve_poc:'cveId', kev_recent:'count', mitre:'technique', subdomains:'domain', jwt:'token', cidr:'input', hash_id:'hash', encode:'input', timestamp:'input', vuln_scan:'target', keybase:'username', devto_user:'username', people_search:'name', edgar:'name', opencorporates:'name', phone_osint:'phone', holehe:'email', exposure_search:'selector' };
async function loadCatalog(){
  try{
    var d=await (await fetch('/api/tools/catalog')).json();
    el('t-mode').textContent=(d.safeMode?'SAFE MODE on':'safe mode OFF')+(d.requireConfirm?' · confirm unlocks all tools':'')+(d.brokerConfigured?' · broker wired':' · no broker');
    el('t-mode').className='t-badge'+(d.safeMode?' safe':'');
    var cat=el('t-catalog'); cat.innerHTML=''; var sel=el('t-tool'); sel.innerHTML='';
    var tools=(d.tools||[]).slice().sort(function(a,b){ return (a.category+a.name).localeCompare(b.category+b.name); });
    var hdr=document.createElement('div'); hdr.className='tool-item'; hdr.style.color='var(--blue)'; hdr.style.marginBottom='4px';
    hdr.textContent=tools.length+' tools available (confirm box unlocks any of them)'; cat.appendChild(hdr);
    var curCat='';
    tools.forEach(function(t){
      if(t.category!==curCat){ curCat=t.category; var ch=document.createElement('div'); ch.className='tool-item'; ch.style.color='var(--muted)'; ch.style.textTransform='uppercase'; ch.style.letterSpacing='.08em'; ch.style.marginTop='6px'; ch.textContent='— '+curCat+' —'; cat.appendChild(ch); }
      var row=document.createElement('div'); row.className='tool-item';
      row.innerHTML='<strong style="color:#bbb">'+t.name+'</strong> <span class="tool-pill '+(t.passive?'passive':'active')+'">'+(t.passive?'passive':'active')+'</span> '+(t.description||'');
      cat.appendChild(row);
      var o=document.createElement('option'); o.value=t.name; o.textContent=t.name+'  ('+t.category+')'; sel.appendChild(o);
    });
    if(d.targetAllowlist && d.targetAllowlist.length){ var sc=document.createElement('div'); sc.className='tool-item'; sc.style.marginTop='6px'; sc.textContent='in-scope targets: '+d.targetAllowlist.join(', '); cat.appendChild(sc); }
  }catch(e){ el('t-catalog').textContent='catalog unavailable: '+e.message; }
}
el('t-run').onclick=async function(){
  var tool=el('t-tool').value, val=el('t-target').value.trim();
  var args={}; var k=TOOL_ARGKEY[tool]||'target'; if(val) args[k]=val;
  var out=el('t-result'); out.innerHTML='<div class="t-out">running '+tool+'…</div>';
  try{
    var r=await fetch('/api/tools/run',{ method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ tool:tool, args:args, target:val, confirm:el('t-confirm').checked, settings:curOpts() }) });
    var d=await r.json();
    if(!d.ok){ out.innerHTML=''; var er=document.createElement('div'); er.className='t-out'; er.textContent='error: '+(d.error||('HTTP '+r.status)); out.appendChild(er); return; }
    var res=typeof d.result==='string'?d.result:JSON.stringify(d.result,null,2);
    out.innerHTML=''; var pre=document.createElement('div'); pre.className='t-out';
    pre.textContent='['+d.via+'] '+tool+(d.target?' ('+d.target+')':'')+'\\n\\n'+res; out.appendChild(pre);
  }catch(e){ out.innerHTML=''; var er2=document.createElement('div'); er2.className='t-out'; er2.textContent='error: '+e.message; out.appendChild(er2); }
};
async function startOsint(obj){
  if(!obj || !obj.trim()) return;
  var od=detectOsint(obj, window.__lastOsint); od.isOsint=true;
  window.__lastOsint={emails:od.emails,ips:od.ips,domains:od.domains,handles:od.handles,cves:od.cves,images:od.images,crypto:od.crypto,onions:od.onions,hashes:od.hashes,persons:od.persons};
  busy=true; inp.disabled=true;
  var c=active(); addMsg('user',obj); c.msgs.push({role:'user',content:obj}); if(c.msgs.length===1) c.title='[osint] '+obj.slice(0,30); saveChats(chats); renderChats();
  try{ await runOsintFlow(obj, od, c); }catch(e){ addMsg('system','OSINT error: '+e.message); }
  busy=false; inp.disabled=false; inp.focus();
}
el('j-run').onclick=function(){ var tpl=el('j-tpl').value, obj=el('j-obj').value.trim(); if(tpl==='osint') startOsint(obj); else runSwarmToChat(obj, tpl); };
var JOB_TEMPLATES=[
  {label:'CVE deep-dive', tpl:'cve', text:'Profile CVE-2026-2005: CVSS severity, EPSS score, CISA KEV status, affected PostgreSQL versions, the patched release, public PoC availability, and detection guidance.'},
  {label:'Passive domain recon', tpl:'infra', text:'Passive recon of example.com using OSINT only (no scanning): RDAP ownership/registrar, DNS records (A/MX/NS/TXT), TLS certificate-transparency subdomains, and any related items in the research corpus.'},
  {label:'Attack-surface map', tpl:'infra', text:'Map the public attack surface of cloudflare.com from certificate-transparency and DNS data (passive only). List discovered subdomains, the services they imply, and defensive notes.'},
  {label:'Malware family brief', tpl:'malware', text:'Brief on Lumma Stealer: overview, MITRE ATT&CK TTPs, notable IOCs from the research, and detection + mitigation guidance.'},
  {label:'Patch-priority triage', tpl:'free', text:'Compare CVE-2026-42945 and CVE-2026-46333 using CVSS, EPSS, and CISA KEV status: which should be patched first and why? Give a short remediation order.'},
  {label:'Detection engineering', tpl:'free', text:'Draft detection logic (log sources, candidate signatures, and hunt queries) for the techniques in the DirtyDecrypt research. Defensive use only.'},
  {label:'Corpus threat brief', tpl:'free', text:'Summarize what the research corpus covers about ClickFix-style social-engineering campaigns on Windows and macOS, and how defenders detect them.'}
];
(function renderChips(){
  var box=el('j-chips'); if(!box) return;
  JOB_TEMPLATES.forEach(function(t){
    var b=document.createElement('button'); b.className='jchip'; b.type='button'; b.textContent=t.label;
    b.title='Click to load this example';
    b.onclick=function(){ el('j-obj').value=t.text; el('j-tpl').value=t.tpl; el('j-obj').focus(); };
    box.appendChild(b);
  });
})();
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

    // ── Access gate (custom login overlay) ──────────────────────────────────
    const ACCESS_PW = String(env.ACCESS_PASSWORD || '');
    const ACCESS_USER = String(env.ACCESS_USER || '');
    if (ACCESS_PW || ACCESS_USER) {
      const expected = await sha256hex('gsa|' + ACCESS_USER + '|' + ACCESS_PW);
      const cookie = request.headers.get('Cookie') || '';
      const authed = cookie.split(/;\s*/).some(c => c === 'gsa_auth=' + expected);
      const setCookie = `gsa_auth=${expected}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`;
      if (url.pathname === '/api/login' && request.method === 'POST') {
        let b = {}; try { b = await request.json(); } catch {}
        const okUser = !ACCESS_USER || String(b.user || '') === ACCESS_USER;
        const okPass = !ACCESS_PW   || String(b.password || '') === ACCESS_PW;
        if (okUser && okPass) {
          return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json', 'Set-Cookie': setCookie } });
        }
        return json({ ok: false, error: 'Invalid credentials' }, 401);
      }
      if (url.pathname === '/api/logout') {
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json', 'Set-Cookie': 'gsa_auth=; Path=/; Max-Age=0' } });
      }
      if (!authed) {
        if (url.pathname === '/' && request.method === 'GET') {
          return new Response(loginUI(env.SITE_NAME || 'Security Research', !!ACCESS_USER, !!ACCESS_PW), { status: 401, headers: { ...cors, 'Content-Type': 'text/html;charset=UTF-8' } });
        }
        return json({ ok: false, error: 'Authentication required' }, 401);
      }
    }

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
        const policy = getToolPolicy(env);
        return json({
          ok: true,
          docCount:   docIds.size,
          chunkCount: chunks.length,
          totalChars: chunks.reduce((s, c) => s + c.text.length, 0),
          retrieval:  env.VECTORIZE ? 'vectorize-semantic' : 'bm25-chunk',
          memory:     !!env.SESSIONS,
          ctfSafeMode: policy.safeMode,
          toolAllowlistCount: policy.toolAllowlist.size,
          targetAllowlistCount: policy.targetAllowlist.size,
          customToolCount: parseCustomTools(env).length,
        });
      } catch (e) { return json({ ok: false, error: e.message }, 500); }
    }

    // GET /api/tools/catalog — advertise wired tools and current policy state
    if (url.pathname === '/api/tools/catalog' && request.method === 'GET') {
      const policy = getToolPolicy(env);
      return json({
        ok: true,
        safeMode: policy.safeMode,
        requireConfirm: policy.requireConfirm,
        allowlistedTools: [...policy.toolAllowlist],
        targetAllowlist: [...policy.targetAllowlist],
        tools: toolCatalog(env),
        brokerConfigured: !!env.TOOL_BROKER_URL,
      });
    }

    // POST /api/tools/run — guarded tool execution entrypoint for CTF workflows
    if (url.pathname === '/api/tools/run' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch { return new Response('Bad JSON', { status: 400, headers: cors }); }
      const tool = String(body.tool || '').trim().toLowerCase();
      const args = body.args && typeof body.args === 'object' ? body.args : {};
      for (const k in args) { if (typeof args[k] === 'string') { const mm = args[k].match(/\]\((https?:\/\/[^)\s]+)\)/); if (mm) args[k] = mm[1]; args[k] = args[k].replace(/^[\[<("'\s]+|[\]>)"'\s]+$/g, '').trim(); } }
      const target = normalizeTarget(body.target || args.target || args.url || args.domain || args.ip || '');
      const policy = getToolPolicy(env);
      if (!tool) return json({ ok: false, error: 'tool is required' }, 400);
      if (policy.requireConfirm && body.confirm !== true) {
        return json({ ok: false, error: 'confirm=true is required in CTF safe mode' }, 400);
      }

      const access = validateToolAccess(policy, tool, target, body.confirm === true);
      if (!access.ok) return json(access, access.status || 403);

      const known = toolCatalog(env).some(t => t.name === tool);
      if (!known) return json({ ok: false, error: `Unknown tool: ${tool}` }, 404);

      try {
        const started = Date.now();
        let result;
        let via = 'builtin';
        if (isBuiltinTool(tool)) {
          result = await runBuiltinCached(env, tool, args);
        } else {
          via = 'broker';
          result = await runBrokerTool(env, {
            tool,
            args,
            target,
            reason: String(body.reason || ''),
            sessionId: String(body.sessionId || ''),
            requestedAt: new Date().toISOString(),
          });
        }

        console.log(JSON.stringify({
          event: 'tool_run',
          tool,
          via,
          target,
          safeMode: policy.safeMode,
          elapsedMs: Date.now() - started,
        }));

        return json({ ok: true, tool, via, target, result });
      } catch (e) {
        return json({ ok: false, tool, target, error: e.message }, 500);
      }
    }

    // POST /api/send-disclosure — human-approved responsible-disclosure send (OFF by default)
    if (url.pathname === '/api/send-disclosure' && request.method === 'POST') {
      let b; try { b = await request.json(); } catch { return json({ ok: false, error: 'bad json' }, 400); }
      if (!isTruthy(env.DISCLOSURE_SEND_ENABLED, false)) return json({ ok: false, error: 'Disclosure sending is OFF. Set DISCLOSURE_SEND_ENABLED=true and a verified provider to enable.' }, 403);
      if (b.confirm !== true) return json({ ok: false, error: 'confirm=true is required to send.' }, 400);
      const fromEmail = String(env.DISCLOSURE_FROM_EMAIL || '');
      const resend = String(env.RESEND_API_KEY || ''); const mgKey = String(env.MAILGUN_API_KEY || ''); const mgDom = String(env.MAILGUN_DOMAIN || '');
      if (!fromEmail || (!resend && !(mgKey && mgDom))) return json({ ok: false, error: 'No verified sender configured. Set DISCLOSURE_FROM_EMAIL + RESEND_API_KEY (or MAILGUN_API_KEY + MAILGUN_DOMAIN).' }, 400);
      const to = String(b.to || '').trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) return json({ ok: false, error: 'valid recipient email required' }, 400);
      const local = to.split('@')[0].replace(/[.+\-_].*$/, '');
      const ROLE = ['security', 'abuse', 'secure', 'soc', 'cert', 'psirt', 'hostmaster', 'postmaster', 'contact', 'info', 'admin', 'it', 'privacy', 'support'];
      if (!ROLE.includes(local)) return json({ ok: false, error: `Recipient must be a role/security address (security@, abuse@, ...). Got "${to.split('@')[0]}".` }, 400);
      const subject = String(b.subject || '').slice(0, 200).trim();
      const body = String(b.body || '').slice(0, 8000).trim();
      if (!subject || !body) return json({ ok: false, error: 'subject and body are required' }, 400);
      try { const cache = caches.default; const ck = 'https://disclose.local/cap/' + new Date().toISOString().slice(0, 10); const hit = await cache.match(ck); const nn = hit ? (parseInt(await hit.text(), 10) || 0) : 0; if (nn >= 10) return json({ ok: false, error: 'daily disclosure send cap (10) reached.' }, 429); await cache.put(ck, new Response(String(nn + 1), { headers: { 'Cache-Control': 'max-age=86400' } })); } catch (e) {}
      try {
        let id = '', provider = '';
        if (resend) {
          const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': 'Bearer ' + resend, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: fromEmail, to: [to], subject, text: body }), signal: AbortSignal.timeout(10000) });
          const d = await r.json().catch(() => ({})); if (!r.ok) return json({ ok: false, error: 'Resend ' + r.status + ': ' + String(d.message || JSON.stringify(d)).slice(0, 200) }, 502); id = d.id || ''; provider = 'resend';
        } else {
          const form = new URLSearchParams(); form.set('from', fromEmail); form.set('to', to); form.set('subject', subject); form.set('text', body);
          const r = await fetch('https://api.mailgun.net/v3/' + mgDom + '/messages', { method: 'POST', headers: { 'Authorization': 'Basic ' + btoa('api:' + mgKey), 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString(), signal: AbortSignal.timeout(10000) });
          const d = await r.json().catch(() => ({})); if (!r.ok) return json({ ok: false, error: 'Mailgun ' + r.status }, 502); id = d.id || ''; provider = 'mailgun';
        }
        console.log(JSON.stringify({ event: 'disclosure_sent', to, provider }));
        return json({ ok: true, provider, id, to });
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
      const { cveIds, ips, domains, wantSearch } = analyseQuery(q);
      const toolContext = [];
      for (const cveId of cveIds.slice(0, 3)) toolContext.push(`=== ${cveId} ===\n${await cveIntel(env, cveId)}`);
      for (const ip of (ips || []).slice(0, 2)) toolContext.push(`=== IP: ${ip} ===\n${await ipIntel(env, ip)}`);
      for (const dom of (domains || []).slice(0, 2)) toolContext.push(`=== Domain: ${dom} ===\n${await domainIntel(dom)}`);
      let chunks = await vectorRetrieve(env, q, body.topK || TOP_K);
      const usedVectorize = chunks !== null;
      if (!chunks) chunks = bm25Chunks(await getChunks(env), q, body.topK || TOP_K);
      const sys = buildSystemPrompt(env, { summary: '', chunks, toolContext });
      return json({
        cveIds, ips, domains, wantSearch, usedVectorize,
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
      const reasoning = String(opts.reasoning || 'normal').toLowerCase();
      const braveKey  = opts.brave || env.BRAVE_API_KEY || '';
      const objective = (body.objective || body.message || '').toString();
      const context   = (body.context || '').toString();
      const clientMemory = typeof body.memory === 'string' ? body.memory : '';
      try {
        if (body.grounded === true) {
          const sysG = 'You are a precise intelligence-report writer. Write the report STRICTLY from the FINDINGS / CONTEXT supplied by the user below - those tool results are the ONLY permitted source. Do NOT use outside knowledge, training data, blog/corpus content, or prior reports. NEVER invent or borrow files, filenames, hashes, malware names/families, loaders, payloads, CVEs, IPs, emails, domains, or attributions that do not appear verbatim in the FINDINGS. If the findings contain no malware/exploit evidence, do NOT mention malware at all. Mark anything not present as UNKNOWN. Where practical, attribute each claim to the tool that produced it.';
          const rG = await env.AI.run(MODEL, { messages: [{ role: 'system', content: sysG }, { role: 'user', content: objective + '\n\nFINDINGS / CONTEXT (the ONLY source you may use):\n' + context }], stream: false, max_tokens: 2048, temperature: 0.2 });
          return json({ ok: true, text: (rG.response || '').trim(), meta: { grounded: true } });
        }
        const { cveIds, ips, domains, wantSearch } = analyseQuery(objective + ' ' + context);
        const toolContext = [];
        for (const cveId of cveIds.slice(0, 3)) toolContext.push(`=== ${cveId} ===\n${await cveIntel(env, cveId)}`);
        for (const ip of (ips || []).slice(0, 2)) toolContext.push(`=== IP: ${ip} ===\n${await ipIntel(env, ip)}`);
        for (const dom of (domains || []).slice(0, 2)) toolContext.push(`=== Domain: ${dom} ===\n${await domainIntel(dom)}`);
        if (useSearch && wantSearch) {
          const s = await webSearch(cveIds.length ? `${cveIds[0]} exploit PoC advisory` : objective, braveKey, env);
          toolContext.push(s ? `=== Web Search ===\n${formatSearch(s)}` : '=== Search Unavailable ===\nDo NOT fabricate details; rely on corpus or state what is unknown.');
        }
        let chunks = await vectorRetrieve(env, objective, topK);
        const usedVectorize = chunks !== null;
        if (!chunks) chunks = bm25Chunks(await getChunks(env), objective, topK);
        let sysPrompt = buildSystemPrompt(env, { summary: '', chunks, toolContext, clientMemory, reasoning });
        if (reasoning === 'deep') {
          const notes = await reasonPass(env, objective, toolContext, chunks, temp);
          if (notes) sysPrompt += `\n\nPRELIMINARY ANALYSIS (your private notes — verify, do not treat as fact):\n${notes}`;
        }
        const userContent = context ? `${objective}\n\nContext from earlier steps:\n${context.slice(0, 14000)}` : objective;
        const r = await env.AI.run(MODEL, {
          messages: [{ role: 'system', content: sysPrompt }, { role: 'user', content: userContent }],
          stream: false, max_tokens: 2048, temperature: temp,
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
      const reasoning = String(opts.reasoning || 'normal').toLowerCase();
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
          const { cveIds, ips, domains, wantSearch } = analyseQuery(lastUser);
          const toolContext = [];

          // CVE intel — NVD + EPSS + CISA KEV
          for (const cveId of cveIds.slice(0, 3)) {
            dbg('cve_intel', cveId);
            const intel = await cveIntel(env, cveId);
            dbg('cve result', intel.slice(0, 160));
            toolContext.push(`=== ${cveId} ===\n${intel}`);
          }

          // Passive IP intel — RDAP + reverse DNS + Shodan InternetDB. No scanning by us.
          for (const ip of (ips || []).slice(0, 2)) {
            dbg('ip_intel', ip);
            const intel = await ipIntel(env, ip);
            dbg('ip result', intel.slice(0, 160));
            toolContext.push(`=== IP: ${ip} ===\n${intel}`);
          }

          // Passive domain intel — RDAP + DNS (DoH) + certificate transparency. No scanning.
          for (const dom of (domains || []).slice(0, 2)) {
            dbg('domain_intel', dom);
            const intel = await domainIntel(dom);
            dbg('domain result', intel.slice(0, 160));
            toolContext.push(`=== Domain: ${dom} ===\n${intel}`);
          }

          // Web search
          if (useSearch && wantSearch) {
            const q = cveIds.length ? `${cveIds[0]} exploit PoC advisory` : lastUser;
            dbg('search_web', q);
            const s = await webSearch(q, braveKey, env);
            if (s) { dbg('search result', s.provider + ': ' + s.results.length + ' hits'); toolContext.push(`=== Web Search ===\n${formatSearch(s)}`); }
            else {
              dbg('search result', 'all providers unavailable');
              toolContext.push('=== Search Unavailable ===\nAll web search providers failed. Do NOT fabricate CVE IDs, CVSS scores, affected versions, PoC URLs, or patch dates. If the corpus does not contain the answer, say so clearly.');
            }
          }

          // ── Agentic tool loop — the AI chooses tools from the full catalog ──
          if (opts.aiTools !== false) {
            const ranTools = [];
            for (let step = 0; step < 3; step++) {
              const choice = await toolRouter(env, lastUser, ranTools, toolContext.join('\n'));
              if (!choice || !choice.tool || !choice.arg) break;
              const tool = choice.tool, arg = choice.arg;
              if (ranTools.includes(tool)) break;
              if (!toolCatalog(env).some(t => t.name === tool)) { dbg('ai_tool skip', tool + ' (unknown)'); break; }
              dbg('ai_tool', tool + ' <- ' + arg.slice(0, 80)); send('TOOL:' + tool);
              try {
                let result;
                if (isBuiltinTool(tool)) {
                  result = await runBuiltinCached(env, tool, { target: arg, url: arg, domain: arg, ip: arg, email: arg, hash: arg, query: arg, vector: arg, input: arg, text: arg, username: arg, host: arg, cveId: arg, address: arg, onion: arg });
                } else {
                  const out = await runBrokerTool(env, { tool, args: { target: arg, url: arg, query: arg }, target: arg, requestedAt: new Date().toISOString() });
                  result = typeof out === 'string' ? out : (out && (out.result || JSON.stringify(out)));
                }
                result = String(result || '');
                dbg('ai_tool result', result.slice(0, 160));
                toolContext.push(`=== AI-selected tool: ${tool}(${arg}) ===\n${result.slice(0, 2800)}`);
                ranTools.push(tool);
              } catch (e) { dbg('ai_tool err', tool + ': ' + e.message); break; }
            }
          }

          // Retrieval — Vectorize semantic, BM25 fallback
          let chunks = await vectorRetrieve(env, lastUser, topK);
          const usedVectorize = chunks !== null;
          if (!chunks) chunks = bm25Chunks(await getChunks(env), lastUser, topK);
          dbg('retrieval', (usedVectorize ? 'vectorize' : 'bm25') + ' · ' + chunks.length + ' chunks · ' +
              chunks.map(c => (c.title || '?').slice(0, 24) + '(' + (c.score ?? '') + ')').join(', '));

          // Build prompt
          let sysPrompt = buildSystemPrompt(env, { summary: sess?.summary || '', chunks, toolContext, clientMemory, reasoning });
          if (reasoning === 'deep') {
            dbg('reasoning', 'deep analysis pass');
            const notes = await reasonPass(env, lastUser, toolContext, chunks, temp);
            if (notes) sysPrompt += `\n\nPRELIMINARY ANALYSIS (your private notes — verify against tools/corpus, do not treat as fact):\n${notes}`;
          }
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
