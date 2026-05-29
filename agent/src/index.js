/**
 * Garrett Stimpson — Security Research Agent  v3.0
 *
 * Architecture: deterministic pre-processing, single streaming LLM call.
 * We extract CVE IDs and search intent from the query ourselves — no LLM
 * tool-call format required, zero message-schema errors, stays within the
 * llama-3.1-8b 7968-token context window.
 *
 *  1. BM25-lite corpus retrieval  (top 2 docs, bodies capped at 900 chars)
 *  2. Pre-process query           (regex CVE IDs, search-intent keywords)
 *  3. Run tools deterministically (NVD lookup, Jina/Brave search, URL fetch)
 *  4. Single streaming LLM call   (tool results + corpus context injected)
 */

const MODEL      = '@cf/meta/llama-3.1-8b-instruct';
const TOP_K      = 2;     // corpus docs injected per query
const DOC_CHARS  = 900;   // max chars per doc body (keeps tokens sane)
const HIST_MSGS  = 6;     // max prior messages carried in context
const CORPUS_TTL = 3600;  // corpus cache TTL (seconds)

// ── Corpus helpers ────────────────────────────────────────────────────────────

function parseCorpus(raw) {
  const docs = [];
  const re = /<DOCUMENT[^>]*>([\s\S]*?)<\/DOCUMENT>/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    const block = m[1];
    const fm   = (/<FRONTMATTER>([\s\S]*?)<\/FRONTMATTER>/.exec(block) || [])[1] || '';
    const body = (/<BODY>([\s\S]*?)<\/BODY>/.exec(block)               || [])[1] || '';
    const title = (/TITLE\s*:\s*(.+)/.exec(fm)  || [])[1]?.trim() || '';
    const cves  = (/CVE\s*:\s*(.+)/.exec(fm)    || [])[1]?.trim() || '';
    const tags  = (/TAGS\s*:\s*(.+)/.exec(fm)   || [])[1]?.trim() || '';
    docs.push({ title, cves, tags, frontmatter: fm, body, full: fm + '\n' + body });
  }
  return docs;
}

function tok(text) {
  return text.toLowerCase().replace(/[^a-z0-9\-\.]/g, ' ').split(/\s+/).filter(t => t.length > 1);
}

function bm25(doc, qToks, avgLen) {
  const k1 = 1.5, b = 0.75;
  const tokens = tok(doc.full);
  const len = tokens.length || 1;
  const tf = {};
  tokens.forEach(t => (tf[t] = (tf[t] || 0) + 1));
  let score = 0;
  for (const qt of qToks) {
    const f = tf[qt] || 0;
    if (f === 0) { if (doc.frontmatter.toLowerCase().includes(qt)) score += 2; continue; }
    const tfNorm = (f * (k1 + 1)) / (f + k1 * (1 - b + b * (len / avgLen)));
    score += tfNorm;
    if (doc.frontmatter.toLowerCase().includes(qt)) score += 5;
    if (/^cve-\d+-\d+$/.test(qt) && doc.cves.toLowerCase().includes(qt)) score += 30;
  }
  return score;
}

function retrieve(docs, query, k) {
  if (!docs.length) return [];
  const qToks  = tok(query);
  const avgLen = docs.reduce((s, d) => s + tok(d.full).length, 0) / docs.length;
  return docs
    .map(doc => ({ doc, score: bm25(doc, qToks, avgLen) }))
    .sort((a, b) => b.score - a.score)
    .filter(x => x.score > 0)
    .slice(0, k)
    .map(x => x.doc);
}

function formatDoc(doc) {
  const fm   = doc.frontmatter.trim();
  const body = doc.body.trim().slice(0, DOC_CHARS);
  const ellipsis = doc.body.trim().length > DOC_CHARS ? '\n[…truncated]' : '';
  return `### ${doc.title}\n${fm}\n\n${body}${ellipsis}`;
}

// ── Query pre-processing ──────────────────────────────────────────────────────

const SEARCH_TRIGGERS = [
  'latest', 'recent', 'new ', 'current', 'today', 'this week',
  'in the wild', 'active exploit', 'patch', 'advisory', 'poc', 'proof of concept',
  'github', 'shodan', 'search', 'find', 'look up'
];

function analyseQuery(query) {
  const q   = query.toLowerCase();
  const cveIds = [...new Set(
    (query.match(/CVE-\d{4}-\d+/gi) || []).map(c => c.toUpperCase())
  )];
  const wantSearch = SEARCH_TRIGGERS.some(t => q.includes(t)) || cveIds.length === 0;
  return { cveIds, wantSearch };
}

// ── Tool execution ────────────────────────────────────────────────────────────

const FETCH_ALLOWLIST = [
  'github.com', 'raw.githubusercontent.com',
  'nvd.nist.gov', 'cve.org',
  'exploit-db.com', 'www.exploit-db.com',
  'microsoft.com', 'msrc.microsoft.com',
  'kernel.org', 'lore.kernel.org',
  'ubuntu.com', 'usn.ubuntu.com',
  'redhat.com', 'access.redhat.com',
  'cisco.com', 'tools.cisco.com',
  'nginx.org', 'nginx.com',
  'postgresql.org',
  'openssh.com', 'www.openssh.com',
  'debian.org', 'security.debian.org',
];

async function nvdLookup(cveId) {
  try {
    const r = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
      { headers: { 'User-Agent': 'garrettstimpson-agent/3.0' }, signal: AbortSignal.timeout(8000) }
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

async function webSearch(query, braveKey) {
  // ── Brave Search (when API key is set) ──────────────────────────────────────
  if (braveKey) {
    try {
      const r = await fetch(
        `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=6&search_lang=en`,
        {
          headers: { 'X-Subscription-Token': braveKey, 'Accept': 'application/json' },
          signal: AbortSignal.timeout(8000)
        }
      );
      const data = await r.json();
      const results = (data?.web?.results || []).slice(0, 6);
      if (results.length) {
        return '[Brave Search]\n\n' + results.map((x, i) =>
          `[${i + 1}] ${x.title}\n${x.url}\n${x.description || ''}`
        ).join('\n\n');
      }
    } catch (_) { /* fall through */ }
  }

  // ── Jina AI Search — free, no key required (default) ────────────────────────
  try {
    const r = await fetch(
      `https://s.jina.ai/${encodeURIComponent(query)}`,
      {
        headers: { 'User-Agent': 'garrettstimpson-agent/3.0', 'Accept': 'text/plain' },
        signal: AbortSignal.timeout(12000)
      }
    );
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const text = (await r.text()).trim();
    return text ? '[Jina AI Search]\n\n' + text.slice(0, 4000) : 'No search results found.';
  } catch (e) {
    return `Search failed: ${e.message}`;
  }
}

async function fetchUrl(url) {
  let hostname;
  try { hostname = new URL(url).hostname; } catch { return `Invalid URL: ${url}`; }
  if (!FETCH_ALLOWLIST.some(d => hostname === d || hostname.endsWith('.' + d)))
    return `fetch_url: ${hostname} not in security domain allowlist.`;
  try {
    const r = await fetch(url, {
      headers: { 'User-Agent': 'garrettstimpson-agent/3.0' },
      signal: AbortSignal.timeout(8000)
    });
    const text = await r.text();
    return text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 5000);
  } catch (e) { return `fetch failed: ${e.message}`; }
}

// ── Corpus cache ──────────────────────────────────────────────────────────────

async function getCorpusDocs(env) {
  const cache  = caches.default;
  const cKey   = new Request('https://corpus-cache/docs-v3');
  const cached = await cache.match(cKey);
  if (cached) {
    try { return JSON.parse(await cached.text()); } catch {}
  }
  const llmsUrl = env.LLMS_URL || 'https://raw.githubusercontent.com/gary23w/garrettstimpson.ca/main/llms.txt';
  const r = await fetch(llmsUrl, { signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error(`Corpus fetch failed: ${r.status}`);
  const docs = parseCorpus(await r.text());
  await cache.put(cKey, new Response(JSON.stringify(docs), {
    headers: { 'Cache-Control': `max-age=${CORPUS_TTL}`, 'Content-Type': 'application/json' }
  }));
  return docs;
}

// ── Terminal UI ───────────────────────────────────────────────────────────────

function terminalUI(siteName) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${siteName} — Research Agent</title>
<style>
:root{--green:#00ff41;--blue:#00d4ff;--bg:#000;--border:#1a1a1a;--muted:#444;}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--bg);color:var(--green);font-family:'JetBrains Mono',Menlo,monospace;font-size:13px;}
#app{display:flex;flex-direction:column;height:100vh;max-width:900px;margin:0 auto;padding:12px;}
header{border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:10px;}
.h-title{font-size:11px;color:var(--muted);letter-spacing:.15em;text-transform:uppercase;}
.h-model{color:var(--blue);font-size:10px;margin-top:3px;}
.h-meta{font-size:10px;color:var(--muted);margin-top:2px;}
#log{flex:1;overflow-y:auto;padding:4px 0;display:flex;flex-direction:column;gap:10px;}
.msg{line-height:1.65;white-space:pre-wrap;word-break:break-word;}
.msg.user::before{content:'> ';color:var(--green);}
.msg.user{color:#ccc;}
.msg.agent{color:var(--green);}
.msg.system{color:var(--muted);font-size:11px;font-style:italic;}
.msg.tool{color:var(--blue);font-size:11px;border-left:2px solid var(--blue);padding-left:8px;opacity:.8;}
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
    <div class="h-title">${siteName}</div>
    <div class="h-model">llama-3.1-8b · workers ai · BM25 RAG · NVD + Jina Search · Brave (optional)</div>
    <div class="h-meta" id="status">initialising…</div>
  </header>
  <div id="log"></div>
  <div id="input-row">
    <span id="prompt">&gt;_</span>
    <input id="inp" autocomplete="off" autocorrect="off" spellcheck="false"
           placeholder="ask about a CVE, exploit, technique…" autofocus>
  </div>
</div>
<script>
const log  = document.getElementById('log');
const inp  = document.getElementById('inp');
const stat = document.getElementById('status');
// Keep only last N user/assistant turns to avoid bloating the request
const MAX_HIST = 6;
const hist = [];
let busy   = false;

function ts() { return new Date().toLocaleTimeString(); }

function addMsg(role, text) {
  const d = document.createElement('div');
  d.className = 'msg ' + role;
  d.textContent = text;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
  return d;
}

function appendTo(el, chunk) {
  el.textContent += chunk;
  log.scrollTop = log.scrollHeight;
}

async function init() {
  try {
    const d = await (await fetch('/api/status')).json();
    stat.textContent = ts() + ' · corpus: ' + d.docCount + ' posts · ' + d.totalChars.toLocaleString() + ' chars';
    addMsg('system', 'Agent online. Ask about any CVE, exploit technique, affected system, detection strategy, or PoC mechanics covered in the research.');
  } catch(e) {
    stat.textContent = 'corpus unavailable';
    addMsg('system', 'Warning: corpus load failed — ' + e.message);
  }
}

inp.addEventListener('keydown', async e => {
  if (e.key !== 'Enter' || busy || !inp.value.trim()) return;
  const q = inp.value.trim();
  inp.value = '';
  busy = true;
  inp.disabled = true;

  addMsg('user', q);
  hist.push({ role: 'user', content: q });
  // Trim history to MAX_HIST messages
  while (hist.length > MAX_HIST) hist.shift();

  const el = addMsg('agent', '');
  let full = '';

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: hist.slice(-MAX_HIST) })
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const reader  = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\\n');
      buf = lines.pop();
      for (const line of lines) {
        if (line.startsWith('data: [DONE]')) continue;
        if (line.startsWith('data: TOOL:')) { addMsg('tool', line.slice(11).trim()); continue; }
        if (!line.startsWith('data: ')) continue;
        try {
          const obj = JSON.parse(line.slice(6));
          const tok = obj.response || obj.choices?.[0]?.delta?.content || '';
          if (tok) { full += tok; appendTo(el, tok); }
        } catch {}
      }
    }
  } catch(e) {
    appendTo(el, '[error] ' + e.message);
  }

  if (full.trim()) {
    hist.push({ role: 'assistant', content: full });
    while (hist.length > MAX_HIST) hist.shift();
  }
  busy = false;
  inp.disabled = false;
  inp.focus();
});

init();
</script>
</body>
</html>`;
}

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const cors = {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    // ── GET / ──────────────────────────────────────────────────────────────────
    if (url.pathname === '/') {
      return new Response(terminalUI(env.SITE_NAME || 'Security Research'), {
        headers: { ...cors, 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }

    // ── GET /api/status ────────────────────────────────────────────────────────
    if (url.pathname === '/api/status' && request.method === 'GET') {
      try {
        const docs       = await getCorpusDocs(env);
        const totalChars = docs.reduce((s, d) => s + d.full.length, 0);
        return new Response(JSON.stringify({ docCount: docs.length, totalChars, ok: true }), {
          headers: { ...cors, 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message, ok: false }), {
          status: 500, headers: { ...cors, 'Content-Type': 'application/json' }
        });
      }
    }

    // ── POST /api/chat ─────────────────────────────────────────────────────────
    if (url.pathname === '/api/chat' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch {
        return new Response('Bad JSON', { status: 400, headers: cors });
      }

      const userMessages = (body.messages || []).slice(-(HIST_MSGS));
      const lastUser     = [...userMessages].reverse().find(m => m.role === 'user')?.content || '';

      const { readable, writable } = new TransformStream();
      const writer   = writable.getWriter();
      const enc      = new TextEncoder();
      const send     = d  => writer.write(enc.encode('data: ' + d + '\n\n'));
      const sendTool = msg => send('TOOL: ' + msg);

      (async () => {
        try {
          // 1. Analyse query — extract CVEs and search intent ourselves
          const { cveIds, wantSearch } = analyseQuery(lastUser);
          const toolContext = [];

          // 2. NVD lookups for any CVE IDs found
          for (const cveId of cveIds.slice(0, 3)) {
            sendTool(`[lookup_nvd] ${cveId}`);
            const result = await nvdLookup(cveId);
            sendTool(`[nvd result] ${result.slice(0, 120)}…`);
            toolContext.push(`=== NVD: ${cveId} ===\n${result}`);
          }

          // 3. Web search when useful
          if (wantSearch) {
            const q = cveIds.length ? `${cveIds[0]} exploit PoC` : lastUser;
            sendTool(`[search_web] ${q}`);
            const result = await webSearch(q, env.BRAVE_API_KEY || '');
            sendTool(`[search result] ${result.slice(0, 120)}…`);
            toolContext.push(`=== Web Search ===\n${result}`);
          }

          // 4. BM25 retrieval from corpus
          const docs    = await getCorpusDocs(env);
          const topDocs = retrieve(docs, lastUser, TOP_K);

          // 5. Build system prompt — tool results + corpus (tight budget)
          const toolSection = toolContext.length
            ? `LIVE TOOL RESULTS:\n${toolContext.join('\n\n').slice(0, 3000)}`
            : '';
          const corpusSection = topDocs.length
            ? `CORPUS (top ${topDocs.length} posts by BM25 relevance):\n${topDocs.map(formatDoc).join('\n\n---\n\n')}`
            : '';

          const sysPrompt = [
            `You are a senior offensive security researcher for ${env.SITE_NAME || 'Garrett Stimpson Security Research'}.`,
            `Answer with technical precision. Include CVE IDs, CVSS scores, affected versions, and PoC details where known.`,
            toolSection,
            corpusSection,
          ].filter(Boolean).join('\n\n');

          // 6. Build final messages — clean string content only, no null
          const messages = [
            { role: 'system', content: sysPrompt },
            // Include prior conversation (user/assistant only, strings only)
            ...userMessages
              .filter(m => m.role === 'user' || m.role === 'assistant')
              .filter(m => typeof m.content === 'string' && m.content.trim()),
          ];

          // 7. Stream the response — explicit max_tokens keeps input+output within 7968-token window
          const stream = await env.AI.run(MODEL, { messages, stream: true, max_tokens: 1024 });
          const reader = stream.getReader();
          const dec    = new TextDecoder();
          let buf = '';
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += dec.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop();
            for (const line of lines) {
              if (line.startsWith('data: [DONE]')) { send('[DONE]'); continue; }
              if (!line.startsWith('data: ')) continue;
              try {
                const obj = JSON.parse(line.slice(6));
                const tok = obj.response || obj.choices?.[0]?.delta?.content || '';
                if (tok) send(JSON.stringify({ response: tok }));
              } catch {}
            }
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
        headers: {
          ...cors,
          'Content-Type':      'text/event-stream',
          'Cache-Control':     'no-cache',
          'X-Accel-Buffering': 'no',
        }
      });
    }

    return new Response('Not found', { status: 404, headers: cors });
  }
};
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      