/**
 * Garrett Stimpson — Security Research Agent  v2.0
 *
 * Improvements over v1:
 *  • BM25-lite corpus retrieval  — only the most relevant docs go into context
 *  • Tool calling loop           — NVD CVE lookup, Brave web search, URL fetch
 *  • SSE streaming preserved     — final answer streams token-by-token
 *  • BRAVE_API_KEY env var        — set in CF dashboard; falls back to NVD-only
 */

// ── Constants ─────────────────────────────────────────────────────────────────
const MODEL       = '@cf/meta/llama-3.1-8b-instruct';
const TOP_K       = 4;      // docs injected per query
const MAX_TOOLS   = 5;      // max tool-call rounds before forcing answer
const CORPUS_TTL  = 3600;   // cache TTL in seconds

// ── Corpus helpers ────────────────────────────────────────────────────────────

/** Parse <DOCUMENT> blocks out of llms.txt */
function parseCorpus(raw) {
  const docs = [];
  const re = /<DOCUMENT[^>]*>([\s\S]*?)<\/DOCUMENT>/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    const block = m[1];
    const fm    = (/<FRONTMATTER>([\s\S]*?)<\/FRONTMATTER>/.exec(block) || [])[1] || '';
    const body  = (/<BODY>([\s\S]*?)<\/BODY>/.exec(block)               || [])[1] || '';
    const title = (/TITLE\s*:\s*(.+)/.exec(fm) || [])[1]?.trim() || '';
    const cves  = (/CVE\s*:\s*(.+)/.exec(fm)   || [])[1]?.trim() || '';
    const tags  = (/TAGS\s*:\s*(.+)/.exec(fm)  || [])[1]?.trim() || '';
    docs.push({ title, cves, tags, frontmatter: fm, body, full: fm + '\n' + body });
  }
  return docs;
}

/** Tokenise text into lowercase terms */
function tok(text) {
  return text.toLowerCase().replace(/[^a-z0-9\-\.]/g, ' ').split(/\s+/).filter(t => t.length > 1);
}

/** BM25-lite score for a single document against query tokens */
function bm25(doc, qToks, avgLen) {
  const k1 = 1.5, b = 0.75;
  const tokens = tok(doc.full);
  const len    = tokens.length || 1;
  const tf     = {};
  tokens.forEach(t => (tf[t] = (tf[t] || 0) + 1));

  let score = 0;
  for (const qt of qToks) {
    const f = tf[qt] || 0;
    if (f === 0) {
      // partial substring bonus for the frontmatter
      if (doc.frontmatter.toLowerCase().includes(qt)) score += 2;
      continue;
    }
    const tfNorm = (f * (k1 + 1)) / (f + k1 * (1 - b + b * (len / avgLen)));
    score += tfNorm;
    if (doc.frontmatter.toLowerCase().includes(qt)) score += 5;
    // heavy CVE ID boost
    if (/^cve-\d+-\d+$/.test(qt) && doc.cves.toLowerCase().includes(qt)) score += 30;
  }
  return score;
}

/** Return top-K most relevant docs for a query */
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

/** Format retrieved docs for the system prompt */
function formatContext(docs) {
  if (!docs.length) return '(no matching documents in corpus)';
  return docs.map((d, i) =>
    `--- Research Post ${i + 1}: ${d.title} ---\n${d.frontmatter.trim()}\n\n${d.body.trim()}`
  ).join('\n\n');
}

// ── Tool definitions (OpenAI-style) ──────────────────────────────────────────

const TOOLS = [
  {
    type: 'function',
    function: {
      name: 'lookup_cve',
      description:
        'Look up authoritative CVE details from the NIST National Vulnerability Database. ' +
        'Call this for any CVE ID the user mentions. No API key needed.',
      parameters: {
        type: 'object',
        properties: {
          cve_id: { type: 'string', description: 'CVE identifier, e.g. CVE-2026-31431' }
        },
        required: ['cve_id']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'search_web',
      description:
        'Search the web for current threat intelligence, PoC code, advisories, or ' +
        'any security topic not covered in the corpus. Returns top results with titles and snippets.',
      parameters: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Search query' }
        },
        required: ['query']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'fetch_url',
      description:
        'Fetch the raw content of a URL from allowlisted security domains ' +
        '(github.com, nvd.nist.gov, exploit-db.com, cve.org, microsoft.com, kernel.org, etc.).',
      parameters: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Full URL to fetch' }
        },
        required: ['url']
      }
    }
  }
];

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

async function runTool(name, args, env) {
  // ── lookup_cve ──────────────────────────────────────────────────────────────
  if (name === 'lookup_cve') {
    const id = (args.cve_id || '').toUpperCase().trim();
    if (!/^CVE-\d{4}-\d+$/.test(id)) return `Invalid CVE ID format: ${id}`;
    try {
      const r = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`,
        { headers: { 'User-Agent': 'garrettstimpson-agent/2.0' }, signal: AbortSignal.timeout(8000) }
      );
      const data = await r.json();
      const vuln = data?.vulnerabilities?.[0]?.cve;
      if (!vuln) return `NVD: no entry found for ${id}.`;
      const desc  = vuln.descriptions?.find(d => d.lang === 'en')?.value || 'No description.';
      const v31   = vuln.metrics?.cvssMetricV31?.[0]?.cvssData;
      const v30   = vuln.metrics?.cvssMetricV30?.[0]?.cvssData;
      const cvss  = v31 || v30;
      const score = cvss ? `CVSS ${cvss.baseScore} (${cvss.baseSeverity}) — ${cvss.vectorString}` : 'No CVSS score';
      const refs  = (vuln.references || []).slice(0, 5).map(x => x.url).join('\n');
      const cwes  = (vuln.weaknesses || []).flatMap(w => w.description.map(d => d.value)).join(', ') || 'none';
      return `${id}\n${score}\nCWE: ${cwes}\n\n${desc}\n\nReferences:\n${refs}`;
    } catch (e) {
      return `NVD lookup failed: ${e.message}`;
    }
  }

  // ── search_web ──────────────────────────────────────────────────────────────
  if (name === 'search_web') {
    const query = (args.query || '').trim();
    const braveKey = env.BRAVE_API_KEY || '';

    if (braveKey) {
      try {
        const r = await fetch(
          `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=6&search_lang=en`,
          {
            headers: {
              'X-Subscription-Token': braveKey,
              'Accept': 'application/json',
              'User-Agent': 'garrettstimpson-agent/2.0'
            },
            signal: AbortSignal.timeout(8000)
          }
        );
        const data = await r.json();
        const results = (data?.web?.results || []).slice(0, 6);
        if (!results.length) return 'Brave search returned no results.';
        return results.map((x, i) =>
          `[${i + 1}] ${x.title}\n${x.url}\n${x.description || ''}`
        ).join('\n\n');
      } catch (e) {
        return `Brave search failed: ${e.message}`;
      }
    }

    // No Brave key — fall back to DuckDuckGo Instant Answers
    try {
      const r = await fetch(
        `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_redirect=1`,
        { headers: { 'User-Agent': 'garrettstimpson-agent/2.0' }, signal: AbortSignal.timeout(6000) }
      );
      const data = await r.json();
      const parts = [];
      if (data.AbstractText)  parts.push(data.AbstractText);
      if (data.Answer)        parts.push(`Answer: ${data.Answer}`);
      (data.RelatedTopics || []).slice(0, 4).forEach(t => t.Text && parts.push(t.Text));
      return parts.length ? parts.join('\n\n') : 'No results found. Consider setting BRAVE_API_KEY for full web search.';
    } catch (e) {
      return `Search failed: ${e.message}`;
    }
  }

  // ── fetch_url ───────────────────────────────────────────────────────────────
  if (name === 'fetch_url') {
    const url = (args.url || '').trim();
    let hostname;
    try { hostname = new URL(url).hostname; } catch { return `Invalid URL: ${url}`; }
    const allowed = FETCH_ALLOWLIST.some(d => hostname === d || hostname.endsWith('.' + d));
    if (!allowed) return `fetch_url: ${hostname} is not in the security domain allowlist.`;
    try {
      const r = await fetch(url, {
        headers: { 'User-Agent': 'garrettstimpson-agent/2.0' },
        signal: AbortSignal.timeout(8000)
      });
      const text = await r.text();
      // Strip HTML tags roughly, trim to 6000 chars
      const clean = text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 6000);
      return clean || '(empty response)';
    } catch (e) {
      return `fetch failed: ${e.message}`;
    }
  }

  return `Unknown tool: ${name}`;
}

// ── AI call helpers ───────────────────────────────────────────────────────────

/** Parse tool_calls out of a Workers AI response (handles both response shapes) */
function extractToolCalls(response) {
  // Shape 1: { tool_calls: [...] }
  if (Array.isArray(response?.tool_calls)) return response.tool_calls;
  // Shape 2: OpenAI-style choices
  const msg = response?.choices?.[0]?.message;
  if (Array.isArray(msg?.tool_calls)) return msg.tool_calls;
  return null;
}

function extractText(response) {
  if (typeof response?.response === 'string') return response.response;
  return response?.choices?.[0]?.message?.content || '';
}

/** Parse tool call arguments — Workers AI may return a string or object */
function parseArgs(raw) {
  if (typeof raw === 'object' && raw !== null) return raw;
  try { return JSON.parse(raw); } catch { return {}; }
}

/** One non-streaming AI call (for tool call detection) */
async function aiCall(env, messages, useTools) {
  return env.AI.run(MODEL, {
    messages,
    tools: useTools ? TOOLS : undefined,
    stream: false,
  });
}

/** Streaming AI call — returns a ReadableStream of SSE chunks */
async function aiStream(env, messages) {
  return env.AI.run(MODEL, { messages, stream: true });
}

// ── Corpus cache ──────────────────────────────────────────────────────────────

async function getCorpusDocs(env) {
  const cache  = caches.default;
  const cKey   = new Request('https://corpus-cache/docs');
  const cached = await cache.match(cKey);
  if (cached) {
    const text = await cached.text();
    try { return JSON.parse(text); } catch {}
  }

  const llmsUrl = env.LLMS_URL || 'https://raw.githubusercontent.com/gary23w/garrettstimpson.ca/main/llms.txt';
  const r = await fetch(llmsUrl, { signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error(`Corpus fetch failed: ${r.status} ${llmsUrl}`);
  const raw  = await r.text();
  const docs = parseCorpus(raw);

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
:root{--green:#00ff41;--blue:#00d4ff;--bg:#000;--panel:#0a0a0a;--border:#1a1a1a;--muted:#444;}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--bg);color:var(--green);font-family:'JetBrains Mono',Menlo,monospace;font-size:13px;}
#app{display:flex;flex-direction:column;height:100vh;max-width:900px;margin:0 auto;padding:12px;}
header{border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:10px;}
.h-title{font-size:11px;color:var(--muted);letter-spacing:.15em;text-transform:uppercase;}
.h-model{color:var(--blue);font-size:10px;margin-top:3px;}
.h-meta{font-size:10px;color:var(--muted);margin-top:2px;}
#log{flex:1;overflow-y:auto;padding:4px 0;display:flex;flex-direction:column;gap:10px;}
.msg{line-height:1.6;white-space:pre-wrap;word-break:break-word;}
.msg.user{color:#ccc;}
.msg.user::before{content:'> ';color:var(--green);}
.msg.agent{color:var(--green);}
.msg.agent::before{content:'';}
.msg.system{color:var(--muted);font-size:11px;font-style:italic;}
.msg.tool{color:var(--blue);font-size:11px;border-left:2px solid var(--blue);padding-left:8px;opacity:.8;}
#input-row{display:flex;gap:8px;margin-top:10px;border-top:1px solid var(--border);padding-top:10px;}
#prompt{color:var(--green);flex-shrink:0;}
#inp{flex:1;background:transparent;border:none;outline:none;color:var(--green);font:inherit;caret-color:var(--green);}
#inp::placeholder{color:var(--muted);}
.blink{animation:blink 1s step-end infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
</head>
<body>
<div id="app">
  <header>
    <div class="h-title">${siteName}</div>
    <div class="h-model">llama-3.1-8b · workers ai · BM25 RAG · NVD + Brave tools</div>
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
    const r = await fetch('/api/status');
    const d = await r.json();
    stat.textContent = ts() + ' · corpus: ' + d.docCount + ' posts · ' + d.totalChars.toLocaleString() + ' chars';
    addMsg('system', 'Agent online. BM25 retrieval active.  Ask about any CVE, exploit technique, affected systems, detection strategies, or PoC mechanics.');
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

  const el = addMsg('agent', '');
  let full = '';

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: hist })
    });

    if (!res.ok) throw new Error('HTTP ' + res.status);
    if (!res.body) throw new Error('No stream body');

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
        if (line.startsWith('data: TOOL:')) {
          addMsg('tool', line.slice(11).trim());
          continue;
        }
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

  if (full.trim()) hist.push({ role: 'assistant', content: full });
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
      const siteName = env.SITE_NAME || 'Security Research';
      return new Response(terminalUI(siteName), {
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

      const userMessages = body.messages || [];
      const lastUser     = [...userMessages].reverse().find(m => m.role === 'user')?.content || '';

      // Build SSE stream
      const { readable, writable } = new TransformStream();
      const writer  = writable.getWriter();
      const enc     = new TextEncoder();
      const send    = (data) => writer.write(enc.encode('data: ' + data + '\n\n'));
      const sendTool = (msg) => send('TOOL: ' + msg);

      // Run async — don't await
      (async () => {
        try {
          // 1. Retrieve relevant docs
          const docs    = await getCorpusDocs(env);
          const topDocs = retrieve(docs, lastUser, TOP_K);
          const context = formatContext(topDocs);

          // 2. Build system prompt
          const sysPrompt = [
            `You are a senior offensive security researcher and assistant for ${env.SITE_NAME || 'Garrett Stimpson Security Research'}.`,
            `You have deep expertise in CVEs, exploit development, malware analysis, EDR evasion, and threat intelligence.`,
            ``,
            `You have access to tools:`,
            `  • lookup_cve(cve_id)  — NIST NVD authoritative CVE data. Use for any CVE ID mentioned.`,
            `  • search_web(query)   — Live Brave/DDG web search for current threat intel.`,
            `  • fetch_url(url)      — Fetch content from trusted security domains.`,
            ``,
            `CORPUS CONTEXT (top ${topDocs.length} most relevant research posts retrieved by BM25):`,
            context,
            ``,
            `Instructions:`,
            `1. Check the corpus context above first — it contains Garrett's own PoC analysis.`,
            `2. Use lookup_cve for any CVE ID mentioned, even if in the corpus.`,
            `3. Use search_web for current data, recent exploits, or anything not in the corpus.`,
            `4. Be technical, precise, and answer as an expert would — no hand-waving.`,
          ].join('\n');

          const messages = [
            { role: 'system', content: sysPrompt },
            ...userMessages
          ];

          // 3. Tool-calling loop (max MAX_TOOLS rounds)
          let rounds = 0;
          while (rounds < MAX_TOOLS) {
            rounds++;
            const resp = await aiCall(env, messages, true);
            const toolCalls = extractToolCalls(resp);

            if (!toolCalls || toolCalls.length === 0) {
              // No tool calls — stream the final text response
              const text = extractText(resp);
              if (text) {
                // Simulate streaming by sending in chunks
                const words = text.split(/(\s+)/);
                for (const w of words) {
                  send(JSON.stringify({ response: w }));
                }
              }
              break;
            }

            // Execute tools sequentially
            messages.push({ role: 'assistant', content: null, tool_calls: toolCalls });

            for (const tc of toolCalls) {
              // Handle both Workers AI shapes
              const fnName = tc.name || tc.function?.name || '';
              const fnArgs = parseArgs(tc.arguments || tc.function?.arguments || {});
              const toolId = tc.id || `call_${Date.now()}`;

              sendTool(`[${fnName}] ${JSON.stringify(fnArgs)}`);
              const result = await runTool(fnName, fnArgs, env);
              sendTool(`[${fnName} result] ${result.slice(0, 200)}${result.length > 200 ? '…' : ''}`);

              messages.push({
                role:         'tool',
                tool_call_id: toolId,
                name:         fnName,
                content:      result,
              });
            }
          }

          if (rounds >= MAX_TOOLS) {
            // Force a final answer without tools
            const finalResp = await aiCall(env, messages, false);
            const text = extractText(finalResp);
            if (text) {
              const words = text.split(/(\s+)/);
              for (const w of words) send(JSON.stringify({ response: w }));
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
