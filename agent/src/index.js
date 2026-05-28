/**
 * garrettstimpson.ca — llms.txt Research Agent
 * Cloudflare Worker: fetches corpus, streams answers via Workers AI.
 *
 * Deploy button:
 * https://deploy.workers.cloudflare.com/?url=https://github.com/gary23w/garrettstimpson.ca/tree/main/agent
 *
 * To adapt for YOUR site: change LLMS_URL and SITE_NAME in wrangler.toml.
 */

const MODEL           = '@cf/meta/llama-3.1-8b-instruct';
const MAX_CORPUS_CHARS = 14000; // ~3.5k tokens; leaves room for conversation history

// ── Corpus fetcher (cached 1 hour in CF Cache API) ───────────────────────────
async function getCorpus(env, ctx) {
  const llmsUrl = env.LLMS_URL || 'https://garrettstimpson.ca/llms.txt';
  const cache   = caches.default;
  const cacheKey = new Request('https://llms-corpus-cache/' + encodeURIComponent(llmsUrl));

  const hit = await cache.match(cacheKey);
  if (hit) return { text: await hit.text(), fromCache: true };

  const resp = await fetch(llmsUrl, {
    headers: { 'User-Agent': 'llms-agent/1.0' },
    cf: { cacheTtl: 3600 },
  });
  if (!resp.ok) throw new Error(`Corpus fetch failed: ${resp.status} ${llmsUrl}`);

  const text = await resp.text();
  ctx.waitUntil(cache.put(cacheKey, new Response(text, {
    headers: { 'Cache-Control': 'max-age=3600', 'Content-Type': 'text/plain' },
  })));
  return { text, fromCache: false };
}

// ── System prompt builder ─────────────────────────────────────────────────────
function buildSystem(corpus, siteName) {
  const trimmed  = corpus.slice(0, MAX_CORPUS_CHARS);
  const overflow = corpus.length > MAX_CORPUS_CHARS;
  return [
    `You are a specialized research assistant for "${siteName}".`,
    `Answer questions using only the security research corpus below.`,
    `Be technical, precise, and direct — this audience is security professionals.`,
    `Never fabricate CVE IDs, CVSS scores, EPSS values, or exploit details.`,
    `If the answer isn't in the corpus, say so explicitly.`,
    overflow ? `\n[Corpus truncated to ${MAX_CORPUS_CHARS} chars; some posts may be partial.]\n` : '',
    '\n---\n',
    trimmed,
  ].join('\n');
}

// ── Terminal chat UI (matches garrettstimpson.ca cyber theme) ─────────────────
function buildUI(siteName) {
  const short = siteName.split(' ').slice(-2).join(' ');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${siteName} — Research Agent</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--g:#00ff41;--gd:#00b32c;--gk:#003d0d;--bg:#000;--card:#0a0f0a;--bdr:rgba(0,255,65,.18);--bdrf:rgba(0,255,65,.07);--tx:#c8d8c8;--mu:#5a7a5a;--fa:#2a3d2a;--bl:#00d4ff;--rd:#ff2d55;}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--bg);color:var(--tx);font-family:'JetBrains Mono',monospace;font-size:14px;}
body{display:flex;flex-direction:column;}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.04) 2px,rgba(0,0,0,.04) 4px);}
header{padding:13px 20px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;gap:10px;
  background:rgba(0,0,0,.97);position:sticky;top:0;z-index:10;backdrop-filter:blur(8px);}
.logo{color:var(--g);font-weight:700;font-size:15px;text-shadow:0 0 10px rgba(0,255,65,.5);letter-spacing:.03em;}
.logo::after{content:'█';animation:blink 1.1s step-end infinite;font-size:11px;margin-left:3px;}
.tag{font-size:10px;color:var(--mu);letter-spacing:.1em;text-transform:uppercase;
  border:1px solid var(--bdr);padding:2px 8px;border-radius:2px;}
.mtag{margin-left:auto;font-size:10px;color:var(--fa);letter-spacing:.07em;}
#log{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:14px;scroll-behavior:smooth;}
#log::-webkit-scrollbar{width:4px;}
#log::-webkit-scrollbar-track{background:var(--bg);}
#log::-webkit-scrollbar-thumb{background:var(--gk);}
.msg{display:flex;flex-direction:column;gap:3px;max-width:860px;}
.msg.user{align-self:flex-end;}.msg.bot{align-self:flex-start;}
.meta{font-size:10px;letter-spacing:.07em;color:var(--mu);}
.msg.user .meta{text-align:right;color:var(--bl);}
.msg.user .meta::before{content:'you@terminal ';}
.msg.bot .meta::before{content:'agent@gs ';color:var(--gd);}
.body{padding:11px 15px;border-radius:2px;line-height:1.75;white-space:pre-wrap;word-break:break-word;}
.msg.user .body{background:rgba(0,212,255,.05);border:1px solid rgba(0,212,255,.18);border-left:3px solid var(--bl);}
.msg.bot  .body{background:var(--card);border:1px solid var(--bdr);border-left:3px solid var(--g);}
.body code{background:rgba(0,255,65,.08);color:var(--g);padding:1px 5px;border-radius:2px;font-size:.88em;}
.err .body{border-left-color:var(--rd)!important;color:var(--rd);}
.typing{display:flex;align-items:center;gap:5px;padding:12px 15px;
  background:var(--card);border:1px solid var(--bdr);border-left:3px solid var(--g);border-radius:2px;}
.dot{width:5px;height:5px;background:var(--g);border-radius:50%;animation:pulse 1.2s ease-in-out infinite;}
.dot:nth-child(2){animation-delay:.2s;}.dot:nth-child(3){animation-delay:.4s;}
#bar{padding:14px 20px;border-top:1px solid var(--bdr);background:rgba(0,0,0,.97);display:flex;gap:10px;align-items:flex-end;}
.pl{color:var(--g);font-size:13px;white-space:nowrap;padding-bottom:10px;}
#inp{flex:1;background:var(--card);border:1px solid var(--bdr);border-radius:2px;padding:10px 13px;
  color:var(--tx);font-family:inherit;font-size:13px;resize:none;min-height:42px;max-height:130px;
  line-height:1.5;outline:none;transition:border-color .15s;}
#inp:focus{border-color:var(--g);box-shadow:0 0 0 1px rgba(0,255,65,.12);}
#inp::placeholder{color:var(--mu);}
#btn{background:var(--gk);border:1px solid var(--g);color:var(--g);font-family:inherit;
  font-size:11px;letter-spacing:.1em;text-transform:uppercase;padding:10px 16px;
  border-radius:2px;cursor:pointer;white-space:nowrap;transition:all .15s;}
#btn:hover:not(:disabled){background:rgba(0,255,65,.12);box-shadow:0 0 12px rgba(0,255,65,.18);}
#btn:disabled{opacity:.35;cursor:default;}
#sbar{font-size:10px;color:var(--fa);letter-spacing:.07em;padding:5px 20px;
  border-top:1px solid rgba(0,255,65,.05);background:rgba(0,0,0,.8);}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
@keyframes pulse{0%,100%{opacity:.3;transform:scale(.8)}50%{opacity:1;transform:scale(1)}}
</style>
</head>
<body>
<header>
  <div class="logo">${short}</div>
  <span class="tag">Research Agent</span>
  <span class="mtag">llama-3.1-8b · workers ai · no api key required</span>
</header>
<div id="log">
  <div class="msg bot">
    <div class="meta"></div>
    <div class="body">Agent online. Corpus loaded from <code>llms.txt</code>.

Ask about any CVE, exploit technique, affected systems, detection strategies, or PoC mechanics covered in the research here.</div>
  </div>
</div>
<div id="bar">
  <span class="pl">&gt;_</span>
  <textarea id="inp" rows="1" placeholder="Ask about a CVE, technique, or exploit..."></textarea>
  <button id="btn">Send</button>
</div>
<div id="sbar">corpus: loading...</div>
<script>
const log=document.getElementById('log'),inp=document.getElementById('inp'),
  btn=document.getElementById('btn'),sbar=document.getElementById('sbar');
let hist=[],busy=false;
const ts=()=>new Date().toISOString().slice(0,19).replace('T',' ');

// init timestamps
document.querySelector('.meta').textContent=ts();

inp.addEventListener('input',()=>{inp.style.height='auto';inp.style.height=Math.min(inp.scrollHeight,130)+'px';});
inp.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();}});
btn.addEventListener('click',send);

fetch('/api/status').then(r=>r.json()).then(d=>{
  sbar.textContent='corpus: '+d.chars.toLocaleString()+' chars · '+d.docs+' documents · cached: '+d.fromCache;
}).catch(()=>{sbar.textContent='corpus: unavailable';});

function addMsg(role,text){
  const w=document.createElement('div'); w.className='msg '+(role==='user'?'user':'bot');
  w.innerHTML='<div class="meta">'+ts()+'</div><div class="body"></div>';
  w.querySelector('.body').textContent=text;
  log.appendChild(w); log.scrollTop=log.scrollHeight;
  return w.querySelector('.body');
}
function addTyping(){
  const w=document.createElement('div'); w.className='msg bot'; w.id='typing';
  w.innerHTML='<div class="meta">'+ts()+'</div>'+
    '<div class="typing"><div class="dot"></div><div class="dot"></div><div class="dot"></div></div>';
  log.appendChild(w); log.scrollTop=log.scrollHeight; return w;
}

async function send(){
  const q=inp.value.trim(); if(!q||busy)return;
  busy=true; btn.disabled=true; inp.value=''; inp.style.height='auto';
  addMsg('user',q);
  const ty=addTyping();
  try{
    const r=await fetch('/api/chat',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message:q,history:hist})});
    ty.remove();
    if(!r.ok)throw new Error('HTTP '+r.status);
    const el=addMsg('bot','');
    const rd=r.body.getReader(),dc=new TextDecoder();
    let full='',buf='';
    for(;;){
      const{done,value}=await rd.read(); if(done)break;
      buf+=dc.decode(value,{stream:true});
      const lines=buf.split('\\n'); buf=lines.pop();
      for(const ln of lines){
        if(!ln.startsWith('data: '))continue;
        const d=ln.slice(6).trim(); if(d==='[DONE]')break;
        try{const o=JSON.parse(d);const t=o?.response??o?.choices?.[0]?.delta?.content??'';
          if(t){full+=t;el.textContent=full;log.scrollTop=log.scrollHeight;}}catch{}
      }
    }
    hist.push({role:'user',content:q},{role:'assistant',content:full});
    if(hist.length>12)hist=hist.slice(-12);
  }catch(e){
    ty?.remove(); const el=addMsg('bot','Error: '+e.message);
    el.closest('.msg').classList.add('err');
  }
  busy=false; btn.disabled=false; inp.focus();
}
</script>
</body>
</html>`;
}

// ── Main handler ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const { pathname, method } = Object.assign(new URL(request.url), { method: request.method });
    const siteName = env.SITE_NAME || 'Security Research';

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: {
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      }});
    }

    // Chat UI
    if (pathname === '/' && method === 'GET') {
      return new Response(buildUI(siteName), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    // Corpus status
    if (pathname === '/api/status' && method === 'GET') {
      try {
        const { text, fromCache } = await getCorpus(env, ctx);
        return Response.json({
          chars: text.length,
          docs:  (text.match(/<DOCUMENT/g) || []).length,
          fromCache,
        });
      } catch (e) {
        return Response.json({ error: e.message }, { status: 500 });
      }
    }

    // Streaming chat
    if (pathname === '/api/chat' && method === 'POST') {
      let body;
      try { body = await request.json(); }
      catch { return new Response('Bad JSON', { status: 400 }); }

      const { message, history = [] } = body;
      if (!message?.trim()) return new Response('Empty message', { status: 400 });

      let corpus;
      try { ({ text: corpus } = await getCorpus(env, ctx)); }
      catch (e) { return new Response('Corpus unavailable: ' + e.message, { status: 502 }); }

      const messages = [
        { role: 'system', content: buildSystem(corpus, siteName) },
        ...history.slice(-8),
        { role: 'user', content: message.trim() },
      ];

      const stream = await env.AI.run(MODEL, { messages, stream: true });

      return new Response(stream, {
        headers: {
          'Content-Type':              'text/event-stream',
          'Cache-Control':             'no-cache',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    return new Response('Not found', { status: 404 });
  },
};
