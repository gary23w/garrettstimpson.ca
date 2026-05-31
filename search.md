---
layout: page
title: Search
permalink: /search/
---

<input id="site-search" class="search-box" type="search" placeholder="search research — title, tag, or keyword…" autocomplete="off" autofocus>
<div id="search-count" class="search-count"></div>
<div id="search-results" class="search-results"></div>

<script>
(function(){
  var inp=document.getElementById('site-search');
  var out=document.getElementById('search-results');
  var cnt=document.getElementById('search-count');
  var idx=[];
  fetch('{{ "/search.json" | relative_url }}').then(function(r){return r.json();}).then(function(data){ idx=data; run(); });
  function esc(s){ return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function card(p){
    var tags=(p.tags||[]).slice(0,6).map(function(t){return '<span class="tag">'+esc(t)+'</span>';}).join('');
    return '<a class="post-card" href="'+p.url+'" style="display:block;"><div class="post-card-link"><div class="post-card-meta"><span class="post-date">'+esc(p.date)+'</span></div><h3 class="post-card-title">'+esc(p.title)+'</h3><p class="post-card-excerpt">'+esc(p.excerpt)+'</p><div class="post-tags">'+tags+'</div></div></a>';
  }
  function run(){
    var q=(inp.value||'').toLowerCase().trim();
    if(!q){ out.innerHTML=''; cnt.textContent=idx.length+' posts indexed — start typing.'; return; }
    var res=idx.filter(function(p){ var hay=(p.title+' '+(p.tags||[]).join(' ')+' '+(p.categories||[]).join(' ')+' '+p.excerpt).toLowerCase(); return q.split(/\s+/).every(function(w){ return hay.indexOf(w)>=0; }); });
    cnt.textContent=res.length+' result'+(res.length===1?'':'s')+' for "'+q+'"';
    out.innerHTML=res.map(card).join('');
  }
  inp.addEventListener('input',run);
})();
</script>
