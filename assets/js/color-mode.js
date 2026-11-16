/* Shared by the research blog and Agent Garrett. Run in the head, before paint. */
(()=>{
 'use strict';
 const root=document.documentElement,key='garrett-color-mode',valid=value=>value==='light'||value==='dark';
 let current='light';
 const stored=()=>{
  try{const match=document.cookie.match(/(?:^|;\s*)garrett_color_mode=(light|dark)(?:;|$)/);if(match)return match[1];}catch{}
  try{const value=localStorage.getItem(key);if(valid(value))return value;}catch{}
  return null;
 };
 function styleSources(){
  const sources=[...document.querySelectorAll('link[rel="stylesheet"]')].map(link=>{
   try{return new URL(link.href,location.href).pathname.split('/').pop().replace(/\.css$/,'');}catch{return '';}
  }).filter(name=>/^[\w-]+$/.test(name)&&!name.startsWith('color-mode'));
  const value=[...new Set(sources)].join(' ');
  if(root.getAttribute('data-color-styles')!==value)root.setAttribute('data-color-styles',value);
 }
 const moon='<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 13.2A8.6 8.6 0 0 1 10.8 3.5 8.7 8.7 0 1 0 20.5 13.2Z"/></svg>';
 const sun='<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/></svg>';
 function updateControls(){
  for(const button of document.querySelectorAll('[data-color-mode-toggle]')){
   const next=current==='light'?'dark':'light';
   button.setAttribute('aria-label','Switch to '+next+' mode');
   button.setAttribute('aria-pressed',String(current==='dark'));
   button.title='Switch to '+next+' mode';
   button.innerHTML=(next==='dark'?moon:sun)+'<span class="color-mode-label">'+(next==='dark'?'Dark':'Light')+'</span>';
  }
 }
 function apply(mode,persist=false){
  if(!valid(mode))return;current=mode;
  root.setAttribute('data-color-mode',mode);
  const meta=document.querySelector('meta[name="theme-color"]');if(meta)meta.content=mode==='light'?'#ffffff':'#000000';
  if(persist){
   try{localStorage.setItem(key,mode);}catch{}
   try{const shared=/(^|\.)garrettstimpson\.ca$/.test(location.hostname)?'; Domain=garrettstimpson.ca':'';document.cookie='garrett_color_mode='+mode+'; Path=/; Max-Age=31536000; SameSite=Lax'+shared+(location.protocol==='https:'?'; Secure':'');}catch{}
  }
  updateControls();
  document.dispatchEvent(new CustomEvent('garrett:color-mode',{detail:{mode}}));
  for(const frame of document.querySelectorAll('iframe.giscus-frame'))frame.contentWindow?.postMessage({giscus:{setConfig:{theme:mode==='light'?'light':'transparent_dark'}}},'https://giscus.app');
 }
 function mount(){
  if(!document.querySelector('[data-color-mode-toggle]')){
   const candidates=[...document.querySelectorAll('.funnel-header-inner,.auth-header-inner,.site-header .wrapper,.workspace-bar,.workspace-topbar,.workspace-header,.chat-topbar,.chat-header,body > header')].sort((a,b)=>Number(a.matches('body > header'))-Number(b.matches('body > header')));
   const container=candidates.find(element=>element.getClientRects().length);
   const button=document.createElement('button');button.type='button';button.className='color-mode-toggle';button.setAttribute('data-color-mode-toggle','');
   if(container){container.classList.add('has-color-toggle');const menu=container.querySelector('.funnel-menu,.site-nav');container.insertBefore(button,menu||null);}
   else{button.classList.add('color-mode-fallback');document.body.append(button);}
  }
  updateControls();
  const comments=document.querySelector('script[src="https://giscus.app/client.js"]');if(comments)comments.setAttribute('data-theme',current==='light'?'light':'transparent_dark');
 }
 styleSources();apply(stored()||'light');
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();
 document.addEventListener('click',event=>{if(event.target.closest?.('[data-color-mode-toggle]'))apply(current==='light'?'dark':'light',true);});
 document.addEventListener('load',event=>{if(event.target.matches?.('iframe.giscus-frame'))event.target.contentWindow?.postMessage({giscus:{setConfig:{theme:current==='light'?'light':'transparent_dark'}}},'https://giscus.app');},true);
 addEventListener('storage',event=>{if(event.key===key&&valid(event.newValue))apply(event.newValue);});
 addEventListener('pageshow',()=>{const value=stored();if(value&&value!==current)apply(value);});
 addEventListener('focus',()=>{const value=stored();if(value&&value!==current)apply(value);});
 if(typeof MutationObserver!=='undefined')new MutationObserver(styleSources).observe(document.head,{childList:true,subtree:true});
})();
