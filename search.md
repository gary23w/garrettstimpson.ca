---
layout: page
title: Search
permalink: /search/
description: "Search the research posts on garrettstimpson.ca by title, tag or keyword."
sitemap: false
robots: noindex, follow
---

<form class="research-search" role="search" data-research-search data-index-url="{{ '/search.json' | relative_url }}" data-topics-url="{{ '/topics/' | relative_url }}" action="{{ '/search/' | relative_url }}" method="get">
  <label for="site-search">Search the research</label>
  <p id="search-hint" class="search-hint">Find a CVE, product, tag or keyword. Use a few words to narrow your search.</p>
  <div class="search-input-row"><input id="site-search" class="search-box" name="q" type="search" placeholder="Try a CVE, OpenSSH, or authentication…" autocomplete="off" maxlength="200" aria-describedby="search-hint"><button class="research-button" type="button" data-search-clear hidden>Clear</button></div>
</form>
<div class="search-toolbar"><p id="search-count" class="search-count" role="status" aria-live="polite" aria-atomic="true">Loading the research index…</p><a class="research-text-link" href="{{ '/topics/' | relative_url }}">Browse by topic →</a></div>
<h2 id="search-results-title" class="search-results-title">Latest research</h2>
<div id="search-results" class="search-results" aria-busy="true" aria-labelledby="search-results-title"></div>
<template id="search-ad-template">{%- include removal-ad.html -%}</template>
<noscript><p>Search needs JavaScript. You can still <a href="{{ '/topics/' | relative_url }}">browse research by topic</a> or <a href="{{ '/' | relative_url }}">read the latest articles</a>.</p></noscript>
<script type="module" src="{{ '/assets/js/research-search.js' | relative_url }}?v={{ site.time | date: '%s' }}"></script>
