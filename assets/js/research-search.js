import {compactQuery, searchResearch} from './search-model.js';

const form = document.querySelector('[data-research-search]');
if (form) {
  const input = form.querySelector('input[type="search"]');
  const clear = form.querySelector('[data-search-clear]');
  const status = document.getElementById('search-count');
  const results = document.getElementById('search-results');
  const title = document.getElementById('search-results-title');
  const promotion = document.getElementById('search-ad-template');
  let index = [], loaded = false, loading = false, failed = false, debounce;

  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text) element.textContent = text;
    if (className) element.className = className;
    return element;
  }

  function safeLink(url) {
    try {
      const target = new URL(url, location.href);
      return target.origin === location.origin && target.pathname.startsWith('/') ? target.pathname + target.search + target.hash : null;
    } catch { return null; }
  }

  function card(post) {
    const article = node('article', '', 'post-card');
    const link = node('a', '', 'post-card-link');
    link.href = safeLink(post.url);
    const meta = node('div', '', 'post-card-meta');
    meta.append(node('span', post.date, 'post-date'));
    link.append(meta, node('h3', post.title, 'post-card-title'), node('p', post.excerpt, 'post-card-excerpt'));
    const tags = node('div', '', 'post-tags');
    for (const tag of (Array.isArray(post.tags) ? post.tags : []).slice(0, 6)) tags.append(node('span', tag, 'tag'));
    link.append(tags);
    article.append(link);
    return article;
  }

  function panel(heading, description, retry) {
    const box = node('div', '', 'search-state');
    box.append(node('h3', heading), node('p', description));
    const actions = node('div', '', 'search-state-actions');
    const button = node('button', retry ? 'Try again' : 'Clear search', 'research-button');
    button.type = 'button';
    button.addEventListener('click', retry ? () => { input.focus(); load(); } : reset);
    const topics = node('a', 'Browse topics →', 'research-text-link');
    topics.href = form.dataset.topicsUrl;
    actions.append(button, topics);
    box.append(actions);
    return box;
  }

  function syncURL() {
    const url = new URL(location.href);
    const query = compactQuery(input.value);
    if (query) url.searchParams.set('q', query);
    else url.searchParams.delete('q');
    history.replaceState(null, '', url);
  }

  function reset() {
    clearTimeout(debounce);
    input.value = '';
    syncURL();
    render();
    input.focus();
  }

  function render() {
    const query = compactQuery(input.value);
    clear.hidden = !input.value;
    results.setAttribute('aria-busy', String(loading));
    if (loading || !loaded && !failed) {
      status.textContent = 'Loading the research index…';
      title.textContent = 'Loading research';
      results.replaceChildren(node('p', 'Getting the latest research index…', 'search-hint'));
      return;
    }
    results.replaceChildren();
    if (failed) {
      title.textContent = 'Search is temporarily unavailable';
      status.textContent = 'Your query is saved. Try loading the index again, or browse the topic guides.';
      results.append(panel('Let’s try that again.', 'The research index could not load. Your search has not been lost.', true));
      return;
    }
    const matches = searchResearch(index, query);
    title.textContent = query ? 'Search results' : 'Latest research';
    status.textContent = query
      ? `${matches.length} result${matches.length === 1 ? '' : 's'} for “${query}”`
      : `${index.length} articles indexed. Search a CVE, product, tag or keyword.`;
    if (!matches.length && query) {
      results.append(panel('No matching research yet.', 'Try a shorter query, a product name or a CVE number. You can also explore the topic guides.', false));
    }
    const shown = query ? matches : matches.slice(0, 6);
    shown.forEach((post, position) => {
      results.append(card(post));
      if (position === 1 && promotion) results.append(promotion.content.cloneNode(true));
    });
    if (shown.length < 2 && promotion) results.append(promotion.content.cloneNode(true));
  }

  async function load() {
    if (loading) return;
    loading = true;
    failed = false;
    render();
    try {
      const response = await fetch(form.dataset.indexUrl, {headers: {Accept: 'application/json'}});
      if (!response.ok) throw new Error('Search index unavailable');
      const data = await response.json();
      if (!Array.isArray(data)) throw new Error('Invalid search index');
      index = data.filter(post => post && typeof post.title === 'string' && typeof post.url === 'string' && safeLink(post.url));
      loaded = true;
    } catch { failed = true; }
    finally { loading = false; render(); }
  }

  function restore() {
    clearTimeout(debounce);
    input.value = compactQuery(new URL(location.href).searchParams.get('q'));
    render();
  }
  input.addEventListener('input', () => {
    clear.hidden = !input.value;
    clearTimeout(debounce);
    debounce = setTimeout(() => { syncURL(); render(); }, 160);
  });
  form.addEventListener('submit', event => { event.preventDefault(); clearTimeout(debounce); syncURL(); render(); });
  clear.addEventListener('click', reset);
  window.addEventListener('popstate', restore);
  window.addEventListener('pageshow', event => { if (event.persisted) restore(); });
  restore();
  load();
}
