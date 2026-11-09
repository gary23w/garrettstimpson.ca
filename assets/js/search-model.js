export function compactQuery(value) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, 200);
}

function normalized(value) {
  return String(value || '').normalize('NFKC').toLowerCase()
    .replace(/[\u2010-\u2015]/g, '-').replace(/[‘’]/g, "'");
}

export function searchResearch(posts, query) {
  const phrase = normalized(compactQuery(query));
  if (!phrase) return posts.slice();
  const terms = phrase.split(' ');
  return posts.map((post, index) => {
    const title = normalized(post.title);
    const tags = (Array.isArray(post.tags) ? post.tags : []).map(normalized);
    const categories = (Array.isArray(post.categories) ? post.categories : []).map(normalized);
    const excerpt = normalized(post.excerpt);
    const haystack = [title, ...tags, ...categories, excerpt].join(' ');
    if (!terms.every(term => haystack.includes(term))) return null;
    let score = title === phrase ? 100 : title.startsWith(phrase) ? 50 : 0;
    for (const term of terms) {
      if (title.includes(term)) score += 8;
      if (tags.includes(term)) score += 12;
      if (categories.includes(term)) score += 10;
      if (excerpt.includes(term)) score += 1;
    }
    return {post, index, score};
  }).filter(Boolean).sort((a, b) => b.score - a.score || a.index - b.index).map(item => item.post);
}
