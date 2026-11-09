import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

async function moduleFrom(path) {
  const source = await readFile(new URL(path, import.meta.url), 'utf8');
  return import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
}
const {compactQuery, searchResearch} = await moduleFrom('../assets/js/search-model.js');
const {canonicalShareURL, copyText} = await moduleFrom('../assets/js/site-controls.js');
const posts = [
  {title:'A recent update', tags:[], categories:[], excerpt:'An overview mentioning OpenSSH.', url:'/recent/'},
  {title:'OpenSSH authentication research', tags:['openssh','authentication'], categories:['linux'], excerpt:'An account issue on musl.', url:'/openssh/'},
  {title:'CVE-2026-123158', tags:['musl'], categories:['linux'], excerpt:'OpenSSH authentication on Linux.', url:'/cve/'},
  {title:'Another recent update', tags:[], categories:[], excerpt:'An overview mentioning OpenSSH.', url:'/another/'}
];
test('queries ignore redundant whitespace and stay within the visible field limit', () => {
  assert.equal(compactQuery('  OpenSSH\n  musl  '), 'OpenSSH musl');
  assert.equal(compactQuery('x'.repeat(400)).length, 200);
});
test('multi-word searches can match across title, tag, category and summary', () => {
  assert.deepEqual(searchResearch(posts, 'openssh musl linux').map(p=>p.url), ['/openssh/','/cve/']);
  assert.deepEqual(searchResearch(posts, 'openssh impossible'), []);
});
test('a title or exact tag match outranks an incidental mention, while ties keep recency', () => {
  assert.deepEqual(searchResearch(posts, 'openssh').map(p=>p.url), ['/openssh/','/recent/','/cve/','/another/']);
  assert.deepEqual(searchResearch(posts, ''), posts);
  assert.deepEqual(searchResearch([], 'openssh'), []);
});
test('CVE queries remain useful when pasted with typographic hyphens', () => {
  assert.equal(searchResearch(posts, 'CVE–2026–123158')[0].url, '/cve/');
});
test('sharing uses the canonical article URL rather than a campaign query or heading', () => {
  assert.equal(canonicalShareURL('https://example.com/post/?utm_source=campaign#details','https://example.com/post/'), 'https://example.com/post/');
  assert.equal(canonicalShareURL('https://example.com/post/?utm_source=campaign#details'), 'https://example.com/post/');
  assert.equal(canonicalShareURL('https://example.com/post/','javascript:alert(1)'), 'https://example.com/post/');
});
test('clipboard denial and unavailable APIs return the manual-copy path without rejecting', async () => {
  let copied;
  assert.equal(await copyText('article', {async writeText(value){copied=value;}}), true);
  assert.equal(copied, 'article');
  assert.equal(await copyText('article', undefined), false);
  assert.equal(await copyText('article', {async writeText(){throw new Error('Permission denied');}}), false);
});
