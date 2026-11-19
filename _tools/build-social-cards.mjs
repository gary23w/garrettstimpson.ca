import {createHash} from 'node:crypto';
import {mkdir, readFile, unlink, writeFile} from 'node:fs/promises';
import {dirname, extname, isAbsolute, relative, resolve, sep} from 'node:path';
import {DomUtils, parseDocument} from 'htmlparser2';
import {renderCard} from './social-card.mjs';

const site = resolve(process.argv[2] || '_site');
const manifest = resolve(site, 'assets/og/pages.json');
const routes = JSON.parse(await readFile(manifest, 'utf8'));
let count = 0;

for (const route of new Set(routes)) {
  const path = decodeURI(route);
  const filename = path.endsWith('/') ? path + 'index.html' : extname(path) ? path : path + '.html';
  const documentPath = resolve(site, '.' + filename);
  const pagePath = relative(site, documentPath);
  if (isAbsolute(pagePath) || pagePath === '..' || pagePath.startsWith('..' + sep)) {
    throw new Error(`Invalid social card page path ${route}`);
  }

  const html = await readFile(documentPath, 'utf8');
  const end = html.indexOf('</head>');
  if (end === -1) continue;
  const head = html.slice(0, end);
  const tags = DomUtils.getElementsByTagName('meta', parseDocument(head).children);
  const meta = property => tags.find(tag => tag.attribs.property === property)?.attribs;
  const image = meta('og:image');
  if (image?.['data-social-card'] === undefined) continue;

  const original = new URL(image.content);
  const brand = meta('og:site_name').content;
  const title = meta('og:title').content;
  const suffix = ' | ' + brand;
  const png = renderCard({
    brand,
    domain: original.hostname,
    section: image['data-social-card'],
    title: title.endsWith(suffix) ? title.slice(0, -suffix.length) : title,
    description: meta('og:description').content,
  });
  const version = createHash('sha256').update(png).digest('hex').slice(0, 12);
  const asset = pagePath.split(sep).map(encodeURIComponent).join('/').replace(/\.html$/, '') + '-' + version + '.png';
  const target = resolve(site, 'assets/og', asset);
  const url = new URL('../og/' + asset, original).href;
  await mkdir(dirname(target), {recursive: true});
  await writeFile(target, png);
  await writeFile(documentPath, head.replaceAll(`"${original.href}"`, `"${url}"`) + html.slice(end));
  count++;
}

if (!count) throw new Error('The social card build did not find any page metadata');
await unlink(manifest);
console.log(`Generated ${count} page-specific social cards`);
