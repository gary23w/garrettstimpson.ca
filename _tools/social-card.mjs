import {createCanvas, GlobalFonts} from '@napi-rs/canvas';
import {createRequire} from 'node:module';

const width = 1200;
const height = 630;

const require = createRequire(import.meta.url);
for (const [file, family] of [
  ['@fontsource/geist/files/geist-latin-400-normal.woff2', 'Card Geist'],
  ['@fontsource/jetbrains-mono/files/jetbrains-mono-latin-500-normal.woff2', 'Card Mono'],
  ['@fontsource/jetbrains-mono/files/jetbrains-mono-latin-700-normal.woff2', 'Card Mono'],
]) {
  if (!GlobalFonts.registerFromPath(require.resolve(file), family)) {
    throw new Error(`Could not load social card font ${file}`);
  }
}

const segmenter = new Intl.Segmenter('en', {granularity: 'grapheme'});

function wrap(context, text, maxWidth) {
  const lines = [];
  let line = '';
  for (const word of text.split(/\s+/u).filter(Boolean)) {
    const next = line ? `${line} ${word}` : word;
    if (line && context.measureText(next).width > maxWidth) {
      lines.push(line);
      line = word;
    } else {
      line = next;
    }
  }
  if (line) lines.push(line);
  return lines;
}

function fitLine(context, text, maxWidth, more = false) {
  if (!more && context.measureText(text).width <= maxWidth) return text;
  const letters = Array.from(segmenter.segment(text.replace(/…$/u, '')), item => item.segment);
  while (context.measureText(letters.join('') + '…').width > maxWidth) letters.pop();
  return letters.join('').trimEnd() + '…';
}

function drawLines(context, lines, x, top, lineHeight, maxWidth, limit) {
  lines.slice(0, limit).forEach((line, index) => {
    context.fillText(fitLine(context, line, maxWidth, index === limit - 1 && lines.length > limit),
      x, top + index * lineHeight);
  });
}

export function renderCard({brand, domain, section, title, description}) {
  const canvas = createCanvas(width, height);
  const context = canvas.getContext('2d');
  const left = 98;
  const textWidth = width - 2 * left;
  context.textBaseline = 'top';

  context.fillStyle = '#f4f4f4';
  context.fillRect(0, 0, width, height);
  context.beginPath();
  context.roundRect(48.5, 44.5, 1103, 541, 13);
  context.fillStyle = '#fff';
  context.fill();
  context.strokeStyle = '#c9c9c9';
  context.stroke();
  context.fillStyle = '#dedede';
  context.fillRect(49, 128, 1102, 1);

  context.beginPath();
  context.roundRect(left, 67, 38, 38, 6);
  context.fillStyle = '#111';
  context.fill();
  context.strokeStyle = '#fff';
  context.lineWidth = 1.8;
  context.lineCap = 'round';
  context.lineJoin = 'round';
  context.beginPath();
  context.moveTo(left + 10, 79);
  context.lineTo(left + 16, 85);
  context.lineTo(left + 10, 91);
  context.moveTo(left + 20, 91);
  context.lineTo(left + 28, 91);
  context.stroke();

  context.fillStyle = '#111';
  context.font = '700 23px "Card Mono"';
  context.fillText(brand, left + 55, 72);
  context.fillStyle = '#555';
  context.font = '500 18px "Card Mono"';
  context.textAlign = 'right';
  context.fillText(domain, width - left, 75);
  context.textAlign = 'left';

  const preferredLines = title.length <= 48 ? 2 : 3;
  let titleSize = 66;
  let titleLines;
  do {
    context.font = `700 ${titleSize}px "Card Mono"`;
    titleLines = wrap(context, title, textWidth);
    if (titleLines.length <= preferredLines || titleSize <= 42) break;
    titleSize -= 5;
  } while (true);

  const titleFont = context.font;
  const titleTop = titleLines.length === 1 ? 235 : 215;
  context.font = '700 19px "Card Mono"';
  context.fillText(fitLine(context, section.toUpperCase(), textWidth), left, titleTop - 46);
  context.font = titleFont;

  const titleLineHeight = Math.round(titleSize * 1.13);
  context.fillStyle = '#111';
  drawLines(context, titleLines, left, titleTop, titleLineHeight, textWidth, 3);

  const descriptionTop = titleTop + Math.min(3, titleLines.length) * titleLineHeight + 24;
  const descriptionLineHeight = 35;
  const descriptionLines = Math.min(3, Math.floor((555 - descriptionTop) / descriptionLineHeight));
  context.font = '400 28px "Card Geist"';
  context.fillStyle = '#454545';
  drawLines(context, wrap(context, description, textWidth), left, descriptionTop, descriptionLineHeight, textWidth,
    descriptionLines);

  return canvas.toBuffer('image/png');
}
