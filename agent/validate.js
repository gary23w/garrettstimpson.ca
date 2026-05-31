// Validates the embedded browser <script> inside the terminalUI template literal —
// the part `node --check index.js` cannot see (it's a string to Node).
const fs = require('fs');
const s = fs.readFileSync(__dirname + '/src/index.js', 'utf8');
function extractTemplate(fnName) {
  const i = s.indexOf('function ' + fnName + '(');
  if (i < 0) throw new Error('missing function ' + fnName);
  const r = s.indexOf('return `', i) + 7;
  let j = r + 1, e = -1;
  for (; j < s.length; j++) { if (s[j] === '`' && s[j - 1] !== '\\') { e = j; break; } }
  if (e < 0) throw new Error('unterminated template in ' + fnName);
  return s.slice(r, e + 1);
}
let blocks = 0;
['terminalUI', 'loginUI'].forEach(function (fn) {
  const html = new Function('siteName', 'needUser', 'needPass', 'return ' + extractTemplate(fn) + ';')('Test', true, true);
  const matches = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  matches.forEach(function (m) { new Function(m[1]); blocks++; });
});
console.log('OK — embedded client <script> blocks compiled:', blocks);
