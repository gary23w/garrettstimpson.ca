import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {lightStyles} from '../_tools/color-mode-css.mjs';
test('every standard blog layout starts light and loads the shared switch before paint',async()=>{
 const html=await readFile(new URL('../_layouts/default.html',import.meta.url),'utf8');assert.match(html,/<html[^>]*data-color-mode="light"/);assert.ok(html.indexOf('id="color-mode-script"')<html.indexOf('</head>'));assert.match(html,/assets\/css\/color-mode.css/);
});
test('the light rain uses normal blending and excludes lightning strikes and flashes',async()=>{
 const js=await readFile(new URL('../assets/js/digital-storm.js',import.meta.url),'utf8');assert.match(js,/rain\.material\.blending = light \? THREE\.NormalBlending/);assert.match(js,/if \(contextLost \|\| motionPreference\.matches \|\| uniforms\.uLightMode\.value\) return/);assert.match(js,/bolts\.visible = !uniforms\.uLightMode\.value/);assert.match(js,/garrett:color-mode/);assert.match(js,/mix\(col, vec3\(1\.\), uLightMode\)/);
});
test('a monochrome skin changes paint while preserving responsive rules and media',()=>{
 const css=lightStyles('@media(max-width:700px){.hero{background:#000;color:#fff;display:flex}.image{background:url("/green.jpg") #001805}}','style');assert.match(css,/@media\(max-width:700px\)/);assert.match(css,/color:#000000!important/);assert.match(css,/url\("\/green.jpg"\)/);assert.doesNotMatch(css,/display:flex/);
});

test('the compiled light palette covers imported storm reading layers',async()=>{
 const css=await readFile(new URL('../assets/css/color-mode.css',import.meta.url),'utf8');
 assert.match(css,/\.storm-reading-shade::before\{background:rgba\(252,252,252,0?\.94\)!important/);
 assert.match(css,/\.removal-ad \.removal-ad-cta\{[^}]*background:var\(--green\)!important/);
});
