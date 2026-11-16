// Build the light palette from the same selectors as the original dark styles.
// Only paint properties change: layout, images, media queries and motion stay intact.
const paint=/^(?:color|background(?:-color|-image)?|border(?:-(?:top|right|bottom|left|inline|block|inline-start|inline-end|block-start|block-end))?(?:-color)?|outline(?:-color)?|box-shadow|text-shadow|fill|stroke|caret-color|accent-color|text-decoration-color|scrollbar-color|--[\w-]+)$/;

export function splitTopLevel(text,separator){
 const parts=[];let start=0,depth=0,quote='';
 for(let i=0;i<text.length;i++){
  const c=text[i];if(c==='\\'){i++;continue;}
  if(quote){if(c===quote)quote='';continue;}
  if(c==='"'||c==="'"){quote=c;continue;}
  if(c==='('||c==='[')depth++;else if(c===')'||c===']')depth--;
  else if(c===separator&&depth===0){parts.push(text.slice(start,i));start=i+1;}
 }
 parts.push(text.slice(start));return parts;
}
function gray(r,g,b,foreground){
 const lightness=.2126*r+.7152*g+.0722*b;
 let value=g>140&&g>r*1.4&&g>b*1.2?0:Math.round(255-lightness);
 if(foreground&&lightness>=40)value=Math.min(value,110);
 return Math.max(0,Math.min(255,value));
}
export function lightValue(value,foreground=false){
 // Never rewrite filenames, SVG data URLs, quoted content or image pixels.
 return value.split(/(url\((?:[^()"']|"[^"]*"|'[^']*')*\)|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/gi).map((part,index)=>{
  if(index%2)return part;
  return part.replace(/#([\da-f]{8}|[\da-f]{6}|[\da-f]{4}|[\da-f]{3})(?![\da-f])/gi,(_all,hex)=>{
   if(hex.length<=4)hex=[...hex].map(c=>c+c).join('');
   const shade=gray(parseInt(hex.slice(0,2),16),parseInt(hex.slice(2,4),16),parseInt(hex.slice(4,6),16),foreground).toString(16).padStart(2,'0');
   return '#'+shade.repeat(3)+hex.slice(6);
  }).replace(/rgba?\(([^()]*)\)/gi,(all,body)=>{
   const pieces=body.trim().split(/[\s,\/]+/);if(pieces.length<3||pieces.length>4)return all;
   const channels=pieces.slice(0,3).map(v=>v.endsWith('%')?parseFloat(v)*2.55:Number(v));
   if(channels.some(v=>!Number.isFinite(v)))return all;
   const shade=gray(...channels,foreground);
   return pieces.length===4?`rgba(${shade},${shade},${shade},${pieces[3]})`:`rgb(${shade},${shade},${shade})`;
  }).replace(/(?<![-\w])(?:black|white)(?![-\w])/gi,name=>name.toLowerCase()==='black'?'#fff':'#000');
 }).join('');
}
function cleanComments(text){
 let out='',quote='';
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(c==='\\'){out+=c+(text[++i]||'');continue;}
  if(quote){out+=c;if(c===quote)quote='';continue;}
  if(c==='"'||c==="'"){quote=c;out+=c;continue;}
  if(c==='/'&&text[i+1]==='*'){const end=text.indexOf('*/',i+2);i=end<0?text.length:end+1;out+=' ';continue;}
  out+=c;
 }
 return out;
}
function boundary(text,start,closing=false){
 let quote='',round=0,square=0,depth=1;
 for(let i=start;i<text.length;i++){
  const c=text[i];if(c==='\\'){i++;continue;}
  if(quote){if(c===quote)quote='';continue;}
  if(c==='"'||c==="'"){quote=c;continue;}
  if(c==='(')round++;else if(c===')')round--;else if(c==='[')square++;else if(c===']')square--;
  if(round||square)continue;
  if(closing){if(c==='{')depth++;if(c==='}'&&--depth===0)return i;}
  else if(c==='{'||c===';')return i;
 }
 return text.length;
}
function declarations(body){
 return splitTopLevel(body,';').flatMap(declaration=>{
  const colon=declaration.indexOf(':');if(colon<0)return[];
  const property=declaration.slice(0,colon).trim(),value=declaration.slice(colon+1).trim();
  if(!paint.test(property)||!value)return[];
  const foreground=/^(?:color|fill|stroke|caret-color|text-decoration-color)$/.test(property);
  const light=property==='text-shadow'?'none':lightValue(value,foreground);
  // Keep unchanged paint declarations too: a later var(), inherit or transparent
  // must still reset an earlier translated rule in the same cascade.
  return property+':'+light.replace(/\s*!important\s*$/,'')+'!important';
 }).join(';');
}
export function lightStyles(source,key){
 if(!/^[\w-]+$/.test(key))throw Error('Invalid stylesheet key');
 const root=`:root[data-color-mode="light"][data-color-styles~="${key}"]`;
 const prefix=selector=>selector.startsWith(':root')?selector.replace(':root',root):/^html(?=[\s.#[:]|$)/.test(selector)?selector.replace(/^html/,`html[data-color-mode="light"][data-color-styles~="${key}"]`):root+' '+selector;
 function rules(text){
  let out='',start=0;
  while(start<text.length){
   const open=boundary(text,start);if(open>=text.length)break;
   if(text[open]===';'){start=open+1;continue;}
   const header=text.slice(start,open).trim(),end=boundary(text,open+1,true),body=text.slice(open+1,end);start=end+1;
   if(header.startsWith('@')){
    if(/^@(media|supports|container|layer)\b/.test(header)){const nested=rules(body);if(nested)out+=header+'{'+nested+'}\n';}
   }else{
    const translated=declarations(body);
    if(translated)out+=splitTopLevel(header,',').map(s=>prefix(s.trim())).join(',')+'{'+translated+'}\n';
   }
  }
  return out;
 }
 return rules(cleanComments(source.replace(/^---\s*\n[\s\S]*?\n---\s*\n/,'')));
}
