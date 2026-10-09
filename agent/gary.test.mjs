import test from 'node:test';
import assert from 'node:assert/strict';
import { garyToolCatalog, getGaryToolSpec, validateGaryArguments, collectGaryTargets, runGaryTool, parseGaryRouterObject, routeExplicitGaryCall } from './src/gary-tools.mjs';
import { mcpToolDefinition, handleMcpRequest } from './src/mcp.mjs';
import { routeGaryRequest, runGaryAI } from './gary/gateway.mjs';

test('Gary catalog has the complete native capability families and English schemas', () => {
  const catalog=garyToolCatalog();
  assert.equal(catalog.length,72);
  for(const name of ['bash','read','write','edit','multiedit','glob','grep','shell_open','shell_send','shell_read','shell_close','shell_list','taskoutput','taskstop','tasklist','todowrite','skill','traffic_search','traffic_get','traffic_blob','insert_assets','report_finding','spawn_task','create_mcp','create_custom_tool','get_finding_retest_context']) assert.ok(getGaryToolSpec('gary_'+name), name);
  assert.equal(/[\p{Script=Han}]/u.test(JSON.stringify(catalog)),false);
  assert.equal(getGaryToolSpec('gary_read').available,false);
  assert.equal(getGaryToolSpec('gary_grep',{GARY_RUNTIME:{fetch(){}}}).available,true);
  assert.equal(garyToolCatalog({GARY_TOOLS_ENABLED:'false'}).length,0);
});

test('Gary arguments retain native nested arrays and numeric IDs', () => {
  const spec=getGaryToolSpec('gary_report_finding');
  const args={vulnclass:'Access control',severity:'low',summary:'Verified finding',evidence:'Observed response',asset_ids:[7],intent_id:8,traffic_refs:[{traffic_id:'9',role:'proof'}],_gary:{sessionId:'local',taskId:'4',intentId:8}};
  assert.equal(validateGaryArguments(spec,args).ok,true);
  assert.equal(validateGaryArguments(getGaryToolSpec('gary_traffic_search'),{host:'example.com',limit:'3'}).ok,false);
  assert.equal(validateGaryArguments(getGaryToolSpec('gary_read'),{}).ok,false);
  assert.equal(validateGaryArguments(spec,{...args,_gary:{sessionId:'../../bad'}}).ok,false);
  assert.equal(validateGaryArguments(spec,JSON.parse('{"__proto__":{}}')).ok,false);
  assert.deepEqual(collectGaryTargets({assets:[{url:'https://example.com:8443/api'},{host:'example.net:443'},{ip:'[2001:db8::1]:443'}],command:'printf hello',_gary:{sessionId:'abc'}}),['example.com','example.net','2001:db8::1']);
});

test('private binding forwards native args without frontend backend secrets', async () => {
  let body;
  const env={GARY_RUNTIME:{async fetch(request){assert.equal(request.headers.has('Authorization'),false);body=await request.json();return Response.json({ok:true,isError:false,result:'recorded',extra:[{role:'user',content:[{type:'text',text:'Skill instructions'}]}]});}}};
  const spec=getGaryToolSpec('gary_traffic_search',env);
  const result=await runGaryTool(env,spec,{host:'example.com',limit:3,_gary:{sessionId:'alpha',taskId:'2'}});
  assert.equal(body.tool,'traffic_search');assert.equal(body.args.limit,3);assert.equal(body.context.taskId,'2');assert.equal(body.args._gary,undefined);assert.ok(result.extra.length);
  await assert.rejects(runGaryTool({...env,GARY_TOOLS_ENABLED:'false'},spec,{}),/disabled/);
});

test('MCP exposes native Gary schema and preserves errors and skill guidance', async () => {
  const spec=getGaryToolSpec('gary_traffic_search',{GARY_RUNTIME:{fetch(){}}});
  assert.equal(mcpToolDefinition(spec).inputSchema.properties.limit.type,'integer');
  const env={MCP_API_TOKEN:'mcp-test-token-with-32-characters'};
  const make=args=>new Request('https://garrett.example/mcp',{method:'POST',headers:{Authorization:'Bearer '+env.MCP_API_TOKEN},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:spec.name,arguments:args}})});
  let calls=0;
  const handlers={readJson:r=>r.json(),getToolSpec:()=>spec,callTool:async()=>{calls++;return {result:'Native failure',content:[{type:'text',text:'Native failure'}],extra:[{role:'user',content:[{type:'text',text:'Guidance'}]}],isError:true,via:'gary'};}};
  const bad=await handleMcpRequest(make({host:'example.com',limit:'3'}),env,handlers);assert.equal(bad.status,400);assert.equal(calls,0);
  const good=await handleMcpRequest(make({host:'example.com',limit:3}),env,handlers);const data=await good.json();assert.equal(data.result.isError,true);assert.equal(data.result.structuredContent.via,'gary');assert.equal(data.result.structuredContent.extra.length,1);assert.equal(calls,1);
});

test('backend gateway is private, bounded, and replaces caller credentials', async () => {
  let forwarded;
  const env={GARY_RUNTIME_TOKEN:'backend-token-with-32-characters',GARY_STATE:{},GARY_CONTAINER:{idFromName:n=>n,get:()=>({fetch:async r=>{forwarded=r;return Response.json({ok:true});}})}};
  const request=new Request('http://backend/tools/run',{method:'POST',headers:{Authorization:'Bearer wrong'},body:'{"tool":"Read","args":{"file_path":"note.txt"}}'});
  assert.equal((await routeGaryRequest(request,env)).status,200);
  assert.equal(forwarded.headers.get('Authorization'),'Bearer '+env.GARY_RUNTIME_TOKEN);
  assert.equal((await routeGaryRequest(new Request('http://backend/tools/run',{method:'POST',headers:{Origin:'https://browser.example'},body:'{}'}),env)).status,403);
  assert.equal((await routeGaryRequest(new Request('http://backend/admin',{method:'POST',body:'{}'}),env)).status,404);
});

test('Cloudflare AI relay retains tool calls for the native orchestration engine', async () => {
  let input;
  const response=await runGaryAI(new Request('http://gary.ai/v1/chat/completions',{method:'POST',body:JSON.stringify({messages:[{role:'user',content:'List assets'}],tools:[{type:'function',function:{name:'list_assets',parameters:{type:'object'}}}]})}),{AI:{run:async(model,args)=>{input=args;return {response:'',tool_calls:[{name:'list_assets',arguments:{limit:3}}]};}}});
  const data=await response.json();assert.equal(input.tools[0].type,'function');assert.equal(input.tools[0].function.name,'list_assets');assert.equal(data.choices[0].finish_reason,'tool_calls');assert.equal(data.choices[0].message.tool_calls[0].function.arguments,'{"limit":3}');
});

test('router reads nested Gary objects and braces inside strings', () => {
  assert.deepEqual(parseGaryRouterObject('```json\n{"tool":"gary_bash","args":{"command":"printf \\\"{}\\\""}}\n```'),{tool:'gary_bash',args:{command:'printf "{}"'}});
  assert.equal(parseGaryRouterObject('{bad'),null);
});

test('Cloudflare AI relay serves native streaming callers and indexed tool deltas', async () => {
  const response = await runGaryAI(new Request('http://gary.ai/v1/chat/completions',{method:'POST',body:JSON.stringify({stream:true,messages:[{role:'user',content:'Read saved evidence'}]})}),{AI:{run:async()=>({response:'Evidence follows',tool_calls:[{name:'Read',arguments:{file_path:'evidence.txt'}}]})}});
  assert.match(response.headers.get('Content-Type'),/text\/event-stream/);
  const frames=(await response.text()).split('\n\n').filter(Boolean).map(line=>line.slice(6));
  assert.equal(frames.at(-1),'[DONE]');
  const content=JSON.parse(frames[0]).choices[0].delta;
  assert.equal(content.content,'Evidence follows');
  assert.equal(content.tool_calls[0].index,0);
  assert.equal(content.tool_calls[0].function.arguments,'{"file_path":"evidence.txt"}');
  assert.equal(JSON.parse(frames[1]).choices[0].finish_reason,'tool_calls');
});

test('explicit Gary chat calls retain native arguments and cannot select a disallowed tool', async () => {
  let calls=0;
  const env={GARY_RUNTIME:{fetch(){}},AI:{async run(model,input){calls++;assert.equal(input.max_tokens,2400);return {choices:[{message:{content:'{"file_path":"/app/data/fixture.txt"}'}}]};}}};
  const routed=await routeExplicitGaryCall(env,'Use gary_read with file_path /app/data/fixture.txt',['gary_read']);
  assert.equal(routed.choice.tool,'gary_read');assert.equal(routed.choice.args.file_path,'/app/data/fixture.txt');assert.equal(calls,1);
  const blocked=await routeExplicitGaryCall(env,'Use gary_bash command echo hello',['gary_read']);
  assert.equal(blocked.choice,null);assert.equal(calls,1);
  const missing=await routeExplicitGaryCall({...env,AI:{run:async()=>({response:'{"missingInput":true}'})}},'Use gary_read',['gary_read']);
  assert.equal(missing.choice,null);
  const supplied=await routeExplicitGaryCall(env,'Use gary_insert_assets {"assets":[{"type":"ip","ip":"127.0.0.1"}]}',['gary_insert_assets']);
  assert.equal(supplied.choice.args.assets[0].ip,'127.0.0.1');assert.equal(calls,1);
});

test('native AI relay reports provider errors with an OpenAI error response', async () => {
  const response=await runGaryAI(new Request('http://gary.ai/v1/chat/completions',{method:'POST',body:JSON.stringify({messages:[{role:'user',content:'Marker'}]})}),{AI:{run:async()=>{throw Error('Provider temporarily unavailable');}}});
  assert.equal(response.status,502);assert.equal((await response.json()).error.type,'gary_ai_error');
});
