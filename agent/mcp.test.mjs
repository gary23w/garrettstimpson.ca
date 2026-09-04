import test from 'node:test';
import assert from 'node:assert/strict';
import { handleMcpRequest, mcpToolDefinition, MCP_PROTOCOLS } from './src/mcp.mjs';

const env = { MCP_API_TOKEN: 'a-test-token-long-enough', MCP_ALLOW_ACTIVE_TOOLS: 'false' };
const handlers = {
  readJson: request => request.json(),
  listTools: async () => [{ name: 'nvd_lookup', passive: true, description: 'NVD lookup' }],
  callTool: async (name, args) => ({ result: `${name}:${args.cveId}`, via: 'builtin', target: args.cveId }),
};
const post = (body, headers = {}) => new Request('https://agent.example/mcp', {
  method: 'POST',
  headers: { Authorization: `Bearer ${env.MCP_API_TOKEN}`, 'Content-Type': 'application/json', ...headers },
  body: JSON.stringify(body),
});

test('MCP fails closed without a configured token', async () => {
  const response = await handleMcpRequest(post({ jsonrpc: '2.0', id: 1, method: 'ping' }), {}, handlers);
  assert.equal(response.status, 503);
});

test('MCP rejects invalid bearer credentials', async () => {
  const request = post({ jsonrpc: '2.0', id: 1, method: 'ping' }, { Authorization: 'Bearer wrong' });
  const response = await handleMcpRequest(request, env, handlers);
  assert.equal(response.status, 401);
  assert.match(response.headers.get('www-authenticate'), /^Bearer/);
});

test('legacy initialization returns server instructions and tool capability', async () => {
  const response = await handleMcpRequest(post({
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: MCP_PROTOCOLS.legacy, capabilities: {}, clientInfo: { name: 'test', version: '1' } },
  }), env, handlers);
  const body = await response.json();
  assert.equal(body.result.protocolVersion, MCP_PROTOCOLS.legacy);
  assert.equal(body.result.serverInfo.name, 'agent-garrett');
  assert.match(body.result.instructions, /authorization/i);
});

test('widely deployed Streamable HTTP protocol versions remain compatible', async () => {
  const response = await handleMcpRequest(post({
    jsonrpc: '2.0', id: 7, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'codex-test', version: '1' } },
  }), env, handlers);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).result.protocolVersion, '2025-06-18');
});

test('modern requests require method and tool-name headers', async () => {
  const request = post({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'nvd_lookup', arguments: { cveId: 'CVE-2026-1' } } }, {
    'MCP-Protocol-Version': MCP_PROTOCOLS.current,
    'Mcp-Method': 'tools/call',
  });
  const response = await handleMcpRequest(request, env, handlers);
  assert.equal(response.status, 400);
  assert.match((await response.json()).error.message, /Mcp-Name/);
});

test('tools/list returns private cache metadata and annotations', async () => {
  const response = await handleMcpRequest(post({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }), env, handlers);
  const body = await response.json();
  assert.equal(body.result.cacheScope, 'private');
  assert.equal(body.result.tools[0].annotations.readOnlyHint, true);
});

test('network-free passive compute tools advertise a closed-world contract', () => {
  const tool = mcpToolDefinition({
    name: 'persistence_analyze',
    passive: true,
    openWorld: false,
    description: 'Passive persistence evidence triage',
  });
  assert.equal(tool.annotations.readOnlyHint, true);
  assert.equal(tool.annotations.openWorldHint, false);
});

test('tools/call returns MCP content and structured evidence metadata', async () => {
  const response = await handleMcpRequest(post({
    jsonrpc: '2.0', id: 4, method: 'tools/call',
    params: { name: 'nvd_lookup', arguments: { cveId: 'CVE-2026-1' } },
  }), env, handlers);
  const body = await response.json();
  assert.equal(body.result.content[0].text, 'nvd_lookup:CVE-2026-1');
  assert.equal(body.result.structuredContent.target, 'CVE-2026-1');
});

test('tools/call preserves persistence uncertainty metadata', async () => {
  const evidenceHandlers = {
    ...handlers,
    callTool: async () => ({
      result: 'persistence_analyze — passive textual evidence only',
      via: 'builtin',
      target: '',
      evidence: {
        confidence: 'low',
        confidenceScore: 0.55,
        uncertain: true,
        evidenceBasis: 'textual-evidence-only',
      },
    }),
  };
  const response = await handleMcpRequest(post({
    jsonrpc: '2.0', id: 9, method: 'tools/call',
    params: { name: 'persistence_analyze', arguments: { text: 'Analyze this persistence report: scheduled task' } },
  }), env, evidenceHandlers);
  const body = await response.json();
  assert.equal(body.result.structuredContent.confidence, 'low');
  assert.equal(body.result.structuredContent.uncertain, true);
  assert.equal(body.result.structuredContent.evidenceBasis, 'textual-evidence-only');
});

test('tools/call enforces its advertised argument schema', async () => {
  const response = await handleMcpRequest(post({
    jsonrpc: '2.0', id: 8, method: 'tools/call',
    params: { name: 'nvd_lookup', arguments: { unexpected: 'value' } },
  }), env, handlers);
  assert.equal(response.status, 400);
  assert.match((await response.json()).error.message, /Unknown tool argument/);

  const structured = await handleMcpRequest(post({
    jsonrpc: '2.0', id: 10, method: 'tools/call',
    params: { name: 'nvd_lookup', arguments: { cveId: ['CVE-2026-1'] } },
  }), env, handlers);
  assert.equal(structured.status, 400);
  assert.match((await structured.json()).error.message, /cveId must be a string/);

  const schema = mcpToolDefinition({ name: 'jwt', passive: true }).inputSchema;
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.properties.token, { type: 'string', maxLength: 12000 });
  assert.deepEqual(schema.properties.scope, { type: 'string', maxLength: 12000 });
});

test('cross-origin browser requests are rejected', async () => {
  const response = await handleMcpRequest(post({ jsonrpc: '2.0', id: 5, method: 'ping' }, { Origin: 'https://evil.example' }), env, handlers);
  assert.equal(response.status, 403);
});
