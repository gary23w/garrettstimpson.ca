import { GARY_TOOL_CATALOG } from './gary-catalog.mjs';

const cache = new Map();
const forbiddenKeys = new Set(['__proto__', 'constructor', 'prototype']);
const contextSchema = {
  type: 'object', additionalProperties: false,
  properties: {
    sessionId: { type: 'string', pattern: '^[A-Za-z0-9_-]{1,64}$', description: 'Reuse this session for shell state, files, background processes and connected tools.' },
    taskId: { type: 'string', pattern: '^[0-9]+$', description: 'For task-bound graph, intent and finding tools, use an existing task ID returned by gary_list_tasks or gary_spawn_task.' },
    intentId: { type: 'integer', minimum: 0 },
    conversationId: { type: 'integer', minimum: 0 },
  },
};

function enabled(env = {}) {
  return !['false', '0', 'off'].includes(String(env.GARY_TOOLS_ENABLED ?? 'true').toLowerCase());
}

export function garyRuntimeConfigured(env = {}) {
  return !!(env.GARY_RUNTIME?.fetch || env.GARY_RUNTIME_URL);
}

function runtimeKey(env) {
  return env.GARY_RUNTIME?.fetch ? env.GARY_RUNTIME : String(env.GARY_RUNTIME_URL || 'unconfigured');
}

function wrap(spec, env = {}) {
  const inputSchema = {
    ...spec.inputSchema,
    properties: { ...spec.inputSchema?.properties, _gary: contextSchema },
  };
  return {
    name: spec.name,
    upstreamName: spec.upstreamName,
    description: spec.description,
    category: spec.category || 'gary-security',
    passive: spec.readOnly === true,
    openWorld: true,
    via: 'gary',
    inputSchema,
    available: garyRuntimeConfigured(env) && !spec.unavailableReason,
    unavailableReason: spec.unavailableReason || (garyRuntimeConfigured(env) ? '' : 'Gary runtime is not configured.'),
  };
}

export function garyToolCatalog(env = {}) {
  if (!enabled(env)) return [];
  const loaded = cache.get(runtimeKey(env));
  const specs = loaded?.tools || GARY_TOOL_CATALOG.tools;
  return specs.map(spec => wrap(spec, env));
}

export function getGaryToolSpec(name, env = {}) {
  return garyToolCatalog(env).find(spec => spec.name === name) || null;
}

function endpoint(env, operation) {
  const base = String(env.GARY_RUNTIME_URL || '').trim();
  if (env.GARY_RUNTIME?.fetch && !base) return new URL(operation, 'https://gary-runtime.invalid/');
  let url;
  try { url = new URL(base); } catch { throw new Error('Configure GARY_RUNTIME_URL or the GARY_RUNTIME service binding.'); }
  if (url.username || url.password || url.hash || url.search) throw new Error('Gary runtime URL cannot contain credentials, a query, or a fragment.');
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:' && String(env.GARY_RUNTIME_LOCAL) === 'true')) {
    throw new Error('Gary runtime requires HTTPS; loopback HTTP is available only with GARY_RUNTIME_LOCAL=true.');
  }
  if (!local && /^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(url.hostname)) throw new Error('Use the Gary service binding for private runtimes.');
  url.pathname = url.pathname.replace(/\/$/, '') + '/' + operation;
  return url;
}

async function requestRuntime(env, operation, payload, timeoutMs = 180000) {
  const token = String(env.GARY_RUNTIME_TOKEN || '');
  if (!env.GARY_RUNTIME?.fetch && token.length < 24) throw new Error('GARY_RUNTIME_TOKEN must contain at least 24 characters.');
  const url = endpoint(env, operation);
  const request = new Request(url, {
    method: 'POST', redirect: 'manual',
    headers: { ...(!env.GARY_RUNTIME?.fetch ? { Authorization: `Bearer ${token}` } : {}), 'Content-Type': 'application/json' },
    body: JSON.stringify(payload), signal: AbortSignal.timeout(timeoutMs),
  });
  const response = env.GARY_RUNTIME?.fetch ? await env.GARY_RUNTIME.fetch(request) : await fetch(request);
  if (response.status >= 300 && response.status < 400) throw new Error('Gary runtime redirects are refused.');
  const reader = response.body?.getReader();
  const chunks = []; let size = 0;
  if (!reader) throw new Error('Gary runtime returned no response body.');
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > 4 * 1024 * 1024) { await reader.cancel(); throw new Error('Gary runtime response exceeds 4 MiB.'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  let result;
  try { result = JSON.parse(new TextDecoder().decode(bytes)); } catch { throw new Error('Gary runtime returned invalid JSON.'); }
  if (!response.ok || result.ok !== true) throw new Error(result.error || `Gary runtime returned HTTP ${response.status}.`);
  return result;
}

export async function loadGaryToolCatalog(env = {}) {
  if (!enabled(env) || !garyRuntimeConfigured(env)) return garyToolCatalog(env);
  const key = runtimeKey(env);
  const current = cache.get(key);
  if (current && Date.now() - current.loadedAt < 60000) return garyToolCatalog(env);
  const result = await requestRuntime(env, 'tools/catalog', { context: defaultContext(env) }, 30000);
  if (!Array.isArray(result.tools) || result.tools.length > 512) throw new Error('Invalid Gary tool catalog.');
  const seen = new Set();
  for (const spec of result.tools) {
    if (!/^gary_[a-z0-9_-]+$/.test(spec.name) || !spec.upstreamName || !spec.inputSchema || seen.has(spec.name)) throw new Error('Invalid or duplicate Gary tool definition.');
    seen.add(spec.name);
  }
  cache.set(key, { tools: result.tools, loadedAt: Date.now() });
  return garyToolCatalog(env);
}

function defaultContext(env) {
  return { sessionId: String(env.GARY_SESSION_ID || 'garrett'), ...(env.GARY_TASK_ID ? { taskId: String(env.GARY_TASK_ID) } : {}) };
}

function matchesType(type, value) {
  if (type === 'null') return value === null;
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (type === 'array') return Array.isArray(value);
  if (type === 'integer') return Number.isSafeInteger(value);
  if (type === 'number') return typeof value === 'number' && Number.isFinite(value);
  return typeof value === type;
}

function validateValue(schema = {}, value, at, depth, budget) {
  if (depth > 16 || ++budget.nodes > 4096) throw new Error('Gary arguments exceed the nesting or item limit.');
  if (schema.anyOf && !schema.anyOf.some(part => { try { validateValue(part, value, at, depth, { nodes: 0 }); return true; } catch { return false; } })) throw new Error(`${at} does not match any allowed type.`);
  if (schema.oneOf && schema.oneOf.filter(part => { try { validateValue(part, value, at, depth, { nodes: 0 }); return true; } catch { return false; } }).length !== 1) throw new Error(`${at} must match one allowed type.`);
  for (const part of schema.allOf || []) validateValue(part, value, at, depth, budget);
  const types = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : [];
  if (types.length && !types.some(type => matchesType(type, value))) throw new Error(`${at} must be ${types.join(' or ')}.`);
  if (schema.enum && !schema.enum.some(item => JSON.stringify(item) === JSON.stringify(value))) throw new Error(`${at} is not an allowed value.`);
  if ('const' in schema && JSON.stringify(schema.const) !== JSON.stringify(value)) throw new Error(`${at} does not match the required value.`);
  if (typeof value === 'string') {
    if (value.length > Math.min(schema.maxLength ?? 65536, 65536) || value.length < (schema.minLength || 0)) throw new Error(`${at} has an invalid length.`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) throw new Error(`${at} has an invalid format.`);
  } else if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < (schema.minimum ?? -Infinity) || value > (schema.maximum ?? Infinity)) throw new Error(`${at} is outside its allowed range.`);
  } else if (Array.isArray(value)) {
    if (value.length > Math.min(schema.maxItems ?? 1024, 1024) || value.length < (schema.minItems || 0)) throw new Error(`${at} has an invalid item count.`);
    for (let i = 0; i < value.length; i++) validateValue(schema.items || {}, value[i], `${at}[${i}]`, depth + 1, budget);
  } else if (value && typeof value === 'object') {
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`${at} must be a plain object.`);
    for (const required of schema.required || []) if (!Object.hasOwn(value, required)) throw new Error(`${at}.${required} is required.`);
    for (const [key, item] of Object.entries(value)) {
      if (forbiddenKeys.has(key)) throw new Error(`Unsafe Gary argument: ${key}`);
      const child = schema.properties?.[key];
      if (!child && schema.additionalProperties === false) throw new Error(`Unknown Gary argument: ${at}.${key}`);
      validateValue(child || (typeof schema.additionalProperties === 'object' ? schema.additionalProperties : {}), item, `${at}.${key}`, depth + 1, budget);
    }
  } else if (value !== null && typeof value !== 'boolean') throw new Error(`${at} must be JSON data.`);
}

export function validateGaryArguments(spec, args) {
  try {
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Gary arguments must be a JSON object.');
    validateValue(spec.inputSchema, args, 'arguments', 0, { nodes: 0 });
    if (JSON.stringify(args).length > 262144) throw new Error('Gary arguments exceed 256 KiB.');
    return { ok: true, args };
  } catch (error) { return { ok: false, status: 400, error: error.message }; }
}

export function collectGaryTargets(args = {}) {
  const targets = [];
  function visit(value, key = '', depth = 0) {
    if (depth > 16 || key === '_gary') return;
    if (typeof value === 'string' && /^(?:url|target|domain|host|ip|endpoint|website)$/.test(key)) {
      const input = value.trim();
      try {
        const url = new URL(input.includes('://') ? input : 'https://' + input);
        if (url.username || url.password || /\s/.test(input)) return;
        const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
        if (host && (host.includes('.') || host.includes(':') || host === 'localhost')) targets.push(host);
      } catch {}
    } else if (Array.isArray(value)) value.forEach(item => visit(item, key, depth + 1));
    else if (value && typeof value === 'object') for (const [name, item] of Object.entries(value)) visit(item, name, depth + 1);
  }
  visit(args);
  return [...new Set(targets)];
}

export async function runGaryTool(env, spec, args) {
  if (!enabled(env)) throw new Error('Gary tools are disabled.');
  if (spec.unavailableReason) throw new Error(spec.unavailableReason);
  const checked = validateGaryArguments(spec, args); if (!checked.ok) throw new Error(checked.error);
  const { _gary, ...input } = checked.args;
  const context = { ...defaultContext(env), ...(_gary || {}) };
  validateValue(contextSchema, context, '_gary', 0, { nodes: 0 });
  return requestRuntime(env, 'tools/run', { tool: spec.upstreamName, args: input, context });
}

export function parseGaryRouterObject(text) {
  const value = String(text || '').replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
  const first = value.indexOf('{');
  if (first < 0) return null;
  let depth = 0, quoted = false, escaped = false;
  for (let i = first; i < value.length; i++) {
    const c = value[i];
    if (quoted) { if (escaped) escaped = false; else if (c === '\\') escaped = true; else if (c === '"') quoted = false; continue; }
    if (c === '"') quoted = true;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) { try { return JSON.parse(value.slice(first, i + 1)); } catch { return null; } }
  }
  return null;
}

export async function routeExplicitGaryCall(env, message, allowedTools, context = '') {
  const names = [...new Set(String(message).match(/\bgary_[a-z0-9_-]+\b/gi) || [])].map(name => name.toLowerCase());
  if (names.length !== 1) return { handled: false };
  const spec = getGaryToolSpec(names[0], env);
  const allowed = allowedTools == null || new Set(allowedTools).has(names[0]);
  if (!spec || !allowed || !spec.available) return { handled: true, choice: null };
  const stated = parseGaryRouterObject(message);
  let args = stated?.args || stated;
  if (!args) {
    const result = await env.AI.run('@cf/zai-org/glm-4.7-flash', {
      messages: [
        { role: 'system', content: 'Return only one JSON object of arguments for ' + spec.name + '. Follow the schema exactly. Preserve numbers, arrays and objects. Use only values explicitly stated by the user or present in the supplied evidence. Never invent identifiers, targets or authorization. Omit _gary unless explicitly provided. If required input is missing, return {"missingInput":true}. Schema: ' + JSON.stringify(spec.inputSchema) },
        { role: 'user', content: String(message) + (context ? '\nEvidence: ' + context : '') },
      ], stream: false, max_tokens: 2400, temperature: 0, chat_template_kwargs: { enable_thinking: false },
    });
    args = parseGaryRouterObject(result.response || result.choices?.[0]?.message?.content || '');
  }
  if (args?.missingInput || !validateGaryArguments(spec, args).ok) return { handled: true, choice: null };
  const evidence = (String(message) + ' ' + context).toLowerCase();
  if (collectGaryTargets(args).some(target => !evidence.includes(target))) return { handled: true, choice: null };
  return { handled: true, choice: { tool: spec.name, args, arg: JSON.stringify(args) } };
}
