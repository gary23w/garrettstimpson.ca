import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIntelPlan,
  collectToolTargets,
  extractAiText,
  extractSecurityTargets,
  isPublicIpv4,
  removeSessionIndexEntry,
  renderBalancedContext,
  resolveScopedRedirect,
  splitSseLines,
  toolCallKey,
} from './src/harness.mjs';

test('email targets do not silently become domain targets', () => {
  const targets = extractSecurityTargets('Check hunter@acme.com for breach exposure');
  assert.deepEqual(targets.emails, ['hunter@acme.com']);
  assert.deepEqual(targets.domains, []);
});

test('explicit URLs still produce URL and domain targets', () => {
  const targets = extractSecurityTargets('Inspect https://login.example.com/reset).');
  assert.equal(targets.urls[0], 'https://login.example.com/reset');
  assert.deepEqual(targets.domains, ['login.example.com']);
});

test('public and private IPs are separated for automatic lookups', () => {
  const targets = extractSecurityTargets('Compare 8.8.8.8 with 192.168.1.10');
  assert.deepEqual(targets.ips, ['8.8.8.8', '192.168.1.10']);
  assert.deepEqual(targets.publicIps, ['8.8.8.8']);
});

test('automatic IP enrichment rejects every special-purpose IPv4 class', () => {
  for (const ip of ['100.64.0.1', '169.254.169.254', '192.0.2.1', '198.18.0.1', '203.0.113.7', '224.0.0.1', '255.255.255.255']) {
    assert.equal(isPublicIpv4(ip), false, ip);
  }
  assert.equal(isPublicIpv4('8.8.8.8'), true);
});

test('Workers AI response shapes normalize to text', () => {
  assert.equal(extractAiText({ response: 'legacy' }), 'legacy');
  assert.equal(extractAiText({ choices: [{ message: { content: 'chat' } }] }), 'chat');
  assert.equal(extractAiText({ choices: [{ delta: { content: 'stream' } }] }), 'stream');
  assert.equal(extractAiText({ result: { response: 'wrapped' } }), 'wrapped');
});

test('balanced evidence budgeting gives every result representation', () => {
  const rendered = renderBalancedContext(['T1 ' + 'a'.repeat(2000), 'T2 ' + 'b'.repeat(2000), 'T3 ' + 'c'.repeat(2000)], 900, 800);
  assert.ok(rendered.length <= 900);
  assert.match(rendered, /T1/);
  assert.match(rendered, /T2/);
  assert.match(rendered, /T3/);
});

test('tiny evidence budgets still represent every block', () => {
  const rendered = renderBalancedContext(['A-first', 'B-second', 'C-third'], 8, 800);
  assert.equal(rendered, 'A\n\nB\n\nC');
});

test('every target-bearing alias is included in scope validation', () => {
  assert.deepEqual(collectToolTargets('safe.example', {
    image: 'https://images.example/a.jpg',
    sample: 'https://samples.example/a.bin',
    path: '/evidence/outside-scope.pcap',
    addr: 'OUT_OF_SCOPE_WALLET',
    token: 'OUT_OF_SCOPE_TOKEN',
  }), ['safe.example', 'images.example', 'samples.example', '/evidence/outside-scope.pcap', 'out_of_scope_wallet', 'out_of_scope_token']);
});

test('redirects may stay on host but cannot escape target scope', () => {
  assert.equal(resolveScopedRedirect('https://safe.example/a', '/b').toString(), 'https://safe.example/b');
  assert.throws(() => resolveScopedRedirect('https://safe.example/a', 'https://other.example/b'), /outside the authorized target/);
});

test('session deletion removes both legacy object and current string index entries', () => {
  assert.deepEqual(removeSessionIndexEntry(['keep', 'remove', { id: 'remove' }, { id: 'other' }], 'remove'), ['keep', { id: 'other' }]);
});

test('intel plan is stable and profile-aware', () => {
  const compact = buildIntelPlan({ cveIds: ['CVE-2026-1'], ips: ['8.8.8.8'], domains: ['example.com'] }, 'debug');
  assert.deepEqual(compact.map(x => x.tool), [
    'nvd_lookup', 'epss_lookup', 'kev_lookup',
    'rdap_ip', 'reverse_dns', 'ip_geo',
    'rdap_domain', 'dns_lookup', 'cert_ct',
  ]);
  assert.equal(buildIntelPlan({ ips: ['8.8.8.8'] }, 'full').length, 5);
});

test('tool call identity deduplicates exact calls, not whole tools', () => {
  assert.equal(toolCallKey('DNS_LOOKUP', 'Example.COM'), 'dns_lookup::example.com');
  assert.notEqual(toolCallKey('dns_lookup', 'one.example'), toolCallKey('dns_lookup', 'two.example'));
});

test('SSE parser flushes a final non-newline-terminated event', () => {
  const first = splitSseLines('data: {"response":"one"}\n' + 'data: {"response":"tw');
  assert.deepEqual(first.lines, ['data: {"response":"one"}']);
  assert.equal(first.remainder, 'data: {"response":"tw');
  const final = splitSseLines(first.remainder + 'o"}', true);
  assert.deepEqual(final.lines, ['data: {"response":"two"}']);
  assert.equal(final.remainder, '');
});
