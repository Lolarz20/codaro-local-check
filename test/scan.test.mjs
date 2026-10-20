import test from 'node:test';
import assert from 'node:assert/strict';
import { scan, DetectorRegistry, RULES } from '../dist/index.js';
import { lookupPackage } from '../dist/cli/audit.js';
import { secret } from './helpers.mjs';
test('clean supplied content, no account or network capability', async () => { const result = await scan({ file: 'a.ts', content: 'const x = 1;' }); assert.equal(result.complete, true); assert.deepEqual(result.findings, []); });
test('detector scan and applicability throws propagate as incomplete without echoing content', async () => {
  for (const phase of ['scan', 'appliesTo']) {
    const registry = new DetectorRegistry().register({ id: 'throws', category: 'secret', scan: () => [], [phase]: () => { throw new Error(secret()); } });
    const result = await scan({ file: 'a.ts', content: '' }, {}, registry);
    assert.equal(result.complete, false); assert.equal(result.detectorErrors.length, 1); assert.ok(!JSON.stringify(result).includes(secret()));
  }
});
test('duplicate detector IDs are rejected', () => { const detector = { id: 'same', category: 'secret', scan: () => [] }; assert.throws(() => new DetectorRegistry().register(detector).register(detector)); });
const literals = [
 ['provider-key', () => secret()], ['cloud-key', () => 'AKIA' + 'EXAMPLE0'.repeat(2)],
 ['github-token', () => 'ghp_' + 'SYNTHETIC'.repeat(4)], ['assigned-literal', () => 'api_key = "' + 'SYNTHETIC'.repeat(4) + '"'],
 ['jwt', () => ['eyJSYNTHETIC', 'eyJSYNTHETIC', 'SYNTHETIC'].join('.')],
 ['pem', () => ['-----BEGIN ', 'PRIVATE KEY-----'].join('')], ['database-uri', () => 'postgres://synthetic:synthetic@localhost/example']
];
for (const [id, value] of literals) test(`secret ${id} is completely redacted`, async () => {
  const literal = value(); const result = await scan({ file: 'synthetic.ts', content: 'first\n' + literal });
  assert.ok(result.findings.some(f => f.ruleId === 'secret.' + id)); assert.ok(result.findings.every(f => f.evidence === '[REDACTED]')); assert.ok(!JSON.stringify(result).includes(literal)); assert.equal(result.findings[0].line, 2);
});
for (const file of ['package.json', 'composer.json']) {
  for (const content of ['{', '[]', '{"license":42}', file === 'package.json' ? '{"dependencies":[]}' : '{"require":[]}']) test(`${file}: malformed ${content}`, async () => { const result = await scan({ file, content }); assert.equal(result.complete, false); assert.equal(result.detectorErrors[0].detector, 'manifest-policy'); });
  test(`${file}: exact dependency and license policy`, async () => {
    const content = JSON.stringify({ [file === 'package.json' ? 'dependencies' : 'require']: { 'synthetic-package': '*' }, license: 'GPL-3.0-only' });
    assert.equal((await scan({ file, content })).findings.length, 0);
    const result = await scan({ file, content }, { deniedDependencies: ['synthetic-package'], deniedLicenses: ['GPL-3.0-only'] });
    assert.equal(result.complete, true); assert.equal(result.findings.length, 2); assert.ok(result.findings.every(f => f.blocking));
  });
}
test('license declaration is not a security vulnerability and compound SPDX is exact string policy', async () => {
  const request = { file: 'package.json', content: '{"license":"MIT OR GPL-3.0-only"}', categories: ['license'] };
  assert.equal((await scan(request, { deniedLicenses: ['GPL-3.0-only'] })).findings.length, 0);
  const blocked = await scan(request, { allowedLicenses: ['MIT'] }); assert.equal(blocked.findings[0].category, 'license');
  assert.equal((await scan({ file: 'package.json', content: '{}' }, { requireLicense: true })).findings.length, 1);
});
test('category filter controls execution and manifest finding categories', async () => {
  const request = { file: 'package.json', content: '{"dependencies":{"blocked":"*"},"license":"MIT"}', categories: ['license'] };
  const result = await scan(request, { deniedDependencies: ['blocked'], deniedLicenses: ['MIT'] });
  assert.deepEqual(result.detectorsRun, ['manifest-policy']); assert.equal(result.findings.length, 1); assert.equal(result.findings[0].category, 'license');
});
test('input size limit is incomplete', async () => { assert.equal((await scan({ file: 'a', content: 'x'.repeat(1_048_577) })).complete, false); });
test('no inaccurate bundled dependency allegations', async () => {
  const result = await scan({ file: 'package.json', content: '{"dependencies":{"chatgpt-api":"*","framer":"*"}}' });
  assert.equal(result.findings.length, 0); assert.ok(!RULES.some(rule => /non-existent|hallucinated/.test(rule.rationale)));
  assert.ok(RULES.every(rule => rule.source && rule.reviewed && rule.type && rule.rationale && rule.confidence));
});
test('registry lookup is explicit and refuses private namespaces unless exact name allowed', async () => {
  let calls = 0;
  const options = { endpoint: 'https://registry.invalid/', allowedNames: [], fetch: async () => { calls++; return new Response(null, { status: 200 }); } };
  assert.equal((await lookupPackage('@private/example', options)).status, 'not_allowed'); assert.equal(calls, 0);
  assert.equal((await lookupPackage('@private/example', { ...options, allowedNames: ['@private/example'] })).status, 'exists'); assert.equal(calls, 1);
});
for (const [status, expected] of [[200, 'exists'], [404, 'missing'], [429, 'unavailable'], [503, 'unavailable'], [302, 'unavailable']]) test(`registry ${status} truthfulness`, async () => {
  const result = await lookupPackage('synthetic', { endpoint: 'https://registry.invalid/', allowedNames: ['synthetic'], fetch: async () => new Response(null, { status }) });
  assert.equal(result.status, expected); assert.equal(result.safety, 'not_assessed');
});
test('registry failures/timeouts are unavailable, never verified existence', async () => {
  for (const fetch of [async () => { throw new Error(secret()); }, () => new Promise(() => {})]) assert.equal((await lookupPackage('synthetic', { endpoint: 'https://registry.invalid/', allowedNames: ['synthetic'], fetch, timeoutMs: 20 })).status, 'unavailable');
});
