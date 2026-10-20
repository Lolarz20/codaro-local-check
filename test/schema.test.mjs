import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import { audit } from '../dist/cli/audit.js';
import { fixture, secret } from './helpers.mjs';
const ajv = new Ajv2020({ strict: true, formats: { 'date-time': /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/ } });
const validate = ajv.compile(JSON.parse(readFileSync(new URL('../docs/scan-result.schema.json', import.meta.url))));
test('success, findings and incomplete reports satisfy the published schema', async () => {
  const { root, put } = fixture();
  for (const value of ['clean', secret(), Buffer.from([0])]) {
    put('input', value); const report = await audit({ root });
    assert.equal(validate(report), true, JSON.stringify(validate.errors));
  }
});
test('schema rejects missing completeness and raw extra output fields', async () => {
  const { root } = fixture(); const report = await audit({ root });
  const missing = { ...report }; delete missing.complete;
  assert.equal(validate(missing), false);
  assert.equal(validate({ ...report, rawSecret: 'synthetic' }), false);
});
