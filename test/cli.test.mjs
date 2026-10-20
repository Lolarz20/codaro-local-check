import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join, resolve } from 'node:path';
import { audit } from '../dist/cli/audit.js';
import { formatHuman, formatJson } from '../dist/cli/format.js';
import { DetectorRegistry } from '../dist/index.js';
import { runGit } from '../dist/cli/git.js';
import { fixture, secret, cli, git, init } from './helpers.mjs';
test('CLI actual invocation, version and rules', () => { const { root } = fixture(); assert.equal(cli(root, ['version']).stdout.trim(), '0.1.0'); assert.equal(cli(root, ['rules']).status, 0); assert.equal(cli(root, ['--help']).status, 0); assert.equal(cli(root, ['unknown']).status, 2); });
test('exit 0 clean, exit 1 blocking, exit 2 incomplete and versioned JSON', async () => {
  const { root, put } = fixture(); put('a.ts', 'const x = 1;');
  for (const [value, expected] of [['const x = 1;', 0], [secret(), 1], [Buffer.from([0, 1]), 2]]) {
    put('a.ts', value); const process = cli(root, ['audit', 'a.ts', '--json']); const report = JSON.parse(process.stdout);
    assert.equal(process.status, expected); assert.equal(report.exitCode, expected); assert.equal(report.schemaVersion, 1); assert.equal(report.onlineChecks.status, 'disabled'); assert.equal(report.complete, expected !== 2); assert.ok(!process.stdout.includes(secret()));
    for (const field of ['toolVersion', 'startedAt', 'completedAt', 'filesConsidered', 'filesScanned', 'filesSkipped', 'detectorsRun', 'detectorErrors', 'findings', 'exitReason']) assert.ok(field in report);
  }
});
test('human output makes incomplete explicit and escapes unusual filenames', async () => {
  const { root, put } = fixture(); put('binary', Buffer.from([0])); const report = await audit({ root });
  assert.match(formatHuman(report), /INCOMPLETE/); assert.match(formatHuman(report), /binary/); assert.equal(JSON.parse(formatJson(report)).complete, false);
});
test('invalid CLI configuration still emits versioned incomplete JSON', () => { const { root } = fixture(); for (const args of [['--unknown'], ['--include', '[unsupported]'], ['missing']]) { const p = cli(root, ['audit', ...args, '--json']); const value = JSON.parse(p.stdout); assert.equal(p.status, 2); assert.equal(value.complete, false); assert.equal(value.schemaVersion, 1); } });
test('detector failure reaches CLI report and exit 2', async () => {
  const { root, put } = fixture(); put('a.ts', 'ok');
  const registry = new DetectorRegistry().register({ id: 'throws', category: 'secret', scan: () => { throw new Error(secret()); } });
  const report = await audit({ root }, { registry }); assert.equal(report.exitCode, 2); assert.equal(report.complete, false); assert.ok(!JSON.stringify(report).includes(secret()));
});
test('gitignore nested rules, negation and explicit file selection respect parent ignores', async () => {
  const { root, put } = fixture(); put('.gitignore', '*.ignored\n!keep.ignored\n'); put('bad.ignored', secret()); put('keep.ignored', 'ok'); put('nested/.gitignore', 'bad.ts\n'); put('nested/bad.ts', secret()); put('nested/good.ts', 'ok');
  const report = await audit({ root }); assert.equal(report.exitCode, 0); assert.equal(report.findings.length, 0); assert.equal(report.skippedInputs.filter(s => s.reason === 'excluded').length, 2);
  const explicit = await audit({ root, paths: ['nested/bad.ts'] }); assert.equal(explicit.filesScanned, 0); assert.equal(explicit.exitCode, 0);
});
test('explicit includes/excludes and generated directories', async () => {
  const { root, put } = fixture(); put('good.ts', 'ok'); put('bad.js', secret()); put('nested/excluded.ts', secret()); put('node_modules/bad.ts', secret());
  const report = await audit({ root, include: ['**/*.ts'], exclude: ['nested/**'] }); assert.equal(report.exitCode, 0); assert.equal(report.filesScanned, 1); assert.equal(report.filesSkipped, 3);
});
test('explicit selected paths do not read unrelated files', async () => { const { root, put } = fixture(); put('good.ts', 'ok'); put('bad.ts', secret()); const report = await audit({ root, paths: ['good.ts'] }); assert.equal(report.filesScanned, 1); assert.equal(report.findings.length, 0); });
test('path traversal outside root is refused', async () => { const { root } = fixture(); const report = await audit({ root, paths: ['../outside'] }); assert.equal(report.exitCode, 2); assert.equal(report.complete, false); });
test('binary, invalid UTF-8 and large files are explicit incomplete skips', async () => {
  const { root, put } = fixture(); put('binary', Buffer.from([0])); put('non-utf8', Buffer.from([255])); put('large', 'x'.repeat(100));
  const report = await audit({ root, maxFileBytes: 10 }); assert.equal(report.exitCode, 2); assert.equal(report.filesSkipped, 3); assert.deepEqual(report.skippedInputs.map(s => s.reason).sort(), ['binary', 'large_file', 'non_utf8']);
});
test('symlink outside root is never followed', async () => {
  const { root } = fixture(); const outside = fixture(); outside.put('secret.ts', secret());
  // Directory junctions require no Windows developer-mode privilege.
  fs.symlinkSync(outside.root, join(root, 'outside'), process.platform === 'win32' ? 'junction' : 'dir');
  const report = await audit({ root }); assert.equal(report.filesScanned, 0); assert.equal(report.findings.length, 0); assert.equal(report.skippedInputs[0].reason, 'symlink'); assert.equal(report.exitCode, 2);
});
for (const [name, method] of [['unreadable', 'openSync'], ['disappearing', 'lstatSync']]) test(`${name} input is incomplete`, async () => {
  const { root, put } = fixture(); put('gone.ts', 'ok'); const target = join(root, 'gone.ts');
  const io = { ...fs, [method](path, ...rest) { if (String(path) === target) { const error = new Error('synthetic'); error.code = 'EACCES'; throw error; } return fs[method](path, ...rest); } };
  const report = await audit({ root }, { fs: io }); assert.equal(report.exitCode, 2); assert.ok(report.skippedInputs.length || report.detectorErrors.length);
});
test('strict blocks informational JWT-like findings', async () => { const { root, put } = fixture(); put('example', ['eyJSYNTHETIC', 'eyJSYNTHETIC', 'SYNTHETIC'].join('.')); assert.equal((await audit({ root })).exitCode, 0); assert.equal((await audit({ root, strict: true })).exitCode, 1); });
test('staged scan reads partially staged index bytes, never working content', async () => {
  const { root, put } = fixture(); init(root); put('with spaces.ts', secret()); git(root, ['add', '--', 'with spaces.ts']); put('with spaces.ts', 'working tree is clean');
  const report = await audit({ root, staged: true }); assert.equal(report.exitCode, 1); assert.equal(report.filesScanned, 1); assert.equal(report.findings[0].file, 'with spaces.ts');
  put('with spaces.ts', 'index is clean'); git(root, ['add', '--', 'with spaces.ts']); put('with spaces.ts', secret()); assert.equal((await audit({ root, staged: true })).exitCode, 0);
});
test('staged added/deleted/renamed and unusual names are NUL safe', async () => {
  const { root, put } = fixture(); init(root); put('old.ts', 'ok'); put('deleted.ts', 'ok'); git(root, ['add', '.']); git(root, ['commit', '-m', 'synthetic']);
  git(root, ['mv', 'old.ts', 'new name.ts']); git(root, ['rm', 'deleted.ts']);
  const unusual = process.platform === 'win32' ? 'ünicode [name].ts' : 'ünicode\n[name].ts'; put(unusual, secret()); git(root, ['add', '--', unusual]);
  const report = await audit({ root, staged: true }); assert.equal(report.exitCode, 1); assert.equal(report.filesScanned, 2); assert.equal(report.skippedInputs.filter(s => s.reason === 'staged_deletion').length, 2); assert.equal(report.findings[0].file, unusual);
});
test('staged binary is incomplete and staged ignores are explicit selection', async () => {
  const { root, put } = fixture(); init(root); put('.gitignore', '*.ignored'); put('bad.ignored', secret()); put('binary', Buffer.from([0])); git(root, ['add', '-f', 'bad.ignored', 'binary']);
  const report = await audit({ root, staged: true }); assert.equal(report.exitCode, 2); assert.equal(report.findings.length, 1); assert.equal(report.skippedInputs[0].reason, 'binary');
});
test('no staged changes differs from non-repository and Git failure', async () => {
  const { root } = fixture(); assert.equal((await audit({ root, staged: true })).exitCode, 2);
  init(root); const clean = await audit({ root, staged: true }); assert.equal(clean.exitCode, 0); assert.equal(clean.filesConsidered, 0);
  const failure = await audit({ root, staged: true }, { git: () => { throw new Error(secret()); } }); assert.equal(failure.exitCode, 2); assert.ok(!JSON.stringify(failure).includes(secret()));
});
test('staged explicit path option is rejected rather than ignored', async () => { const { root } = fixture(); assert.equal((await audit({ root, staged: true, paths: ['x'] })).exitCode, 2); });
test('Git root aliases are resolved before containment checks', async () => {
  const { root, put } = fixture(); init(root); put('staged.ts', secret()); git(root, ['add', 'staged.ts']);
  const aliases = fixture(); const alias = join(aliases.root, 'alias');
  fs.symlinkSync(root, alias, process.platform === 'win32' ? 'junction' : 'dir');
  const report = await audit({ root, staged: true }, { git: (args, cwd, maxBuffer) => args[0] === 'rev-parse' ? Buffer.from(alias + '\n') : runGit(args, cwd, maxBuffer) });
  assert.equal(report.exitCode, 1, JSON.stringify(report)); assert.equal(report.filesScanned, 1);
});
test('Windows separators in supplied manifest paths', async () => { const { scan } = await import('../dist/index.js'); const report = await scan({ file: 'src\\package.json', content: '{' }); assert.equal(report.complete, false); });
test('path separators stay relative in report', async () => { const { root, put } = fixture(); put('nested/a.ts', secret()); const report = await audit({ root, paths: [resolve(root, 'nested/a.ts')] }); assert.equal(report.findings[0].file, 'nested/a.ts'); });
