import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
export const secret = () => 'sk-' + 'SYNTHETIC'.repeat(4);
export function fixture() { const root = fs.mkdtempSync(join(tmpdir(), 'codaro-scan-')); const put = (name, value) => { const file = join(root, name); fs.mkdirSync(join(file, '..'), { recursive: true }); fs.writeFileSync(file, value); }; return { root, put }; }
export function git(root, args) { return execFileSync('git', ['-c', 'core.autocrlf=false', ...args], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
export function cli(root, args) { return spawnSync(process.execPath, [fileURLToPath(new URL('../dist/cli/main.js', import.meta.url)), ...args], { cwd: root, encoding: 'utf8' }); }
export function init(root) { git(root, ['init', '-b', 'main']); git(root, ['config', 'user.name', 'Synthetic Test']); git(root, ['config', 'user.email', 'synthetic@example.invalid']); }
