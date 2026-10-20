import * as fs from 'node:fs';
import { resolve, relative, join, isAbsolute } from 'node:path';
import ignore from 'ignore';
import type { Ignore } from 'ignore';
import { scan, type DetectorRegistry } from '../index.js';
import type { DetectorError, Finding, ScanPolicy, SkippedInput, Category } from '../types.js';
import { glob } from './glob.js';
import { stagedEntries, indexContent, runGit, type GitRunner } from './git.js';
export interface AuditOptions {
  readonly root: string;
  readonly paths?: readonly string[];
  readonly staged?: boolean;
  readonly strict?: boolean;
  readonly include?: readonly string[];
  readonly exclude?: readonly string[];
  readonly maxFileBytes?: number;
  readonly categories?: readonly Category[];
  readonly policy?: ScanPolicy;
}
export interface AuditReport {
  readonly schemaVersion: 1;
  readonly toolVersion: '0.1.0';
  readonly startedAt: string;
  readonly completedAt: string;
  readonly complete: boolean;
  readonly filesConsidered: number;
  readonly filesScanned: number;
  readonly filesSkipped: number;
  readonly skippedInputs: readonly SkippedInput[];
  readonly detectorsRun: readonly string[];
  readonly detectorErrors: readonly DetectorError[];
  readonly findings: readonly Finding[];
  readonly onlineChecks: { readonly enabled: false; readonly status: 'disabled' };
  readonly exitReason: 'completed' | 'blocking_findings' | 'incomplete';
  readonly exitCode: 0 | 1 | 2;
}
export interface AuditCapabilities { readonly fs?: Pick<typeof fs, 'lstatSync' | 'readdirSync' | 'readFileSync' | 'realpathSync' | 'openSync' | 'fstatSync' | 'readSync' | 'closeSync'>; readonly git?: GitRunner; readonly registry?: DetectorRegistry; readonly now?: () => Date }
const slash = (value: string) => value.replace(/\\/g, '/');
const inside = (root: string, path: string) => { const rel = relative(root, path); return rel !== '..' && !rel.startsWith('..' + (process.platform === 'win32' ? '\\' : '/')) && !isAbsolute(rel); };
const generated = new Set(['.git', 'node_modules', '.venv', 'venv', 'vendor', 'dist', 'build', 'coverage', '.next', '.cache']);

export async function audit(options: AuditOptions, capabilities: AuditCapabilities = {}): Promise<AuditReport> {
  const io = capabilities.fs ?? fs, now = capabilities.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const findings: Finding[] = [], detectorErrors: DetectorError[] = [], skippedInputs: SkippedInput[] = [];
  const detectorsRun = new Set<string>(), seen = new Set<string>();
  let filesScanned = 0;
  const skip = (file: string, reason: string, affectsCompleteness: boolean) => skippedInputs.push({ file, reason, affectsCompleteness });
  const error = (file: string, detector = 'input') => detectorErrors.push({ file, detector, message: 'Input collection failed; scan is incomplete. Inspect permissions, paths or Git locally.' });
  const limit = options.maxFileBytes ?? 1_048_576;
  const selected = (file: string, directory = false) => {
    if (options.exclude?.some(pattern => glob(pattern, file) || (directory && glob(pattern, file + '/')))) return false;
    return directory || !options.include?.length || options.include.some(pattern => glob(pattern, file));
  };
  async function consume(file: string, bytes: Buffer) {
    if (bytes.length > limit) { skip(file, 'large_file', true); return; }
    if (bytes.includes(0)) { skip(file, 'binary', true); return; }
    let content: string;
    try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { skip(file, 'non_utf8', true); return; }
    const result = await scan({ file, content, ...(options.categories ? { categories: options.categories } : {}) }, options.policy, capabilities.registry);
    filesScanned++;
    findings.push(...result.findings); detectorErrors.push(...result.detectorErrors);
    for (const detector of result.detectorsRun) detectorsRun.add(detector);
  }
  type Layer = { base: string; matcher: Ignore };
  const ignored = (file: string, directory: boolean, layers: readonly Layer[]) => layers.some(layer => {
    const local = layer.base ? file.slice(layer.base.length + 1) : file;
    return local && layer.matcher.ignores(local + (directory ? '/' : ''));
  });
  const declaredRoot = resolve(options.root);
  let root = declaredRoot;
  let requested: readonly string[] = [];
  const canonical = (path: string) => String((io.realpathSync.native ?? io.realpathSync)(path));
  function readBounded(path: string, expected: fs.Stats, maximum: number): Buffer {
    const fd = io.openSync(path, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const actual = io.fstatSync(fd);
      if (!actual.isFile() || actual.dev !== expected.dev || actual.ino !== expected.ino || !inside(root, canonical(path))) throw new Error('Changed input');
      const bytes = Buffer.alloc(maximum + 1);
      let length = 0;
      while (length < bytes.length) {
        const count = io.readSync(fd, bytes, length, bytes.length - length, null);
        if (!count) break;
        length += count;
      }
      return bytes.subarray(0, length);
    } finally { io.closeSync(fd); }
  }
  async function walk(path: string, layers: readonly Layer[], depth = 0): Promise<void> {
    if (requested.length && !requested.some(target => inside(target, path) || inside(path, target))) return;
    const file = slash(relative(root, path)) || '.';
    if (depth > 64 || seen.size >= 100_000) { skip(file, 'traversal_limit', true); return; }
    if (seen.has(path)) return;
    seen.add(path);
    if (!inside(root, path)) { skip(file, 'outside_root', true); return; }
    let stat: fs.Stats;
    try { stat = io.lstatSync(path); } catch { skip(file, 'unreadable_or_missing', true); return; }
    if (stat.isSymbolicLink()) { skip(file, 'symlink', true); return; }
    const directory = stat.isDirectory();
    if (file !== '.' && (file.split('/').some(part => generated.has(part)) || !selected(file, directory) || ignored(file, directory, layers))) { skip(file, 'excluded', false); return; }
    try { if (!inside(root, canonical(path))) { skip(file, 'outside_root', true); return; } }
    catch { skip(file, 'unreadable_or_missing', true); return; }
    if (directory) {
      let next = layers;
      const ignorePath = join(path, '.gitignore');
      try {
        const stat = io.lstatSync(ignorePath);
        if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 65_536) { skip(slash(relative(root, ignorePath)), 'invalid_ignore_file', true); }
        else {
          const bytes = readBounded(ignorePath, stat, 65_536);
          if (bytes.length > 65_536) throw new Error('Ignore size exceeded');
          next = [...layers, { base: file === '.' ? '' : file, matcher: ignore().add(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) }];
        }
      } catch (err) { if ((err as NodeJS.ErrnoException).code !== 'ENOENT') error(file, 'gitignore'); }
      let children: string[];
      try { children = (io.readdirSync(path) as string[]).sort(); } catch { skip(file, 'unreadable_directory', true); return; }
      for (const child of children) await walk(join(path, child), next, depth + 1);
    } else if (stat.isFile()) {
      if (stat.size > limit) { skip(file, 'large_file', true); return; }
      try { await consume(file, readBounded(path, stat, limit)); } catch { skip(file, 'unreadable_or_missing', true); }
    } else skip(file, 'unsupported_file_type', true);
  }
  try {
    if (!Number.isSafeInteger(limit) || limit <= 0 || limit > 1_048_576 || (options.staged && options.paths?.length)) throw new Error('Invalid options');
    for (const pattern of [...options.include ?? [], ...options.exclude ?? []]) glob(pattern, 'validation');
    root = canonical(root);
    if (!io.lstatSync(root).isDirectory()) throw new Error('Root must be a directory');
    if (options.staged) {
      const git = capabilities.git ?? runGit;
      const staged = stagedEntries(root, git);
      // Git and Node can spell the same Windows directory differently (8.3 aliases/junctions).
      const indexRoot = canonical(staged.root);
      if (!inside(indexRoot, root)) throw new Error('Selected root does not belong to Git root');
      for (const entry of staged.entries) {
        const absolute = resolve(indexRoot, entry.file), file = slash(relative(root, absolute));
        if (!inside(root, absolute)) continue;
        if (entry.deleted) { skip(file, 'staged_deletion', false); continue; }
        if (!selected(file)) { skip(file, 'excluded', false); continue; }
        if (!['100644', '100755'].includes(entry.mode ?? '')) { skip(file, 'index_symlink_or_submodule', true); continue; }
        try { await consume(file, indexContent(entry, staged.root, git, limit)); }
        catch (err) { skip(file, err instanceof Error && err.message === 'index_size' ? 'large_file' : 'index_read_failure', true); }
      }
    } else {
      // Walking the root once loads parent/nested ignores correctly, including for explicit files.
      requested = options.paths?.length ? options.paths.map(value => {
        const path = resolve(declaredRoot, value);
        // Rebase lexical descendants without resolving/following symlink components.
        return inside(declaredRoot, path) ? resolve(root, relative(declaredRoot, path)) : path;
      }) : [root];
      for (const path of requested) if (!inside(root, path)) throw new Error('Path outside root');
      if (requested.some(path => { try { io.lstatSync(path); return false; } catch { return true; } })) throw new Error('Missing selected path');
      await walk(root, []);
    }
  } catch { error('.', options.staged ? 'git' : 'configuration'); }
  findings.sort((a, b) => a.file.localeCompare(b.file, 'en') || a.line - b.line || a.column - b.column || a.ruleId.localeCompare(b.ruleId, 'en'));
  const complete = detectorErrors.length === 0 && !skippedInputs.some(input => input.affectsCompleteness);
  const blocked = findings.some(finding => finding.blocking || options.strict);
  const exitCode = !complete ? 2 : blocked ? 1 : 0;
  return { schemaVersion: 1, toolVersion: '0.1.0', startedAt, completedAt: now().toISOString(), complete,
    filesConsidered: filesScanned + skippedInputs.length, filesScanned, filesSkipped: skippedInputs.length,
    skippedInputs, detectorsRun: [...detectorsRun].sort(), detectorErrors, findings,
    onlineChecks: { enabled: false, status: 'disabled' }, exitReason: !complete ? 'incomplete' : blocked ? 'blocking_findings' : 'completed', exitCode };
}
export { lookupPackage } from './registry-lookup.js';
