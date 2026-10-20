import { execFileSync } from 'node:child_process';
export type GitRunner = (args: readonly string[], cwd: string, maxBuffer?: number) => Buffer;
export const runGit: GitRunner = (args, cwd, maxBuffer = 2_097_152) => execFileSync('git', [...args], { cwd, maxBuffer, timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'] });
export interface IndexEntry { readonly file: string; readonly deleted: boolean; readonly mode?: string; readonly object?: string }
export function stagedEntries(root: string, run: GitRunner): { root: string; entries: readonly IndexEntry[] } {
  const top = run(['rev-parse', '--show-toplevel'], root).toString('utf8').trimEnd();
  const data = run(['diff', '--cached', '--name-status', '-z', '--no-renames', '--no-ext-diff'], top).toString('utf8').split('\0');
  const entries: IndexEntry[] = [];
  for (let i = 0; i + 1 < data.length && data[i]; i += 2) {
    const status = data[i]!, file = data[i + 1]!;
    if (status === 'D') { entries.push({ file, deleted: true }); continue; }
    if (!['A', 'M', 'T'].includes(status)) throw new Error('Unsupported or unmerged staged status');
    const indexed = run(['ls-files', '--stage', '-z', '--', `:(literal)${file}`], top).toString('utf8');
    const matches = [...indexed.matchAll(/(?:^|\0)(\d+) ([a-f0-9]+) ([0-3])\t([^\0]*)/g)];
    if (matches.length !== 1 || matches[0]![3] !== '0') throw new Error('Unmerged or missing index entry');
    entries.push({ file, deleted: false, mode: matches[0]![1]!, object: matches[0]![2]! });
  }
  return { root: top, entries };
}
export function indexContent(entry: IndexEntry, root: string, run: GitRunner, limit: number): Buffer {
  const size = Number(run(['cat-file', '-s', entry.object!], root).toString().trim());
  if (!Number.isSafeInteger(size) || size < 0 || size > limit) throw new Error('index_size');
  return run(['cat-file', 'blob', entry.object!], root, limit + 4096);
}
