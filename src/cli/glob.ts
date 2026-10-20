/** Explicit include/exclude glob subset: *, ** and ?. Gitignore uses the ignore package separately. */
export function glob(pattern: string, file: string): boolean {
  if (pattern.length > 256 || /[\[\]{}]/.test(pattern)) throw new Error('Unsupported glob');
  let result = '^';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '*' && pattern[i + 1] === '*') { i++; if (pattern[i + 1] === '/') { i++; result += '(?:.*/)?'; } else result += '.*'; }
    else if (c === '*') result += '[^/]*';
    else if (c === '?') result += '[^/]';
    else result += /[.()+^$|\\]/.test(c) ? `\\${c}` : c;
  }
  return new RegExp(result + '$').test(file);
}
