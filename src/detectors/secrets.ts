import type { Detector, Finding } from '../types.js';
const patterns: readonly [string, RegExp, boolean][] = [
  ['secret.provider-key', /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{35})\b/g, true],
  ['secret.cloud-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, true],
  ['secret.github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/g, true],
  ['secret.assigned-literal', /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|aws_secret_access_key|password|auth[_-]?token|access[_-]?token)\s*[:=]\s*["'][A-Za-z0-9_+/=-]{20,}["']/gi, true],
  ['secret.jwt', /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, false],
  ['secret.pem', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, true],
  ['secret.database-uri', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+/gi, true]
];
export const secretsDetector: Detector = {
  id: 'secrets', category: 'secret',
  scan({ file, content }) {
    const starts = [0];
    for (let i = 0; i < content.length; i++) if (content[i] === '\n') starts.push(i + 1);
    const findings: Finding[] = [];
    for (const [ruleId, regex, blocking] of patterns) {
      for (const match of content.matchAll(new RegExp(regex))) {
        let low = 0, high = starts.length;
        while (low < high) { const mid = (low + high) >>> 1; if (starts[mid]! <= match.index) low = mid + 1; else high = mid; }
        findings.push({ ruleId, category: 'secret', severity: blocking ? 'high' : 'medium', blocking, file, line: low, column: match.index - starts[low - 1]! + 1, message: 'Potential credential-shaped literal. Review locally; rotate if real.', evidence: '[REDACTED]' });
        if (findings.length >= 10_000) throw new Error('Finding limit reached');
      }
    }
    return findings;
  }
};
