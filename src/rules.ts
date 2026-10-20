import type { Rule } from './types.js';
const rule = (id: string, category: Rule['category'], type: Rule['type'], source: string, rationale: string, blocking: boolean): Rule => Object.freeze({ id, category, type, source, reviewed: '2026-10-21', rationale, confidence: type === 'pattern' ? 'heuristic' : 'exact-policy', blocking });
export const RULES: readonly Rule[] = Object.freeze([
  rule('secret.provider-key', 'secret', 'pattern', 'Locally defined heuristic; docs/rule-reference.md', 'Provider-shaped credential prefix with a long literal suffix.', true),
  rule('secret.cloud-key', 'secret', 'pattern', 'Locally defined heuristic; docs/rule-reference.md', 'Cloud access-key identifier shape; not proof a credential is active.', true),
  rule('secret.github-token', 'secret', 'pattern', 'Locally defined heuristic; docs/rule-reference.md', 'GitHub credential-shaped literal; no validation request is made.', true),
  rule('secret.assigned-literal', 'secret', 'pattern', 'Locally defined heuristic; docs/rule-reference.md', 'Long literal assigned to a credential-like name.', true),
  rule('secret.jwt', 'secret', 'pattern', 'Locally defined heuristic; docs/rule-reference.md', 'Three JWT-like encoded segments; may be a public example.', false),
  rule('secret.pem', 'secret', 'pattern', 'Locally defined heuristic; docs/rule-reference.md', 'Private-key boundary marker; key material is never returned.', true),
  rule('secret.database-uri', 'secret', 'pattern', 'Locally defined heuristic; docs/rule-reference.md', 'Database URI with embedded username and password.', true),
  rule('dependency.denied-name', 'dependency', 'policy', 'Caller-supplied exact name policy', 'A declared dependency exactly matches the caller deny policy; no package safety allegation.', true),
  rule('license.declaration', 'license', 'declaration', 'Caller-supplied declaration policy', 'A missing/disallowed license declaration violates the caller policy; no legal compatibility analysis.', true)
]);
