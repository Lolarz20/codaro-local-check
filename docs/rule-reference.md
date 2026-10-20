# Rule reference

`codaro-check rules` emits per-rule source, reviewed date (2026-10-21), rule type, rationale, confidence and blocking status. These are locally defined heuristic shapes and exact caller policies, not imported vulnerability/advisory data. There is no bundled claim that a named package does not exist or is malicious.

| ID | Pattern/policy | Blocking |
|---|---|---|
| secret.provider-key | sk-/optional proj-/ant- with long suffix; Google-shaped prefix | Yes |
| secret.cloud-key | AKIA/ASIA plus 16 uppercase letters/digits | Yes |
| secret.github-token | classic gh credential prefixes or long fine-grained prefix | Yes |
| secret.assigned-literal | long quoted value assigned to a credential-like name | Yes |
| secret.jwt | JWT-like three encoded segments | No (strict blocks) |
| secret.pem | private-key opening boundary marker, even if unterminated | Yes |
| secret.database-uri | supported database scheme with username/password | Yes |
| dependency.denied-name | exact caller name list against npm/Composer direct declarations | Yes |
| license.declaration | required/allowed/denied exact declaration policy | Yes |

False positives and false negatives are expected. Tokens are not validated online. Secrets split across expressions, encoded values, other formats and novel prefixes may be missed. Redacted evidence is fixed, positions are 1-based. No raw source snippets are returned.

Only package.json and composer.json have manifest declaration analysis in v0.1. Malformed JSON, non-object manifests or invalid dependency/license value shapes make the detector fail explicitly. Composer license arrays are accepted. npm dependencies/devDependencies/optionalDependencies/peerDependencies and Composer require/require-dev are inspected. Transitive versions and lockfiles are not resolved. Declaration-policy findings use line/column 1 because precise JSON property locations are not parsed.

No default license is considered dangerous. Exact SPDX compound strings are not decomposed or interpreted. This is declaration/policy checking, not legal compatibility analysis. A future ecosystem parser must include malformed and unsupported-syntax tests before it is advertised.
