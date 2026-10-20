# Codaro Local Check

Account-free deterministic local checks with explicit scan-completeness and failure semantics. Scan selected files without uploading source, contacting a service or requiring an account.

v0.1 includes curated credential-shape checks, npm/Composer JSON manifest validation, caller-configured exact dependency-name policy and declared-license policy. **It is not a complete vulnerability scanner.** There is no CVE/lockfile resolution, malware detection, legal compatibility analysis, AI review, source modification or complete secret-coverage claim.

## Install v0.1.0

Download `codaro-local-check-0.1.0.tgz` and `SHA256SUMS` from [GitHub Releases](https://github.com/Lolarz20/codaro-local-check/releases/tag/v0.1.0), verify the checksum, then:

```sh
npm install ./codaro-local-check-0.1.0.tgz
npx --no-install codaro-check audit src --json
```

The package is not published to npm. The binary comes from the installed tarball. Node.js 22 and 24 are tested on Windows and Linux. Compiled ESM JavaScript and declarations are shipped. The only runtime dependency is the MIT-licensed `ignore` package for Gitignore semantics; no installation lifecycle script runs. From source: `npm ci --ignore-scripts && npm run verify`.

## CLI

```sh
codaro-check audit src test --exclude '**/generated/**'
codaro-check audit --staged --json
codaro-check audit --strict --include '**/*.ts'
codaro-check audit package.json --deny-dependency example-policy-name --allow-license MIT --require-license
codaro-check rules
codaro-check version
```

`--root DIR` selects a root (default current directory). Explicit paths must stay within it. `--include` and `--exclude` accept repeated patterns with `*`, `**`, `?`; bracket/brace expansion is unsupported and produces an incomplete configuration result. Dotfiles are included unless ignored. Root/nested `.gitignore` files and common generated/dependency directories are respected. Global Git excludes and `.git/info/exclude` are not imported. Symlinks are skipped, including those pointing inside the root. Files are UTF-8 only, capped at 1 MiB by default; binary/oversize/unreadable/missing inputs explicitly make the scan incomplete.

`--staged` reads Git index blobs, including partially staged files, additions and renames. It reports deletions as intentional skips. NUL-delimited paths support spaces, tabs and newlines where the filesystem permits them. No staged changes is a completed empty scan; missing Git/repository or Git command failure is incomplete. Staged files are explicit inputs: `.gitignore` and generated-directory defaults do not hide staged files. Explicit include/exclude flags still apply. Staged symlinks/submodules are incomplete skips. Do not combine `--staged` with positional paths; use `--root` to select a repository/subtree.

## Completeness and exit codes

| Exit | Meaning |
|---|---|
| 0 | Scan completed, no blocking findings (informational findings may exist) |
| 1 | Scan completed, blocking findings exist; `--strict` blocks any finding |
| 2 | Scan incomplete, invalid configuration, failed detector or input collection |

Incomplete takes precedence over findings. Ignored/excluded files and staged deletions are intentional scope exclusions; binary, large, unreadable, disappearing, unsupported-type and symlink inputs are incomplete skips. JSON includes `schemaVersion`, timestamps, completeness, all skip reasons, detector failures, findings and online-check status. Evidence is fully redacted, with 1-based lines/columns. Human output also says INCOMPLETE explicitly. See [completeness model](docs/completeness-model.md) and the [versioned JSON Schema](docs/scan-result.schema.json).

## SDK

```js
import { scan } from 'codaro-local-check/scan';
const result = await scan({ file: 'package.json', content: '{"license":"MIT"}' }, {
  allowedLicenses: ['MIT'], requireLicense: true
});
console.log(result.complete, result.findings, result.detectorErrors);
```

The SDK owns no filesystem, Git or network. `DetectorRegistry` accepts caller-owned detectors. Category filters control execution; manifest policy runs for dependency or license, and filters each category independently. Default license/dependency deny policies are empty. Copyleft is not labelled a security vulnerability. SPDX compound expressions are compared as exact declarations, not interpreted. Unsupported manifest ecosystems are scanned only as text; no dependency analysis for them is claimed. See [rule reference](docs/rule-reference.md).

All normal scans and tests are offline. A separate explicitly invoked `lookupPackage` helper under `/cli` accepts an injected fetch, explicit HTTPS registry and exact allowed-name list; it returns exists/missing/unavailable/not_allowed and never infers safety. It is not called by the CLI and no `--online` mode is included. Private package names are never queried without an exact allow entry. See [privacy](docs/privacy.md).

## CI and development

After installing the tarball in CI, run `codaro-check audit src --json`; preserve exit 2 as a scan failure. Do not treat a missing/incomplete report as success. `npm run verify` typechecks, lints, builds, runs offline tests/coverage, inspects tarball contents, installs it in a fresh project and executes the real installed CLI plus SDK declarations. No former gateway administration or external-agent hook command is included.

## Codaro Open Source

This project was extracted from engineering work developed while building Codaro.
Focused infrastructure extracted from the engineering work behind Codaro.

Related projects:
- [codaro-agent-protocol](https://github.com/Lolarz20/codaro-agent-protocol)
- [codaro-text-patch](https://github.com/Lolarz20/codaro-text-patch)
- [codaro-local-check](https://github.com/Lolarz20/codaro-local-check)
