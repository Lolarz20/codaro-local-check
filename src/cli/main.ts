#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { audit } from './audit.js';
import { formatHuman, formatJson } from './format.js';
import { RULES } from '../rules.js';
export async function main(args = process.argv.slice(2)): Promise<number> {
  const command = args[0];
  if (command === 'version' || command === '--version') { console.log('0.1.0'); return 0; }
  if (!command || command === '--help' || command === 'help') {
    console.log('codaro-check audit [paths...] [--root DIR] [--staged] [--json] [--strict] [--include GLOB] [--exclude GLOB]\nPolicy: --deny-dependency NAME --deny-license SPDX --allow-license SPDX --require-license\nOther commands: rules, version. Offline; reads selected local content only.'); return 0;
  }
  if (command === 'rules') { console.log(JSON.stringify(RULES, null, 2)); return 0; }
  if (command !== 'audit') { console.error('Unknown command. Run codaro-check --help.'); return 2; }
  let values: ReturnType<typeof parseArgs>['values'];
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({ args: args.slice(1), allowPositionals: true, strict: true, options: {
      root: { type: 'string' }, json: { type: 'boolean' }, staged: { type: 'boolean' }, strict: { type: 'boolean' },
      include: { type: 'string', multiple: true }, exclude: { type: 'string', multiple: true },
      'deny-dependency': { type: 'string', multiple: true }, 'deny-license': { type: 'string', multiple: true }, 'allow-license': { type: 'string', multiple: true }, 'require-license': { type: 'boolean' }
    } }));
  } catch {
    // Retain the same versioned machine-readable shape even for invalid CLI syntax.
    const report = await audit({ root: process.cwd(), maxFileBytes: -1 });
    console.log(args.includes('--json') ? formatJson(report) : formatHuman(report)); return 2;
  }
  const report = await audit({ root: typeof values.root === 'string' ? resolve(values.root) : process.cwd(), paths: positionals,
    staged: Boolean(values.staged), strict: Boolean(values.strict), include: values.include as string[] | undefined, exclude: values.exclude as string[] | undefined,
    policy: { deniedDependencies: values['deny-dependency'] as string[] | undefined, deniedLicenses: values['deny-license'] as string[] | undefined, allowedLicenses: values['allow-license'] as string[] | undefined, requireLicense: Boolean(values['require-license']) } });
  console.log(values.json ? formatJson(report) : formatHuman(report));
  return report.exitCode;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().then(code => { process.exitCode = code; }).catch(() => { console.error('Internal failure; scan incomplete.'); process.exitCode = 2; });
}
