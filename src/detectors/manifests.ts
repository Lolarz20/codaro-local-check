import type { Detector, Finding } from '../types.js';
function basename(file: string) { return file.replace(/\\/g, '/').split('/').at(-1); }
export function supportedManifest(file: string): boolean { return ['package.json', 'composer.json'].includes(basename(file) ?? ''); }
export const manifestDetector: Detector = {
  id: 'manifest-policy', category: 'dependency', appliesTo: request => supportedManifest(request.file),
  scan({ file, content, categories }, policy) {
    const value: unknown = JSON.parse(content);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Manifest must be an object');
    const data = value as Record<string, unknown>;
    const findings: Finding[] = [];
    const finding = (category: 'dependency' | 'license', ruleId: string, message: string): Finding => ({ ruleId, category, severity: 'medium', blocking: true, file, line: 1, column: 1, message, evidence: '[declaration policy]' });
    const dependencyEnabled = !categories?.length || categories.includes('dependency');
    const licenseEnabled = !categories?.length || categories.includes('license');
    for (const key of basename(file) === 'package.json' ? ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] : ['require', 'require-dev']) {
      const group = data[key];
      if (group === undefined) continue;
      if (!group || typeof group !== 'object' || Array.isArray(group) || Object.values(group).some(v => typeof v !== 'string')) throw new Error('Invalid dependency declaration');
      for (const name of Object.keys(group)) if (dependencyEnabled && policy.deniedDependencies?.includes(name)) findings.push(finding('dependency', 'dependency.denied-name', 'A dependency name matches the configured deny policy.'));
    }
    const license = data.license;
    if (license !== undefined && typeof license !== 'string' && !(basename(file) === 'composer.json' && Array.isArray(license) && license.every(v => typeof v === 'string'))) throw new Error('Invalid license declaration');
    const declared = typeof license === 'string' ? [license] : Array.isArray(license) ? license as string[] : [];
    // Exact strings only: SPDX expressions are not flattened or interpreted as legal compatibility.
    if (licenseEnabled && ((policy.requireLicense && declared.length === 0) || declared.some(item => policy.deniedLicenses?.includes(item) || (policy.allowedLicenses && !policy.allowedLicenses.includes(item))))) findings.push(finding('license', 'license.declaration', 'License declaration does not satisfy the configured policy.'));
    return findings;
  }
};
