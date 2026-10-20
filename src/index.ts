import type { ScanPolicy, ScanRequest, ScanResult, Finding, DetectorError } from './types.js';
import { DetectorRegistry } from './registry.js';
import { secretsDetector } from './detectors/secrets.js';
import { manifestDetector } from './detectors/manifests.js';
export * from './types.js';
export { DetectorRegistry, secretsDetector, manifestDetector };
export { RULES } from './rules.js';
export function defaultDetectors(): DetectorRegistry { return new DetectorRegistry().register(secretsDetector).register(manifestDetector); }
/** Supplied-content SDK. No filesystem, Git, network, clock or account ownership. */
export async function scan(request: ScanRequest, policy: ScanPolicy = {}, registry = defaultDetectors()): Promise<ScanResult> {
  const findings: Finding[] = [], detectorErrors: DetectorError[] = [], detectorsRun: string[] = [];
  if (request.content.length > 1_048_576) return { complete: false, findings, detectorsRun, detectorErrors: [{ file: request.file, detector: 'input', message: 'Content size limit exceeded' }] };
  for (const detector of registry.all()) {
    // The manifest detector emits dependency AND license findings, selected individually below.
    if (request.categories?.length && !request.categories.includes(detector.category) && !(detector.id === 'manifest-policy' && request.categories.includes('license'))) continue;
    try {
      if (detector.appliesTo && !detector.appliesTo(request)) continue;
      detectorsRun.push(detector.id);
      findings.push(...await detector.scan(request, policy));
    } catch { detectorErrors.push({ file: request.file, detector: detector.id, message: 'Detector failed; scan is incomplete. Inspect the input locally.' }); }
  }
  return { complete: detectorErrors.length === 0, findings, detectorErrors, detectorsRun };
}
