import type { Detector } from './types.js';
export class DetectorRegistry {
  private readonly detectors = new Map<string, Detector>();
  register(detector: Detector): this {
    if (!detector.id || this.detectors.has(detector.id)) throw new Error('Duplicate or empty detector id');
    this.detectors.set(detector.id, detector); return this;
  }
  all(): readonly Detector[] { return [...this.detectors.values()]; }
}
