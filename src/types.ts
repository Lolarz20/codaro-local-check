export type Category = 'secret' | 'dependency' | 'license';
export interface Finding {
  readonly ruleId: string;
  readonly category: Category;
  readonly severity: 'high' | 'medium' | 'info';
  readonly blocking: boolean;
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly message: string;
  /** Evidence never includes the matched credential. */
  readonly evidence: string;
}
export interface Rule { readonly id: string; readonly category: Category; readonly type: 'pattern' | 'declaration' | 'policy'; readonly source: string; readonly reviewed: string; readonly rationale: string; readonly confidence: 'heuristic' | 'exact-policy'; readonly blocking: boolean }
export interface ScanRequest { readonly file: string; readonly content: string; readonly categories?: readonly Category[] }
export interface ScanPolicy { readonly deniedDependencies?: readonly string[]; readonly deniedLicenses?: readonly string[]; readonly allowedLicenses?: readonly string[]; readonly requireLicense?: boolean }
export interface DetectorError { readonly file: string; readonly detector: string; readonly message: string }
export interface SkippedInput { readonly file: string; readonly reason: string; readonly affectsCompleteness: boolean }
export interface ScanResult { readonly complete: boolean; readonly findings: readonly Finding[]; readonly detectorErrors: readonly DetectorError[]; readonly detectorsRun: readonly string[] }
export interface Detector { readonly id: string; readonly category: Category; appliesTo?(request: ScanRequest): boolean; scan(request: ScanRequest, policy: ScanPolicy): readonly Finding[] | Promise<readonly Finding[]> }
export interface RegistryResult { readonly status: 'exists' | 'missing' | 'unavailable' | 'not_allowed'; readonly safety: 'not_assessed' }
