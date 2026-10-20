import type { AuditReport } from './audit.js';
export function formatJson(report: AuditReport): string { return JSON.stringify(report, null, 2); }
export function formatHuman(report: AuditReport): string {
  return [
    `Scan ${report.complete ? 'complete' : 'INCOMPLETE'}: ${report.filesScanned} scanned, ${report.filesSkipped} skipped, ${report.findings.length} findings.`,
    ...report.findings.map(f => `${JSON.stringify(f.file)}:${f.line}:${f.column} ${f.ruleId} ${f.blocking ? '[blocking]' : '[informational]'} ${f.evidence}`),
    ...report.skippedInputs.map(s => `Skipped ${JSON.stringify(s.file)}: ${s.reason}${s.affectsCompleteness ? ' (incomplete)' : ' (outside selected scope)'}`),
    ...report.detectorErrors.map(e => `Failure ${JSON.stringify(e.file)} [${e.detector}]: ${e.message}`),
    `Online checks: disabled. Exit ${report.exitCode}: ${report.exitReason}.`
  ].join('\n');
}
