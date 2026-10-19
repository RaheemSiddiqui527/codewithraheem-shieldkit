import { ScanResult } from '../types/index.js';

export const JSON_SCHEMA_VERSION = '1.0.0';

export function formatJsonReport(result: ScanResult): string {
  const payload = {
    $schema:
      'https://raw.githubusercontent.com/codewithraheem/shieldkit/main/docs/report-schema.json',
    schemaVersion: JSON_SCHEMA_VERSION,
    tool: {
      name: result.toolName,
      version: result.version,
      brand: 'CodeWithRaheem',
      tagline: 'Build with AI. Ship with Confidence.',
    },
    scan: {
      timestamp: result.timestamp,
      durationMs: result.durationMs,
      targetPath: result.project.rootPath,
      scannedFilesCount: result.scannedFilesCount,
      skippedFilesCount: result.skippedFilesCount,
      checksPerformed: result.checksPerformed,
      checksSkipped: result.checksSkipped,
    },
    project: {
      languages: result.project.languages,
      frameworks: result.project.frameworks,
      hasPackageJson: result.project.hasPackageJson,
      packageName: result.project.packageName,
      packageVersion: result.project.packageVersion,
      manifestFiles: result.project.manifestFiles,
    },
    summary: result.summary,
    findings: result.findings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      title: f.title,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      location: {
        file: f.filePath,
        startLine: f.startLine,
        endLine: f.endLine,
        startColumn: f.startColumn,
        endColumn: f.endColumn,
      },
      sanitizedEvidence: f.sanitizedEvidence,
      explanation: f.explanation,
      remediation: f.remediation,
      hasFix: f.hasFix,
      patchProposal: f.fixProposal
        ? {
            riskLevel: f.fixProposal.riskLevel,
            explanation: f.fixProposal.explanation,
            validationRequirements: f.fixProposal.validationRequirements,
            diff: f.fixProposal.diff,
          }
        : undefined,
      docUrl: f.docUrl,
    })),
  };

  return JSON.stringify(payload, null, 2);
}
