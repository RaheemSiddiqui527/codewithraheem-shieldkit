import { describe, expect, it } from 'vitest';
import { formatTerminalReport } from '../../src/reporters/terminal.js';
import { formatJsonReport, JSON_SCHEMA_VERSION } from '../../src/reporters/json.js';
import { formatMarkdownReport } from '../../src/reporters/markdown.js';
import { ScanResult } from '../../src/types/index.js';

function createMockScanResult(): ScanResult {
  return {
    toolName: 'ShieldKit',
    version: '0.1.0',
    timestamp: '2026-10-19T10:00:00.000Z',
    project: {
      rootPath: '/mock/my-project',
      languages: ['typescript', 'javascript'],
      frameworks: ['express', 'node'],
      hasPackageJson: true,
      packageName: 'my-service',
      packageVersion: '1.0.0',
      dependencies: { express: '^4.19.0' },
      devDependencies: { typescript: '^5.0.0' },
      scripts: { test: 'vitest run' },
      manifestFiles: ['package.json', 'package-lock.json'],
    },
    scannedFilesCount: 15,
    skippedFilesCount: 2,
    durationMs: 42,
    checksPerformed: ['SK-SEC-003: Potential SQL Injection'],
    checksSkipped: [],
    summary: {
      total: 1,
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      informational: 0,
      fixable: 0,
    },
    findings: [
      {
        id: 'find-mock-1234',
        ruleId: 'SK-SEC-003',
        title: 'SQL Injection via Template Literal',
        category: 'security',
        severity: 'high',
        confidence: 'high',
        filePath: 'src/db.ts',
        startLine: 12,
        endLine: 12,
        startColumn: 5,
        endColumn: 45,
        sanitizedEvidence: 'db.query(`SELECT * FROM users WHERE id = ${userId}`)',
        explanation: 'Dynamic query interpolation allows query manipulation.',
        remediation: 'Use parameterized queries with placeholders.',
        hasFix: false,
        docUrl: 'https://github.com/codewithraheem/shieldkit/docs',
      },
    ],
  };
}

describe('Reporters', () => {
  it('formats terminal report correctly with no-color support', () => {
    const result = createMockScanResult();
    const output = formatTerminalReport(result, { noColor: true });

    expect(output).toContain('ShieldKit Static Security & Quality Scanner');
    expect(output).toContain('/mock/my-project');
    expect(output).toContain('SQL Injection via Template Literal');
    expect(output).toContain('src/db.ts:12:5');
    expect(output).toContain('Critical: 0  High: 1  Medium: 0  Low: 0');
  });

  it('formats valid JSON report compliant with schema v1.0.0', () => {
    const result = createMockScanResult();
    const jsonStr = formatJsonReport(result);
    const parsed = JSON.parse(jsonStr);

    expect(parsed.schemaVersion).toBe(JSON_SCHEMA_VERSION);
    expect(parsed.tool.name).toBe('ShieldKit');
    expect(parsed.tool.brand).toBe('CodeWithRaheem');
    expect(parsed.summary.high).toBe(1);
    expect(parsed.findings.length).toBe(1);
    expect(parsed.findings[0].id).toBe('find-mock-1234');
    expect(parsed.findings[0].location.file).toBe('src/db.ts');
  });

  it('formats comprehensive Markdown report with tables and guidance', () => {
    const result = createMockScanResult();
    const md = formatMarkdownReport(result);

    expect(md).toContain('# ShieldKit Security & Code-Quality Report');
    expect(md).toContain('| **Total Findings** | 1 |');
    expect(md).toContain('### 1. [HIGH] SQL Injection via Template Literal');
    expect(md).toContain('`src/db.ts:12:5`');
    expect(md).toContain('## Limitations & Disclaimer');
  });
});
