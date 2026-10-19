import { ScanResult } from '../types/index.js';

export function formatMarkdownReport(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('# ShieldKit Security & Code-Quality Report');
  lines.push('');
  lines.push(`**Brand:** CodeWithRaheem  `);
  lines.push(`**Tagline:** Build with AI. Ship with Confidence.  `);
  lines.push(`**Scan Date:** ${result.timestamp}  `);
  lines.push(`**Target Path:** \`${result.project.rootPath}\`  `);
  lines.push('');

  lines.push('## Executive Summary');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('| :--- | :--- |');
  lines.push(`| **Total Findings** | ${result.summary.total} |`);
  lines.push(`| **Critical Severity** | ${result.summary.critical} |`);
  lines.push(`| **High Severity** | ${result.summary.high} |`);
  lines.push(`| **Medium Severity** | ${result.summary.medium} |`);
  lines.push(`| **Low Severity** | ${result.summary.low} |`);
  lines.push(`| **Informational** | ${result.summary.informational} |`);
  lines.push(`| **Automated Fixes Available** | ${result.summary.fixable} |`);
  lines.push(`| **Files Scanned** | ${result.scannedFilesCount} |`);
  lines.push(`| **Files Skipped** | ${result.skippedFilesCount} |`);
  lines.push(`| **Scan Duration** | ${result.durationMs}ms |`);
  lines.push('');

  lines.push('### Detected Project Context');
  lines.push('');
  lines.push(`- **Languages:** ${result.project.languages.join(', ') || 'generic'}`);
  lines.push(`- **Frameworks:** ${result.project.frameworks.join(', ') || 'generic'}`);
  if (result.project.manifestFiles.length > 0) {
    lines.push(
      `- **Manifest Files:** ${result.project.manifestFiles.map((m) => `\`${m}\``).join(', ')}`,
    );
  }
  lines.push('');

  lines.push('## Detailed Findings');
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('> [!NOTE]');
    lines.push(
      '> No security or quality findings were identified meeting the current scan criteria.',
    );
    lines.push('');
  } else {
    for (let i = 0; i < result.findings.length; i++) {
      const f = result.findings[i];
      const fixBadge = f.hasFix ? ' *(Safe Fix Available)*' : '';
      lines.push(`### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}${fixBadge}`);
      lines.push('');
      lines.push(`- **Rule ID:** \`${f.ruleId}\``);
      lines.push(`- **Category:** \`${f.category}\``);
      lines.push(`- **Confidence:** \`${f.confidence}\``);
      lines.push(`- **Location:** \`${f.filePath}:${f.startLine}:${f.startColumn}\``);
      lines.push('');
      lines.push('**Sanitized Evidence:**');
      lines.push('```');
      lines.push(f.sanitizedEvidence || 'N/A');
      lines.push('```');
      lines.push('');
      lines.push(`**Explanation:**  \n${f.explanation}`);
      lines.push('');
      lines.push(`**Remediation:**  \n${f.remediation}`);
      lines.push('');
      if (f.docUrl) {
        lines.push(`[Rule Documentation](${f.docUrl})`);
        lines.push('');
      }
      lines.push('---');
      lines.push('');
    }
  }

  if (result.checksSkipped.length > 0) {
    lines.push('## Checks Skipped / Not Available');
    lines.push('');
    for (const skipped of result.checksSkipped) {
      lines.push(`- ${skipped}`);
    }
    lines.push('');
  }

  lines.push('## Limitations & Disclaimer');
  lines.push('');
  lines.push(
    'ShieldKit performs static analysis based on source code syntax, AST patterns, and configuration heuristics. ' +
      'It does not execute untrusted project scripts, build artifacts, or simulate runtime exploit payloads. ' +
      'Static analysis alone is not proof of exploitability or security correctness. ' +
      'ShieldKit is intended to augment, rather than replace, manual peer review, dynamic application security testing (DAST), ' +
      'and certified penetration testing.',
  );
  lines.push('');

  return lines.join('\n');
}
