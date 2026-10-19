import pc from 'picocolors';
import { Finding, ScanResult, Severity } from '../types/index.js';

export function formatTerminalReport(
  result: ScanResult,
  options: { verbose?: boolean; noColor?: boolean } = {},
): string {
  const { verbose = false, noColor = false } = options;
  const lines: string[] = [];

  const c = {
    bold: (s: string) => (noColor ? s : pc.bold(s)),
    dim: (s: string) => (noColor ? s : pc.dim(s)),
    cyan: (s: string) => (noColor ? s : pc.cyan(s)),
    green: (s: string) => (noColor ? s : pc.green(s)),
    yellow: (s: string) => (noColor ? s : pc.yellow(s)),
    red: (s: string) => (noColor ? s : pc.red(s)),
    magenta: (s: string) => (noColor ? s : pc.magenta(s)),
    bgRed: (s: string) => (noColor ? s : pc.bgRed(pc.white(s))),
  };

  function severityBadge(sev: Severity): string {
    switch (sev) {
      case 'critical':
        return c.bgRed(' CRITICAL ');
      case 'high':
        return c.red(' HIGH ');
      case 'medium':
        return c.yellow(' MEDIUM ');
      case 'low':
        return c.cyan(' LOW ');
      case 'informational':
        return c.dim(' INFO ');
    }
  }

  // Header Banner
  lines.push('');
  lines.push(c.bold(c.cyan('  ShieldKit Static Security & Quality Scanner')));
  lines.push(c.dim('  Build with AI. Ship with Confidence.'));
  lines.push('');

  // Project Info
  lines.push(`  ${c.bold('Target:')}      ${result.project.rootPath}`);
  lines.push(`  ${c.bold('Languages:')}   ${result.project.languages.join(', ') || 'generic'}`);
  lines.push(`  ${c.bold('Frameworks:')}   ${result.project.frameworks.join(', ') || 'generic'}`);
  lines.push(
    `  ${c.bold('Scanned:')}      ${result.scannedFilesCount} files (${result.skippedFilesCount} skipped) in ${result.durationMs}ms`,
  );
  lines.push('');

  // Findings list
  if (result.findings.length === 0) {
    lines.push(c.green('  ✔ No findings detected meeting current scan threshold.'));
    lines.push('');
  } else {
    lines.push(c.bold(`  Findings (${result.findings.length}):`));
    lines.push(c.dim('  ' + '─'.repeat(70)));

    for (let i = 0; i < result.findings.length; i++) {
      const f = result.findings[i];
      const fixBadge = f.hasFix ? c.green(' [Safe Fix Available] ') : '';
      const location = `${f.filePath}:${f.startLine}:${f.startColumn}`;

      lines.push(`  ${severityBadge(f.severity)} ${c.bold(f.title)}${fixBadge}`);
      lines.push(`  ${c.dim('Rule:')}     ${f.ruleId}  ${c.dim('Location:')} ${c.cyan(location)}`);

      if (f.sanitizedEvidence) {
        lines.push(`  ${c.dim('Evidence:')} ${f.sanitizedEvidence}`);
      }

      lines.push(`  ${c.dim('Impact:')}   ${f.explanation}`);
      lines.push(`  ${c.dim('Action:')}   ${f.remediation}`);

      if (verbose && f.docUrl) {
        lines.push(`  ${c.dim('Docs:')}     ${f.docUrl}`);
      }

      lines.push('');
    }
  }

  // Summary Table
  lines.push(c.bold('  Summary:'));
  lines.push(
    `    Critical: ${result.summary.critical > 0 ? c.red(String(result.summary.critical)) : '0'}  ` +
      `High: ${result.summary.high > 0 ? c.red(String(result.summary.high)) : '0'}  ` +
      `Medium: ${result.summary.medium > 0 ? c.yellow(String(result.summary.medium)) : '0'}  ` +
      `Low: ${result.summary.low > 0 ? c.cyan(String(result.summary.low)) : '0'}  ` +
      `Info: ${result.summary.informational}  ` +
      `Fixable: ${c.green(String(result.summary.fixable))}`,
  );
  lines.push('');
  lines.push(
    c.dim(
      '  Notice: Static analysis aids code review but cannot guarantee complete security or exploitability.',
    ),
  );
  lines.push('');

  return lines.join('\n');
}
