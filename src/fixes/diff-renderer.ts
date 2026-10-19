import pc from 'picocolors';
import { PatchProposal } from '../types/index.js';

export function renderDiff(patch: PatchProposal, noColor: boolean = false): string {
  const lines = patch.diff.split('\n');
  const renderedLines: string[] = [];

  const riskBadge =
    patch.riskLevel === 'low'
      ? noColor
        ? '[LOW RISK]'
        : pc.green('[LOW RISK]')
      : patch.riskLevel === 'medium'
        ? noColor
          ? '[MEDIUM RISK]'
          : pc.yellow('[MEDIUM RISK]')
        : noColor
          ? '[HIGH RISK]'
          : pc.red('[HIGH RISK]');

  renderedLines.push(
    `\n--- Proposed Fix for ${noColor ? patch.targetFile : pc.bold(patch.targetFile)} ${riskBadge} ---`,
  );
  renderedLines.push(`Explanation: ${patch.explanation}`);
  renderedLines.push('Unified Diff:');

  for (const line of lines) {
    if (noColor) {
      renderedLines.push(line);
    } else if (line.startsWith('---') || line.startsWith('+++')) {
      renderedLines.push(pc.bold(line));
    } else if (line.startsWith('@@')) {
      renderedLines.push(pc.cyan(line));
    } else if (line.startsWith('+')) {
      renderedLines.push(pc.green(line));
    } else if (line.startsWith('-')) {
      renderedLines.push(pc.red(line));
    } else {
      renderedLines.push(pc.dim(line));
    }
  }

  if (patch.validationRequirements.length > 0) {
    renderedLines.push('\nValidation Requirements:');
    for (const req of patch.validationRequirements) {
      renderedLines.push(`  * ${req}`);
    }
  }

  return renderedLines.join('\n');
}
