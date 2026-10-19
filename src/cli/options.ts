import { Severity } from '../types/index.js';

export const SEVERITY_RANKS: Record<Severity, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function meetsSeverityThreshold(
  findingSeverity: Severity,
  threshold: Severity = 'high',
): boolean {
  const findingRank = SEVERITY_RANKS[findingSeverity] ?? 0;
  const thresholdRank = SEVERITY_RANKS[threshold] ?? SEVERITY_RANKS.high;
  return findingRank >= thresholdRank;
}
