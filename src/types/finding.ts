import { Confidence, RuleCategory, Severity } from './rule.js';
import { PatchProposal } from './fix.js';

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  category: RuleCategory;
  severity: Severity;
  confidence: Confidence;
  filePath: string;
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
  sanitizedEvidence: string;
  explanation: string;
  remediation: string;
  hasFix: boolean;
  fixProposal?: PatchProposal;
  docUrl?: string;
}
