export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type Confidence = 'high' | 'medium' | 'low';

export type RuleCategory = 'security' | 'quality' | 'secrets' | 'configuration';

export type Framework =
  'node' | 'express' | 'react' | 'vite' | 'next' | 'react-native' | 'expo' | 'mongoose' | 'generic';

export type Language = 'javascript' | 'typescript' | 'json' | 'yaml' | 'env' | 'generic';

export interface RuleFindingInput {
  title: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  rawEvidence: string;
  explanation?: string;
  remediation?: string;
  customSeverity?: Severity;
  customConfidence?: Confidence;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: Severity;
  confidence: Confidence;
  languages: Language[];
  frameworks: Framework[];
  filePatterns: string[];
  explanation: string;
  remediation: string;
  docUrl?: string;
  hasFix: boolean;
  check: (
    context: import('./analyzer.js').RuleContext,
  ) => Promise<RuleFindingInput[]> | RuleFindingInput[];
  getFix?: (
    finding: import('./finding.js').Finding,
    fileContent: string,
  ) => import('./fix.js').PatchProposal | null;
}
