export type RiskLevel = 'low' | 'medium' | 'high';

export interface PatchProposal {
  findingId: string;
  targetFile: string;
  originalContentHash: string;
  proposedContent: string;
  diff: string;
  riskLevel: RiskLevel;
  explanation: string;
  validationRequirements: string[];
}

export interface FixResult {
  applied: boolean;
  targetFile: string;
  error?: string;
}
