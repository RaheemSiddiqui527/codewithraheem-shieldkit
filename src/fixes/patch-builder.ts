import crypto from 'node:crypto';
import { createTwoFilesPatch } from 'diff';
import { PatchProposal, RiskLevel } from '../types/index.js';

export function calculateContentHash(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}

export function buildPatchProposal(params: {
  findingId: string;
  targetFile: string;
  originalContent: string;
  proposedContent: string;
  riskLevel?: RiskLevel;
  explanation: string;
  validationRequirements?: string[];
}): PatchProposal {
  const {
    findingId,
    targetFile,
    originalContent,
    proposedContent,
    riskLevel = 'low',
    explanation,
    validationRequirements = ['Verify that code compiles and existing tests pass.'],
  } = params;

  const originalContentHash = calculateContentHash(originalContent);
  const diff = createTwoFilesPatch(
    `a/${targetFile}`,
    `b/${targetFile}`,
    originalContent,
    proposedContent,
    'original',
    'proposed',
  );

  return {
    findingId,
    targetFile,
    originalContentHash,
    proposedContent,
    diff,
    riskLevel,
    explanation,
    validationRequirements,
  };
}
