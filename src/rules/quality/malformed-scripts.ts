import path from 'node:path';
import { Rule, RuleFindingInput } from '../../types/index.js';

export const malformedScriptsRule: Rule = {
  id: 'SK-QUAL-005',
  name: 'Missing or Placeholder Project Scripts',
  description:
    'Detects missing, empty, or default unconfigured placeholder scripts in package.json.',
  category: 'quality',
  severity: 'low',
  confidence: 'high',
  languages: ['json', 'generic'],
  frameworks: ['node'],
  filePatterns: ['package.json'],
  explanation:
    'Projects lacking basic automated test or build scripts are prone to shipping broken changes. Placeholder error scripts left from npm init indicate incomplete project setup.',
  remediation: 'Configure working test, build, and lint scripts in package.json.',
  docUrl:
    'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-qual-005',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];

    if (path.basename(context.file.relativePath) === 'package.json') {
      try {
        const parsed = JSON.parse(context.file.content);
        const scripts = parsed.scripts || {};

        if (!scripts.test || scripts.test.includes('no test specified')) {
          findings.push({
            title: 'Missing or Placeholder "test" Script in package.json',
            startLine: 1,
            endLine: 1,
            rawEvidence: scripts.test ? `"test": "${scripts.test}"` : 'Missing "test" script',
            explanation:
              'The project lacks a defined automated test command in package.json scripts.',
          });
        }
      } catch (parseErr: unknown) {
        // Malformed JSON is caught by json parse analyzer
        void parseErr;
      }
    }

    return findings;
  },
};
