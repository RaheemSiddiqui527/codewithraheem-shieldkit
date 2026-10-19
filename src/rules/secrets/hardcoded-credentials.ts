import { Rule, RuleFindingInput } from '../../types/index.js';
import { SECRET_PATTERNS } from '../../safety/redaction.js';

export const hardcodedCredentialsRule: Rule = {
  id: 'SK-SEC-001',
  name: 'Hardcoded Secret or Credential',
  description:
    'Detects hardcoded API keys, tokens, passwords, and sensitive credentials in source code.',
  category: 'secrets',
  severity: 'critical',
  confidence: 'high',
  languages: ['javascript', 'typescript', 'json', 'yaml', 'env'],
  frameworks: ['generic'],
  filePatterns: ['**/*'],
  explanation:
    'Hardcoding secrets in source files exposes credentials in version control, build artifacts, and client bundles. Anyone with repository access can extract these keys.',
  remediation:
    'Store secrets in environment variables or an external secret manager (e.g. AWS Secrets Manager, Vault) and load them at runtime.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-001',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const lines = context.lines;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];

      // Skip comment-only lines or test mock indicators
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) {
        continue;
      }

      for (const pattern of SECRET_PATTERNS) {
        pattern.regex.lastIndex = 0;
        const match = pattern.regex.exec(line);
        if (match) {
          findings.push({
            title: `Hardcoded ${pattern.name} Detected`,
            startLine: lineIndex + 1,
            endLine: lineIndex + 1,
            startColumn: match.index + 1,
            endColumn: match.index + match[0].length + 1,
            rawEvidence: line,
            explanation: `Found potential ${pattern.name} hardcoded directly in file.`,
          });
          break; // Avoid duplicate findings per line
        }
      }
    }

    return findings;
  },
};
