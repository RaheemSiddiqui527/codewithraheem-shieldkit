import { Rule, RuleFindingInput } from '../../types/index.js';

export const privateKeyExposureRule: Rule = {
  id: 'SK-SEC-002',
  name: 'Committed Private Key Material',
  description: 'Detects committed cryptographic private keys (RSA, OpenSSH, EC, PGP).',
  category: 'secrets',
  severity: 'critical',
  confidence: 'high',
  languages: ['javascript', 'typescript', 'json', 'yaml', 'env', 'generic'],
  frameworks: ['generic'],
  filePatterns: ['**/*'],
  explanation:
    'Private cryptographic keys must never be committed to source code or bundled with application distributions. Exposure allows attackers to forge signatures or decrypt traffic.',
  remediation:
    'Revoke and regenerate the compromised private key immediately. Store private keys in secure hardware or encrypted secret stores.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-002',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const lines = context.lines;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (/^-----BEGIN [A-Z0-9_-]*\s*PRIVATE KEY-----/.test(trimmed)) {
        findings.push({
          title: 'Exposed Cryptographic Private Key',
          startLine: i + 1,
          endLine: Math.min(i + 5, lines.length),
          rawEvidence: line,
          explanation: 'Found header indicating unencrypted cryptographic private key material.',
        });
      }
    }

    return findings;
  },
};
