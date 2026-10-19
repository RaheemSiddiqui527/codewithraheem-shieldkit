import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';

export const permissiveCorsRule: Rule = {
  id: 'SK-SEC-010',
  name: 'Permissive CORS Configuration',
  description:
    'Detects overly permissive Cross-Origin Resource Sharing (CORS) configurations such as wildcard origin with credentials.',
  category: 'configuration',
  severity: 'medium',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['express', 'node', 'next', 'generic'],
  filePatterns: ['**/*.js', '**/*.ts'],
  explanation:
    'Permitting wildcard origins ("*") or dynamically reflecting any Origin header while allowing credentials exposes authenticated user data to unauthorized third-party domains.',
  remediation:
    'Specify an explicit allowlist of authorized domain origins rather than using wildcard "*" or dynamic reflection.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-010',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          // Detect cors({ origin: '*' }) or cors({ origin: true, credentials: true })
          if (node.type === 'CallExpression' && node.callee?.name === 'cors') {
            if (node.arguments.length > 0 && node.arguments[0]?.type === 'ObjectExpression') {
              const obj = node.arguments[0];
              let originWildcard = false;
              let credentialsTrue = false;

              for (const prop of obj.properties) {
                if (prop.type === 'ObjectProperty') {
                  const keyName = prop.key?.name || prop.key?.value;
                  if (keyName === 'origin' && prop.value?.value === '*') {
                    originWildcard = true;
                  }
                  if (keyName === 'credentials' && prop.value?.value === true) {
                    credentialsTrue = true;
                  }
                }
              }

              if (originWildcard) {
                const startLine = node.loc?.start.line ?? 1;
                findings.push({
                  title: 'Wildcard CORS Origin Detected',
                  startLine,
                  endLine: node.loc?.end.line ?? startLine,
                  rawEvidence: lines[startLine - 1] || 'cors({ origin: "*" })',
                  explanation:
                    'CORS configured with wildcard origin "*" allows any website to make requests to this API.',
                });
              }

              if (credentialsTrue && originWildcard) {
                const startLine = node.loc?.start.line ?? 1;
                findings.push({
                  title: 'CORS Credentials with Wildcard Origin',
                  startLine,
                  endLine: node.loc?.end.line ?? startLine,
                  rawEvidence: lines[startLine - 1] || 'cors({ origin: "*", credentials: true })',
                  explanation:
                    'Enabling credentials with wildcard origins violates the CORS specification and introduces security risks.',
                  customSeverity: 'high',
                });
              }
            }
          }
        },
      });
    }

    return findings;
  },
};
