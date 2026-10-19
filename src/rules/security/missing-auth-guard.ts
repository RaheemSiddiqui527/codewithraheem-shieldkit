import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';

export const missingAuthGuardRule: Rule = {
  id: 'SK-SEC-011',
  name: 'Potential Missing Route Authentication Guard',
  description:
    'Detects sensitive administrative or mutation endpoints that appear to lack authentication or authorization middleware.',
  category: 'security',
  severity: 'low',
  confidence: 'low',
  languages: ['javascript', 'typescript'],
  frameworks: ['express', 'node', 'generic'],
  filePatterns: ['**/*.js', '**/*.ts'],
  explanation:
    'Endpoints matching sensitive or administrative paths (e.g., /api/admin/*, /api/users/delete) should be protected by explicit authentication/authorization guards. Note: This finding is marked as a potential risk requiring manual review because authentication may be enforced by global middleware or an API gateway.',
  remediation:
    'Confirm whether an authentication guard (e.g. verifyAuth, passport.authenticate, jwtMiddleware) protects this route directly or at the router mount level.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-011',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (node.type !== 'CallExpression') return;

          const callee = node.callee;
          if (callee.type === 'MemberExpression') {
            const prop = callee.property;
            if (
              prop &&
              prop.type === 'Identifier' &&
              ['post', 'put', 'delete', 'patch'].includes(prop.name)
            ) {
              if (node.arguments.length >= 2) {
                const firstArg = node.arguments[0];

                if (firstArg.type === 'StringLiteral') {
                  const routePath = firstArg.value.toLowerCase();
                  const isSensitivePath =
                    routePath.includes('/admin') ||
                    routePath.includes('/manage') ||
                    routePath.includes('/delete') ||
                    routePath.includes('/internal');

                  // If route only has path and handler (2 arguments, meaning 0 intermediate middleware)
                  if (isSensitivePath && node.arguments.length === 2) {
                    const startLine = node.loc?.start.line ?? 1;
                    findings.push({
                      title:
                        'Sensitive Route Without Explicit Middleware Guard (Potential Risk - Manual Review Required)',
                      startLine,
                      endLine: node.loc?.end.line ?? startLine,
                      rawEvidence:
                        lines[startLine - 1] || `app.${prop.name}('${firstArg.value}', ...)`,
                      explanation: `Sensitive endpoint "${firstArg.value}" has no inline middleware. Ensure parent router or gateway enforces authentication.`,
                    });
                  }
                }
              }
            }
          }
        },
      });
    }

    return findings;
  },
};
