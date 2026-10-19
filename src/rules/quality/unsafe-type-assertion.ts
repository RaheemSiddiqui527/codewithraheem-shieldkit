import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';

export const unsafeTypeAssertionRule: Rule = {
  id: 'SK-QUAL-003',
  name: 'Unsafe Type Assertion (as any)',
  description:
    'Detects TypeScript type assertions to "any" (e.g. value as any), which bypass type safety.',
  category: 'quality',
  severity: 'low',
  confidence: 'high',
  languages: ['typescript'],
  frameworks: ['generic'],
  filePatterns: ['**/*.ts', '**/*.tsx'],
  explanation:
    'Casting values to "any" disables TypeScript type checking for that expression and any downstream operations, obscuring potential bugs and refactoring issues.',
  remediation:
    'Use explicit interfaces, generics, "unknown" with runtime type guards, or specific union types instead of "any".',
  docUrl:
    'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-qual-003',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (node.type === 'TSAsExpression') {
            if (node.typeAnnotation && node.typeAnnotation.type === 'TSAnyKeyword') {
              const startLine = node.loc?.start.line ?? 1;
              findings.push({
                title: 'Unsafe Type Assertion (as any)',
                startLine,
                endLine: node.loc?.end.line ?? startLine,
                startColumn: node.loc?.start.column,
                endColumn: node.loc?.end.column,
                rawEvidence: lines[startLine - 1] || 'value as any',
                explanation: 'Type assertion to "any" suppresses compiler type verification.',
              });
            }
          }
        },
      });
    }

    return findings;
  },
};
