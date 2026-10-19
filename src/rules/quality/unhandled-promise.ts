import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';

export const unhandledPromiseRule: Rule = {
  id: 'SK-QUAL-002',
  name: 'Async Promise Executor Antipattern',
  description:
    'Detects new Promise(async (resolve, reject) => { ... }) which swallows thrown errors inside the executor.',
  category: 'quality',
  severity: 'medium',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['generic'],
  filePatterns: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
  explanation:
    'Passing an async function to the Promise constructor is an antipattern: if an error is thrown inside an async executor, it produces an unhandled promise rejection that the promise itself cannot catch or reject.',
  remediation:
    'Do not use async executors in new Promise(). Use standard async/await or handle errors with try/catch and reject(err).',
  docUrl:
    'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-qual-002',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (
            node.type === 'NewExpression' &&
            node.callee?.type === 'Identifier' &&
            node.callee.name === 'Promise'
          ) {
            if (node.arguments.length > 0) {
              const executor = node.arguments[0];
              if (
                (executor.type === 'ArrowFunctionExpression' ||
                  executor.type === 'FunctionExpression') &&
                executor.async
              ) {
                const startLine = executor.loc?.start.line ?? 1;
                findings.push({
                  title: 'Async Executor in Promise Constructor',
                  startLine,
                  endLine: executor.loc?.end.line ?? startLine,
                  startColumn: executor.loc?.start.column,
                  endColumn: executor.loc?.end.column,
                  rawEvidence:
                    lines[startLine - 1] || 'new Promise(async (resolve, reject) => { ... })',
                  explanation:
                    'Async executor in new Promise() leads to unhandled rejections if an error throws.',
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
