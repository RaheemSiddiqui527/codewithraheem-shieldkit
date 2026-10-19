import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';

export const nosqlInjectionRule: Rule = {
  id: 'SK-SEC-008',
  name: 'Potential NoSQL Injection',
  description:
    'Detects use of MongoDB $where operators or direct binding of unvalidated request bodies to Mongoose queries.',
  category: 'security',
  severity: 'high',
  confidence: 'medium',
  languages: ['javascript', 'typescript'],
  frameworks: ['mongoose', 'node', 'express'],
  filePatterns: ['**/*.js', '**/*.ts'],
  explanation:
    'Passing unvalidated client objects directly to MongoDB query filters allows attackers to inject query operators (such as $gt, $ne, or $where), bypassing password checks or executing server-side JavaScript.',
  remediation:
    'Sanitize query filters, validate inputs with schemas (e.g. Zod), or use express-mongo-sanitize to strip leading dollar signs.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-008',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          // Check for $where operator in object properties
          if (node.type === 'ObjectProperty') {
            const key = node.key;
            if (
              (key.type === 'Identifier' && key.name === '$where') ||
              (key.type === 'StringLiteral' && key.value === '$where')
            ) {
              const startLine = node.loc?.start.line ?? 1;
              findings.push({
                title: 'Use of MongoDB $where Clause Detected',
                startLine,
                endLine: node.loc?.end.line ?? startLine,
                startColumn: node.loc?.start.column,
                endColumn: node.loc?.end.column,
                rawEvidence: lines[startLine - 1] || '$where: ...',
                explanation:
                  'MongoDB $where clause evaluates JavaScript on the database server and is vulnerable to code injection.',
              });
            }
          }

          // Check for Model.find(req.body) or Model.findOne(req.body)
          if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
            const prop = node.callee.property;
            if (
              prop &&
              prop.type === 'Identifier' &&
              ['find', 'findOne', 'countDocuments', 'deleteMany'].includes(prop.name)
            ) {
              if (node.arguments.length > 0) {
                const firstArg = node.arguments[0];
                if (
                  firstArg.type === 'MemberExpression' &&
                  firstArg.object?.type === 'Identifier' &&
                  firstArg.object.name === 'req' &&
                  firstArg.property?.type === 'Identifier' &&
                  firstArg.property.name === 'body'
                ) {
                  const startLine = firstArg.loc?.start.line ?? 1;
                  findings.push({
                    title: 'Direct req.body Bound to NoSQL Query',
                    startLine,
                    endLine: firstArg.loc?.end.line ?? startLine,
                    startColumn: firstArg.loc?.start.column,
                    endColumn: firstArg.loc?.end.column,
                    rawEvidence: lines[startLine - 1] || 'Model.findOne(req.body)',
                    explanation:
                      'Directly passing req.body to a MongoDB query filter enables operator injection attacks.',
                  });
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
