import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';

export const pathTraversalRule: Rule = {
  id: 'SK-SEC-006',
  name: 'Potential Path Traversal',
  description:
    'Detects unsanitized request parameters or variables passed directly to filesystem access methods.',
  category: 'security',
  severity: 'high',
  confidence: 'medium',
  languages: ['javascript', 'typescript'],
  frameworks: ['node', 'express', 'generic'],
  filePatterns: ['**/*.js', '**/*.ts'],
  explanation:
    'Joining user input into filesystem paths without validating against directory boundaries allows attackers to supply "../" sequences and read or overwrite arbitrary files on the server.',
  remediation:
    'Resolve the target path using path.resolve(), check that it starts with the intended base directory using a boundary check, or restrict inputs to a strict allowlist.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-006',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (node.type !== 'CallExpression') return;

          let isFsSink = false;
          const callee = node.callee;

          if (
            callee.type === 'MemberExpression' &&
            callee.property &&
            callee.property.type === 'Identifier'
          ) {
            if (
              [
                'readFile',
                'readFileSync',
                'createReadStream',
                'writeFile',
                'writeFileSync',
                'unlink',
                'sendFile',
              ].includes(callee.property.name)
            ) {
              isFsSink = true;
            }
          }

          if (isFsSink && node.arguments.length > 0) {
            const firstArg = node.arguments[0];

            // Check if argument includes req.query, req.params, or path.join with req
            let hasReqInput = false;
            walkAST(firstArg, {
              enter: (innerNode) => {
                if (innerNode.type === 'MemberExpression') {
                  const obj = innerNode.object;
                  if (obj && obj.type === 'Identifier' && obj.name === 'req') {
                    hasReqInput = true;
                  }
                }
              },
            });

            if (hasReqInput) {
              const startLine = firstArg.loc?.start.line ?? 1;
              findings.push({
                title: 'Potential Path Traversal via Request Parameter',
                startLine,
                endLine: firstArg.loc?.end.line ?? startLine,
                startColumn: firstArg.loc?.start.column,
                endColumn: firstArg.loc?.end.column,
                rawEvidence: lines[startLine - 1] || 'fs.readFile(req.query.file)',
                explanation:
                  'Request parameters passed directly to filesystem sink without safe boundary validation.',
              });
            }
          }
        },
      });
    }

    return findings;
  },
};
