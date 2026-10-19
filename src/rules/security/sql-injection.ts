import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';

export const sqlInjectionRule: Rule = {
  id: 'SK-SEC-003',
  name: 'Potential SQL Injection',
  description:
    'Detects dynamic SQL queries constructed via string concatenation or template literal interpolation.',
  category: 'security',
  severity: 'high',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['generic', 'node', 'express'],
  filePatterns: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
  explanation:
    'Concatenating or interpolating untrusted input directly into raw SQL strings allows attackers to manipulate query logic, bypass authentication, and extract or corrupt database records.',
  remediation:
    'Use parameterized queries, prepared statements (e.g., db.query("SELECT * FROM users WHERE id = $1", [userId])), or an ORM query builder.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-003',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (node.type !== 'CallExpression') return;

          const callee = node.callee;
          let methodName = '';

          if (
            callee.type === 'MemberExpression' &&
            callee.property &&
            callee.property.type === 'Identifier'
          ) {
            methodName = callee.property.name;
          } else if (callee.type === 'Identifier') {
            methodName = callee.name;
          }

          if (['query', 'raw', 'execute'].includes(methodName) && node.arguments.length > 0) {
            const firstArg = node.arguments[0];

            // Case 1: Template literal with dynamic expressions
            if (firstArg.type === 'TemplateLiteral' && firstArg.expressions.length > 0) {
              const startLine = firstArg.loc?.start.line ?? 1;
              const evidence = lines[startLine - 1] || 'db.query(`...${var}...`)';

              // Ensure it looks like a SQL statement
              const quasisText = firstArg.quasis.map((q: any) => q.value?.raw || '').join(' ');
              if (/\b(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)\b/i.test(quasisText)) {
                findings.push({
                  title: 'SQL Injection via Template Literal',
                  startLine,
                  endLine: firstArg.loc?.end.line ?? startLine,
                  startColumn: firstArg.loc?.start.column,
                  endColumn: firstArg.loc?.end.column,
                  rawEvidence: evidence,
                  explanation: `Dynamic template interpolation found in SQL ${methodName}() call.`,
                });
              }
            }

            // Case 2: BinaryExpression string concatenation (e.g. "SELECT * FROM users WHERE id = " + id)
            if (firstArg.type === 'BinaryExpression' && firstArg.operator === '+') {
              const startLine = firstArg.loc?.start.line ?? 1;
              const evidence = lines[startLine - 1] || 'db.query("..." + var)';

              if (/\b(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)\b/i.test(evidence)) {
                findings.push({
                  title: 'SQL Injection via String Concatenation',
                  startLine,
                  endLine: firstArg.loc?.end.line ?? startLine,
                  startColumn: firstArg.loc?.start.column,
                  endColumn: firstArg.loc?.end.column,
                  rawEvidence: evidence,
                  explanation: `String concatenation with '+' operator found in SQL ${methodName}() call.`,
                });
              }
            }
          }
        },
      });
    } else {
      // Fallback regex detection if AST not available
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (
          /\b(?:db|client|pool|connection)\.query\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/i.test(line) &&
          /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(line)
        ) {
          findings.push({
            title: 'SQL Injection via Template Literal (Regex match)',
            startLine: i + 1,
            endLine: i + 1,
            rawEvidence: line,
          });
        }
      }
    }

    return findings;
  },
};
