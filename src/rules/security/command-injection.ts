import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';

export const commandInjectionRule: Rule = {
  id: 'SK-SEC-004',
  name: 'Potential Command Injection',
  description:
    'Detects shell command execution with dynamic user input or unsanitized string construction.',
  category: 'security',
  severity: 'critical',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['node', 'express', 'generic'],
  filePatterns: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
  explanation:
    'Invoking system commands using child_process.exec or execSync with dynamically constructed arguments allows an attacker to inject shell metacharacters (e.g., ; && |) and execute arbitrary operating system commands.',
  remediation:
    'Use child_process.execFile or child_process.spawn with an array of arguments and { shell: false } instead of exec.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-004',
  hasFix: false,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (node.type !== 'CallExpression') return;

          const callee = node.callee;
          let isExec = false;

          if (
            callee.type === 'MemberExpression' &&
            callee.property &&
            callee.property.type === 'Identifier'
          ) {
            if (['exec', 'execSync'].includes(callee.property.name)) {
              isExec = true;
            }
          } else if (callee.type === 'Identifier' && ['exec', 'execSync'].includes(callee.name)) {
            isExec = true;
          }

          if (isExec && node.arguments.length > 0) {
            const firstArg = node.arguments[0];

            // If first arg is a dynamic template literal with expressions
            if (firstArg.type === 'TemplateLiteral' && firstArg.expressions.length > 0) {
              const startLine = firstArg.loc?.start.line ?? 1;
              findings.push({
                title: 'Command Injection via Dynamic Shell Template',
                startLine,
                endLine: firstArg.loc?.end.line ?? startLine,
                startColumn: firstArg.loc?.start.column,
                endColumn: firstArg.loc?.end.column,
                rawEvidence: lines[startLine - 1] || 'exec(`...${input}...`)',
                explanation:
                  'Dynamic shell command constructed with template literal expression in exec call.',
              });
            }

            // Or if first arg is binary concatenation with +
            if (firstArg.type === 'BinaryExpression' && firstArg.operator === '+') {
              const startLine = firstArg.loc?.start.line ?? 1;
              findings.push({
                title: 'Command Injection via String Concatenation',
                startLine,
                endLine: firstArg.loc?.end.line ?? startLine,
                startColumn: firstArg.loc?.start.column,
                endColumn: firstArg.loc?.end.column,
                rawEvidence: lines[startLine - 1] || 'exec("..." + input)',
                explanation:
                  'Dynamic shell command constructed with string concatenation in exec call.',
              });
            }
          }
        },
      });
    } else {
      // Fallback regex
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/\b(?:child_process\.)?(?:exec|execSync)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/i.test(line)) {
          findings.push({
            title: 'Command Injection via Dynamic Shell Template (Regex match)',
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
