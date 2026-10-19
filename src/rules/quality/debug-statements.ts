import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';
import { buildPatchProposal } from '../../fixes/patch-builder.js';

export const debugStatementsRule: Rule = {
  id: 'SK-QUAL-004',
  name: 'Leftover Debugger Statement or Sensitive Logging',
  description:
    'Detects leftover debugger; statements and suspicious logging of secrets or passwords.',
  category: 'quality',
  severity: 'low',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['generic'],
  filePatterns: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
  explanation:
    'Leaving debugger statements in production can cause client-side applications to freeze or open developer consoles unexpectedly. Logging variables named password or token risks leaking secrets to log aggregators.',
  remediation:
    'Remove debugger statements before committing. Use structured logging without sensitive fields.',
  docUrl:
    'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-qual-004',
  hasFix: true,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (node.type === 'DebuggerStatement') {
            const startLine = node.loc?.start.line ?? 1;
            findings.push({
              title: 'Leftover debugger; Statement',
              startLine,
              endLine: node.loc?.end.line ?? startLine,
              startColumn: node.loc?.start.column,
              endColumn: node.loc?.end.column,
              rawEvidence: lines[startLine - 1] || 'debugger;',
              explanation: 'A debugger; breakpoint was left in the source code.',
            });
          }

          if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
            const obj = node.callee.object;
            const prop = node.callee.property;
            if (obj?.name === 'console' && prop?.name === 'log') {
              for (const arg of node.arguments) {
                if (
                  arg.type === 'Identifier' &&
                  /^(password|passwd|secret|apiKey|token)$/i.test(arg.name)
                ) {
                  const startLine = node.loc?.start.line ?? 1;
                  findings.push({
                    title: `Suspicious Console Logging of "${arg.name}"`,
                    startLine,
                    endLine: node.loc?.end.line ?? startLine,
                    rawEvidence: lines[startLine - 1] || `console.log(${arg.name})`,
                    explanation: `Logging potential credential variable "${arg.name}" to stdout.`,
                    customSeverity: 'medium',
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
  getFix: (finding, fileContent) => {
    if (fileContent.includes('debugger;')) {
      const fixed = fileContent.replace(/^\s*debugger;\s*$\n?/gm, '');
      if (fixed !== fileContent) {
        return buildPatchProposal({
          findingId: finding.id,
          targetFile: finding.filePath,
          originalContent: fileContent,
          proposedContent: fixed,
          riskLevel: 'low',
          explanation: 'Remove leftover debugger; statement.',
          validationRequirements: ['Verify code formatting remains intact.'],
        });
      }
    }
    return null;
  },
};
