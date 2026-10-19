import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';
import { buildPatchProposal } from '../../fixes/patch-builder.js';

export const dynamicCodeExecutionRule: Rule = {
  id: 'SK-SEC-005',
  name: 'Dynamic Code Execution (eval/Function)',
  description: 'Detects use of eval(), new Function(), or vm execution of dynamic code strings.',
  category: 'security',
  severity: 'critical',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['generic'],
  filePatterns: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
  explanation:
    'Evaluating dynamic code allows arbitrary JavaScript execution within the process context, bypassing all security controls and exposing application memory and capabilities.',
  remediation:
    'Avoid eval() and new Function(). Use structured parsers like JSON.parse() or dedicated domain-specific evaluators.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-005',
  hasFix: true,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (
            node.type === 'CallExpression' &&
            node.callee.type === 'Identifier' &&
            node.callee.name === 'eval'
          ) {
            const startLine = node.loc?.start.line ?? 1;
            findings.push({
              title: 'Use of eval() Detected',
              startLine,
              endLine: node.loc?.end.line ?? startLine,
              startColumn: node.loc?.start.column,
              endColumn: node.loc?.end.column,
              rawEvidence: lines[startLine - 1] || 'eval(...)',
              explanation: 'Direct invocation of eval() executes code in the local lexical scope.',
            });
          }

          if (
            node.type === 'NewExpression' &&
            node.callee.type === 'Identifier' &&
            node.callee.name === 'Function'
          ) {
            const startLine = node.loc?.start.line ?? 1;
            findings.push({
              title: 'Use of new Function() Detected',
              startLine,
              endLine: node.loc?.end.line ?? startLine,
              startColumn: node.loc?.start.column,
              endColumn: node.loc?.end.column,
              rawEvidence: lines[startLine - 1] || 'new Function(...)',
              explanation: 'Constructor new Function() compiles code dynamically at runtime.',
            });
          }
        },
      });
    } else {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/\beval\s*\(/.test(line)) {
          findings.push({
            title: 'Use of eval() Detected (Regex match)',
            startLine: i + 1,
            endLine: i + 1,
            rawEvidence: line,
          });
        }
      }
    }

    return findings;
  },
  getFix: (finding, fileContent) => {
    // If the finding is an eval pattern parsing JSON like `eval('(' + data + ')')` or `eval("(" + data + ")")`
    const regex = /eval\s*\(\s*['"]\(?['"]?\s*\+\s*([a-zA-Z0-9_$.]+)\s*\+\s*['"]\)?['"]?\s*\)/;
    if (regex.test(fileContent)) {
      const fixed = fileContent.replace(regex, 'JSON.parse($1)');
      return buildPatchProposal({
        findingId: finding.id,
        targetFile: finding.filePath,
        originalContent: fileContent,
        proposedContent: fixed,
        riskLevel: 'low',
        explanation: 'Replace dangerous eval-based JSON parsing with standard JSON.parse().',
        validationRequirements: ['Ensure the input variable is valid JSON formatted string.'],
      });
    }
    return null;
  },
};
