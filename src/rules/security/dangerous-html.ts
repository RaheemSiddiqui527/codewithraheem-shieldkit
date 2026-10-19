import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';
import { buildPatchProposal } from '../../fixes/patch-builder.js';

export const dangerousHtmlRule: Rule = {
  id: 'SK-SEC-007',
  name: 'Dangerous HTML Injection (XSS)',
  description:
    'Detects use of dangerouslySetInnerHTML or innerHTML assignments that may lead to Cross-Site Scripting (XSS).',
  category: 'security',
  severity: 'high',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['react', 'next', 'vite', 'generic'],
  filePatterns: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
  explanation:
    'Rendering unsanitized HTML directly into the DOM allows attackers to inject malicious scripts, steal cookies/tokens, or impersonate users.',
  remediation:
    'Use standard JSX children rendering, textContent, or sanitize the HTML string using DOMPurify before inserting.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-007',
  hasFix: true,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          // React dangerouslySetInnerHTML
          if (node.type === 'JSXAttribute' && node.name?.name === 'dangerouslySetInnerHTML') {
            const startLine = node.loc?.start.line ?? 1;
            findings.push({
              title: 'Use of dangerouslySetInnerHTML in JSX',
              startLine,
              endLine: node.loc?.end.line ?? startLine,
              startColumn: node.loc?.start.column,
              endColumn: node.loc?.end.column,
              rawEvidence: lines[startLine - 1] || 'dangerouslySetInnerHTML={{ __html: ... }}',
              explanation: 'dangerouslySetInnerHTML bypasses React built-in XSS protections.',
            });
          }

          // DOM innerHTML assignment
          if (node.type === 'AssignmentExpression' && node.left?.type === 'MemberExpression') {
            const prop = node.left.property;
            if (prop && prop.type === 'Identifier' && prop.name === 'innerHTML') {
              const startLine = node.loc?.start.line ?? 1;
              findings.push({
                title: 'Direct Assignment to innerHTML',
                startLine,
                endLine: node.loc?.end.line ?? startLine,
                startColumn: node.loc?.start.column,
                endColumn: node.loc?.end.column,
                rawEvidence: lines[startLine - 1] || 'element.innerHTML = ...',
                explanation:
                  'Assigning to innerHTML creates an XSS vulnerability if input contains unescaped markup.',
              });
            }
          }
        },
      });
    }

    return findings;
  },
  getFix: (finding, fileContent) => {
    // If it's a simple element.innerHTML = text where textContent is safer
    if (fileContent.includes('.innerHTML =')) {
      const fixed = fileContent.replace(
        /(\b[a-zA-Z0-9_$]+)\.innerHTML\s*=\s*/g,
        '$1.textContent = ',
      );
      if (fixed !== fileContent) {
        return buildPatchProposal({
          findingId: finding.id,
          targetFile: finding.filePath,
          originalContent: fileContent,
          proposedContent: fixed,
          riskLevel: 'medium',
          explanation: 'Replace dangerous innerHTML assignment with safe textContent.',
          validationRequirements: [
            'Verify that the assigned value is plain text and does not require HTML parsing.',
          ],
        });
      }
    }
    return null;
  },
};
