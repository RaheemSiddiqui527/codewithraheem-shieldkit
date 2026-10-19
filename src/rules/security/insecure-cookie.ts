import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';
import { buildPatchProposal } from '../../fixes/patch-builder.js';

export const insecureCookieRule: Rule = {
  id: 'SK-SEC-009',
  name: 'Insecure Cookie Configuration',
  description:
    'Detects cookies set without httpOnly: true, secure: true, or safe sameSite attributes.',
  category: 'security',
  severity: 'medium',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['express', 'node', 'generic'],
  filePatterns: ['**/*.js', '**/*.ts'],
  explanation:
    'Cookies lacking httpOnly can be accessed by client-side scripts via document.cookie (enabling XSS-based session hijacking). Cookies lacking secure flag can be intercepted in transit over unencrypted connections.',
  remediation:
    'Set httpOnly: true, secure: true, and sameSite: "strict" (or "lax") when issuing cookies.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-009',
  hasFix: true,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (node.type !== 'CallExpression') return;

          const callee = node.callee;
          if (callee.type === 'MemberExpression' && callee.property?.name === 'cookie') {
            // res.cookie(name, val, options)
            if (node.arguments.length >= 2) {
              const optionsArg = node.arguments[2];

              if (!optionsArg || optionsArg.type !== 'ObjectExpression') {
                const startLine = node.loc?.start.line ?? 1;
                findings.push({
                  title: 'Cookie Set Without Security Options',
                  startLine,
                  endLine: node.loc?.end.line ?? startLine,
                  rawEvidence: lines[startLine - 1] || 'res.cookie(...)',
                  explanation:
                    'Cookie is defined without any security options object (missing httpOnly, secure, and sameSite).',
                });
                return;
              }

              let hasHttpOnly = false;
              let hasSecure = false;

              for (const prop of optionsArg.properties) {
                if (prop.type === 'ObjectProperty') {
                  const keyName = prop.key.name || prop.key.value;
                  if (keyName === 'httpOnly' && prop.value.value === true) hasHttpOnly = true;
                  if (keyName === 'secure' && prop.value.value === true) hasSecure = true;
                }
              }

              if (!hasHttpOnly || !hasSecure) {
                const startLine = node.loc?.start.line ?? 1;
                findings.push({
                  title: 'Insecure Cookie Flags (Missing httpOnly or secure)',
                  startLine,
                  endLine: node.loc?.end.line ?? startLine,
                  rawEvidence: lines[startLine - 1] || 'res.cookie(...)',
                  explanation: `Cookie options missing: ${!hasHttpOnly ? 'httpOnly: true ' : ''}${!hasSecure ? 'secure: true' : ''}`,
                });
              }
            }
          }
        },
      });
    }

    return findings;
  },
  getFix: (finding, fileContent) => {
    // If res.cookie('name', val) without options
    const noOptRegex = /(res\.cookie\s*\(\s*['"][^'"]+['"]\s*,\s*[^,)]+)\s*\)/;
    if (noOptRegex.test(fileContent)) {
      const fixed = fileContent.replace(
        noOptRegex,
        `$1, { httpOnly: true, secure: true, sameSite: 'strict' })`,
      );
      return buildPatchProposal({
        findingId: finding.id,
        targetFile: finding.filePath,
        originalContent: fileContent,
        proposedContent: fixed,
        riskLevel: 'low',
        explanation: 'Add secure cookie options: httpOnly: true, secure: true, sameSite: "strict".',
        validationRequirements: ['Ensure server is accessed via HTTPS in production environment.'],
      });
    }
    return null;
  },
};
