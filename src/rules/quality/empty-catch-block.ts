import { Rule, RuleFindingInput } from '../../types/index.js';
import { walkAST } from '../../analyzers/javascript/ast-visitor.js';
import { buildPatchProposal } from '../../fixes/patch-builder.js';

export const emptyCatchBlockRule: Rule = {
  id: 'SK-QUAL-001',
  name: 'Empty Catch Block (Swallowed Exception)',
  description:
    'Detects empty catch clauses that swallow errors silently without logging or handling.',
  category: 'quality',
  severity: 'medium',
  confidence: 'high',
  languages: ['javascript', 'typescript'],
  frameworks: ['generic'],
  filePatterns: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
  explanation:
    'Silently swallowing exceptions prevents debugging, conceals failed operations, and can hide critical security or integrity failures from operators.',
  remediation: 'Log the error, rethrow it, or handle the expected condition explicitly.',
  docUrl:
    'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-qual-001',
  hasFix: true,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const { ast, lines } = context;

    if (ast) {
      walkAST(ast, {
        enter: (node) => {
          if (node.type === 'CatchClause') {
            const body = node.body;
            if (body && body.type === 'BlockStatement' && body.body.length === 0) {
              const startLine = node.loc?.start.line ?? 1;
              findings.push({
                title: 'Empty Catch Block Swallowing Error',
                startLine,
                endLine: node.loc?.end.line ?? startLine,
                startColumn: node.loc?.start.column,
                endColumn: node.loc?.end.column,
                rawEvidence: lines[startLine - 1] || 'catch (err) {}',
                explanation:
                  'Catch clause contains no statements; any caught exception is silently ignored.',
              });
            }
          }
        },
      });
    }

    return findings;
  },
  getFix: (finding, fileContent) => {
    // Replace catch (err) {} with catch (err) { console.error(err); }
    const regex = /catch\s*\(\s*([a-zA-Z0-9_$]+)\s*\)\s*\{\s*\}/;
    if (regex.test(fileContent)) {
      const fixed = fileContent.replace(regex, 'catch ($1) {\n    console.error($1);\n  }');
      return buildPatchProposal({
        findingId: finding.id,
        targetFile: finding.filePath,
        originalContent: fileContent,
        proposedContent: fixed,
        riskLevel: 'low',
        explanation: 'Add error logging inside empty catch block to avoid swallowing exceptions.',
        validationRequirements: ['Verify logging level fits your project logging standards.'],
      });
    }
    return null;
  },
};
