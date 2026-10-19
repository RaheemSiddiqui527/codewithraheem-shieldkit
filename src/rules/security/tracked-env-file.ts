import fs from 'node:fs';
import path from 'node:path';
import { Rule, RuleFindingInput } from '../../types/index.js';
import { buildPatchProposal } from '../../fixes/patch-builder.js';

export const trackedEnvFileRule: Rule = {
  id: 'SK-SEC-012',
  name: 'Environment File Committed or Not Gitignored',
  description:
    'Detects .env files in the repository that are not ignored by .gitignore, risking accidental credential leakage.',
  category: 'configuration',
  severity: 'high',
  confidence: 'high',
  languages: ['env', 'generic'],
  frameworks: ['generic'],
  filePatterns: ['.env', '.env.local', '.env.production'],
  explanation:
    'Environment (.env) files often contain production secrets, database credentials, and API keys. If not listed in .gitignore, they are easily committed to source control.',
  remediation:
    'Add .env and .env.* (except .env.example) to your .gitignore file and remove any tracked .env files from git history.',
  docUrl: 'https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-012',
  hasFix: true,
  check: (context) => {
    const findings: RuleFindingInput[] = [];
    const fileName = path.basename(context.file.relativePath);

    if (fileName === '.env' || (fileName.startsWith('.env.') && !fileName.endsWith('.example'))) {
      const gitignorePath = path.join(context.project.rootPath, '.gitignore');
      let isIgnored = false;

      if (fs.existsSync(gitignorePath)) {
        try {
          const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
          const lines = gitignoreContent.split('\n').map((l) => l.trim());
          if (lines.includes('.env') || lines.includes('.env*') || lines.includes('*.env')) {
            isIgnored = true;
          }
        } catch (readErr: unknown) {
          // unreadable gitignore handled safely
          void readErr;
        }
      }

      if (!isIgnored) {
        findings.push({
          title: `Environment File "${fileName}" Not Protected by .gitignore`,
          startLine: 1,
          endLine: 1,
          rawEvidence: fileName,
          explanation: `File ${fileName} was discovered in project root but .gitignore does not explicitly ignore .env files.`,
        });
      }
    }

    return findings;
  },
  getFix: (finding, _fileContent) => {
    const gitignorePath = '.gitignore';
    const targetFile = gitignorePath;
    const originalContent = ''; // If creating or appending
    const proposedContent =
      '\n# ShieldKit Security: Ignore local environment secrets\n.env\n.env.*\n!.env.example\n';

    return buildPatchProposal({
      findingId: finding.id,
      targetFile,
      originalContent,
      proposedContent,
      riskLevel: 'low',
      explanation: 'Append .env and .env.* to .gitignore to prevent accidental credential commits.',
      validationRequirements: ['Ensure git status shows .env as untracked.'],
    });
  },
};
