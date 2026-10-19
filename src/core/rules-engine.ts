import crypto from 'node:crypto';
import { Finding, Rule, RuleContext, ScanFile, ShieldKitConfig } from '../types/index.js';
import { redactSensitiveData } from '../safety/redaction.js';
import { sanitizeTerminalString, truncateEvidence } from '../safety/sanitization.js';

export function generateStableFindingId(
  ruleId: string,
  filePath: string,
  startLine: number,
  sanitizedEvidence: string,
): string {
  const payload = `${ruleId}:${filePath}:${startLine}:${sanitizedEvidence.trim()}`;
  return crypto.createHash('sha256').update(payload, 'utf-8').digest('hex').slice(0, 16);
}

export class RulesEngine {
  private rules: Map<string, Rule> = new Map();

  registerRule(rule: Rule): void {
    if (this.rules.has(rule.id)) {
      throw new Error(`Rule with ID "${rule.id}" is already registered.`);
    }
    this.rules.set(rule.id, rule);
  }

  registerRules(rules: Rule[]): void {
    for (const rule of rules) {
      this.registerRule(rule);
    }
  }

  getAllRules(): Rule[] {
    return Array.from(this.rules.values());
  }

  getRule(id: string): Rule | undefined {
    return this.rules.get(id);
  }

  async executeRules(
    file: ScanFile,
    context: RuleContext,
    config: ShieldKitConfig = {},
  ): Promise<Finding[]> {
    const findings: Finding[] = [];
    const suppressedRules = config.ignoreRules || {};

    for (const rule of this.rules.values()) {
      // 1. Check if rule is suppressed via config
      if (suppressedRules[rule.id]) {
        continue;
      }

      // 2. Check if rule is disabled in config rules table
      if (config.rules && config.rules[rule.id] && config.rules[rule.id].enabled === false) {
        continue;
      }

      // 3. Language matching
      if (
        rule.languages.length > 0 &&
        !rule.languages.includes('generic') &&
        !rule.languages.includes(file.language)
      ) {
        continue;
      }

      // 4. Framework matching: if rule targets specific frameworks, check if project has at least one
      if (rule.frameworks.length > 0 && !rule.frameworks.includes('generic')) {
        const matchesFramework = rule.frameworks.some((fw) =>
          context.project.frameworks.includes(fw),
        );
        if (!matchesFramework) {
          continue;
        }
      }

      // 5. Execute rule check safely
      try {
        const rawFindings = await Promise.resolve(rule.check(context));
        for (const input of rawFindings) {
          // Guaranteed secret redaction and terminal escape sanitization on evidence
          const sanitizedEvidence = truncateEvidence(
            redactSensitiveData(sanitizeTerminalString(input.rawEvidence)),
            250,
          );

          const findingId = generateStableFindingId(
            rule.id,
            file.relativePath,
            input.startLine,
            sanitizedEvidence,
          );

          const effectiveSeverity =
            (config.rules && config.rules[rule.id]?.severity) ||
            input.customSeverity ||
            rule.severity;

          const effectiveConfidence = input.customConfidence || rule.confidence;

          const finding: Finding = {
            id: findingId,
            ruleId: rule.id,
            title: input.title || rule.name,
            category: rule.category,
            severity: effectiveSeverity,
            confidence: effectiveConfidence,
            filePath: file.relativePath,
            startLine: input.startLine,
            endLine: input.endLine,
            startColumn: input.startColumn ?? 1,
            endColumn: input.endColumn ?? 1,
            sanitizedEvidence,
            explanation: input.explanation || rule.explanation,
            remediation: input.remediation || rule.remediation,
            hasFix: rule.hasFix && typeof rule.getFix === 'function',
            docUrl: rule.docUrl,
          };

          if (finding.hasFix && rule.getFix) {
            const proposal = rule.getFix(finding, file.content);
            if (proposal) {
              finding.fixProposal = proposal;
            }
          }

          findings.push(finding);
        }
      } catch (err: unknown) {
        // Individual rule failure is isolated to prevent scanner crash
        void err;
      }
    }

    return findings;
  }
}
