import {
  Finding,
  RuleContext,
  ScanFile,
  ScanOptions,
  ScanResult,
  ScanSummary,
  Severity,
} from '../types/index.js';
import { validateProjectPath } from '../safety/path-validation.js';
import { loadConfig } from '../config/loader.js';
import { detectProject } from './project-detector.js';
import { discoverFiles } from './file-discovery.js';
import { RulesEngine } from './rules-engine.js';
import { createDefaultRuleRegistry } from '../rules/registry.js';
import { parseSourceToAST } from '../analyzers/javascript/ast-visitor.js';

export const SHIELDKIT_VERSION = '0.1.0';

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const projectRoot = validateProjectPath(options.targetPath);
  const config = loadConfig(projectRoot, options.configPath);

  const project = detectProject(projectRoot);

  const limits = {
    maxFileSize: config.maxFileSize,
    maxFiles: config.maxFiles,
  };

  const { files, skippedCount } = discoverFiles({
    projectRoot,
    ignorePaths: config.ignorePaths,
    limits,
  });

  const engine = new RulesEngine();
  const allRules = createDefaultRuleRegistry();

  // Filter rules based on category options if specified
  const filteredRules = allRules.filter((rule) => {
    if (options.securityOnly && rule.category !== 'security' && rule.category !== 'secrets') {
      return false;
    }
    if (options.qualityOnly && rule.category !== 'quality') {
      return false;
    }
    if (options.category && rule.category !== options.category) {
      return false;
    }
    return true;
  });

  engine.registerRules(filteredRules);

  const checksPerformed = filteredRules.map((r) => `${r.id}: ${r.name}`);
  const checksSkipped: string[] = [];

  if (
    project.languages.includes('generic') &&
    !project.languages.includes('javascript') &&
    !project.languages.includes('typescript')
  ) {
    checksSkipped.push(
      'Python, PHP, and Go static analysis (language adapters planned for future release).',
    );
  }

  const allFindings: Finding[] = [];

  for (const file of files) {
    let ast: any = null;
    if (file.language === 'javascript' || file.language === 'typescript') {
      ast = parseSourceToAST(file.content, file.language === 'typescript');
    }

    const context: RuleContext = {
      file,
      project,
      ast,
      lines: file.content.split('\n'),
    };

    const fileFindings = await engine.executeRules(file, context, config);
    allFindings.push(...fileFindings);
  }

  // Calculate summary counts
  const summary: ScanSummary = {
    total: allFindings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    fixable: 0,
  };

  for (const f of allFindings) {
    if (f.severity in summary) {
      summary[f.severity]++;
    }
    if (f.hasFix) {
      summary.fixable++;
    }
  }

  const durationMs = Date.now() - startTime;

  return {
    toolName: 'ShieldKit',
    version: SHIELDKIT_VERSION,
    timestamp: new Date().toISOString(),
    project,
    scannedFilesCount: files.length,
    skippedFilesCount: skippedCount,
    durationMs,
    checksPerformed,
    checksSkipped,
    summary,
    findings: allFindings,
  };
}
