import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command } from 'commander';
import pc from 'picocolors';
import { runScan, SHIELDKIT_VERSION } from '../core/scanner.js';
import { createDefaultRuleRegistry } from '../rules/registry.js';
import { formatTerminalReport } from '../reporters/terminal.js';
import { formatJsonReport } from '../reporters/json.js';
import { formatMarkdownReport } from '../reporters/markdown.js';
import { renderDiff } from '../fixes/diff-renderer.js';
import { promptUserApproval } from '../fixes/approval.js';
import { applyPatch } from '../fixes/verifier.js';
import { meetsSeverityThreshold } from './options.js';
import { Severity } from '../types/index.js';
import { validateSafeOutputPath } from '../safety/path-validation.js';

export function createCli(): Command {
  const program = new Command();

  program
    .name('shieldkit')
    .description(
      'CodeWithRaheem ShieldKit — Build with AI. Ship with Confidence.\nModular security and code-quality static analysis toolkit.',
    )
    .version(SHIELDKIT_VERSION, '--version', 'Output the current version of ShieldKit')
    .argument('[path]', 'Path to the directory to scan', '.')
    .option('-s, --security', 'Run only security and secret checks')
    .option('-q, --quality', 'Run only code-quality checks')
    .option('-f, --format <type>', 'Output format: terminal, json, markdown', 'terminal')
    .option('-o, --output <file>', 'Save the scan report to a file')
    .option('--suggest-fixes', 'Display available automated fix proposals without modifying files')
    .option('--diff', 'Display unified diffs for available fixes without modifying files')
    .option('--fix', 'Interactively review and apply safe automated patches')
    .option('--rules', 'List all registered rules and exit')
    .option('-c, --config <file>', 'Path to custom ShieldKit configuration file')
    .option(
      '--severity <threshold>',
      'Failure exit code threshold (critical, high, medium, low, informational)',
      'high',
    )
    .option('-v, --verbose', 'Show detailed evidence and documentation references')
    .option('--no-color', 'Disable colored terminal output');

  return program;
}

export async function runCli(argv: string[] = process.argv): Promise<number> {
  const program = createCli();

  try {
    program.parse(argv);
  } catch {
    return 2;
  }

  const options = program.opts();
  const args = program.args;
  const targetPath = args[0] || '.';
  const noColor = options.color === false;

  // Handle --rules listing
  if (options.rules) {
    const rules = createDefaultRuleRegistry();
    console.log(
      noColor
        ? '\nRegistered ShieldKit Rules:\n'
        : pc.bold(pc.cyan('\nRegistered ShieldKit Rules:\n')),
    );
    for (const rule of rules) {
      const fixBadge = rule.hasFix
        ? noColor
          ? '[Fix Available]'
          : pc.green('[Fix Available]')
        : '';
      console.log(
        `  ${noColor ? rule.id : pc.bold(rule.id)} [${rule.severity.toUpperCase()}] ${rule.name} ${fixBadge}`,
      );
      console.log(`    ${noColor ? rule.description : pc.dim(rule.description)}`);
    }
    console.log('');
    return 0;
  }

  // Validate format option
  const validFormats = ['terminal', 'json', 'markdown'];
  if (!validFormats.includes(options.format)) {
    console.error(
      pc.red(
        `Error: Invalid format "${options.format}". Supported formats: ${validFormats.join(', ')}`,
      ),
    );
    return 2;
  }

  // Validate severity threshold
  const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];
  if (!validSeverities.includes(options.severity)) {
    console.error(
      pc.red(
        `Error: Invalid severity threshold "${options.severity}". Allowed values: ${validSeverities.join(', ')}`,
      ),
    );
    return 2;
  }

  try {
    const scanResult = await runScan({
      targetPath,
      securityOnly: options.security,
      qualityOnly: options.quality,
      format: options.format,
      outputPath: options.output,
      verbose: options.verbose,
      noColor,
      severityThreshold: options.severity,
      configPath: options.config,
    });

    // Handle --diff display
    if (options.diff) {
      const fixableFindings = scanResult.findings.filter((f) => f.fixProposal);
      if (fixableFindings.length === 0) {
        console.log(pc.yellow('\nNo automated diff proposals available for current findings.'));
      } else {
        console.log(pc.bold(`\nProposed Unified Diffs (${fixableFindings.length}):`));
        for (const f of fixableFindings) {
          if (f.fixProposal) {
            console.log(renderDiff(f.fixProposal, noColor));
          }
        }
      }
    }

    // Handle --suggest-fixes display
    if (options.suggestFixes && !options.diff) {
      const fixableFindings = scanResult.findings.filter((f) => f.fixProposal);
      console.log(pc.bold(`\nSafe Fix Proposals (${fixableFindings.length} available):`));
      for (const f of fixableFindings) {
        console.log(`  * [${f.ruleId}] ${f.title} -> ${f.filePath}:${f.startLine}`);
        if (f.fixProposal) {
          console.log(`    Fix: ${f.fixProposal.explanation} (Risk: ${f.fixProposal.riskLevel})`);
        }
      }
      console.log('');
    }

    // Handle --fix interactive remediation
    if (options.fix) {
      const fixableFindings = scanResult.findings.filter((f) => f.fixProposal);
      if (fixableFindings.length === 0) {
        console.log(pc.yellow('\nNo fixable findings detected to remediate.'));
      } else {
        console.log(
          pc.bold(`\nStarting Interactive Remediation (${fixableFindings.length} proposals):`),
        );

        if (!process.stdin.isTTY) {
          console.error(
            pc.red(
              'Interactive patch confirmation requires an interactive TTY terminal. In non-interactive environments, --fix is rejected to prevent unconfirmed modifications.',
            ),
          );
          return 2;
        }

        for (const f of fixableFindings) {
          if (!f.fixProposal) continue;

          console.log(renderDiff(f.fixProposal, noColor));
          const approved = await promptUserApproval(
            `Apply this fix to ${pc.bold(f.fixProposal.targetFile)}?`,
          );

          if (approved) {
            const result = applyPatch(scanResult.project.rootPath, f.fixProposal);
            if (result.applied) {
              console.log(pc.green(`✔ Successfully patched ${f.fixProposal.targetFile}`));
            } else {
              console.error(pc.red(`✖ Failed to apply patch: ${result.error}`));
            }
          } else {
            console.log(pc.dim('Patch skipped by user.'));
          }
        }
      }
    }

    // Generate report content
    let outputContent = '';
    if (options.format === 'json') {
      outputContent = formatJsonReport(scanResult);
    } else if (options.format === 'markdown') {
      outputContent = formatMarkdownReport(scanResult);
    } else {
      outputContent = formatTerminalReport(scanResult, {
        verbose: options.verbose,
        noColor,
      });
    }

    // Write to file or stdout
    if (options.output) {
      const safeOut = validateSafeOutputPath(options.output, scanResult.project.rootPath);
      fs.writeFileSync(safeOut, outputContent, 'utf-8');
      console.log(pc.green(`\nReport written successfully to: ${safeOut}`));
    } else {
      console.log(outputContent);
    }

    // Check exit code threshold
    const hasFailingFindings = scanResult.findings.some((f) =>
      meetsSeverityThreshold(f.severity, options.severity),
    );

    return hasFailingFindings ? 1 : 0;
  } catch (err: any) {
    console.error(pc.red(`\nShieldKit Execution Error: ${err?.message || err}\n`));
    return 2;
  }
}

// Direct binary invocation check
const currentFilePath = fileURLToPath(import.meta.url);
const invokedFilePath = process.argv[1] ? path.resolve(process.argv[1]) : '';

if (
  currentFilePath.toLowerCase() === invokedFilePath.toLowerCase() ||
  (process.argv[1] &&
    (process.argv[1].endsWith('shieldkit') ||
      process.argv[1].endsWith('cli.js') ||
      process.argv[1].endsWith('cli.ts')))
) {
  runCli().then((code) => {
    process.exit(code);
  });
}
