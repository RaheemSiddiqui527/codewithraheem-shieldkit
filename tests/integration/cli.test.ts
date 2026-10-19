import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { runCli } from '../../src/cli/index.js';

describe('CLI Integration & Execution', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-cli-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('prints rules list with exit code 0 when --rules is passed', async () => {
    const exitCode = await runCli(['node', 'shieldkit', '--rules', '--no-color']);
    expect(exitCode).toBe(0);
  });

  it('returns exit code 2 when target directory does not exist', async () => {
    const exitCode = await runCli(['node', 'shieldkit', './non_existent_folder_foo_bar_123']);
    expect(exitCode).toBe(2);
  });

  it('returns exit code 2 when invalid format is provided', async () => {
    const exitCode = await runCli(['node', 'shieldkit', tempDir, '--format', 'invalid_format']);
    expect(exitCode).toBe(2);
  });

  it('returns exit code 0 for a clean project with no findings', async () => {
    const cleanFile = path.join(tempDir, 'clean.js');
    fs.writeFileSync(cleanFile, 'console.log("Hello, ShieldKit!");\n', 'utf-8');

    const exitCode = await runCli(['node', 'shieldkit', tempDir, '--no-color']);
    expect(exitCode).toBe(0);
  });

  it('returns exit code 1 when findings meet failure threshold', async () => {
    const vulnFile = path.join(tempDir, 'vuln.js');
    fs.writeFileSync(
      vulnFile,
      'const query = db.query(`SELECT * FROM users WHERE id = ${userId}`);\n',
      'utf-8',
    );

    const exitCode = await runCli([
      'node',
      'shieldkit',
      tempDir,
      '--severity',
      'high',
      '--no-color',
    ]);
    expect(exitCode).toBe(1);
  });

  it('writes JSON report to file when --output and --format json are used', async () => {
    const cleanFile = path.join(tempDir, 'index.ts');
    fs.writeFileSync(cleanFile, 'export const val: number = 42;\n', 'utf-8');

    const reportPath = path.join(tempDir, 'report.json');
    const exitCode = await runCli([
      'node',
      'shieldkit',
      tempDir,
      '--format',
      'json',
      '--output',
      reportPath,
      '--no-color',
    ]);

    expect(exitCode).toBe(0);
    expect(fs.existsSync(reportPath)).toBe(true);

    const content = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
    expect(content.tool.name).toBe('ShieldKit');
    expect(content.summary.total).toBe(0);
  });

  it('runs safely in read-only mode and does NOT modify files during default scan', async () => {
    const testFile = path.join(tempDir, 'test.js');
    const originalContent = 'function debugMe() {\n  debugger;\n}\n';
    fs.writeFileSync(testFile, originalContent, 'utf-8');

    await runCli(['node', 'shieldkit', tempDir, '--suggest-fixes', '--diff', '--no-color']);

    const currentContent = fs.readFileSync(testFile, 'utf-8');
    expect(currentContent).toBe(originalContent);
  });
});
