import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { buildPatchProposal, calculateContentHash } from '../../src/fixes/patch-builder.js';
import { renderDiff } from '../../src/fixes/diff-renderer.js';
import { applyPatch } from '../../src/fixes/verifier.js';

describe('Safe Patch Engine & Atomic Remediation', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-fix-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('builds a valid PatchProposal with unified diff and content hash', () => {
    const original = 'function foo() {\n  debugger;\n  return 1;\n}\n';
    const proposed = 'function foo() {\n  return 1;\n}\n';

    const patch = buildPatchProposal({
      findingId: 'find-123',
      targetFile: 'src/foo.js',
      originalContent: original,
      proposedContent: proposed,
      explanation: 'Remove leftover debugger statement',
    });

    expect(patch.findingId).toBe('find-123');
    expect(patch.targetFile).toBe('src/foo.js');
    expect(patch.originalContentHash).toBe(calculateContentHash(original));
    expect(patch.diff).toContain('-  debugger;');
  });

  it('renders a formatted unified diff without errors', () => {
    const patch = buildPatchProposal({
      findingId: 'find-123',
      targetFile: 'src/foo.js',
      originalContent: 'const a = 1;',
      proposedContent: 'const a = 2;',
      explanation: 'Update constant',
    });

    const rendered = renderDiff(patch, true);
    expect(rendered).toContain('Proposed Fix for src/foo.js');
    expect(rendered).toContain('-const a = 1;');
    expect(rendered).toContain('+const a = 2;');
  });

  it('applies a patch atomically when content hash matches', () => {
    const filePath = path.join(tempDir, 'test.js');
    const originalContent = 'const x = eval(input);';
    const proposedContent = 'const x = JSON.parse(input);';

    fs.writeFileSync(filePath, originalContent, 'utf-8');

    const patch = buildPatchProposal({
      findingId: 'find-456',
      targetFile: 'test.js',
      originalContent,
      proposedContent,
      explanation: 'Replace eval with JSON.parse',
    });

    const result = applyPatch(tempDir, patch);
    expect(result.applied).toBe(true);

    const onDiskContent = fs.readFileSync(filePath, 'utf-8');
    expect(onDiskContent).toBe(proposedContent);
  });

  it('rejects patch and detects race condition when file changed on disk', () => {
    const filePath = path.join(tempDir, 'race.js');
    const originalContent = 'line 1';
    const modifiedOnDisk = 'line 1 modified by another editor';

    fs.writeFileSync(filePath, modifiedOnDisk, 'utf-8');

    // Patch generated from older version
    const patch = buildPatchProposal({
      findingId: 'find-789',
      targetFile: 'race.js',
      originalContent,
      proposedContent: 'line 1 fixed',
      explanation: 'Fix line 1',
    });

    const result = applyPatch(tempDir, patch);
    expect(result.applied).toBe(false);
    expect(result.error).toContain('Conflict detected');

    // Ensure original file was NOT overwritten
    expect(fs.readFileSync(filePath, 'utf-8')).toBe(modifiedOnDisk);
  });

  it('rejects patch attempting path traversal outside project root', () => {
    const patch = buildPatchProposal({
      findingId: 'find-hack',
      targetFile: '../outside.js',
      originalContent: 'bad',
      proposedContent: 'pwned',
      explanation: 'Attempt traversal',
    });

    const result = applyPatch(tempDir, patch);
    expect(result.applied).toBe(false);
    expect(result.error).toContain('boundary violation');
  });
});
