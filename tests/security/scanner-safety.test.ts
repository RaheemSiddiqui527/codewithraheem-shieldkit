import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import https from 'node:https';
import { runScan } from '../../src/core/scanner.js';
import { discoverFiles } from '../../src/core/file-discovery.js';
import { loadConfig } from '../../src/config/loader.js';

describe('Advanced Security & Hardening Assurances', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-security-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('verifies ZERO network requests are made during default scans', async () => {
    let networkRequestMade = false;

    // Monkeypatch global fetch and node http/https
    const originalFetch = globalThis.fetch;
    const originalHttpRequest = http.request;
    const originalHttpsRequest = https.request;

    globalThis.fetch = (() => {
      networkRequestMade = true;
      throw new Error('NETWORK_ATTEMPT_BLOCKED: fetch called during scan');
    }) as any;

    (http as any).request = () => {
      networkRequestMade = true;
      throw new Error('NETWORK_ATTEMPT_BLOCKED: http.request called during scan');
    };

    (https as any).request = () => {
      networkRequestMade = true;
      throw new Error('NETWORK_ATTEMPT_BLOCKED: https.request called during scan');
    };

    try {
      const dummyFile = path.join(tempDir, 'index.ts');
      fs.writeFileSync(dummyFile, 'export const x = 1;', 'utf-8');

      const result = await runScan({
        targetPath: tempDir,
      });

      expect(result.scannedFilesCount).toBe(1);
      expect(networkRequestMade).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
      http.request = originalHttpRequest;
      https.request = originalHttpsRequest;
    }
  });

  it('handles corrupted and malformed JSON configuration gracefully', () => {
    const corruptPath = path.join(tempDir, 'shieldkit.config.json');
    fs.writeFileSync(corruptPath, '{ invalid json syntax ...', 'utf-8');

    expect(() => loadConfig(tempDir)).toThrow(/Failed to parse JSON config/);
  });

  it('enforces maximum file size limit and skips oversized files', () => {
    const bigFile = path.join(tempDir, 'large.js');
    // Write 2 MB file (default max is 1 MB)
    const bigContent = 'x'.repeat(2 * 1024 * 1024);
    fs.writeFileSync(bigFile, bigContent, 'utf-8');

    const normalFile = path.join(tempDir, 'normal.js');
    fs.writeFileSync(normalFile, 'const a = 1;', 'utf-8');

    const { files, skippedCount } = discoverFiles({
      projectRoot: tempDir,
    });

    expect(files.some((f) => f.relativePath === 'large.js')).toBe(false);
    expect(files.some((f) => f.relativePath === 'normal.js')).toBe(true);
    expect(skippedCount).toBeGreaterThanOrEqual(1);
  });

  it('handles unicode filenames and paths with special characters without crashing', async () => {
    const unicodeDir = path.join(tempDir, '📁-projets-éàç');
    fs.mkdirSync(unicodeDir);

    const unicodeFile = path.join(unicodeDir, 'données-2026.ts');
    fs.writeFileSync(unicodeFile, 'export const secret = "' + ['AKIA', '1'.repeat(16)].join('') + '";', 'utf-8');

    const result = await runScan({
      targetPath: tempDir,
    });

    expect(result.findings.length).toBeGreaterThan(0);
    // Ensure finding is redacted and location is tracked
    expect(result.findings[0].sanitizedEvidence).toContain('[REDACTED_AWS_KEY]');
  });
});
