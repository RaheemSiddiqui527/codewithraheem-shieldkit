import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { validateConfig } from '../../src/config/schema.js';
import { loadConfig } from '../../src/config/loader.js';

describe('Configuration Loader & Schema Validation', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-config-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('validates correct config object', () => {
    const valid = {
      ignorePaths: ['dist', 'coverage'],
      ignoreRules: {
        'SK-SEC-003': 'Legacy internal query verified safe by security audit',
      },
      severityThreshold: 'high',
      maxFileSize: 500000,
      maxFiles: 1000,
    };

    const validated = validateConfig(valid);
    expect(validated.ignorePaths).toEqual(['dist', 'coverage']);
    expect(validated.severityThreshold).toBe('high');
  });

  it('rejects rule suppression without explicit justification string', () => {
    const invalid = {
      ignoreRules: {
        'SK-SEC-003': '', // empty justification
      },
    };

    expect(() => validateConfig(invalid)).toThrow(/requires an explicit justification string/);
  });

  it('rejects invalid severityThreshold', () => {
    const invalid = {
      severityThreshold: 'extreme_danger',
    };

    expect(() => validateConfig(invalid)).toThrow(/Invalid severityThreshold/);
  });

  it('loads and parses JSON configuration file safely without code execution', () => {
    const configPath = path.join(tempDir, 'shieldkit.config.json');
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        severityThreshold: 'critical',
        ignorePaths: ['vendor/**'],
      }),
      'utf-8',
    );

    const loaded = loadConfig(tempDir);
    expect(loaded.severityThreshold).toBe('critical');
    expect(loaded.ignorePaths).toEqual(['vendor/**']);
  });

  it('loads and parses YAML configuration file safely', () => {
    const configPath = path.join(tempDir, 'shieldkit.config.yaml');
    fs.writeFileSync(
      configPath,
      `
severityThreshold: medium
ignorePaths:
  - build/**
  - tmp/**
`,
      'utf-8',
    );

    const loaded = loadConfig(tempDir);
    expect(loaded.severityThreshold).toBe('medium');
    expect(loaded.ignorePaths).toContain('build/**');
  });
});
