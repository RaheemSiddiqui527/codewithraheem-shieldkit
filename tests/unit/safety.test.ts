import { describe, expect, it } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  isPathInside,
  normalizePathSeparators,
  validateProjectPath,
  validateSafeOutputPath,
} from '../../src/safety/path-validation.js';
import { calculateShannonEntropy, redactSensitiveData } from '../../src/safety/redaction.js';
import { sanitizeTerminalString, stripAnsi } from '../../src/safety/sanitization.js';

describe('Safety & Boundary Controls', () => {
  describe('Path Validation', () => {
    it('normalizes path separators to forward slashes', () => {
      expect(normalizePathSeparators('foo\\bar\\baz.ts')).toBe('foo/bar/baz.ts');
    });

    it('resolves and validates existing project directories', () => {
      const cwd = process.cwd();
      const resolved = validateProjectPath('.');
      expect(resolved.toLowerCase()).toBe(path.resolve(cwd).toLowerCase());
    });

    it('throws when target path does not exist', () => {
      expect(() => validateProjectPath('./non_existent_folder_xyz123')).toThrow(/does not exist/);
    });

    it('throws when target path is a file instead of a directory', () => {
      expect(() => validateProjectPath('package.json')).toThrow(/not a directory/);
    });

    it('correctly verifies if a child path is inside parent directory', () => {
      const parent = path.resolve('/test/project');
      const child = path.resolve('/test/project/src/index.ts');
      const outside = path.resolve('/test/other/file.ts');

      expect(isPathInside(parent, child)).toBe(true);
      expect(isPathInside(parent, outside)).toBe(false);
      expect(isPathInside(parent, path.resolve('/test/project/../outside.ts'))).toBe(false);
    });

    it('handles paths with spaces and Windows drive letters', () => {
      const parent = 'C:/Users/My Name/Project With Spaces';
      const child = 'C:/Users/My Name/Project With Spaces/src/index.ts';
      const outside = 'C:/Users/My Name/Other Project/index.ts';

      expect(isPathInside(parent, child)).toBe(true);
      expect(isPathInside(parent, outside)).toBe(false);
    });

    it('validates safe output paths', () => {
      const tmpDir = os.tmpdir();
      const outPath = path.join(tmpDir, 'shieldkit-reports', 'scan.json');
      const validated = validateSafeOutputPath(outPath, process.cwd());
      expect(validated).toBe(outPath);
      expect(fs.existsSync(path.dirname(validated))).toBe(true);
    });

    it('prevents writing output directly to the project root directory as a file', () => {
      const cwd = process.cwd();
      expect(() => validateSafeOutputPath(cwd, cwd)).toThrow(/cannot be the project root/);
    });
  });

  describe('Sanitization & Terminal Escape Prevention', () => {
    it('strips ANSI escape codes from untrusted strings', () => {
      const malicious = '\u001b[31mRed Alert\u001b[0m\u001b[2J';
      expect(stripAnsi(malicious)).toBe('Red Alert');
    });

    it('removes non-printable control characters', () => {
      const withControls = 'Clean\x00Title\x07With\x1FControls';
      expect(sanitizeTerminalString(withControls)).toBe('CleanTitleWithControls');
    });

    it('preserves valid unicode characters', () => {
      const unicodeString = 'Scanning 文件 and 🚀 emoji';
      expect(sanitizeTerminalString(unicodeString)).toBe(unicodeString);
    });
  });

  describe('Secret Redaction & Entropy', () => {
    it('redacts AWS Access Key IDs', () => {
      const raw = 'const key = "' + ['AKIA', 'IOSFODNN7EXAMPLE'].join('') + '";';
      const redacted = redactSensitiveData(raw);
      expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(redacted).toContain('AKIA***[REDACTED_AWS_KEY]***');
    });

    it('redacts GitHub Personal Access Tokens', () => {
      const raw = 'const token = "' + ['ghp_', '1'.repeat(36)].join('') + '";';
      const redacted = redactSensitiveData(raw);
      expect(redacted).not.toContain('ghp_' + '1'.repeat(36));
      expect(redacted).toContain('ghp_***[REDACTED_GITHUB_TOKEN]***');
    });

    it('redacts OpenAI and Anthropic API keys', () => {
      const openai = 'const key = "' + ['sk', 'proj', 'abc1234567890abcdef1234567890abcdef'].join('-') + '";';
      const anthropic = 'const key = "' + ['sk', 'ant', 'api03-1234567890abcdef1234567890abcdef'].join('-') + '";';

      expect(redactSensitiveData(openai)).toContain('***[REDACTED_OPENAI_KEY]***');
      expect(redactSensitiveData(anthropic)).toContain('***[REDACTED_ANTHROPIC_KEY]***');
    });

    it('redacts Slack and Stripe API keys', () => {
      const slack = 'const webhook = "' + ['xoxb', '123456789012', '1234567890123', 'abcdef123456'].join('-') + '";';
      const stripe = 'const stripeKey = "' + ['sk', 'test', '1234567890abcdef12345678'].join('_') + '";';

      expect(redactSensitiveData(slack)).toContain('***[REDACTED_SLACK_TOKEN]***');
      expect(redactSensitiveData(stripe)).toContain('***[REDACTED_STRIPE_KEY]***');
    });

    it('redacts RSA private keys', () => {
      const key =
        '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAz7z\n-----END RSA PRIVATE KEY-----';
      const redacted = redactSensitiveData(key);
      expect(redacted).toContain('***[REDACTED_PRIVATE_KEY]***');
      expect(redacted).not.toContain('MIIEowIBAAKCAQEAz7z');
    });

    it('redacts generic password assignments', () => {
      const raw = 'password = "SuperSecretPassword123!"';
      const redacted = redactSensitiveData(raw);
      expect(redacted).not.toContain('SuperSecretPassword123!');
      expect(redacted).toContain('***[REDACTED_SECRET]***');
    });

    it('computes Shannon entropy correctly', () => {
      expect(calculateShannonEntropy('aaaaaa')).toBe(0);
      const highEntropy = calculateShannonEntropy('g7hK9#vL2!mP5$qR8@zX');
      expect(highEntropy).toBeGreaterThan(3.5);
    });
  });
});
