import { describe, expect, it } from 'vitest';
import { emptyCatchBlockRule } from '../../src/rules/quality/empty-catch-block.js';
import { unhandledPromiseRule } from '../../src/rules/quality/unhandled-promise.js';
import { unsafeTypeAssertionRule } from '../../src/rules/quality/unsafe-type-assertion.js';
import { debugStatementsRule } from '../../src/rules/quality/debug-statements.js';
import { malformedScriptsRule } from '../../src/rules/quality/malformed-scripts.js';
import { parseSourceToAST } from '../../src/analyzers/javascript/ast-visitor.js';
import { DetectedProject, RuleContext, ScanFile } from '../../src/types/index.js';

function createMockContext(code: string, fileName = 'src/test.ts'): RuleContext {
  const ast = parseSourceToAST(code, true);
  const file: ScanFile = {
    absolutePath: `/mock/project/${fileName}`,
    relativePath: fileName,
    content: code,
    size: code.length,
    extension: fileName.endsWith('.ts') ? '.ts' : fileName.endsWith('.json') ? '.json' : '.js',
    language: fileName.endsWith('.ts')
      ? 'typescript'
      : fileName.endsWith('.json')
        ? 'json'
        : 'javascript',
  };

  const project: DetectedProject = {
    rootPath: '/mock/project',
    languages: ['typescript', 'javascript'],
    frameworks: ['node'],
    hasPackageJson: true,
    dependencies: {},
    devDependencies: {},
    scripts: {},
    manifestFiles: ['package.json'],
  };

  return {
    file,
    project,
    ast,
    lines: code.split('\n'),
  };
}

describe('Code Quality Rules (Positive & Negative Test Cases)', () => {
  describe('SK-QUAL-001: Empty Catch Block', () => {
    it('detects empty catch blocks', async () => {
      const code = `
        try {
          doSomething();
        } catch (err) {}
      `;
      const context = createMockContext(code);
      const findings = await emptyCatchBlockRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Empty Catch Block');
    });

    it('proposes safe error logging fix for empty catch block', () => {
      const code = 'try { doSomething(); } catch (err) {}';
      const fix = emptyCatchBlockRule.getFix?.({ id: '1', filePath: 'index.js' } as any, code);
      expect(fix).not.toBeNull();
      expect(fix?.proposedContent).toContain('console.error(err)');
    });

    it('does NOT flag handled catch blocks', async () => {
      const code = `
        try {
          doSomething();
        } catch (err) {
          logger.error(err);
        }
      `;
      const context = createMockContext(code);
      const findings = await emptyCatchBlockRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-QUAL-002: Async Promise Executor', () => {
    it('detects async executor in new Promise', async () => {
      const code = `
        const p = new Promise(async (resolve, reject) => {
          const res = await fetch('/api');
          resolve(res);
        });
      `;
      const context = createMockContext(code);
      const findings = await unhandledPromiseRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Async Executor');
    });

    it('does NOT flag standard synchronous Promise executor', async () => {
      const code = `
        const p = new Promise((resolve, reject) => {
          setTimeout(() => resolve('done'), 100);
        });
      `;
      const context = createMockContext(code);
      const findings = await unhandledPromiseRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-QUAL-003: Unsafe Type Assertion (as any)', () => {
    it('detects "as any" type assertion in TypeScript', async () => {
      const code = `
        const data = response as any;
      `;
      const context = createMockContext(code, 'src/api.ts');
      const findings = await unsafeTypeAssertionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Unsafe Type Assertion');
    });

    it('does NOT flag specific typed assertions', async () => {
      const code = `
        const data = response as UserResponse;
      `;
      const context = createMockContext(code, 'src/api.ts');
      const findings = await unsafeTypeAssertionRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-QUAL-004: Debug Statements & Sensitive Logging', () => {
    it('detects debugger; statement and provides fix to remove it', async () => {
      const code = `
        function test() {
          debugger;
          return 42;
        }
      `;
      const context = createMockContext(code);
      const findings = await debugStatementsRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('debugger;');

      const fix = debugStatementsRule.getFix?.({ id: '1', filePath: 'test.js' } as any, code);
      expect(fix).not.toBeNull();
      expect(fix?.proposedContent).not.toContain('debugger;');
    });

    it('detects console.log(password)', async () => {
      const code = `
        function login(user, password) {
          console.log(password);
        }
      `;
      const context = createMockContext(code);
      const findings = await debugStatementsRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Suspicious Console Logging');
    });

    it('does NOT flag regular non-sensitive console logging', async () => {
      const code = `
        console.log('Server started on port 3000');
        console.log(users.length);
      `;
      const context = createMockContext(code);
      const findings = await debugStatementsRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-QUAL-005: Malformed Project Scripts', () => {
    it('detects placeholder test script in package.json', async () => {
      const code = JSON.stringify({
        name: 'my-app',
        scripts: {
          test: 'echo "Error: no test specified" && exit 1',
        },
      });
      const context = createMockContext(code, 'package.json');
      const findings = await malformedScriptsRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Placeholder "test" Script');
    });

    it('does NOT flag configured test script', async () => {
      const code = JSON.stringify({
        name: 'my-app',
        scripts: {
          test: 'vitest run',
        },
      });
      const context = createMockContext(code, 'package.json');
      const findings = await malformedScriptsRule.check(context);
      expect(findings.length).toBe(0);
    });
  });
});
