import { describe, expect, it } from 'vitest';
import { sqlInjectionRule } from '../../src/rules/security/sql-injection.js';
import { commandInjectionRule } from '../../src/rules/security/command-injection.js';
import { dynamicCodeExecutionRule } from '../../src/rules/security/dynamic-code-execution.js';
import { pathTraversalRule } from '../../src/rules/security/path-traversal.js';
import { dangerousHtmlRule } from '../../src/rules/security/dangerous-html.js';
import { nosqlInjectionRule } from '../../src/rules/security/nosql-injection.js';
import { insecureCookieRule } from '../../src/rules/security/insecure-cookie.js';
import { permissiveCorsRule } from '../../src/rules/security/permissive-cors.js';
import { missingAuthGuardRule } from '../../src/rules/security/missing-auth-guard.js';
import { parseSourceToAST } from '../../src/analyzers/javascript/ast-visitor.js';
import { DetectedProject, RuleContext, ScanFile } from '../../src/types/index.js';

function createMockContext(code: string, fileName = 'src/test.ts'): RuleContext {
  const ast = parseSourceToAST(code, true);
  const file: ScanFile = {
    absolutePath: `/mock/project/${fileName}`,
    relativePath: fileName,
    content: code,
    size: code.length,
    extension: fileName.endsWith('.ts') ? '.ts' : '.js',
    language: fileName.endsWith('.ts') ? 'typescript' : 'javascript',
  };

  const project: DetectedProject = {
    rootPath: '/mock/project',
    languages: ['typescript', 'javascript'],
    frameworks: ['node', 'express', 'react', 'mongoose'],
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

describe('Security Rules (Positive & Negative Test Cases)', () => {
  describe('SK-SEC-003: SQL Injection', () => {
    it('detects SQL injection via template literal interpolation', async () => {
      const code = `
        const query = db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
      `;
      const context = createMockContext(code);
      const findings = await sqlInjectionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Template Literal');
    });

    it('detects SQL injection via string concatenation', async () => {
      const code = `
        const query = db.query("SELECT * FROM users WHERE email = " + userEmail);
      `;
      const context = createMockContext(code);
      const findings = await sqlInjectionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('String Concatenation');
    });

    it('does NOT flag safe parameterized SQL queries', async () => {
      const code = `
        const query = db.query("SELECT * FROM users WHERE id = $1", [userId]);
        const query2 = client.execute("SELECT * FROM products WHERE price > ?", [minPrice]);
      `;
      const context = createMockContext(code);
      const findings = await sqlInjectionRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-SEC-004: Command Injection', () => {
    it('detects command injection via template literal in exec', async () => {
      const code = `
        import { exec } from 'child_process';
        exec(\`git checkout \${branchName}\`);
      `;
      const context = createMockContext(code);
      const findings = await commandInjectionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Dynamic Shell Template');
    });

    it('detects command injection via string concatenation in execSync', async () => {
      const code = `
        const { execSync } = require('child_process');
        execSync("cat " + userFile);
      `;
      const context = createMockContext(code);
      const findings = await commandInjectionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('String Concatenation');
    });

    it('does NOT flag safe static commands', async () => {
      const code = `
        import { exec } from 'child_process';
        exec('npm run build');
      `;
      const context = createMockContext(code);
      const findings = await commandInjectionRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-SEC-005: Dynamic Code Execution (eval)', () => {
    it('detects eval() calls', async () => {
      const code = `
        const result = eval(userInput);
      `;
      const context = createMockContext(code);
      const findings = await dynamicCodeExecutionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('eval()');
    });

    it('detects new Function() instantiation', async () => {
      const code = `
        const fn = new Function('a', 'b', dynamicCode);
      `;
      const context = createMockContext(code);
      const findings = await dynamicCodeExecutionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('new Function()');
    });

    it('proposes safe JSON.parse fix for eval json parsing', () => {
      const code = `const obj = eval('(' + data + ')');`;
      const proposal = dynamicCodeExecutionRule.getFix?.(
        { id: '1', filePath: 'index.js' } as any,
        code,
      );
      expect(proposal).not.toBeNull();
      expect(proposal?.proposedContent).toContain('JSON.parse(data)');
    });
  });

  describe('SK-SEC-006: Path Traversal', () => {
    it('detects fs.readFile with req.query parameter', async () => {
      const code = `
        import fs from 'fs';
        app.get('/file', (req, res) => {
          fs.readFile(req.query.path, 'utf-8', (err, data) => res.send(data));
        });
      `;
      const context = createMockContext(code);
      const findings = await pathTraversalRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Path Traversal');
    });

    it('does NOT flag safe static file reads', async () => {
      const code = `
        import fs from 'fs';
        fs.readFile('./config.json', 'utf-8', () => {});
      `;
      const context = createMockContext(code);
      const findings = await pathTraversalRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-SEC-007: Dangerous HTML', () => {
    it('detects dangerouslySetInnerHTML in JSX', async () => {
      const code = `
        export function Component({ content }) {
          return <div dangerouslySetInnerHTML={{ __html: content }} />;
        }
      `;
      const context = createMockContext(code, 'src/Component.tsx');
      const findings = await dangerousHtmlRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('dangerouslySetInnerHTML');
    });

    it('detects element.innerHTML assignment and offers safe fix', async () => {
      const code = `element.innerHTML = 'Hello World';`;
      const context = createMockContext(code);
      const findings = await dangerousHtmlRule.check(context);
      expect(findings.length).toBe(1);

      const fix = dangerousHtmlRule.getFix?.({ id: '1', filePath: 'test.js' } as any, code);
      expect(fix).not.toBeNull();
      expect(fix?.proposedContent).toContain('element.textContent =');
    });

    it('does NOT flag standard JSX children', async () => {
      const code = `
        export function SafeComponent({ text }) {
          return <div>{text}</div>;
        }
      `;
      const context = createMockContext(code, 'src/SafeComponent.tsx');
      const findings = await dangerousHtmlRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-SEC-008: NoSQL Injection', () => {
    it('detects MongoDB $where clause in query', async () => {
      const code = `
        const users = await User.find({ $where: "this.credits > 100" });
      `;
      const context = createMockContext(code);
      const findings = await nosqlInjectionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('$where');
    });

    it('detects direct req.body bound to findOne', async () => {
      const code = `
        app.post('/login', async (req, res) => {
          const user = await User.findOne(req.body);
        });
      `;
      const context = createMockContext(code);
      const findings = await nosqlInjectionRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Direct req.body');
    });

    it('does NOT flag validated queries with explicit properties', async () => {
      const code = `
        const user = await User.findOne({ email: req.body.email, status: 'active' });
      `;
      const context = createMockContext(code);
      const findings = await nosqlInjectionRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-SEC-009: Insecure Cookie', () => {
    it('detects cookies issued without security flags and provides fix', async () => {
      const code = `res.cookie('session_id', token);`;
      const context = createMockContext(code);
      const findings = await insecureCookieRule.check(context);
      expect(findings.length).toBe(1);

      const fix = insecureCookieRule.getFix?.({ id: '1', filePath: 'auth.js' } as any, code);
      expect(fix).not.toBeNull();
      expect(fix?.proposedContent).toContain('httpOnly: true, secure: true');
    });

    it('does NOT flag cookies with httpOnly: true and secure: true', async () => {
      const code = `res.cookie('session_id', token, { httpOnly: true, secure: true, sameSite: 'strict' });`;
      const context = createMockContext(code);
      const findings = await insecureCookieRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-SEC-010: Permissive CORS', () => {
    it('detects wildcard origin in CORS', async () => {
      const code = `app.use(cors({ origin: '*' }));`;
      const context = createMockContext(code);
      const findings = await permissiveCorsRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Wildcard CORS');
    });

    it('detects wildcard origin with credentials enabled', async () => {
      const code = `app.use(cors({ origin: '*', credentials: true }));`;
      const context = createMockContext(code);
      const findings = await permissiveCorsRule.check(context);
      expect(findings.some((f) => f.title.includes('Credentials'))).toBe(true);
    });

    it('does NOT flag explicit origin allowlists', async () => {
      const code = `app.use(cors({ origin: 'https://example.com' }));`;
      const context = createMockContext(code);
      const findings = await permissiveCorsRule.check(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('SK-SEC-011: Missing Auth Guard (Manual Review Flagging)', () => {
    it('flags sensitive admin routes without inline middleware as potential risk', async () => {
      const code = `app.post('/api/admin/users', (req, res) => { res.send('ok'); });`;
      const context = createMockContext(code);
      const findings = await missingAuthGuardRule.check(context);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain('Potential Risk - Manual Review Required');
    });

    it('does not flag normal non-sensitive public endpoints', async () => {
      const code = `app.post('/api/contact-us', (req, res) => { res.send('ok'); });`;
      const context = createMockContext(code);
      const findings = await missingAuthGuardRule.check(context);
      expect(findings.length).toBe(0);
    });
  });
});
