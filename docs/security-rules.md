# ShieldKit Security & Code-Quality Rules Catalog

This document details each rule in the ShieldKit registry, explaining the underlying vulnerability, detection mechanics, severity classification, and safe remediation guidance.

---

## Secret & Credential Rules

### `SK-SEC-001`: Hardcoded Secret or Credential
- **Category:** `secrets`
- **Severity:** `critical` | **Confidence:** `high`
- **Languages:** JavaScript, TypeScript, JSON, YAML, Env
- **Description:** Detects hardcoded API keys, tokens, passwords, and sensitive credentials in source code.
- **Risk:** Credentials committed to version control can be discovered by unauthorized contributors or scraped from public registries and build artifacts.
- **Remediation:** Remove the hardcoded string immediately. Load secrets from environment variables (e.g., `process.env.API_KEY`) or dedicated secret managers (e.g. AWS Secrets Manager, HashiCorp Vault).

### `SK-SEC-002`: Committed Private Key Material
- **Category:** `secrets`
- **Severity:** `critical` | **Confidence:** `high`
- **Languages:** All
- **Description:** Detects unencrypted private cryptographic keys (RSA, OpenSSH, EC, PGP).
- **Risk:** Compromised private keys allow attackers to decrypt confidential traffic or forge digital signatures and authentication tokens.
- **Remediation:** Revoke the exposed key immediately and regenerate new keys. Store private keys in secure key management services or hardware security modules (HSMs).

---

## Injection & Unsafe Execution Rules

### `SK-SEC-003`: Potential SQL Injection
- **Category:** `security`
- **Severity:** `high` | **Confidence:** `high`
- **Languages:** JavaScript, TypeScript
- **Description:** Detects dynamic SQL queries constructed via string concatenation or template literal interpolation.
- **Risk:** Dynamic SQL allows attackers to modify query structure, bypass authentication, and read, modify, or drop database records.
- **Remediation:** Use parameterized queries or prepared statements:
  ```javascript
  // Unsafe
  db.query(`SELECT * FROM users WHERE id = ${userId}`);

  // Safe
  db.query('SELECT * FROM users WHERE id = $1', [userId]);
  ```

### `SK-SEC-004`: Potential Command Injection
- **Category:** `security`
- **Severity:** `critical` | **Confidence:** `high`
- **Languages:** JavaScript, TypeScript
- **Description:** Detects shell command execution with dynamic user input or unsanitized string construction.
- **Risk:** Passing unvalidated inputs to `child_process.exec` or `execSync` allows attackers to append shell metacharacters (`&&`, `|`, `;`) and execute arbitrary OS commands.
- **Remediation:** Use `child_process.execFile` or `child_process.spawn` with an array of arguments and `{ shell: false }`.

### `SK-SEC-005`: Dynamic Code Execution (`eval`/`Function`)
- **Category:** `security`
- **Severity:** `critical` | **Confidence:** `high`
- **Languages:** JavaScript, TypeScript
- **Description:** Detects use of `eval()`, `new Function()`, or `vm` modules with dynamic strings.
- **Automated Fix:** Yes, for eval-based JSON parsing patterns.
- **Remediation:** Replace dynamic code execution with structured parsers like `JSON.parse()`.

### `SK-SEC-006`: Potential Path Traversal
- **Category:** `security`
- **Severity:** `high` | **Confidence:** `medium`
- **Languages:** JavaScript, TypeScript
- **Description:** Detects unsanitized request parameters or variables passed directly to filesystem access methods (`fs.readFile`, `res.sendFile`).
- **Risk:** Attackers can pass `../` sequences to read arbitrary files (e.g. `/etc/passwd` or configuration secrets).
- **Remediation:** Use `path.resolve` and verify that the target path starts with the intended directory.

### `SK-SEC-007`: Dangerous HTML Injection (XSS)
- **Category:** `security`
- **Severity:** `high` | **Confidence:** `high`
- **Languages:** JavaScript, TypeScript, React, JSX, TSX
- **Description:** Detects `dangerouslySetInnerHTML` in React or `.innerHTML` assignments.
- **Automated Fix:** Yes, replaces `.innerHTML` with `.textContent`.
- **Remediation:** Render data via JSX children or sanitize HTML strings using DOMPurify before insertion.

### `SK-SEC-008`: Potential NoSQL Injection
- **Category:** `security`
- **Severity:** `high` | **Confidence:** `medium`
- **Languages:** JavaScript, TypeScript, Mongoose
- **Description:** Detects MongoDB `$where` clauses or unvalidated `req.body` passed directly to query methods (`User.findOne(req.body)`).
- **Remediation:** Validate query parameters against strict schemas (e.g., Zod) and avoid using `$where`.

---

## Configuration & Route Security Rules

### `SK-SEC-009`: Insecure Cookie Configuration
- **Category:** `security`
- **Severity:** `medium` | **Confidence:** `high`
- **Automated Fix:** Yes, appends `{ httpOnly: true, secure: true, sameSite: 'strict' }`.
- **Description:** Detects cookies set without `httpOnly: true`, `secure: true`, or safe `sameSite` attributes.

### `SK-SEC-010`: Permissive CORS Configuration
- **Category:** `configuration`
- **Severity:** `medium` | **Confidence:** `high`
- **Description:** Detects wildcard CORS (`origin: '*'`) or wildcard origin with credentials enabled.
- **Remediation:** Restrict allowed origins to an explicit list of authorized domains.

### `SK-SEC-011`: Potential Missing Route Auth Guard
- **Category:** `security`
- **Severity:** `low` | **Confidence:** `low` (Manual Review)
- **Description:** Flags sensitive administrative or mutation routes that lack inline authentication middleware.
- **Remediation:** Confirm that parent routers or API gateways enforce authentication.

### `SK-SEC-012`: Unprotected Environment File (`.env`)
- **Category:** `configuration`
- **Severity:** `high` | **Confidence:** `high`
- **Automated Fix:** Yes, appends `.env` patterns to `.gitignore`.
- **Description:** Detects `.env` files in the repository that are not ignored in `.gitignore`.

---

## Code Quality Rules

### `SK-QUAL-001`: Empty Catch Block (Swallowed Error)
- **Category:** `quality`
- **Severity:** `medium` | **Confidence:** `high`
- **Automated Fix:** Yes, adds `console.error(err);` logging.
- **Description:** Detects empty catch blocks that swallow exceptions without handling or logging.

### `SK-QUAL-002`: Async Promise Executor Antipattern
- **Category:** `quality`
- **Severity:** `medium` | **Confidence:** `high`
- **Description:** Detects `new Promise(async (resolve, reject) => { ... })` which causes unhandled rejections if an error throws.

### `SK-QUAL-003`: Unsafe Type Assertion (`as any`)
- **Category:** `quality`
- **Severity:** `low` | **Confidence:** `high`
- **Description:** Detects TypeScript `as any` type assertions that bypass compiler type safety.

### `SK-QUAL-004`: Leftover `debugger;` Statement
- **Category:** `quality`
- **Severity:** `low` | **Confidence:** `high`
- **Automated Fix:** Yes, cleanly removes the `debugger;` statement.
- **Description:** Detects leftover debugger breakpoints and suspicious logging of passwords or tokens.

### `SK-QUAL-005`: Missing or Placeholder Project Scripts
- **Category:** `quality`
- **Severity:** `low` | **Confidence:** `high`
- **Description:** Detects missing or placeholder `test` scripts in `package.json`.
