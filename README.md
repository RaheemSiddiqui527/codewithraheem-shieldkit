# ShieldKit (`@codewithraheem/shieldkit`)

> **Build with AI. Ship with Confidence.**  
> Privacy-first, local-only static security and code-quality analysis toolkit for modern JavaScript and TypeScript stacks.

ShieldKit is an open-source static analysis engine developed by **CodeWithRaheem**. It helps developers identify potential security vulnerabilities, unsafe configurations, coding mistakes, and maintainability issues in both AI-generated and traditionally written software.

ShieldKit runs entirely on your local machine:
- **Zero network requests** by default.
- **Zero telemetry** or usage tracking.
- **No file uploads** to external servers.
- **Safe secret redaction** before any finding or report is generated.
- **Interactive, verified patch proposals** with unified diff previews.
- **Read-only by default**: never mutates files without explicit consent and never executes project scripts.

---

## Table of Contents

- [Supported Environments](#supported-environments)
- [Quick Start](#quick-start)
- [CLI Command Reference](#cli-command-reference)
- [Supported Languages & Frameworks](#supported-languages--frameworks)
- [Rule Registry & Categories](#rule-registry--categories)
- [Severity Model & Exit Codes](#severity-model--exit-codes)
- [Configuration & Rule Suppression](#configuration--rule-suppression)
- [Safe Remediation Workflow](#safe-remediation-workflow)
- [Reporters (Terminal, JSON, Markdown)](#reporters-terminal-json-markdown)
- [Threat Model & Privacy Guarantees](#threat-model--privacy-guarantees)
- [Limitations & Non-Goals](#limitations--non-goals)
- [Contributing](#contributing)
- [License](#license)

---

## Supported Environments

- **Node.js**: `^18.0.0`, `^20.0.0`, or `^22.0.0` (LTS versions recommended).
- **Operating Systems**: Linux, macOS, and Windows.
- **Package Formats**: Native ESM (`import`) with CommonJS compatibility declarations.

---

## Quick Start

### Using `npx` (No Install)

Scan the current directory:

```bash
npx @codewithraheem/shieldkit .
```

Scan a specific project path:

```bash
npx @codewithraheem/shieldkit ./path/to/my-project
```

### Global Installation

```bash
npm install -g @codewithraheem/shieldkit
shieldkit .
```

### Local Dev Dependency

```bash
npm install -D @codewithraheem/shieldkit
```

Add to your `package.json` scripts:

```json
{
  "scripts": {
    "shieldkit": "shieldkit ."
  }
}
```

---

## CLI Command Reference

```text
Usage: shieldkit [options] [path]

Arguments:
  path                    Target project directory (default: ".")

Options:
  --version               Output current ShieldKit version
  -s, --security          Run only security and secret rules
  -q, --quality           Run only code-quality rules
  -f, --format <type>     Output format: terminal, json, markdown (default: "terminal")
  -o, --output <file>     Write report output to a file
  --suggest-fixes         List available automated fix proposals without modifying files
  --diff                  Display unified diffs for available fixes without modifying files
  --fix                   Interactively review and apply safe automated patches
  --rules                 List all registered rules and exit
  -c, --config <file>     Path to custom ShieldKit configuration file
  --severity <threshold>  Failure threshold: critical, high, medium, low, informational (default: "high")
  -v, --verbose           Show detailed evidence and documentation references
  --no-color              Disable ANSI colors in terminal output
  -h, --help              Display help information
```

### Common Usage Examples

1. **Standard Security Scan**:
   ```bash
   shieldkit . --security
   ```

2. **Generate Machine-Readable JSON Report**:
   ```bash
   shieldkit . --format json --output report.json
   ```

3. **Generate GitHub-Flavored Markdown Report**:
   ```bash
   shieldkit . --format markdown --output audit-report.md
   ```

4. **Preview Automated Fix Diffs Before Applying**:
   ```bash
   shieldkit . --diff
   ```

5. **Interactively Apply Verified Patches**:
   ```bash
   shieldkit . --fix
   ```

6. **Inspect All Active Rules**:
   ```bash
   shieldkit --rules
   ```

---

## Supported Languages & Frameworks

ShieldKit analyzes project structure, manifests (`package.json`, lockfiles), and configuration files (`tsconfig.json`, `next.config.js`, `vite.config.ts`) to determine which rules are applicable:

| Technology | Detection Evidence | Supported Analyzers |
| :--- | :--- | :--- |
| **Node.js** | `package.json`, `.js`, `.cjs`, `.mjs` | Injection, Command Execution, File Safety, Scripts |
| **TypeScript** | `tsconfig.json`, `.ts`, `.tsx`, `.cts`, `.mts` | AST Analysis, Type Assertion (`as any`), Promises |
| **Express** | `express` dependency | Route Security, Auth Guards, CORS, Cookie Security |
| **React / JSX** | `react`, `react-dom`, `.jsx`, `.tsx` | XSS Prevention, `dangerouslySetInnerHTML` |
| **Vite** | `vite.config.js`, `vite` dependency | Configuration, Script Validation |
| **Next.js** | `next.config.js`, `next` dependency | API Routes, Security Headers, Client XSS |
| **MongoDB / Mongoose** | `mongoose`, `mongodb` dependencies | NoSQL Injection, Query Operators (`$where`, `$regex`) |
| **Configuration** | `.env`, `.env.*`, `shieldkit.config.*` | Leaked Env Files, Gitignore Enforcement |

> **Note**: For languages such as Python, PHP, and Go, ShieldKit provides an extensible Language Adapter interface. Analyzers for those languages will be introduced in subsequent releases. When non-JS/TS projects are scanned, ShieldKit runs generic configuration checks and notes that language-specific analyzers were skipped.

---

## Rule Registry & Categories

ShieldKit includes a curated suite of deterministic, low-false-positive static analysis rules:

### Security & Secrets

| Rule ID | Name | Default Severity | Confidence | Safe Fix Available |
| :--- | :--- | :--- | :--- | :--- |
| `SK-SEC-001` | Hardcoded Secret or Credential | Critical | High | No (manual rotation required) |
| `SK-SEC-002` | Committed Private Key Material | Critical | High | No (manual rotation required) |
| `SK-SEC-003` | Potential SQL Injection | High | High | No |
| `SK-SEC-004` | Potential Command Injection | Critical | High | No |
| `SK-SEC-005` | Dynamic Code Execution (`eval`/`Function`) | Critical | High | **Yes** (JSON.parse conversion) |
| `SK-SEC-006` | Potential Path Traversal | High | Medium | No |
| `SK-SEC-007` | Dangerous HTML Injection (XSS) | High | High | **Yes** (`.textContent` conversion) |
| `SK-SEC-008` | Potential NoSQL Injection | High | Medium | No |
| `SK-SEC-009` | Insecure Cookie Configuration | Medium | High | **Yes** (add security flags) |
| `SK-SEC-010` | Permissive CORS Configuration | Medium | High | No |
| `SK-SEC-011` | Potential Missing Route Auth Guard | Low | Low (Review) | No |
| `SK-SEC-012` | Unprotected Environment File (`.env`) | High | High | **Yes** (add to `.gitignore`) |

### Code Quality & Maintainability

| Rule ID | Name | Default Severity | Confidence | Safe Fix Available |
| :--- | :--- | :--- | :--- | :--- |
| `SK-QUAL-001` | Empty Catch Block (Swallowed Error) | Medium | High | **Yes** (add error logging) |
| `SK-QUAL-002` | Async Promise Executor Antipattern | Medium | High | No |
| `SK-QUAL-003` | Unsafe Type Assertion (`as any`) | Low | High | No |
| `SK-QUAL-004` | Leftover `debugger;` Statement | Low | High | **Yes** (clean statement removal) |
| `SK-QUAL-005` | Missing/Placeholder Project Scripts | Low | High | No |

---

## Severity Model & Exit Codes

### Severity Levels

1. **Critical**: Direct risk of remote code execution, database compromise, or credential leakage (e.g. `eval()`, exposed private keys, command injection).
2. **High**: Strong potential for exploitation or data leakage (e.g. SQL injection, path traversal, XSS, exposed `.env` files).
3. **Medium**: Insecure configurations or unhandled exception patterns (e.g. missing cookie flags, permissive CORS, empty catch blocks).
4. **Low**: Maintainability, defensive programming, or minor quality issues (e.g. `debugger;` statements, `as any` casts).
5. **Informational**: Observational guidance and framework telemetry notes.

### Exit Codes

- **`0`**: Scan completed successfully without findings meeting or exceeding the configured failure threshold.
- **`1`**: Scan completed with findings meeting or exceeding the configured failure threshold (default: `--severity high`).
- **`2`**: Operational failure (invalid arguments, missing target path, or unreadable configuration).

---

## Configuration & Rule Suppression

You can customize scanner behavior by creating a `shieldkit.config.json` (or `.shieldkitrc.json` / `shieldkit.config.yaml`) in your project root:

```json
{
  "severityThreshold": "high",
  "ignorePaths": [
    "dist/**",
    "coverage/**",
    "tests/**"
  ],
  "ignoreRules": {
    "SK-SEC-003": "Raw query is restricted to sanitized integer IDs verified by internal review.",
    "SK-SEC-011": "Route is mounted behind corporate authentication API gateway."
  },
  "maxFileSize": 1048576,
  "maxFiles": 5000,
  "rules": {
    "SK-QUAL-003": {
      "enabled": true,
      "severity": "informational"
    }
  }
}
```

> **Mandatory Suppression Justification**: ShieldKit enforces that any rule suppression in `ignoreRules` must provide a non-empty explanation string explaining *why* the rule was suppressed. Unjustified suppressions are rejected at config load time.

---

## Safe Remediation Workflow

Automated fixes in ShieldKit are strictly governed by our **Safe Patch Engine**:

1. **Deterministic Fixes Only**: ShieldKit only offers automated patches for low-risk, deterministic changes (e.g., adding `httpOnly: true, secure: true` to cookie options, replacing empty catch blocks with logging, removing `debugger;`, or updating `.gitignore`).
2. **Cryptographic Content Hashing**: Before applying a patch, ShieldKit checks the SHA-256 hash of the target file on disk against the hash at the time of patch generation. If the file was modified in an editor during review, the patch is aborted to avoid race conditions.
3. **Atomic Writes**: Fixes are written to temporary files and atomically renamed.
4. **Interactive Consent**: `--fix` always displays the unified diff and prompts for explicit `(y/N)` confirmation. In non-interactive pipelines (e.g. CI environments where `stdin` is not a TTY), `--fix` is automatically rejected to prevent accidental alterations.

```bash
# Preview diffs without writing anything
shieldkit . --diff

# Apply interactively
shieldkit . --fix
```

---

## Reporters (Terminal, JSON, Markdown)

### Terminal Reporter (Default)
Displays colorful, readable badges, code snippets with redacted evidence, and an executive summary table. Supports `--no-color` and respects `NO_COLOR` environment variables.

### JSON Reporter (`--format json`)
Outputs a strict, machine-readable JSON object conforming to `schemaVersion: "1.0.0"`. Designed for CI pipelines, GitHub Actions integration, and security dashboards.

### Markdown Reporter (`--format markdown`)
Produces clean, GitHub Flavored Markdown suitable for commit comments, pull request summaries, or documentation archives.

---

## Threat Model & Privacy Guarantees

ShieldKit is designed with a defensive local security model:

1. **Offline & Private**: ShieldKit makes zero network requests during normal scans. Your source code never leaves your local file system.
2. **Redaction Pipeline**: Evidence strings are passed through a multi-stage regex and entropy sanitizer. Secrets (AWS keys, GitHub tokens, OpenAI keys, Anthropic keys, Slack tokens, private keys) are masked before finding objects are created.
3. **Boundary Enforcement**: Paths are canonicalized via `realpath`. Directory traversal attempts (e.g., symlink loops or `../../` outside the root) are caught and rejected.
4. **No Code Execution**: ShieldKit never runs your project's `npm test`, `npm run build`, or arbitrary configuration scripts.

---

## Limitations & Non-Goals

- **Static Analysis Approximation**: Static analysis identifies pattern-based risk indicators; it does not simulate runtime dynamic exploits (DAST) or prove exploitability.
- **Dynamic Typing in JavaScript**: Certain dynamic data-flow paths cannot be completely resolved without runtime execution.
- **Manual Review**: High-impact security decisions (such as full authentication refactoring or database schema redesign) should always be verified by security professionals.

---

## Contributing

Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for instructions on local development, testing, and submitting pull requests.

---

## License

MIT © [CodeWithRaheem](https://github.com/codewithraheem)
#   c o d e w i t h r a h e e m - s h i e l d k i t  
 