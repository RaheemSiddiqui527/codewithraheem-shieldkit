# Changelog

All notable changes to `@codewithraheem/shieldkit` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-19

### Initial Release

#### Core & Architecture
- Local-only, privacy-preserving static analysis engine with zero network calls and zero telemetry.
- Strict resource bounds (max file size, max files, recursion depth, and timeout limits).
- Boundary enforcement preventing directory traversal, path escape, and symlink vulnerabilities.
- Cryptographic stable finding hash generator.
- Multi-format reporters: Terminal (interactive & no-color), JSON (schema v1.0.0), and Markdown.

#### Security & Secret Analyzers
- Secret detection and entropy heuristic scanner with safe multi-pattern redaction (`SK-SEC-001`, `SK-SEC-002`).
- Injection and execution analyzers (`SK-SEC-003` SQL injection, `SK-SEC-004` Command injection, `SK-SEC-005` `eval`/`Function`, `SK-SEC-006` Path traversal, `SK-SEC-007` Dangerous HTML/XSS, `SK-SEC-008` NoSQL injection).
- Insecure cookie flag analyzer (`SK-SEC-009`) with automated fix provider.
- Permissive CORS detection (`SK-SEC-010`).
- Sensitive route authentication guard reviewer (`SK-SEC-011`).
- Unprotected environment file tracker (`SK-SEC-012`) with `.gitignore` automated fix provider.

#### Code Quality Analyzers
- Swallowed exception / empty catch block detection (`SK-QUAL-001`) with automated logging fix provider.
- Async Promise executor antipattern detection (`SK-QUAL-002`).
- Unsafe TypeScript `as any` type assertion analyzer (`SK-QUAL-003`).
- Leftover `debugger;` statement and sensitive logging detector (`SK-QUAL-004`) with statement removal fix provider.
- Missing or placeholder project scripts analyzer (`SK-QUAL-005`).

#### Safe Remediation Engine
- Automated patch proposals with unified diff previews (`--suggest-fixes`, `--diff`).
- Interactive remediation workflow (`--fix`) requiring explicit user confirmation.
- Race condition and conflict detection via SHA-256 original content hashing.
- Atomic temporary-file replacement.

#### Tooling & CI
- TypeScript strict mode build with ESM and CJS bundle generation via `tsup`.
- Multi-OS, multi-Node GitHub Actions CI pipeline (Node.js 18, 20, 22 on Linux, macOS, and Windows).
- Vitest unit, integration, and security test suites with 100% passing tests.
