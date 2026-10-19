# Contributing to ShieldKit

Thank you for your interest in contributing to ShieldKit (`@codewithraheem/shieldkit`)!

ShieldKit is built to provide developers with dependable, privacy-preserving static security and code-quality analysis. We welcome contributions that improve rule accuracy, reduce false positives, expand language support, or optimize performance.

---

## Development Setup

### Prerequisites

- **Node.js**: >= 18.0.0 LTS
- **npm**: >= 9.0.0
- **Git**

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/codewithraheem/shieldkit.git
cd shieldkit
npm install
```

---

## Development Scripts

| Command | Purpose |
| :--- | :--- |
| `npm run typecheck` | Validates TypeScript in strict mode without emitting files. |
| `npm run lint` | Runs ESLint flat config across `src` and `tests`. |
| `npm run format` | Checks code formatting with Prettier. |
| `npm run test` | Runs the test suite via Vitest. |
| `npm run build` | Builds ESM, CJS, CLI binary, and type declarations via `tsup`. |
| `npm run prepack` | Prepares the package for distribution. |

---

## Contribution Guidelines

1. **Deterministic Analysis**:
   - Analyzers must produce identical results regardless of execution order or OS platform.
   - Do not make external network calls during scanning.

2. **Negative Test Cases are Mandatory**:
   - When adding or modifying a rule, you must provide both **positive test cases** (vulnerable code that is detected) and **negative test cases** (legitimate/idiomatic code that is NOT detected).

3. **Safe Redaction**:
   - Any rule dealing with credentials, tokens, or sensitive inputs must sanitize its evidence before generating finding objects.
   - Never store or print raw credentials.

4. **Low-Risk Automated Fixes**:
   - Fix providers should only be implemented for safe, deterministic corrections.
   - High-impact architectural changes (e.g., authentication rewrites, database migrations) must remain guidance-only.

---

## Submitting Pull Requests

1. Fork the repository and create a feature branch (`git checkout -b feature/my-new-rule`).
2. Implement your changes following existing architectural patterns.
3. Verify that all checks pass:
   ```bash
   npm run typecheck
   npm run lint
   npm run test
   npm run build
   ```
4. Commit your changes with clear, descriptive commit messages.
5. Push to your branch and open a Pull Request.
