# ShieldKit Threat Model & Security Posture

This document describes the defensive threat model, trust assumptions, boundary validations, and attack mitigations implemented in `@codewithraheem/shieldkit`.

---

## 1. Trust Boundaries & Assumptions

1. **Untrusted Target Repository**: ShieldKit assumes any repository scanned may be hostile, untrusted, or contain maliciously crafted source files, symlinks, or file names.
2. **Local Execution Environment**: The host developer workstation or CI runner is considered a trusted boundary that must be protected from hostile project contents.
3. **Zero Network Egress**: The scanner does not contact external endpoints by default. Source code, secrets, and AST representations never leave the host machine.

---

## 2. Threat Scenarios & Mitigations

### 2.1 Malicious Filesystem Traversal (Zip Slip / Symlink Escapes)
- **Threat**: A repository contains symlinks pointing to `/etc/passwd` or `C:\Windows\System32`, or directory names containing `../../` attempting to read or overwrite sensitive system files during scanning or patching.
- **Mitigation**: 
  - ShieldKit computes canonical paths using `fs.realpathSync`.
  - The `isPathInside(projectRoot, targetPath)` helper verifies that canonical paths stay strictly inside the project root before reading or applying patches.
  - Symlinks pointing outside the project boundary are rejected.

### 2.2 Terminal Escape Sequence Injection
- **Threat**: A hostile project contains filenames or code snippets embedded with ANSI terminal escape sequences (e.g. `\u001b]50;...` or cursor control codes) that manipulate the developer's terminal, hide output, or execute shell sequences in vulnerable terminal emulators.
- **Mitigation**:
  - The `sanitizeTerminalString` and `stripAnsi` pipeline strips all ANSI CSI/OSC escape sequences and non-printable control characters before rendering evidence or writing reports.

### 2.3 Secret Leakage via Terminal or Reports
- **Threat**: When ShieldKit detects a hardcoded password or private key, printing the raw secret in the terminal, JSON report, or CI logs exposes the credential to unauthorized viewers or log scrapers.
- **Mitigation**:
  - The multi-stage `redactSensitiveData` engine redacts tokens, AWS keys, GitHub PATs, OpenAI keys, Anthropic keys, Slack tokens, Stripe keys, and private keys *before* Findings are instantiated.
  - Raw secret strings are never stored in `Finding` objects.

### 2.4 Arbitrary Code Execution via Config Files
- **Threat**: Many developer tools evaluate JavaScript configuration files (e.g. `eval(require('config.js'))`). A hostile repository could place code in a config file that executes when the scanner initializes.
- **Mitigation**:
  - ShieldKit **never evaluates JavaScript configuration files**. It only parses pure JSON and YAML configs without executing code.

### 2.5 Denial of Service (ReDoS & Resource Exhaustion)
- **Threat**: Massive generated files, infinite symlink loops, or deeply nested directories freeze the developer machine or consume all available memory.
- **Mitigation**:
  - Hard resource limits enforced:
    - Max file size: 1 MB default (larger files are skipped with a warning).
    - Max file count: 5,000 files ceiling.
    - Max directory recursion depth: 25 levels.
    - Execution timeout: 60 seconds.

### 2.6 Race Conditions During Automated Patching
- **Threat**: A developer edits a file in an IDE while `--fix` is preparing to apply a patch, leading to accidental overwriting of newer user code.
- **Mitigation**:
  - The original file content is cryptographically hashed (SHA-256) at scan time.
  - Before writing, `verifier.ts` reads the current file from disk and verifies the SHA-256 hash. If it does not match, the patch is aborted and a conflict warning is issued.
  - Writes are atomic: content is written to a temporary file in the same directory and verified before replacement via atomic rename.
