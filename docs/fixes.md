# ShieldKit Safe Remediation Engine & Fix Workflows

This document explains the design principles, safety checks, preview mechanics, and execution invariants of the ShieldKit Safe Remediation Engine.

---

## 1. Remediation Philosophy

ShieldKit believes that **automated code modification must be conservative, verifiable, and strictly under user control**.

- **No Silent Mutations**: A default scan is always read-only. ShieldKit will never modify files without explicit user activation (`--fix`).
- **Low-Risk Only**: Only deterministic, localized, low-risk patches have automated fix providers. High-impact operations (such as authentication rewrites, database schema changes, or credential rotations) are intentionally marked as *guidance-only*.
- **Race-Condition Defense**: Files on disk are cryptographically hashed at the time the patch proposal is generated. If an external editor touches the file before the patch is confirmed, the patch is rejected.
- **Atomic Operations**: Patches are written to temporary files and atomically moved into place only after validation passes.

---

## 2. Remediation Commands

### Step 1: List Suggested Fixes
```bash
shieldkit . --suggest-fixes
```
Displays all findings for which an automated fix proposal is available, along with a risk classification and brief explanation.

### Step 2: Preview Unified Diffs
```bash
shieldkit . --diff
```
Renders complete unified diffs (`--- a/file +++ b/file`) in color, showing exactly what additions and deletions would be made.

### Step 3: Interactive Application
```bash
shieldkit . --fix
```
Displays each diff sequentially and prompts the user:
```text
Apply this fix to src/auth/cookies.js? (y/N):
```
- Typing `y` or `yes` applies the patch.
- Typing `n` or pressing Enter skips the patch.
- In non-interactive pipelines (e.g. CI / Docker without a TTY), `--fix` exits with code 2 to prevent unauthorized modifications.

---

## 3. Currently Supported Automated Fixes

| Rule ID | Finding | Automated Patch Action | Risk Level |
| :--- | :--- | :--- | :--- |
| `SK-SEC-005` | `eval('(' + x + ')')` | Converts to safe `JSON.parse(x)` | Low |
| `SK-SEC-007` | `element.innerHTML = ...` | Converts to `element.textContent = ...` | Medium |
| `SK-SEC-009` | Insecure cookie flags | Appends `{ httpOnly: true, secure: true, sameSite: 'strict' }` | Low |
| `SK-SEC-012` | Unprotected `.env` file | Appends `.env` and `.env.*` patterns to `.gitignore` | Low |
| `SK-QUAL-001` | Empty catch block | Adds `console.error(err);` statement | Low |
| `SK-QUAL-004` | Leftover `debugger;` | Removes `debugger;` statement cleanly | Low |

---

## 4. Invariants & Guarantees

1. Target files must reside strictly inside the canonical project root (`isPathInside`).
2. Target files must be regular files (symlinks pointing outside the project are rejected).
3. The SHA-256 content hash on disk must match the hash computed during scan.
4. Temporary files are created in the same filesystem directory to guarantee atomic replacement via `fs.renameSync`.
