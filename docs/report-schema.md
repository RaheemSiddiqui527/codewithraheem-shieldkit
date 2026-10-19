# ShieldKit JSON Report Schema Reference (v1.0.0)

ShieldKit provides structured, machine-readable JSON reports via `--format json`. This document describes the schema structure, data types, and field meanings.

---

## Example JSON Output

```json
{
  "$schema": "https://raw.githubusercontent.com/codewithraheem/shieldkit/main/docs/report-schema.json",
  "schemaVersion": "1.0.0",
  "tool": {
    "name": "ShieldKit",
    "version": "0.1.0",
    "brand": "CodeWithRaheem",
    "tagline": "Build with AI. Ship with Confidence."
  },
  "scan": {
    "timestamp": "2026-10-19T10:00:00.000Z",
    "durationMs": 42,
    "targetPath": "/path/to/project",
    "scannedFilesCount": 15,
    "skippedFilesCount": 2,
    "checksPerformed": [
      "SK-SEC-003: Potential SQL Injection"
    ],
    "checksSkipped": []
  },
  "project": {
    "languages": ["typescript", "javascript"],
    "frameworks": ["express", "node"],
    "hasPackageJson": true,
    "packageName": "my-service",
    "packageVersion": "1.0.0",
    "manifestFiles": ["package.json", "package-lock.json"]
  },
  "summary": {
    "total": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "informational": 0,
    "fixable": 0
  },
  "findings": [
    {
      "id": "e6a41f98bc123456",
      "ruleId": "SK-SEC-003",
      "title": "SQL Injection via Template Literal",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "location": {
        "file": "src/db.ts",
        "startLine": 12,
        "endLine": 12,
        "startColumn": 5,
        "endColumn": 45
      },
      "sanitizedEvidence": "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
      "explanation": "Dynamic query interpolation allows query manipulation.",
      "remediation": "Use parameterized queries with placeholders.",
      "hasFix": false,
      "docUrl": "https://github.com/codewithraheem/shieldkit/blob/main/docs/security-rules.md#sk-sec-003"
    }
  ]
}
```

---

## Field Specifications

### `tool`
- `name` (string): Always `"ShieldKit"`.
- `version` (string): SemVer tool version (e.g., `"0.1.0"`).
- `brand` (string): Author and brand designation (`"CodeWithRaheem"`).

### `scan`
- `timestamp` (ISO-8601 string): Scan execution start time.
- `durationMs` (integer): Total scan runtime in milliseconds.
- `targetPath` (string): Canonical root path of the scanned target.
- `scannedFilesCount` (integer): Total files evaluated.
- `skippedFilesCount` (integer): Total files excluded due to size, extension, or ignore patterns.

### `summary`
Counters categorizing findings by severity (`critical`, `high`, `medium`, `low`, `informational`) and total fixable findings.

### `findings[]`
- `id` (string): Stable, deterministic 16-character SHA-256 hash.
- `ruleId` (string): Unique identifier of the triggered rule (`SK-SEC-001`, etc.).
- `location` (object):
  - `file` (string): Relative path within project root (forward slash normalized).
  - `startLine`, `endLine` (integer): 1-indexed line numbers.
  - `startColumn`, `endColumn` (integer): 1-indexed column numbers.
- `sanitizedEvidence` (string): Code snippet with secrets redacted and terminal escapes stripped.
- `patchProposal` (object, optional): Contains `unified diff`, `riskLevel`, and `validationRequirements`.
