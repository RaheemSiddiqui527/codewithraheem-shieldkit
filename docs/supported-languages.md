# ShieldKit Supported Languages & Frameworks

This document outlines the current language and framework support in ShieldKit v0.1.0 and provides an overview of the Language Adapter architecture for future releases.

---

## 1. Supported in Version 0.1.0

### JavaScript & TypeScript Ecosystem

| Language / Dialect | Extensions | AST Parser | Analyzers |
| :--- | :--- | :--- | :--- |
| **JavaScript** | `.js`, `.cjs`, `.mjs` | `@babel/parser` | Security, Quality, Secrets, Config |
| **TypeScript** | `.ts`, `.cts`, `.mts` | `@babel/parser` | Security, Quality, Types, Secrets |
| **JSX** | `.jsx` | `@babel/parser` | React XSS, Dangerous HTML, Quality |
| **TSX** | `.tsx` | `@babel/parser` | React XSS, Dangerous HTML, Types |
| **JSON / JSONC** | `.json`, `.jsonc` | Safe JSON / AST | Manifests, Configs, Scripts |
| **YAML** | `.yaml`, `.yml` | YAML Safe Parser | CI, Configs, Docker-compose |
| **Environment Files** | `.env*` | Line-based regex | Secret leak, Gitignore check |

### Supported Frameworks

- **Node.js**: File system sinks, child processes, server configurations.
- **Express.js**: Routes, authentication middleware, CORS, cookie headers.
- **React**: JSX attributes, DOM properties, Cross-Site Scripting defenses.
- **Vite & Next.js**: Client/server configurations, route guards, environment configs.
- **MongoDB / Mongoose**: NoSQL query filters, operator injection, schema guards.

---

## 2. Planned Language Adapters (Future Roadmap)

ShieldKit defines a pluggable Language Adapter interface for multi-language expansion:

```typescript
export interface LanguageAdapter {
  id: string;
  name: string;
  fileExtensions: string[];
  manifestFiles: string[];
  parseAST?: (source: string) => Promise<unknown> | unknown;
  runChecks: (context: RuleContext) => Promise<RuleFindingInput[]>;
}
```

The following language adapters are planned for subsequent releases:
- **Python**: Django, Flask, FastAPI, raw SQL, subprocess injection.
- **PHP**: Laravel, WordPress, SQL injection, dynamic includes.
- **Go**: Gin, Echo, SQL injection, concurrency patterns.

> **Honest Scope Notice**: These future language adapters are NOT claimed as supported in ShieldKit v0.1.0. When scanning repositories in other languages, ShieldKit will run applicable generic checks and clearly declare language-specific analyzers as skipped in the scan summary.
