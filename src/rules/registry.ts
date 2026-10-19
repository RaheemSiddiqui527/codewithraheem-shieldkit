import { Rule } from '../types/index.js';
import { hardcodedCredentialsRule } from './secrets/hardcoded-credentials.js';
import { privateKeyExposureRule } from './secrets/private-key-exposure.js';
import { sqlInjectionRule } from './security/sql-injection.js';
import { commandInjectionRule } from './security/command-injection.js';
import { dynamicCodeExecutionRule } from './security/dynamic-code-execution.js';
import { pathTraversalRule } from './security/path-traversal.js';
import { dangerousHtmlRule } from './security/dangerous-html.js';
import { nosqlInjectionRule } from './security/nosql-injection.js';
import { insecureCookieRule } from './security/insecure-cookie.js';
import { permissiveCorsRule } from './security/permissive-cors.js';
import { missingAuthGuardRule } from './security/missing-auth-guard.js';
import { trackedEnvFileRule } from './security/tracked-env-file.js';
import { emptyCatchBlockRule } from './quality/empty-catch-block.js';
import { unhandledPromiseRule } from './quality/unhandled-promise.js';
import { unsafeTypeAssertionRule } from './quality/unsafe-type-assertion.js';
import { debugStatementsRule } from './quality/debug-statements.js';
import { malformedScriptsRule } from './quality/malformed-scripts.js';

export const BUILTIN_RULES: Rule[] = [
  hardcodedCredentialsRule,
  privateKeyExposureRule,
  sqlInjectionRule,
  commandInjectionRule,
  dynamicCodeExecutionRule,
  pathTraversalRule,
  dangerousHtmlRule,
  nosqlInjectionRule,
  insecureCookieRule,
  permissiveCorsRule,
  missingAuthGuardRule,
  trackedEnvFileRule,
  emptyCatchBlockRule,
  unhandledPromiseRule,
  unsafeTypeAssertionRule,
  debugStatementsRule,
  malformedScriptsRule,
];

export function createDefaultRuleRegistry(): Rule[] {
  return [...BUILTIN_RULES];
}
