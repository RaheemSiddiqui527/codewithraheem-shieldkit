import { Severity, ShieldKitConfig } from '../types/index.js';

export const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

export function validateConfig(raw: unknown): ShieldKitConfig {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('ShieldKit configuration must be a valid JSON object.');
  }

  const obj = raw as Record<string, unknown>;
  const config: ShieldKitConfig = {};

  if ('ignorePaths' in obj) {
    if (!Array.isArray(obj.ignorePaths) || !obj.ignorePaths.every((p) => typeof p === 'string')) {
      throw new Error('Config "ignorePaths" must be an array of string paths.');
    }
    config.ignorePaths = obj.ignorePaths as string[];
  }

  if ('ignoreRules' in obj) {
    if (
      typeof obj.ignoreRules !== 'object' ||
      obj.ignoreRules === null ||
      Array.isArray(obj.ignoreRules)
    ) {
      throw new Error(
        'Config "ignoreRules" must be a key-value object mapping rule IDs to justification strings.',
      );
    }
    for (const [ruleId, justification] of Object.entries(obj.ignoreRules)) {
      if (typeof justification !== 'string' || justification.trim().length === 0) {
        throw new Error(
          `Rule suppression for "${ruleId}" requires an explicit justification string.`,
        );
      }
    }
    config.ignoreRules = obj.ignoreRules as Record<string, string>;
  }

  if ('severityThreshold' in obj) {
    const sev = obj.severityThreshold as Severity;
    if (!VALID_SEVERITIES.includes(sev)) {
      throw new Error(
        `Invalid severityThreshold "${sev}". Expected one of: ${VALID_SEVERITIES.join(', ')}`,
      );
    }
    config.severityThreshold = sev;
  }

  if ('maxFileSize' in obj) {
    if (typeof obj.maxFileSize !== 'number' || obj.maxFileSize <= 0) {
      throw new Error('Config "maxFileSize" must be a positive number of bytes.');
    }
    config.maxFileSize = obj.maxFileSize;
  }

  if ('maxFiles' in obj) {
    if (typeof obj.maxFiles !== 'number' || obj.maxFiles <= 0) {
      throw new Error('Config "maxFiles" must be a positive integer.');
    }
    config.maxFiles = obj.maxFiles;
  }

  if ('rules' in obj) {
    if (typeof obj.rules !== 'object' || obj.rules === null || Array.isArray(obj.rules)) {
      throw new Error('Config "rules" must be an object.');
    }
    config.rules = obj.rules as Record<string, { enabled?: boolean; severity?: Severity }>;
  }

  return config;
}
