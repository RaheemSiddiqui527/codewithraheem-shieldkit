import { Severity } from './rule.js';

export interface ShieldKitConfig {
  ignorePaths?: string[];
  ignoreRules?: Record<string, string>; // ruleId -> justification
  severityThreshold?: Severity;
  maxFileSize?: number;
  maxFiles?: number;
  rules?: Record<string, { enabled?: boolean; severity?: Severity }>;
}
