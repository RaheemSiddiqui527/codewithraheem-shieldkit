import { Language, RuleCategory, Severity } from './rule.js';
import { Finding } from './finding.js';
import { DetectedProject } from './project.js';

export interface ScanFile {
  absolutePath: string;
  relativePath: string;
  content: string;
  size: number;
  extension: string;
  language: Language;
}

export interface RuleContext {
  file: ScanFile;
  project: DetectedProject;
  ast?: any;
  lines: string[];
}

export interface ScanOptions {
  targetPath: string;
  category?: RuleCategory;
  securityOnly?: boolean;
  qualityOnly?: boolean;
  format?: 'terminal' | 'json' | 'markdown';
  outputPath?: string;
  suggestFixes?: boolean;
  showDiff?: boolean;
  fix?: boolean;
  listRules?: boolean;
  verbose?: boolean;
  noColor?: boolean;
  severityThreshold?: Severity;
  configPath?: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  fixable: number;
}

export interface ScanResult {
  toolName: string;
  version: string;
  timestamp: string;
  project: DetectedProject;
  scannedFilesCount: number;
  skippedFilesCount: number;
  durationMs: number;
  checksPerformed: string[];
  checksSkipped: string[];
  summary: ScanSummary;
  findings: Finding[];
}
