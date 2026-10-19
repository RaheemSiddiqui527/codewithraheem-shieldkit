import fs from 'node:fs';
import path from 'node:path';
import { Language, ScanFile } from '../types/index.js';
import {
  DEFAULT_IGNORED_DIRS,
  DEFAULT_IGNORED_EXTENSIONS,
  DEFAULT_LIMITS,
  ScanLimits,
} from '../safety/limits.js';
import { isPathInside, normalizePathSeparators } from '../safety/path-validation.js';

export interface DiscoverFilesOptions {
  projectRoot: string;
  ignorePaths?: string[];
  limits?: Partial<ScanLimits>;
}

export function detectFileLanguage(filePath: string): Language {
  const base = path.basename(filePath).toLowerCase();
  const ext = path.extname(filePath).toLowerCase();

  if (base.startsWith('.env')) {
    return 'env';
  }
  if (['.ts', '.tsx', '.mts', '.cts'].includes(ext)) {
    return 'typescript';
  }
  if (['.js', '.jsx', '.mjs', '.cjs'].includes(ext)) {
    return 'javascript';
  }
  if (['.json', '.jsonc'].includes(ext)) {
    return 'json';
  }
  if (['.yaml', '.yml'].includes(ext)) {
    return 'yaml';
  }

  return 'generic';
}

export function discoverFiles(options: DiscoverFilesOptions): {
  files: ScanFile[];
  skippedCount: number;
} {
  const { projectRoot, ignorePaths = [], limits = {} } = options;
  const maxFileSize = limits.maxFileSize ?? DEFAULT_LIMITS.maxFileSize;
  const maxFiles = limits.maxFiles ?? DEFAULT_LIMITS.maxFiles;
  const maxDepth = limits.maxDepth ?? DEFAULT_LIMITS.maxDepth;

  const userIgnoredPatterns = ignorePaths.map((p) => normalizePathSeparators(p.trim()));
  const files: ScanFile[] = [];
  let skippedCount = 0;

  function isIgnored(relativeNormalized: string, fileName: string): boolean {
    if (DEFAULT_IGNORED_DIRS.has(fileName)) return true;
    for (const pattern of userIgnoredPatterns) {
      if (!pattern) continue;
      if (
        relativeNormalized === pattern ||
        relativeNormalized.startsWith(pattern + '/') ||
        fileName === pattern
      ) {
        return true;
      }
    }
    return false;
  }

  function walk(currentDir: string, currentDepth: number) {
    if (files.length >= maxFiles || currentDepth > maxDepth) {
      return;
    }

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= maxFiles) break;

      const fullPath = path.join(currentDir, entry.name);

      // Verify the path is strictly inside the project root (symlink escape defense)
      if (!isPathInside(projectRoot, fullPath)) {
        skippedCount++;
        continue;
      }

      const relative = path.relative(projectRoot, fullPath);
      const relativeNormalized = normalizePathSeparators(relative);

      if (entry.isDirectory()) {
        if (isIgnored(relativeNormalized, entry.name)) {
          skippedCount++;
          continue;
        }
        walk(fullPath, currentDepth + 1);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (DEFAULT_IGNORED_EXTENSIONS.has(ext) || isIgnored(relativeNormalized, entry.name)) {
          skippedCount++;
          continue;
        }

        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > maxFileSize) {
            skippedCount++;
            continue;
          }

          const content = fs.readFileSync(fullPath, 'utf-8');
          files.push({
            absolutePath: fullPath,
            relativePath: relativeNormalized,
            content,
            size: stat.size,
            extension: ext,
            language: detectFileLanguage(fullPath),
          });
        } catch {
          skippedCount++;
        }
      }
    }
  }

  walk(projectRoot, 0);

  return { files, skippedCount };
}
