import fs from 'node:fs';
import path from 'node:path';

/**
 * Normalizes path separators to forward slashes for consistent relative paths across platforms.
 */
export function normalizePathSeparators(filePath: string): string {
  return filePath.replace(/\\/g, '/');
}

/**
 * Validates and resolves the project path.
 * Ensures the target exists, is a directory, and returns its canonical real path.
 */
export function validateProjectPath(targetPath: string): string {
  if (!targetPath || typeof targetPath !== 'string') {
    throw new Error('Project path must be a non-empty string.');
  }

  const resolved = path.resolve(process.cwd(), targetPath);

  if (!fs.existsSync(resolved)) {
    throw new Error(`Target path does not exist: ${resolved}`);
  }

  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) {
    throw new Error(`Target path is not a directory: ${resolved}`);
  }

  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

/**
 * Checks whether childPath is strictly inside (or equal to) parentPath.
 * Uses realpath to avoid symlink traversal out of the project root.
 */
export function isPathInside(parentPath: string, childPath: string): boolean {
  try {
    const realParent = fs.realpathSync(path.resolve(parentPath));
    const realChild = fs.realpathSync(path.resolve(childPath));

    const parentNorm = normalizePathSeparators(path.resolve(realParent)).toLowerCase();
    const childNorm = normalizePathSeparators(path.resolve(realChild)).toLowerCase();

    if (parentNorm === childNorm) {
      return true;
    }

    const relative = path.relative(realParent, realChild);
    return !relative.startsWith('..') && !path.isAbsolute(relative);
  } catch {
    // If either doesn't exist yet, fall back to resolved lexical check
    const resolvedParent = path.resolve(parentPath);
    const resolvedChild = path.resolve(childPath);
    const relative = path.relative(resolvedParent, resolvedChild);
    return !relative.startsWith('..') && !path.isAbsolute(relative);
  }
}

/**
 * Validates that an output path is safe to write to.
 * Prevents writing to root directories or dangerous system locations.
 */
export function validateSafeOutputPath(outputPath: string, projectRoot: string): string {
  const resolved = path.resolve(process.cwd(), outputPath);

  // Prevent overwriting the project directory itself as a file
  if (resolved === path.resolve(projectRoot)) {
    throw new Error(`Output path cannot be the project root directory: ${resolved}`);
  }

  // Ensure parent directory exists or can be created safely
  const parentDir = path.dirname(resolved);
  if (!fs.existsSync(parentDir)) {
    fs.mkdirSync(parentDir, { recursive: true });
  }

  return resolved;
}
