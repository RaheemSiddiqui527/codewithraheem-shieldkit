import fs from 'node:fs';
import path from 'node:path';
import { FixResult, PatchProposal } from '../types/index.js';
import { calculateContentHash } from './patch-builder.js';
import { isPathInside } from '../safety/path-validation.js';

export function applyPatch(projectRoot: string, patch: PatchProposal): FixResult {
  const targetFullPath = path.resolve(projectRoot, patch.targetFile);

  // 1. Boundary check: ensure target file is strictly inside the project root
  if (!isPathInside(projectRoot, targetFullPath)) {
    return {
      applied: false,
      targetFile: patch.targetFile,
      error: `Security boundary violation: target path ${patch.targetFile} is outside project root.`,
    };
  }

  // 2. Existence and file type check
  if (!fs.existsSync(targetFullPath)) {
    return {
      applied: false,
      targetFile: patch.targetFile,
      error: `Target file does not exist: ${patch.targetFile}`,
    };
  }

  const stat = fs.statSync(targetFullPath);
  if (!stat.isFile()) {
    return {
      applied: false,
      targetFile: patch.targetFile,
      error: `Target is not a regular file: ${patch.targetFile}`,
    };
  }

  // 3. Race condition check: verify file content hash matches the patch originalContentHash
  let currentContent: string;
  try {
    currentContent = fs.readFileSync(targetFullPath, 'utf-8');
  } catch (err: any) {
    return {
      applied: false,
      targetFile: patch.targetFile,
      error: `Failed to read target file: ${err?.message || err}`,
    };
  }

  const currentHash = calculateContentHash(currentContent);
  if (currentHash !== patch.originalContentHash) {
    return {
      applied: false,
      targetFile: patch.targetFile,
      error: `Conflict detected: file ${patch.targetFile} has changed on disk since patch generation. Patch rejected.`,
    };
  }

  // 4. Atomic write using temporary file in the same directory
  const tempPath = `${targetFullPath}.${Date.now()}.tmp`;
  try {
    fs.writeFileSync(tempPath, patch.proposedContent, { encoding: 'utf-8', mode: stat.mode });
    // Verify written temp file content before replacement
    const writtenContent = fs.readFileSync(tempPath, 'utf-8');
    if (writtenContent !== patch.proposedContent) {
      fs.unlinkSync(tempPath);
      return {
        applied: false,
        targetFile: patch.targetFile,
        error: 'Verification failure: temporary file content does not match proposed patch.',
      };
    }
    // Rename/replace atomically
    fs.renameSync(tempPath, targetFullPath);
    return {
      applied: true,
      targetFile: patch.targetFile,
    };
  } catch (err: any) {
    if (fs.existsSync(tempPath)) {
      try {
        fs.unlinkSync(tempPath);
      } catch (cleanupErr: unknown) {
        // cleanup error handled safely
        void cleanupErr;
      }
    }
    return {
      applied: false,
      targetFile: patch.targetFile,
      error: `Failed to write patch: ${err?.message || err}`,
    };
  }
}
