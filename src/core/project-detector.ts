import fs from 'node:fs';
import path from 'node:path';
import { DetectedProject, Framework, Language } from '../types/index.js';

/**
 * Detects languages, frameworks, manifests, and package metadata
 * based on evidence in package.json, lockfiles, and configuration files.
 */
export function detectProject(rootPath: string): DetectedProject {
  const frameworks = new Set<Framework>();
  const languages = new Set<Language>(['generic']);

  const dependencies: Record<string, string> = {};
  const devDependencies: Record<string, string> = {};
  const scripts: Record<string, string> = {};
  const manifestFiles: string[] = [];

  let hasPackageJson = false;
  let packageName: string | undefined;
  let packageVersion: string | undefined;

  const pkgJsonPath = path.join(rootPath, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    hasPackageJson = true;
    manifestFiles.push('package.json');
    try {
      const raw = fs.readFileSync(pkgJsonPath, 'utf-8');
      const parsed = JSON.parse(raw);
      packageName = parsed.name;
      packageVersion = parsed.version;

      if (parsed.dependencies && typeof parsed.dependencies === 'object') {
        Object.assign(dependencies, parsed.dependencies);
      }
      if (parsed.devDependencies && typeof parsed.devDependencies === 'object') {
        Object.assign(devDependencies, parsed.devDependencies);
      }
      if (parsed.scripts && typeof parsed.scripts === 'object') {
        Object.assign(scripts, parsed.scripts);
      }

      frameworks.add('node');
      languages.add('javascript');
    } catch {
      // Malformed package.json handled gracefully
      frameworks.add('node');
    }
  }

  // Check for lockfiles
  for (const lockfile of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb']) {
    if (fs.existsSync(path.join(rootPath, lockfile))) {
      manifestFiles.push(lockfile);
    }
  }

  // Check dependencies for frameworks
  const allDeps = { ...dependencies, ...devDependencies };

  if (allDeps['express'] || allDeps['koa'] || allDeps['fastify']) {
    frameworks.add('express');
  }

  if (allDeps['react'] || allDeps['react-dom']) {
    frameworks.add('react');
  }

  if (allDeps['next']) {
    frameworks.add('next');
    frameworks.add('react');
    frameworks.add('node');
  }

  if (allDeps['vite']) {
    frameworks.add('vite');
  }

  if (allDeps['react-native'] || allDeps['expo']) {
    frameworks.add('react-native');
    if (allDeps['expo']) {
      frameworks.add('expo');
    }
  }

  if (allDeps['mongoose'] || allDeps['mongodb']) {
    frameworks.add('mongoose');
  }

  // Check configuration files as evidence
  if (fs.existsSync(path.join(rootPath, 'tsconfig.json'))) {
    languages.add('typescript');
  }
  if (
    fs.existsSync(path.join(rootPath, 'next.config.js')) ||
    fs.existsSync(path.join(rootPath, 'next.config.mjs')) ||
    fs.existsSync(path.join(rootPath, 'next.config.ts'))
  ) {
    frameworks.add('next');
  }
  if (
    fs.existsSync(path.join(rootPath, 'vite.config.js')) ||
    fs.existsSync(path.join(rootPath, 'vite.config.ts'))
  ) {
    frameworks.add('vite');
  }

  // Check for environment templates or yaml
  if (
    fs.existsSync(path.join(rootPath, '.env')) ||
    fs.existsSync(path.join(rootPath, '.env.example'))
  ) {
    languages.add('env');
  }

  return {
    rootPath,
    languages: Array.from(languages),
    frameworks: Array.from(frameworks),
    hasPackageJson,
    packageName,
    packageVersion,
    dependencies,
    devDependencies,
    scripts,
    manifestFiles,
  };
}
