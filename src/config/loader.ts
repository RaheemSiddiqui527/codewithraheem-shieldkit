import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { ShieldKitConfig } from '../types/index.js';
import { validateConfig } from './schema.js';

export const CONFIG_FILE_NAMES = [
  'shieldkit.config.json',
  '.shieldkitrc.json',
  '.shieldkit.json',
  'shieldkit.config.yaml',
  'shieldkit.config.yml',
];

/**
 * Searches for and loads a configuration file safely without code execution.
 */
export function loadConfig(projectRoot: string, customConfigPath?: string): ShieldKitConfig {
  if (customConfigPath) {
    const resolvedCustom = path.resolve(projectRoot, customConfigPath);
    if (!fs.existsSync(resolvedCustom)) {
      throw new Error(`Specified configuration file does not exist: ${resolvedCustom}`);
    }
    return parseConfigFile(resolvedCustom);
  }

  for (const fileName of CONFIG_FILE_NAMES) {
    const candidate = path.join(projectRoot, fileName);
    if (fs.existsSync(candidate)) {
      return parseConfigFile(candidate);
    }
  }

  return {};
}

function parseConfigFile(filePath: string): ShieldKitConfig {
  const content = fs.readFileSync(filePath, 'utf-8');
  let parsed: unknown;

  if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
    try {
      parsed = YAML.parse(content);
    } catch (err: any) {
      throw new Error(`Failed to parse YAML config at ${filePath}: ${err?.message || err}`);
    }
  } else {
    try {
      parsed = JSON.parse(content);
    } catch (err: any) {
      throw new Error(`Failed to parse JSON config at ${filePath}: ${err?.message || err}`);
    }
  }

  return validateConfig(parsed);
}
