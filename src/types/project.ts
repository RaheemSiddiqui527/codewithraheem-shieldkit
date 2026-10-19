import { Framework, Language } from './rule.js';

export interface DetectedProject {
  rootPath: string;
  languages: Language[];
  frameworks: Framework[];
  hasPackageJson: boolean;
  packageName?: string;
  packageVersion?: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  scripts: Record<string, string>;
  manifestFiles: string[];
}
