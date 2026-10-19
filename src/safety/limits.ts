export interface ScanLimits {
  maxFileSize: number;
  maxFiles: number;
  maxDepth: number;
  timeoutMs: number;
}

export const DEFAULT_LIMITS: ScanLimits = {
  maxFileSize: 1024 * 1024, // 1 MB
  maxFiles: 5000,
  maxDepth: 25,
  timeoutMs: 60000, // 60 seconds
};

export const DEFAULT_IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.output',
  'coverage',
  '.nyc_output',
  '.vite',
  '.tsup',
  '.turbo',
  '.cache',
  'vendor',
  '.yarn',
  '.pnpm-store',
  '__pycache__',
  '.pytest_cache',
  'venv',
  '.venv',
]);

export const DEFAULT_IGNORED_EXTENSIONS = new Set([
  '.min.js',
  '.min.css',
  '.map',
  '.lock',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.ico',
  '.webp',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.mp4',
  '.mp3',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.exe',
  '.dll',
  '.so',
  '.dylib',
]);
