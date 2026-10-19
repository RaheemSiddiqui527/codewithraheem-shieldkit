import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
    },
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'node18',
    outDir: 'dist',
  },
  {
    entry: {
      cli: 'src/cli/index.ts',
    },
    format: ['esm'],
    banner: {
      js: '#!/usr/bin/env node',
    },
    sourcemap: true,
    target: 'node18',
    outDir: 'dist',
  },
]);
