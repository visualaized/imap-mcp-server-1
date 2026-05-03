import * as esbuild from 'esbuild';
import { readFileSync } from 'fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf8'));

// Get all dependencies to mark as external
const external = [
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.devDependencies || {}),
];

// Build main entry point
await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  outfile: 'dist/index.js',
  external,
});

// Build setup entry point
await esbuild.build({
  entryPoints: ['src/setup.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  outfile: 'dist/setup.js',
  external,
});

// Build web server entry point
await esbuild.build({
  entryPoints: ['src/web/server.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  outfile: 'dist/web/server.js',
  external,
});

// Build HTTP/SSE MCP server for remote hosting
await esbuild.build({
  entryPoints: ['src/server-http.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  outfile: 'dist/server-http.js',
  external,
});

console.log('Build complete!');
