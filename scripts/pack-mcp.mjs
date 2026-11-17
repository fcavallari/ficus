// Packs the Ficus MCP server as a Claude Desktop extension: dist-mcp/ficus.mcpb.
//
//   node scripts/pack-mcp.mjs               stage dist-mcp/bundle/, then zip it with the mcpb packer
//   node scripts/pack-mcp.mjs --stage-only  stage only; starts no process (the pack test uses this)
//
// Run `npm run build:mcp` first (`npm run pack:mcp` does). The staged layout keeps the bundle and the cleaner
// as siblings, because the server looks for the cleaner at ../scripts/ relative to itself (src/mcp/main.ts):
//
//   bundle/manifest.json
//   bundle/server/ficus-mcp.mjs
//   bundle/scripts/ficus-clean.sh   (executable)
//   bundle/scripts/ficus-clean.jq
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'dist-mcp');
const stage = path.join(out, 'bundle');

const files = [
  { from: 'mcp/manifest.json', to: 'manifest.json', mode: 0o644 },
  { from: 'dist-mcp/ficus-mcp.mjs', to: 'server/ficus-mcp.mjs', mode: 0o644 },
  { from: 'scripts/ficus-clean.sh', to: 'scripts/ficus-clean.sh', mode: 0o755 },
  { from: 'scripts/ficus-clean.jq', to: 'scripts/ficus-clean.jq', mode: 0o644 },
];

for (const f of files) {
  if (!fs.existsSync(path.join(root, f.from))) {
    console.error(`pack-mcp: ${f.from} is missing${f.from.startsWith('dist-mcp/') ? ' (run npm run build:mcp first)' : ''}`);
    process.exit(1);
  }
}

fs.rmSync(stage, { recursive: true, force: true });
for (const f of files) {
  const dest = path.join(stage, f.to);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(path.join(root, f.from), dest);
  fs.chmodSync(dest, f.mode); // copyFile keeps the mode only where the umask allows it; set it outright
}
console.log(`staged ${files.length} files in ${path.relative(root, stage)}/`);

if (process.argv.includes('--stage-only')) process.exit(0);

// Build tooling, not the server: running the packer as a child process here does not touch the server's
// no-child-process rule. The packer's own CLI is run with this Node, so no shell and no PATH lookup is involved.
const cli = path.join(root, 'node_modules', '@anthropic-ai', 'mcpb', 'dist', 'cli', 'cli.js');
const mcpb = path.join(out, 'ficus.mcpb');
fs.rmSync(mcpb, { force: true });
execFileSync(process.execPath, [cli, 'pack', stage, mcpb], { stdio: 'inherit', cwd: root });
console.log(`wrote ${path.relative(root, mcpb)} (${fs.statSync(mcpb).size} bytes)`);
