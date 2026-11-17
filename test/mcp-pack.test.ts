import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, expect, test } from 'vitest';

const ROOT = path.resolve(__dirname, '..');
const STAGE = path.join(ROOT, 'dist-mcp', 'bundle');

// `--stage-only` builds dist-mcp/bundle/ without zipping it, so this test starts nothing but the staging script.
beforeAll(() => {
  execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'pack-mcp.mjs'), '--stage-only'], { cwd: ROOT });
});

test('the manifest names the server entry and the five tools', () => {
  const m = JSON.parse(fs.readFileSync(path.join(ROOT, 'mcp', 'manifest.json'), 'utf8'));
  expect(m.name).toBe('ficus');
  expect(m.display_name).toBe('Ficus');
  expect(m.server.type).toBe('node');
  expect(m.server.entry_point).toBe('server/ficus-mcp.mjs');
  expect(m.server.mcp_config).toEqual({ command: 'node', args: ['${__dirname}/server/ficus-mcp.mjs'] });
  expect(m.compatibility.platforms).toEqual(['darwin']);
  expect(m.tools.map((t: { name: string }) => t.name).sort()).toEqual([
    'ficus_analyze',
    'ficus_export',
    'ficus_list_captures',
    'ficus_record_command',
    'ficus_row',
  ]);
  for (const t of m.tools) expect(t.description, t.name).toBeTruthy();
});

test('the staged bundle has the manifest, the server and both cleaner files, byte-equal', () => {
  const pairs: [string, string][] = [
    ['mcp/manifest.json', 'manifest.json'],
    ['dist-mcp/ficus-mcp.mjs', 'server/ficus-mcp.mjs'],
    ['scripts/ficus-clean.sh', 'scripts/ficus-clean.sh'],
    ['scripts/ficus-clean.jq', 'scripts/ficus-clean.jq'],
  ];
  for (const [from, to] of pairs) {
    expect(fs.readFileSync(path.join(STAGE, to)).equals(fs.readFileSync(path.join(ROOT, from))), to).toBe(true);
  }
});

test('the staged cleaner script keeps its executable bit', () => {
  expect(fs.statSync(path.join(STAGE, 'scripts', 'ficus-clean.sh')).mode & 0o111).toBe(0o111);
});

test('the staged server finds the cleaner at ../scripts/', () => {
  // src/mcp/main.ts resolves the cleaner as ../scripts/ relative to the bundle file.
  const serverDir = path.join(STAGE, 'server');
  expect(fs.existsSync(path.join(serverDir, '../scripts/ficus-clean.sh'))).toBe(true);
  expect(fs.existsSync(path.join(serverDir, '../scripts/ficus-clean.jq'))).toBe(true);
});

test('nothing but the four files is staged', () => {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else files.push(path.relative(STAGE, p));
    }
  };
  walk(STAGE);
  expect(files.sort()).toEqual([
    'manifest.json',
    'scripts/ficus-clean.jq',
    'scripts/ficus-clean.sh',
    'server/ficus-mcp.mjs',
  ]);
});
