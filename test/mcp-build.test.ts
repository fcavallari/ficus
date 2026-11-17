import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { expect, test } from 'vitest';

const BUNDLE = 'dist-mcp/ficus-mcp.mjs';

// Every module the bundle can load, by static import, import() or a real require() call. Comment lines are skipped
// (JSDoc type imports), and so are the require("...") strings that ajv's code generator holds in template text.
function moduleSpecifiers(js: string): Set<string> {
  const found = new Set<string>();
  const code = js
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join('\n');
  for (const m of code.matchAll(/^import\s+(?:[^;'"]*?\s+from\s+)?["']([^"']+)["']/gm)) found.add(m[1]!);
  for (const m of code.matchAll(/(?<![`\w.$"'\\])import\(\s*["']([^"']+)["']\s*\)/g)) found.add(m[1]!);
  for (const m of code.matchAll(/(?<![`\w.$"'\\])require\(\s*["']([^"']+)["']\s*\)/g)) found.add(m[1]!);
  return found;
}

test('the bundle opens no network and starts no process', () => {
  const js = fs.readFileSync(BUNDLE, 'utf8');
  // An allowlist of what the bundle may load, not a denylist of bare names: ajv's bundled fast-uri carries a
  // scheme-name table with "http"/"https" strings, so a bare-string denylist cannot tell data from an import.
  // This checks what the bundle can actually load. A new import fails here and has to be reviewed.
  expect([...moduleSpecifiers(js)].sort()).toEqual([
    'node:crypto', 'node:fs', 'node:os', 'node:path', 'node:process', 'node:url',
  ]);
  for (const s of [
    'fetch(', 'XMLHttpRequest', 'new WebSocket',
    'node:http', 'node:https', 'node:net', 'node:dgram', 'node:child_process', 'child_process',
  ])
    expect(js, s).not.toContain(s);
});

test('dist/ still holds only index.html', () => {
  expect(fs.readdirSync('dist')).toEqual(['index.html']);
});

test('the bundle answers over stdio', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-mcp-home-'));
  const exportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-mcp-export-'));
  const client = new Client({ name: 'build-test', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [BUNDLE],
    env: { FICUS_HOME: home, FICUS_EXPORT_DIR: exportDir, HOME: home },
  });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'ficus_analyze',
      'ficus_export',
      'ficus_list_captures',
      'ficus_record_command',
      'ficus_row',
    ]);
  } finally {
    await client.close();
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(exportDir, { recursive: true, force: true });
  }
}, 30_000);
