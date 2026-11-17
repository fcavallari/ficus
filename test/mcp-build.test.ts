import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { expect, test } from 'vitest';

const BUNDLE = 'dist-mcp/ficus-mcp.mjs';

// Every module the bundle can load. No comment stripping and no line skipping, so nothing can hide behind one:
//  - static `import ... from "x"`, `import "x"` and `export ... from "x"` at the start of a line;
//  - any call ending in `require` (require, __require, module.require, createRequire) or `import`, with optional
//    whitespace before the parenthesis and a literal specifier.
// Two narrow exceptions: a relative specifier (JSDoc type imports in comments; a real relative import could not
// run from a single file anyway), and `require("...")` written inside a template literal (ajv's code generator holds
// those as text it emits for standalone validators; they are never executed here).
function moduleSpecifiers(js: string): Set<string> {
  const found = new Set<string>();
  const statics = /^(?:import|export)\s+(?:[^;'"]*?\s+from\s+)?["']([^"']+)["']/gm;
  const calls = /(?<!`)(?:[\w$]*[rR]equire|(?<![\w$.])import)\s*\(\s*["']([^"']+)["']/g;
  for (const re of [statics, calls]) for (const m of js.matchAll(re)) if (!m[1]!.startsWith('.')) found.add(m[1]!);
  return found;
}

// A backstop that needs none of the above: a require or import call of a network or process module, in any form.
const NETWORK_OR_PROCESS_CALL =
  /(?:require|import)\s*\(\s*["'`](?:node:)?(?:http|https|http2|net|tls|dgram|child_process|cluster|worker_threads|inspector)["'`]/;

test('the collector sees every way to load a module', () => {
  for (const probe of [
    'var n = __require("net");',
    'module.require("net")',
    '/* @__PURE__ */ require("net");',
    'x(\n* require("net"))',
    'require ("net")',
    "import('net')",
    'import("node:http")',
    'import net from "net";',
    'import "node:dgram";',
    'export { x } from "node:child_process";',
  ]) {
    const found = [...moduleSpecifiers(probe)];
    expect(found, probe).toHaveLength(1);
    expect(found[0], probe).toMatch(/^(node:)?(net|http|dgram|child_process)$/);
  }
  // What it must leave alone: ajv's template text, JSDoc type imports, and strings that merely mention a module.
  expect([...moduleSpecifiers('code: _`require("ajv/dist/runtime/validation_error").default`')]).toEqual([]);
  expect([...moduleSpecifiers('uri.code = "require(\\"ajv/dist/runtime/uri\\").default";')]).toEqual([]);
  expect([...moduleSpecifiers("\t* @param {import('../types/index').URIComponent} component")]).toEqual([]);
  expect([...moduleSpecifiers('const supportedSchemeNames = ["http", "https", "ws"];')]).toEqual([]);
});

test('the backstop catches a network or process module in any call form', () => {
  for (const probe of [
    'var n = __require("net");',
    'module.require("net")',
    '/* @__PURE__ */ require("net");',
    'require ("net")',
    'import("node:http")',
    "require('node:child_process')",
    'import(`node:dgram`)',
  ])
    expect(probe, probe).toMatch(NETWORK_OR_PROCESS_CALL);
  expect('code: _`require("ajv/dist/runtime/validation_error").default`').not.toMatch(NETWORK_OR_PROCESS_CALL);
  expect('const supportedSchemeNames = ["http", "https", "ws"];').not.toMatch(NETWORK_OR_PROCESS_CALL);
  expect('require("node:fs")').not.toMatch(NETWORK_OR_PROCESS_CALL);
});

test('the bundle opens no network and starts no process', () => {
  const js = fs.readFileSync(BUNDLE, 'utf8');
  // An allowlist of what the bundle may load, not a denylist of bare names: ajv's bundled fast-uri carries a
  // scheme-name table with "http"/"https" strings, so a bare-string denylist cannot tell data from an import.
  // This checks what the bundle can actually load. A new import fails here and has to be reviewed.
  expect([...moduleSpecifiers(js)].sort()).toEqual([
    'node:crypto', 'node:fs', 'node:os', 'node:path', 'node:process', 'node:url',
  ]);
  expect(js).not.toMatch(NETWORK_OR_PROCESS_CALL);
  for (const s of [
    'fetch(', 'XMLHttpRequest', 'new WebSocket', 'getBuiltinModule',
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
