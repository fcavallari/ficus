import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { ficusPaths, type FicusPaths } from '../src/mcp/home';
import { createServer } from '../src/mcp/server';
import { fixture } from './fixtures';

const PASSWORD = 'labpass-not-real';
const N = 'lab.cleaned.jsonl';
const NOW = new Date(2026, 10, 17, 10, 30, 12); // local time
const SCRIPTS = path.resolve(__dirname, '..', 'scripts');

let p: FicusPaths;
let client: Client;

function stage(name: string, content: string | Buffer): void {
  const file = path.join(p.captures, name);
  fs.writeFileSync(file, content);
  const past = (Date.now() - 60_000) / 1000;
  fs.utimesSync(file, past, past);
  fs.writeFileSync(path.join(p.keys, `${name}.key.tsv`), 'k\tv\n');
}

beforeEach(async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-srv-home-'));
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-srv-out-'));
  p = ficusPaths({ HOME: '/nowhere', FICUS_HOME: home, FICUS_EXPORT_DIR: out } as NodeJS.ProcessEnv);
  fs.mkdirSync(p.captures, { recursive: true });
  fs.mkdirSync(p.keys, { recursive: true });
  stage(N, fs.readFileSync(fixture('synthetic-lab.jsonl')));

  const server = createServer({ paths: p, scriptsDir: SCRIPTS, now: () => NOW });
  const [a, b] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
});

afterEach(async () => {
  await client.close();
});

interface Result {
  isError: boolean;
  text: string;
}

async function raw(name: string, args: Record<string, unknown>): Promise<Result> {
  const r = (await client.callTool({ name, arguments: args })) as {
    isError?: boolean;
    content: { type: string; text: string }[];
  };
  return { isError: r.isError === true, text: r.content[0]!.text };
}

async function call(name: string, args: Record<string, unknown> = {}): Promise<any> {
  const r = await raw(name, args);
  if (r.isError) throw new Error(`${name} failed: ${r.text}`);
  return JSON.parse(r.text);
}

async function tool(name: string): Promise<any> {
  return (await client.listTools()).tools.find(t => t.name === name)!;
}

test('lists exactly the five tools', async () => {
  expect((await client.listTools()).tools.map(t => t.name).sort()).toEqual(
    ['ficus_analyze', 'ficus_export', 'ficus_list_captures', 'ficus_record_command', 'ficus_row']);
});

test("ficus_row describes reveal as needing the person's yes in chat", async () => {
  const d = (await tool('ficus_row')).inputSchema.properties.reveal.description;
  expect(d).toMatch(/ask the person/i);
  expect(d).toMatch(/yes/i);
});

test('ficus_export describes asking which mode first and reading the report before sending', async () => {
  const d = (await tool('ficus_export')).description;
  expect(d).toMatch(/ask the person which mode/i);
  expect(d).toMatch(/read the report/i);
});

test('ficus_record_command says it never runs anything', async () => {
  expect((await tool('ficus_record_command')).description).toMatch(/never runs/i);
});

test('ficus_record_command describes domains as the own-company domains that get hidden, never ones to find', async () => {
  const d: string = (await tool('ficus_record_command')).inputSchema.properties.domains.description;
  expect(d).toMatch(/replaced|placeholder/i);
  expect(d).toMatch(/company/i);
  expect(d).toMatch(/never pass a domain you want to find/i);
  expect(d).not.toMatch(/look for/i);
});

test('ficus_analyze exposes capture and offset only, and says the evidence is redacted', async () => {
  const t = await tool('ficus_analyze');
  expect(Object.keys(t.inputSchema.properties).sort()).toEqual(['capture', 'offset']);
  expect(t.inputSchema.required).toEqual(['capture']);
  expect(t.description).toMatch(/redacted/i);
});

test('record → list → analyze → row → export works end to end on the staged fixture', async () => {
  const seen: string[] = [];
  const track = async (name: string, args: Record<string, unknown>): Promise<any> => {
    const r = await raw(name, args);
    expect(r.isError).toBe(false);
    seen.push(r.text);
    return JSON.parse(r.text);
  };

  const rec = await track('ficus_record_command', { seconds: 120, domains: ['example.com'] });
  expect(rec.command).toContain('-t 120');
  expect(rec.command).toContain('-D example.com');
  expect(rec.capture).toBe('capture-2026-11-17-103012.cleaned.jsonl');
  expect(fs.existsSync(path.join(p.bin, 'ficus-clean.sh'))).toBe(true);

  const list = await track('ficus_list_captures', {});
  expect(JSON.stringify(list)).toContain(N);

  const view = await track('ficus_analyze', { capture: N });
  expect(view.rows.length).toBeGreaterThan(0);
  expect(view.rows.length).toBeLessThanOrEqual(40);

  const dscl = view.rows.find((r: any) => r.name === 'dscl');
  const row = await track('ficus_row', { capture: N, key: dscl.key });
  expect(row.key).toBe(dscl.key);

  const exp = await track('ficus_export', { capture: N, mode: 'report', verdict: '# verdict' });
  expect(path.basename(exp.folder)).toBe('Ficus report 2026-11-17 103012');
  expect(exp.files).toContain('agent-verdict.md');
  expect(fs.existsSync(path.join(exp.folder, 'agent-verdict.md'))).toBe(true);

  for (const t of seen) expect(t).not.toContain(PASSWORD);
});

test('reveal returns the password for that row only, and the export lists the reveal', async () => {
  const view = await call('ficus_analyze', { capture: N });
  const dscl = view.rows.find((r: any) => r.name === 'dscl');
  const other = view.rows.find((r: any) => r.key !== dscl.key);

  expect((await raw('ficus_row', { capture: N, key: dscl.key })).text).not.toContain(PASSWORD);
  expect((await raw('ficus_row', { capture: N, key: dscl.key, reveal: true })).text).toContain(PASSWORD);
  expect((await raw('ficus_row', { capture: N, key: other.key })).text).not.toContain(PASSWORD);
  expect(JSON.stringify(await call('ficus_analyze', { capture: N }))).not.toContain(PASSWORD);

  const exp = await call('ficus_export', { capture: N, mode: 'report', verdict: 'v' });
  expect(fs.readFileSync(path.join(exp.folder, 'agent-verdict.md'), 'utf8')).toContain(dscl.key);
});

test('a refused capture is an error result, and the server still answers', async () => {
  stage('raw.jsonl', fs.readFileSync(fixture('synthetic-lab.jsonl')));
  fs.rmSync(path.join(p.keys, 'raw.jsonl.key.tsv'));
  const noKey = await raw('ficus_analyze', { capture: 'raw.jsonl' });
  expect(noKey.isError).toBe(true);
  expect(noKey.text).toMatch(/ficus_record_command/);
  const traversal = await raw('ficus_analyze', { capture: '../etc/passwd' });
  expect(traversal.isError).toBe(true);
  expect(traversal.text).toMatch(/plain file name/);
  expect((await client.listTools()).tools).toHaveLength(5);
  expect((await raw('ficus_list_captures', {})).isError).toBe(false);
});

test('an unknown row key is an error result that points to ficus_analyze', async () => {
  const r = await raw('ficus_row', { capture: N, key: 'no-such-row' });
  expect(r.isError).toBe(true);
  expect(r.text).toBe(`No row no-such-row in ${N}. Call ficus_analyze for the row keys.`);
  expect((await raw('ficus_analyze', { capture: N })).isError).toBe(false);
});

test('a bad domain is an error result', async () => {
  const r = await raw('ficus_record_command', { domains: ['bad domain; rm -rf /'] });
  expect(r.isError).toBe(true);
  expect((await raw('ficus_list_captures', {})).isError).toBe(false);
});

test('a file that is not an eslogger capture is an error result, not a crash', async () => {
  stage('junk.cleaned.jsonl', 'this is not json\n');
  const r = await raw('ficus_analyze', { capture: 'junk.cleaned.jsonl' });
  expect(r.isError).toBe(true);
  expect(r.text).toMatch(/No eslogger or Mac Monitor events/);
  expect((await raw('ficus_analyze', { capture: N })).isError).toBe(false);
});

test('inputs are range-checked by the schema', async () => {
  for (const offset of [-1, 1.5]) {
    expect((await raw('ficus_analyze', { capture: N, offset })).isError).toBe(true);
  }
  expect((await raw('ficus_analyze', { capture: N, offset: 0 })).isError).toBe(false);
  for (const seconds of [59, 1801, 90.5]) {
    expect((await raw('ficus_record_command', { seconds })).isError).toBe(true);
  }
  expect((await raw('ficus_export', { capture: N, mode: 'everything', verdict: 'v' })).isError).toBe(true);
});

test('an offset past the end returns no rows and no truncation', async () => {
  const view = await call('ficus_analyze', { capture: N, offset: 100000 });
  expect(view.rows).toEqual([]);
  expect(view.truncated).toBeNull();
});
