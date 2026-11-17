import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, expect, test } from 'vitest';
import { CaptureRefused, ficusPaths, type FicusPaths } from '../src/mcp/home';
import { writeExport } from '../src/mcp/export';
import { Workspace } from '../src/mcp/workspace';
import { reportFileName } from '../src/report/report';
import { parseExport, saveFileName } from '../src/session/export';
import { fixture } from './fixtures';

const PASSWORD = 'labpass-not-real';
const N = 'lab.cleaned.jsonl';
const NOW = new Date(2026, 10, 17, 10, 30, 12); // local time

let p: FicusPaths;
let ws: Workspace;

beforeEach(() => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-exp-home-'));
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-exp-out-'));
  p = ficusPaths({ HOME: '/nowhere', FICUS_HOME: home, FICUS_EXPORT_DIR: out } as NodeJS.ProcessEnv);
  fs.mkdirSync(p.captures, { recursive: true });
  fs.mkdirSync(p.keys, { recursive: true });
  const file = path.join(p.captures, N);
  fs.writeFileSync(file, fs.readFileSync(fixture('synthetic-lab.jsonl')));
  const past = (Date.now() - 60_000) / 1000;
  fs.utimesSync(file, past, past);
  fs.writeFileSync(path.join(p.keys, `${N}.key.tsv`), 'k\tv\n');
  ws = new Workspace(p, () => NOW);
});

const read = (folder: string, name: string): string => fs.readFileSync(path.join(folder, name), 'utf8');

test('report mode: verdict, README and the two report files, no capture, no key', async () => {
  const r = await writeExport(ws, p, N, { mode: 'report', verdict: '# ALL GOOD' }, NOW);
  expect(path.basename(r.folder)).toBe('Ficus report 2026-11-17 103012');
  expect(path.dirname(r.folder)).toBe(p.exportRoot);
  const s = ws.session(N);
  expect(r.files).toEqual(['README.txt', 'agent-verdict.md', reportFileName(s, 'json'), reportFileName(s, 'md')].sort());
  expect(fs.readdirSync(r.folder).sort()).toEqual(r.files);
});

test('full mode adds the capture and a session file that parseExport accepts', async () => {
  const r = await writeExport(ws, p, N, { mode: 'full', verdict: 'v' }, NOW);
  expect(r.files).toContain(N);
  expect(r.files).toContain(saveFileName(ws.session(N)));
  const data = parseExport(read(r.folder, saveFileName(ws.session(N))));
  expect(data.captures).toHaveLength(1);
  expect(data.captures[0]!.fileName).toBe(N);
  expect(data.session).toEqual({ ...ws.session(N), created: NOW.toISOString(), updated: NOW.toISOString() });
  expect(data.verdicts).toEqual([]);
  expect(data.routine).toEqual([]);
  expect(data.details).toEqual({});
  expect(fs.readFileSync(path.join(r.folder, N)).equals(fs.readFileSync(path.join(p.captures, N)))).toBe(true);
  expect(r.files.some(f => f.endsWith('.key.tsv'))).toBe(false);
  expect(fs.readdirSync(r.folder).some(f => f.endsWith('.key.tsv'))).toBe(false);
});

test('the report files are unredacted by default and redacted with redact: true', async () => {
  const s = ws.session(N);
  const open = await writeExport(ws, p, N, { mode: 'report', verdict: 'v' }, NOW);
  expect(read(open.folder, reportFileName(s, 'json'))).toContain(PASSWORD);
  expect(read(open.folder, reportFileName(s, 'md'))).toContain(PASSWORD);
  const shut = await writeExport(ws, p, N, { mode: 'report', verdict: 'v', redact: true }, NOW);
  expect(shut.folder).not.toBe(open.folder);
  expect(read(shut.folder, reportFileName(s, 'json'))).not.toContain(PASSWORD);
  expect(read(shut.folder, reportFileName(s, 'md'))).not.toContain(PASSWORD);
  expect(JSON.parse(read(shut.folder, reportFileName(s, 'json'))).redacted).toBe(true);
});

test('the JSON report equals ws.report(N, false) apart from generated', async () => {
  const r = await writeExport(ws, p, N, { mode: 'report', verdict: 'v' }, new Date(2026, 10, 17, 11, 0, 0));
  const written = JSON.parse(read(r.folder, reportFileName(ws.session(N), 'json')));
  const expected = JSON.parse(JSON.stringify(await ws.report(N, false)));
  delete written.generated;
  delete expected.generated;
  expect(written).toEqual(expected);
});

test('agent-verdict.md holds the verdict, then the revealed rows or "none"', async () => {
  const none = await writeExport(ws, p, N, { mode: 'report', verdict: '# Verdict\n\nLooks bad.' }, NOW);
  expect(read(none.folder, 'agent-verdict.md')).toBe('# Verdict\n\nLooks bad.\n\n## Shown to the agent with consent\n\nnone\n');
  const view = await ws.analyze(N);
  const dscl = view.rows.find(r => r.name === 'dscl')!;
  await ws.row(N, dscl.key, true);
  const some = await writeExport(ws, p, N, { mode: 'report', verdict: 'v2' }, NOW);
  const text = read(some.folder, 'agent-verdict.md');
  expect(text.startsWith('v2\n\n## Shown to the agent with consent\n')).toBe(true);
  expect(text).toContain('dscl');
  expect(text).not.toContain('none');
  expect(text).not.toContain(PASSWORD);
});

test('a second export in the same second goes to "… 2"', async () => {
  const a = await writeExport(ws, p, N, { mode: 'report', verdict: 'a' }, NOW);
  const b = await writeExport(ws, p, N, { mode: 'report', verdict: 'b' }, NOW);
  const c = await writeExport(ws, p, N, { mode: 'report', verdict: 'c' }, NOW);
  expect(path.basename(a.folder)).toBe('Ficus report 2026-11-17 103012');
  expect(path.basename(b.folder)).toBe('Ficus report 2026-11-17 103012 2');
  expect(path.basename(c.folder)).toBe('Ficus report 2026-11-17 103012 3');
  expect(read(a.folder, 'agent-verdict.md')).toContain('a\n');
  expect(read(b.folder, 'agent-verdict.md')).toContain('b\n');
});

test('reveals on another capture are not listed', async () => {
  const other = 'other.cleaned.jsonl';
  const file = path.join(p.captures, other);
  fs.copyFileSync(path.join(p.captures, N), file);
  const past = (Date.now() - 60_000) / 1000;
  fs.utimesSync(file, past, past);
  fs.writeFileSync(path.join(p.keys, `${other}.key.tsv`), 'k\tv\n');
  const view = await ws.analyze(other);
  await ws.row(other, view.rows.find(r => r.name === 'dscl')!.key, true);
  const r = await writeExport(ws, p, N, { mode: 'report', verdict: 'v' }, NOW);
  expect(read(r.folder, 'agent-verdict.md')).toMatch(/consent\n\nnone\n$/);
});

test('README.txt says the key stays on the Mac and the capture is pseudonymized', async () => {
  const report = await writeExport(ws, p, N, { mode: 'report', verdict: 'v' }, NOW);
  const full = await writeExport(ws, p, N, { mode: 'full', verdict: 'v' }, NOW);
  for (const r of [report, full]) {
    const t = read(r.folder, 'README.txt');
    expect(t).toMatch(/key/i);
    expect(t).toMatch(/stays on (this|the|your) Mac/i);
    expect(t).toMatch(/pseudonymi[sz]ed/i);
  }
  expect(read(full.folder, 'README.txt')).toContain(N);
  expect(read(full.folder, 'README.txt')).toContain(saveFileName(ws.session(N)));
});

test('a refused capture throws and leaves no folder behind', async () => {
  await expect(writeExport(ws, p, 'missing.jsonl', { mode: 'full', verdict: 'v' }, NOW)).rejects.toBeInstanceOf(CaptureRefused);
  await expect(writeExport(ws, p, '../x', { mode: 'report', verdict: 'v' }, NOW)).rejects.toBeInstanceOf(CaptureRefused);
  expect(fs.readdirSync(p.exportRoot)).toEqual([]);
});

test('the export root is created when missing', async () => {
  const nested = path.join(p.exportRoot, 'not', 'yet');
  const r = await writeExport(ws, { ...p, exportRoot: nested }, N, { mode: 'report', verdict: 'v' }, NOW);
  expect(path.dirname(r.folder)).toBe(nested);
});
