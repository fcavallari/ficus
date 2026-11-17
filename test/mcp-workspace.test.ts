import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, expect, test } from 'vitest';
import { loadCapture } from '../src/ingest/load';
import { CaptureRefused, ficusPaths, type FicusPaths } from '../src/mcp/home';
import { PAGE_SIZE, UnknownRow, Workspace } from '../src/mcp/workspace';
import { buildReport } from '../src/report/report';
import { fixture } from './fixtures';

const PASSWORD = 'labpass-not-real';
const N = 'lab.cleaned.jsonl';
const NOW = new Date(2026, 10, 17, 9, 5, 30); // local time

let paths: FicusPaths;
let ws: Workspace;

function freshHome(): FicusPaths {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-ws-'));
  const p = ficusPaths({ HOME: '/nowhere', FICUS_HOME: home } as NodeJS.ProcessEnv);
  fs.mkdirSync(p.captures, { recursive: true });
  fs.mkdirSync(p.keys, { recursive: true });
  return p;
}

/** Copy the synthetic lab (or `body`) into captures/ with a stub key and an mtime 60 s in the past. */
function stage(name: string, body?: Buffer | string): void {
  const file = path.join(paths.captures, name);
  fs.writeFileSync(file, body ?? fs.readFileSync(fixture('synthetic-lab.jsonl')));
  const past = (Date.now() - 60_000) / 1000;
  fs.utimesSync(file, past, past);
  fs.writeFileSync(path.join(paths.keys, `${name}.key.tsv`), 'k\tv\n');
}

beforeEach(() => {
  paths = freshHome();
  stage(N);
  ws = new Workspace(paths, () => NOW);
});

test('analyze matches the app: 17 rows, same order and severities as loadCapture', async () => {
  const v = await ws.analyze(N);
  const cap = await loadCapture(new Blob([fs.readFileSync(fixture('synthetic-lab.jsonl'))]));
  const report = buildReport(
    {
      session: { id: 's', name: 'x' },
      capRecs: [{ sessionId: 's', fingerprint: cap.fingerprint, fileName: N, size: cap.size, events: cap.model.stats.events,
        processes: cap.model.processes.size, flagged: cap.analysis.queue.length, added: 't' }],
      loaded: new Map([[cap.fingerprint, cap]]), verdicts: [], routineKeys: new Set(),
    },
    { redactArgs: true, generated: 'g' },
  );
  const expected = [...report.captures[0]!.rows!].sort((a, b) => a.n - b.n);
  expect(v.summary.rows).toBe(17);
  expect(v.rows.map(r => r.severity)).toEqual(expected.map(r => r.severity));
  expect(v.rows.map(r => r.key)).toEqual(expected.map(r => r.key));
  expect(v.rows.map(r => r.n)).toEqual(expected.map(r => r.n));
  expect(v.capture.events).toBe(111);
  expect(v.capture.name).toBe(N);
  expect(v.truncated).toBeNull();
  expect(v.offset).toBe(0);
  expect(PAGE_SIZE).toBe(40);
});

test('nothing the agent sees by default holds the dscl password', async () => {
  const view = await ws.analyze(N);
  const rows = await Promise.all(view.rows.map(r => ws.row(N, r.key)));
  const text = JSON.stringify(view) + JSON.stringify(rows) + JSON.stringify(await ws.report(N, true));
  expect(text).not.toContain(PASSWORD);
});

test('reveal shows that one row unredacted and is remembered', async () => {
  const view = await ws.analyze(N);
  const dscl = view.rows.find(r => r.name === 'dscl')!;
  expect(JSON.stringify(await ws.row(N, dscl.key, true))).toContain(PASSWORD);
  expect(ws.revealed(N)).toEqual([dscl.key]);
  const other = view.rows.find(r => r.key !== dscl.key)!;
  expect(JSON.stringify(await ws.row(N, other.key))).not.toContain(PASSWORD);
  // a second reveal of the same row is listed once; a plain read after it is redacted again
  await ws.row(N, dscl.key, true);
  expect(ws.revealed(N)).toEqual([dscl.key]);
  expect(JSON.stringify(await ws.row(N, dscl.key))).not.toContain(PASSWORD);
  // analyze after a reveal is still redacted
  expect(JSON.stringify(await ws.analyze(N))).not.toContain(PASSWORD);
});

test('a reveal of an unknown key is not recorded', async () => {
  await expect(ws.row(N, 'no-such-key', true)).rejects.toBeInstanceOf(UnknownRow);
  expect(ws.revealed(N)).toEqual([]);
});

test('paging: pageSize 5 from offset 15 returns 2 rows; offset 0 says 12 remain with their severities', async () => {
  const all = await ws.analyze(N);
  const tail = await ws.analyze(N, 15, 5);
  expect(tail.rows).toHaveLength(2);
  expect(tail.rows.map(r => r.n)).toEqual(all.rows.slice(15).map(r => r.n));
  expect(tail.offset).toBe(15);
  expect(tail.truncated).toBeNull();
  const head = await ws.analyze(N, 0, 5);
  expect(head.rows).toHaveLength(5);
  expect(head.truncated!.remaining).toBe(12);
  const want = { high: 0, med: 0, low: 0 };
  for (const r of all.rows.slice(5)) want[r.severity!]++;
  expect(head.truncated!.bySeverity).toEqual(want);
  // the summary is for the whole capture, not the page
  expect(head.summary.rows).toBe(17);
});

test('rules holds each explanation once, keyed by rule id', async () => {
  const v = await ws.analyze(N);
  const report = await ws.report(N, true);
  // A rule may explain itself differently per finding (recon names what each tool reads): all distinct texts are kept.
  const expl = new Map<string, string[]>();
  for (const row of [...report.captures[0]!.rows!].sort((a, b) => a.n - b.n)) {
    for (const f of row.findings) {
      const list = expl.get(f.ruleId) ?? [];
      if (!list.includes(f.explanation)) list.push(f.explanation);
      expl.set(f.ruleId, list);
    }
  }
  const used = new Set(v.rows.flatMap(r => r.findings.map(f => f.ruleId)));
  expect(used.size).toBeGreaterThan(0);
  expect(Object.keys(v.rules).sort()).toEqual([...used].sort());
  for (const id of used) expect(v.rules[id]).toBe(expl.get(id)!.join('\n'));
  // the findings themselves carry no explanation
  expect(JSON.stringify(v.rows)).not.toContain('"explanation"');
  // rules cover only the rows on the page
  const one = await ws.analyze(N, 0, 1);
  expect(Object.keys(one.rules).sort()).toEqual([...new Set(one.rows[0]!.findings.map(f => f.ruleId))].sort());
});

test('rows carry the latest image path and signature, coverage detail is keyed once by id', async () => {
  const v = await ws.analyze(N);
  const report = await ws.report(N, true);
  const byKey = new Map(report.captures[0]!.rows!.map(r => [r.key, r]));
  for (const r of v.rows) {
    const images = byKey.get(r.key)!.process?.images ?? [];
    const last = images[images.length - 1];
    expect(r.path).toBe(last?.path ?? null);
    expect(r.signature).toBe(last?.signature ?? null);
  }
  expect(v.rows.some(r => r.path !== null)).toBe(true);
  const cov = report.captures[0]!.coverage!;
  expect(Object.keys(v.capture.coverageDetail).sort()).toEqual(cov.map(c => c.id).sort());
  expect(JSON.stringify(v.capture.coverage)).not.toContain('"detail"');
  expect(v.capture.coverage.map(c => c.id)).toEqual(cov.map(c => c.id));
});

test('an unknown row key throws UnknownRow', async () => {
  await expect(ws.row(N, 'no-such-key')).rejects.toBeInstanceOf(UnknownRow);
});

test('the session is stable per capture and named self-check YYYY-MM-DD HH:MM', async () => {
  const s = ws.session(N);
  expect(s.name).toBe('self-check 2026-11-17 09:05');
  expect(s.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  expect(ws.session(N)).toEqual(s);
  expect(ws.session('other.cleaned.jsonl').id).not.toBe(s.id);
  expect((await ws.report(N, true)).session).toEqual(s);
  expect((await ws.captureRec(N)).sessionId).toBe(s.id);
});

test('the capture rec mirrors the app: counts from the model, flagged = queue length, file name = capture name', async () => {
  const rec = await ws.captureRec(N);
  const cap = await ws.load(N);
  expect(rec).toMatchObject({ fingerprint: cap.fingerprint, fileName: N, events: 111, flagged: 17, size: cap.size });
  expect(cap.fileName).toBe(N);
});

test('the same capture is parsed once and served from the loaded copy; the redacted report is stable', async () => {
  const first = await ws.load(N);
  expect(await ws.load(N)).toBe(first);
  expect(await ws.report(N, true)).toBe(await ws.report(N, true));
  // two calls racing on a fresh workspace share one load
  const fresh = new Workspace(paths, () => NOW);
  const [x, y] = await Promise.all([fresh.load(N), fresh.load(N)]);
  expect(x).toBe(y);
  // an unredacted report is a different object and says so
  expect((await ws.report(N, false)).redacted).toBe(false);
  expect((await ws.report(N, true)).redacted).toBe(true);
});

test('switching captures reloads, and reveals stay with their capture', async () => {
  stage('a.cleaned.jsonl');
  stage('b.cleaned.jsonl');
  const a = await ws.analyze('a.cleaned.jsonl');
  const dscl = a.rows.find(r => r.name === 'dscl')!;
  await ws.row('a.cleaned.jsonl', dscl.key, true);
  const b = await ws.analyze('b.cleaned.jsonl');
  await ws.row('b.cleaned.jsonl', b.rows[0]!.key);
  expect(ws.revealed('b.cleaned.jsonl')).toEqual([]);
  expect(ws.revealed('a.cleaned.jsonl')).toEqual([dscl.key]);
  expect((await ws.load('b.cleaned.jsonl')).fileName).toBe('b.cleaned.jsonl');
  expect((await ws.load('a.cleaned.jsonl')).fileName).toBe('a.cleaned.jsonl');
  expect(ws.session('a.cleaned.jsonl').id).not.toBe(ws.session('b.cleaned.jsonl').id);
});

test('an empty cleaned capture is refused with the loader message', async () => {
  stage('empty.cleaned.jsonl', '');
  await expect(ws.analyze('empty.cleaned.jsonl')).rejects.toThrow(/No eslogger or Mac Monitor events/);
});

test('a refused capture rejects with CaptureRefused', async () => {
  await expect(ws.load('../lab.cleaned.jsonl')).rejects.toBeInstanceOf(CaptureRefused);
  await expect(ws.analyze('missing.jsonl')).rejects.toBeInstanceOf(CaptureRefused);
  fs.writeFileSync(path.join(paths.captures, 'nokey.jsonl'), '{}\n');
  fs.utimesSync(path.join(paths.captures, 'nokey.jsonl'), 1, 1);
  await expect(ws.row('nokey.jsonl', 'k')).rejects.toBeInstanceOf(CaptureRefused);
  // a capture already loaded is refused again if it is touched afterwards (the guard runs on every call)
  await ws.analyze(N);
  const now = new Date();
  fs.utimesSync(path.join(paths.captures, N), now, now);
  await expect(ws.analyze(N)).rejects.toBeInstanceOf(CaptureRefused);
});

test('a case variant of a capture name cannot reveal a row, so the reveal list is never split', async ({ skip }) => {
  const variant = N.toUpperCase();
  if (variant === N || !fs.existsSync(path.join(paths.captures, variant))) skip('this temp file system is case-sensitive: the variant does not exist');
  const view = await ws.analyze(N);
  const dscl = view.rows.find(r => r.name === 'dscl')!;
  await expect(ws.row(variant, dscl.key, true)).rejects.toBeInstanceOf(CaptureRefused);
  expect(ws.revealed(variant)).toEqual([]);
  expect(ws.revealed(N)).toEqual([]);
});
