import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import type { CaptureModel, Process } from '../src/model/types';
import { analyze, type Analysis, type Finding } from '../src/rules/engine';
import { RULES, type Severity } from '../src/rules/rules';

// scripts/gameleira-lab.sh writes a teaching capture. Run with /bin/bash so macOS's bash 3.2 is what gets tested there.
const SCRIPT = path.resolve(__dirname, '..', 'scripts', 'gameleira-lab.sh');

function runLab(...args: string[]): string {
  return execFileSync('/bin/bash', [SCRIPT, ...args], { maxBuffer: 16 << 20, stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8');
}

describe('the script', () => {
  test('synthetic --stdout is a clean schema 11 capture', () => {
    const m = buildModel(runLab('synthetic', '--stdout').split('\n'));
    expect(m.stats.badLines).toBe(0);
    expect(m.stats.versions).toEqual([11]);
    expect(m.stats.events).toBeGreaterThan(0);
  });
  test('synthetic output is the same on every run', () => {
    expect(runLab('synthetic', '--stdout')).toBe(runLab('synthetic', '--stdout'));
  });
  test('json_str escapes quotes, backslashes and control characters', () => {
    const out = execFileSync('/bin/bash', ['-c', `GAMELEIRA_LAB_SOURCE_ONLY=1 . "${SCRIPT}"; json_str "$1"`, '_', 'a"b\\c\td\ne\u0001'])
      .toString('utf8');
    expect(JSON.parse(out)).toBe('a"b\\c\td\ne\u0001');
  });
  test('-o writes the capture and the answer key, creating the folder', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-'));
    try {
      runLab('synthetic', '-o', path.join(dir, 'sub', 'x.jsonl'));
      expect(fs.readFileSync(path.join(dir, 'sub', 'x.jsonl'), 'utf8')).toBe(runLab('synthetic', '--stdout'));
      expect(fs.readFileSync(path.join(dir, 'sub', 'x.answers.tsv'), 'utf8')).toBe(runLab('synthetic', '--answers'));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  test('an unknown argument exits 2', () => {
    let status: number | null = null;
    try {
      runLab('synthetic', '--nope');
    } catch (e) {
      status = (e as { status: number }).status;
    }
    expect(status).toBe(2);
  });
});

type Queue = 'item' | 'queued' | 'burst' | 'in-chain' | 'context';
interface KeyRow { step: string; rule: string; severity: Severity; queue: Queue; marker: string; note: string }

/** The answer key: tab-separated, a header line, `#` comment lines. */
function parseKey(tsv: string): KeyRow[] {
  const lines = tsv.split('\n').filter(l => l !== '' && !l.startsWith('#'));
  expect(lines[0]).toBe('step\trule\tseverity\tqueue\tmarker\tnote');
  return lines.slice(1).map(l => {
    const [step, rule, severity, queue, marker, note] = l.split('\t');
    return { step: step!, rule: rule!, severity: severity as Severity, queue: queue as Queue, marker: marker!, note: note! };
  });
}

const GATE = new Map(RULES.map(r => [r.id, r.gated]));
const isGated = (f: Finding): boolean => {
  const g = GATE.get(f.ruleId);
  return g === 'always' || (g === 'when-low' && f.severity === 'low');
};

/** How a process shows in the queue, by the spec's precedence: own finding, then burst, then chain; else context. */
function queueStatus(a: Analysis, p: Process): Queue {
  const item = a.queue.find(q => q.procId === p.id);
  if (!item) return 'context';
  if (item.findings.some(f => !isGated(f))) return 'queued';
  if (item.reconBurst) return 'burst';
  if (item.inFlaggedChain) return 'in-chain';
  throw new Error(`pid ${p.pid} is queued for no reason the key knows`);
}

/** The one process whose arguments (all images joined) contain the marker. */
function byMarker(m: CaptureModel, marker: string): Process {
  const hits = [...m.processes.values()].filter(p =>
    p.images.some(i => !i.inherited && i.args !== null && i.args.join(' ').includes(marker)));
  expect(hits.map(p => p.pid), `processes matching "${marker}"`).toHaveLength(1);
  return hits[0]!;
}

describe('the synthetic story', () => {
  const m = buildModel(runLab('synthetic', '--stdout').split('\n'));
  const a = analyze(m);
  const key = parseKey(runLab('synthetic', '--answers'));

  test('every rule fires at least once', () => {
    const fired = new Set<string>();
    for (const list of [...a.findings.values(), ...a.contextOnly.values()]) for (const f of list) fired.add(f.ruleId);
    for (const q of a.queue) for (const f of q.findings) fired.add(f.ruleId);
    expect(RULES.map(r => r.id).filter(id => !fired.has(id))).toEqual([]);
  });

  test('the key covers the queue concepts', () => {
    expect([...new Set(key.map(r => r.queue))].sort()).toEqual(['burst', 'context', 'in-chain', 'item', 'queued']);
  });

  test.each(key.map(r => [`${r.step}: ${r.rule} (${r.severity}, ${r.queue})`, r] as const))('%s', (_name, row) => {
    if (row.queue === 'item') {
      const items = a.queue.filter(q => q.kind === 'persistence'
        && m.persistence.find(it => it.id === q.persistenceId)?.plistPath?.includes(row.marker));
      expect(items).toHaveLength(1);
      expect(items[0]!.findings.map(f => [f.ruleId, f.severity])).toContainEqual([row.rule, row.severity]);
      return;
    }
    const p = byMarker(m, row.marker);
    const findings = a.findings.get(p.id) ?? a.contextOnly.get(p.id) ?? [];
    expect(findings.map(f => [f.ruleId, f.severity])).toContainEqual([row.rule, row.severity]);
    expect(queueStatus(a, p)).toBe(row.queue);
  });
});

describe('live mode', () => {
  test('live --answers names only real rules and lists what live mode cannot set off', () => {
    const tsv = runLab('live', '--answers');
    const ids = new Set(RULES.map(r => r.id));
    const rows = parseKey(tsv);
    expect(rows.length).toBeGreaterThan(10);
    for (const r of rows) expect(ids.has(r.rule), r.rule).toBe(true);
    expect(tsv).toMatch(/^#.*unsigned/m);
    expect(tsv).toMatch(/^#.*gameleira-lab\.sh/m);
  });
  test.runIf(process.platform !== 'darwin')('live refuses to run off macOS', () => {
    expect(() => runLab('live', '-o', path.join(os.tmpdir(), 'x.jsonl'))).toThrow(/macOS/);
  });
  test.runIf(process.platform === 'darwin')('live refuses to run as root', () => {
    let err = '';
    try {
      execFileSync('/bin/bash', [SCRIPT, 'live'], { env: { ...process.env, GAMELEIRA_LAB_FAKE_UID: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      err = String((e as { stderr: Buffer }).stderr);
    }
    expect(err).toMatch(/not as root|without sudo/);
  });
});

describe('live mode, after review', () => {
  const source = fs.readFileSync(SCRIPT, 'utf8');
  const liveSteps = source.slice(source.indexOf('live_steps() {'), source.indexOf('\n}\n', source.indexOf('live_steps() {')));

  test('the steps run in a child named by its arguments, which refuses without a lab folder', () => {
    let status: number | null = null;
    let err = '';
    try {
      execFileSync('/bin/bash', [SCRIPT, '__steps', '/nonexistent'], { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      status = (e as { status: number }).status;
      err = String((e as { stderr: Buffer }).stderr);
    }
    expect(status).not.toBe(0);
    expect(err).toMatch(/lab folder/);
    expect(runLab('live', '--answers')).toMatch(/^#.*gameleira-lab\.sh __steps/m);
  });

  test('stopping the capture ends a recorder that ignores SIGINT, within a few seconds', () => {
    const t0 = Date.now();
    const out = execFileSync('/bin/bash', ['-c', [
      `GAMELEIRA_LAB_SOURCE_ONLY=1 . "${SCRIPT}"`,
      `SUDO_CMD=''`,
      `( trap '' INT; exec sleep 60 ) & ES_PID=$!`,
      'sleep 0.3',
      'stop_capture',
      'if kill -0 $ES_PID 2>/dev/null; then echo alive; else echo stopped; fi',
    ].join('\n')], { stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8');
    expect(out.trim().split('\n').at(-1)).toBe('stopped');
    expect(Date.now() - t0).toBeLessThan(15000);
   }, 20000);

  test('no two commands in live mode carry the same marker, so each names one process', () => {
    // Lines that start a program; builtins (printf, assignments) and the key itself start none.
    const live = source.slice(source.indexOf('# ---- live mode'), source.indexOf('# ---- command line'));
    const lines = live.split('\n').filter(l => !/^\s*(?:#|answer |printf |local |: >|[A-Za-z_]+=|'#)/.test(l));
    for (const row of parseKey(runLab('live', '--answers'))) {
      expect(lines.filter(l => l.includes(row.marker)).length, row.marker).toBeLessThanOrEqual(1);
    }
  });

  test('every step runs a program by its full path', () => {
    const cmds = [...liveSteps.matchAll(/^\s*step '[^']*' (\S+)/gm)].map(x => x[1]!);
    expect(cmds.length).toBeGreaterThan(10);
    for (const c of cmds) expect(c, c).toMatch(/^(\/|"\$LAB\/)/);
  });

  test('the keychain lookup names a keychain file in the lab folder, so it cannot prompt for the real one', () => {
    expect(liveSteps).toMatch(/find-generic-password -s 'Gameleira Lab Safe Storage' -w "\$LAB\//);
  });
});
