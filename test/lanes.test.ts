import { describe, expect, it } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import type { FileOp, Process } from '../src/model/types';
import { analyze, type Finding, type QueueItem } from '../src/rules/engine';
import { binTicks, buildLanes, rulerTicks, type LaneTick } from '../src/ui/lanes';
import { capture, img, op, proc } from './synth';

const T0 = Date.parse('2026-11-12T00:00:00.000Z');
const at = (s: number) => new Date(T0 + s * 1000).toISOString();
const ms = (s: number) => T0 + s * 1000;

/** A process started by a recorded fork from `parent` at `s` seconds (its first image is the inherited copy). */
const forked = (id: string, parent: string, s: number, seq: number, more: Partial<Process> = {}) =>
  proc(id, [img({ token: id, path: '/bin/sh', inherited: true, time: at(s), seq })],
    { forkParent: parent, originalParent: parent, currentParent: parent, ...more });
const wr = (path: string, s: number, seq: number, kind: FileOp['kind'] = 'create'): FileOp => ({ ...op(kind, path, seq), time: at(s) });

function load(procs: Process[], first = 0, last = 100): LoadedCapture {
  const m = capture(procs);
  m.stats.firstTime = at(first);
  m.stats.lastTime = at(last);
  return { fingerprint: 'f', fileName: 'x', size: 0, model: m, analysis: analyze(m) };
}
const finding = (severity: Finding['severity'], imgIndex: number): Finding => ({
  ruleId: 'r', severity, title: 't', explanation: '', mitre: [], evidence: '', imgIndex, persistenceId: null, trait: false,
});

describe('buildLanes', () => {
  it('lays processes out in tree order, each bar running from when it appeared to its recorded exit', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', args: ['/bin/zsh'], path: '/bin/zsh', time: at(5), seq: 1 })], { exitTime: at(60), exitSeq: 50 }),
      forked('2:1', '1:1', 10, 2),
      forked('3:1', '2:1', 20, 3),
      forked('4:1', '1:1', 15, 4),
    ]);
    const { lanes } = buildLanes(cap, { mode: 'original', scope: 'all', flagged: [], selected: null });
    expect(lanes.map(l => [l.id, l.depth, l.parent])).toEqual([
      ['1:1', 0, null], ['2:1', 1, 0], ['3:1', 2, 1], ['4:1', 1, 0],
    ]);
    expect(lanes[0]).toMatchObject({ startMs: ms(5), endMs: ms(60), before: false, after: false });
    // No exit recorded: the bar runs to the end of the capture and says so, rather than drawing an exit.
    expect(lanes[1]).toMatchObject({ startMs: ms(10), endMs: ms(100), after: true });
  });

  it('starts a process that was already running at the start of the capture, and marks it', () => {
    const cap = load([proc('1:1', [img({ token: '1:1', args: null, time: at(30), seq: 9 })], { startTime: '2025-01-01T00:00:00Z' })]);
    const [lane] = buildLanes(cap, { mode: 'original', scope: 'all', flagged: [], selected: null }).lanes;
    expect(lane).toMatchObject({ startMs: ms(0), before: true });
  });

  it('shows the flagged processes with their ancestors and everything under them, and nothing else', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', args: ['/sbin/launchd'], time: at(0), seq: 1 })]),
      forked('2:1', '1:1', 1, 2),
      forked('3:1', '2:1', 2, 3),     // flagged
      forked('4:1', '3:1', 3, 4),     // under the flagged one
      forked('5:1', '1:1', 4, 5),     // unrelated
    ]);
    const { lanes } = buildLanes(cap, { mode: 'original', scope: 'flagged', flagged: ['3:1'], selected: null });
    expect(lanes.map(l => l.id)).toEqual(['1:1', '2:1', '3:1', '4:1']);
    expect(lanes.find(l => l.id === '3:1')!.flagged).toBe(true);
    expect(lanes.find(l => l.id === '2:1')!.flagged).toBe(false);
  });

  it('shows the selected process with its ancestors and everything under it', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', args: ['/sbin/launchd'], time: at(0), seq: 1 })]),
      forked('2:1', '1:1', 1, 2),
      forked('3:1', '2:1', 2, 3),
      forked('5:1', '1:1', 4, 5),
    ]);
    const { lanes } = buildLanes(cap, { mode: 'original', scope: 'selected', flagged: [], selected: '2:1' });
    expect(lanes.map(l => l.id)).toEqual(['1:1', '2:1', '3:1']);
  });

  it('keeps a parent the capture never saw as a lane, so the processes that share it stay together', () => {
    const ghost: Process = { ...proc('ghost:7', []), ghost: true };
    const lonely: Process = { ...proc('ghost:9', []), ghost: true };
    const cap = load([ghost, lonely, forked('8:1', 'ghost:7', 3, 2), forked('9:1', 'ghost:7', 4, 3)]);
    const { lanes } = buildLanes(cap, { mode: 'original', scope: 'flagged', flagged: ['8:1', '9:1'], selected: null });
    expect(lanes.map(l => [l.id, l.depth, l.parent, l.ghost])).toEqual([['ghost:7', 0, null, true], ['8:1', 1, 0, false], ['9:1', 1, 0, false]]);
    // Nothing hangs from the other one: it gets no lane even when every process is shown.
    expect(buildLanes(cap, { mode: 'original', scope: 'all', flagged: [], selected: null }).lanes.map(l => l.id)).not.toContain('ghost:9');
  });

  it('marks every program a process ran, and places its other events as ticks with the worst severity that cites them', () => {
    const p = proc('1:1', [
      img({ token: '1:1', path: '/bin/zsh', args: ['/bin/zsh'], time: at(1), seq: 1 }),
      img({ token: '1:1', path: '/usr/bin/curl', args: ['curl', 'x'], time: at(4), seq: 3 }),
    ], { fileOps: [wr('/tmp/a', 2, 2)], exitTime: at(9), exitSeq: 9 });
    const cap = load([p]);
    cap.analysis.findings.set('1:1', [finding('low', 1), finding('high', 1)]);
    const [lane] = buildLanes(cap, { mode: 'original', scope: 'all', flagged: [], selected: null }).lanes;
    expect(lane!.execs.map(e => [e.ms, e.name])).toEqual([[ms(1), 'zsh'], [ms(4), 'curl']]);
    expect(lane!.ticks.map(t => [t.kind, t.ms, t.severity])).toEqual([
      ['exec', ms(1), null], ['create', ms(2), null], ['exec', ms(4), 'high'],
    ]);
  });

  it('counts events with no usable time and does not place them', () => {
    const p = proc('1:1', [img({ token: '1:1', args: ['/bin/zsh'], time: at(1), seq: 1 })],
      { fileOps: [{ kind: 'create', path: '/tmp/a', time: 'not a time', seq: 2 }] });
    const r = buildLanes(load([p]), { mode: 'original', scope: 'all', flagged: [], selected: null });
    expect(r.untimed).toBe(1);
    expect(r.lanes[0]!.ticks.map(t => t.kind)).toEqual(['exec']);
  });

  it('does not count a program seen without its exec as an unplaced event: the model gives it no time of its own', () => {
    const p = proc('1:1', [img({ token: '1:1', args: null, time: null, seq: 1 }), img({ token: '1:1', path: '/bin/y', args: null, time: null, seq: 2 })]);
    expect(buildLanes(load([p]), { mode: 'original', scope: 'all', flagged: [], selected: null }).untimed).toBe(0);
  });

  it('lists the moments to replay in time order: appearances, programs, launch items, exits and flagged events', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', args: ['/bin/zsh'], path: '/bin/zsh', time: at(1), seq: 1 })],
        { exitTime: at(9), exitSeq: 9, fileOps: [wr('/tmp/quiet', 3, 4)] }),
      forked('2:1', '1:1', 2, 2),
    ]);
    const { moments, lanes } = buildLanes(cap, { mode: 'original', scope: 'all', flagged: [], selected: null });
    expect(moments.map(x => [x.e.kind, x.ms, lanes[x.lane]!.id])).toEqual([
      ['exec', ms(1), '1:1'], ['fork', ms(2), '2:1'], ['exit', ms(9), '1:1'],
    ]);
  });

  it('spans the capture by its first and last recorded times', () => {
    const r = buildLanes(load([proc('1:1', [img({ token: '1:1', args: ['/bin/zsh'], time: at(1), seq: 1 })])], 0, 42),
      { mode: 'original', scope: 'all', flagged: [], selected: null });
    expect([r.t0, r.t1]).toEqual([ms(0), ms(42)]);
  });
});

describe('binTicks', () => {
  const tick = (s: number, severity: LaneTick['severity'] = null, kind: LaneTick['kind'] = 'create'): LaneTick =>
    ({ key: `${s}${kind}`, ms: ms(s), seq: s, kind, severity });

  it('keeps one tick per pixel inside the window, the most severe one', () => {
    const out = binTicks([tick(1), tick(1.001, 'med'), tick(1.002), tick(50), tick(200)], ms(0), ms(100), 100);
    expect(out.map(t => [t.x, t.severity])).toEqual([[1, 'med'], [50, null]]);
  });

  it('prefers a program start over a file event on the same pixel when neither is flagged', () => {
    const out = binTicks([tick(1), tick(1.001, null, 'exec')], ms(0), ms(100), 100);
    expect(out.map(t => t.kind)).toEqual(['exec']);
  });
});

describe('rulerTicks', () => {
  it('picks a round step that leaves room between labels', () => {
    const ticks = rulerTicks(ms(0), ms(60), 600);
    expect(ticks.map(t => (t - T0) / 1000)).toEqual([0, 10, 20, 30, 40, 50, 60]);
  });
  it('goes below a second for a short window', () => {
    const ticks = rulerTicks(ms(1), ms(1.5), 500);
    expect(ticks.length).toBeGreaterThan(3);
    expect((ticks[1]! - ticks[0]!) % 1).toBe(0);
    expect(ticks[1]! - ticks[0]!).toBeLessThan(1000);
  });
});

describe('flaggedIds', () => {
  it('takes the queued processes, and for a launch item no process owns, its app, else its caller, else its reporter', async () => {
    const { flaggedIds } = await import('../src/ui/lanes');
    const { persistenceItem } = await import('./synth');
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })]),
      proc('2:1', [img({ token: '2:1', time: at(1), seq: 2 })]),
      proc('3:1', [img({ token: '3:1', time: at(1), seq: 3 })]),
    ]);
    cap.model.persistence.push(
      persistenceItem({ id: 'btm:7', emitter: '3:1', instigator: '2:1' }),
      persistenceItem({ id: 'btm:8', emitter: '3:1' }),
    );
    const q = (o: { procId: string | null; persistenceId: string | null }): QueueItem =>
      ({ key: String(o.procId ?? o.persistenceId), kind: o.procId ? 'process' : 'persistence', severity: 'high', findings: [], inFlaggedChain: false, reconBurst: false, members: o.procId ? [o.procId] : [], sortSeq: 0, ...o });
    expect(flaggedIds(cap, [q({ procId: '1:1', persistenceId: null }), q({ procId: null, persistenceId: 'btm:7' }), q({ procId: null, persistenceId: 'btm:8' })]))
      .toEqual(['1:1', '2:1', '3:1']);
  });
});
