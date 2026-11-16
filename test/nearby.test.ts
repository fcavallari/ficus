import { describe, expect, it } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import type { FileOp } from '../src/model/types';
import { analyze } from '../src/rules/engine';
import { allTimelineEvents, type TimelineEvent } from '../src/ui/timeline';
import { defaultAnchor, nearby, NEARBY_WINDOWS } from '../src/ui/nearby';
import { capture, img, op, proc } from './synth';

const T0 = Date.parse('2026-11-12T00:00:10.000Z');
const at = (s: number) => new Date(T0 + (s - 10) * 1000).toISOString();
const wr = (path: string, s: number, seq: number, kind: FileOp['kind'] = 'write'): FileOp => ({ ...op(kind, path, seq), time: at(s) });

function load(procs: ReturnType<typeof proc>[]): LoadedCapture {
  const m = capture(procs);
  return { fingerprint: 'f', fileName: 'x', size: 0, model: m, analysis: analyze(m) };
}
const ev = (cap: LoadedCapture, key: string): TimelineEvent => {
  const e = allTimelineEvents(cap).find(x => x.key === key);
  if (!e) throw new Error(`no event ${key}`);
  return e;
};

describe('nearby', () => {
  it('lists other processes\' events inside the window, with offsets', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(0), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 2)] }),
      proc('2:1', [img({ token: '2:1', time: at(0), seq: 3 })], { fileOps: [wr('/tmp/b', 7, 4), wr('/tmp/c', 12, 5), wr('/tmp/d', 20, 6)] }),
    ]);
    const r = nearby(cap, ev(cap, '1:1:op:2'), 5_000);
    const evs = r.groups.flatMap(g => g.events);
    expect(evs.map(x => [x.e.path, x.offsetMs])).toEqual([['/tmp/b', -3000], ['/tmp/c', 2000]]);
    expect(r.total).toBe(2);
  });

  it('leaves out the anchor\'s own process', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(10), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 2), wr('/tmp/a2', 11, 3)] }),
    ]);
    const r = nearby(cap, ev(cap, '1:1:op:2'), 5_000);
    expect(r.groups).toEqual([]);
    expect(r.total).toBe(0);
  });

  it('marks an unrelated process unlinked and a parent linked', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })], { originalParent: '2:1', fileOps: [wr('/tmp/a', 10, 5)] }),
      proc('2:1', [img({ token: '2:1', time: at(1), seq: 2 })], { fileOps: [wr('/tmp/p', 11, 6)] }),
      proc('3:1', [img({ token: '3:1', time: at(1), seq: 3 })], { fileOps: [wr('/tmp/u', 12, 7)] }),
    ]);
    const r = nearby(cap, ev(cap, '1:1:op:5'), 5_000);
    const linked = Object.fromEntries(r.groups.map(g => [g.proc, g.linked]));
    expect(linked).toEqual({ '2:1': true, '3:1': false });
    // A child of the anchor's process is linked too (the anchor process is in its ancestry).
    const cap2 = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 5)] }),
      proc('2:1', [img({ token: '2:1', time: at(1), seq: 2 })], { responsible: '1:1', fileOps: [wr('/tmp/p', 11, 6)] }),
    ]);
    expect(nearby(cap2, ev(cap2, '1:1:op:5'), 5_000).groups[0]!.linked).toBe(true);
  });

  it('marks same-path events', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 5)] }),
      proc('2:1', [img({ token: '2:1', time: at(11), seq: 2, path: '/tmp/a', args: ['/tmp/a'] })]),
    ]);
    const r = nearby(cap, ev(cap, '1:1:op:5'), 5_000);
    const e = r.groups[0]!.events[0]!;
    expect(e.e.kind).toBe('exec');
    expect(e.samePath).toBe(true);
  });

  it('events without a time are left out and counted', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 5)] }),
      proc('2:1', [img({ token: '2:1', time: at(1), seq: 2 })], { fileOps: [{ ...wr('/tmp/n', 10, 6), time: null as unknown as string }, wr('/tmp/y', 11, 7)] }),
    ]);
    const r = nearby(cap, ev(cap, '1:1:op:5'), 5_000);
    expect(r.groups.flatMap(g => g.events.map(x => x.e.path))).toEqual(['/tmp/y']);
    expect(r.untimed).toBe(1);
  });

  it('puts a group with a same-path event first, even before a closer group', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 9)] }),
      proc('2:1', [img({ token: '2:1', time: at(1), seq: 2 })], { fileOps: [wr('/tmp/near', 10.1, 10)] }),
      proc('3:1', [img({ token: '3:1', time: at(1), seq: 3 })], { fileOps: [wr('/tmp/a', 14, 11)] }),
    ]);
    const r = nearby(cap, ev(cap, '1:1:op:9'), 5_000);
    expect(r.groups.map(g => g.proc)).toEqual(['3:1', '2:1']);
    expect(r.groups[0]!.events[0]!.samePath).toBe(true);
  });

  it('orders other groups by their closest event, even when another group starts earlier', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 9)] }),
      proc('2:1', [img({ token: '2:1', time: at(1), seq: 2 })], { fileOps: [wr('/tmp/far', 5.5, 10), wr('/tmp/far2', 6, 11)] }),
      proc('3:1', [img({ token: '3:1', time: at(1), seq: 3 })], { fileOps: [wr('/tmp/mid', 8, 12), wr('/tmp/mid2', 12, 13)] }),
      proc('4:1', [img({ token: '4:1', time: at(1), seq: 4 })], { fileOps: [wr('/tmp/closest', 10.2, 14)] }),
    ]);
    const r = nearby(cap, ev(cap, '1:1:op:9'), 5_000);
    expect(r.groups.map(g => g.proc)).toEqual(['4:1', '3:1', '2:1']);
    // Inside a group the events stay in time order.
    expect(r.groups[1]!.events.map(x => x.offsetMs)).toEqual([-2000, 2000]);
  });

  it('drops a fork entry whose spawn is present', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 9)] }),
      proc('2:1', [img({ token: '2:1', time: at(1), seq: 2 })], { fileOps: [wr('/tmp/late', 13, 10)] }),
      proc('3:1', [img({ token: '3:1', time: at(1), seq: 3 })], { fileOps: [wr('/tmp/early', 8, 11)] }),
    ]);
    const kid = proc('4:1', [img({ token: '4:1', time: at(9), seq: 4, inherited: true })], { forkParent: '2:1' });
    const cap2 = load([...[...cap.model.processes.values()], kid]);
    const forks = allTimelineEvents(cap2).filter(e => e.kind === 'fork');
    expect(forks).toEqual([]);
    expect(allTimelineEvents(cap2).filter(e => e.kind === 'spawn')).toHaveLength(1);
  });

  it('defaultAnchor prefers the first flagged event, then the first exec, then the first event', () => {
    const mk = (key: string, kind: TimelineEvent['kind'], flagged = false): TimelineEvent =>
      ({ key, seq: 1, time: null, kind, proc: 'p', path: null, findings: flagged ? [{} as never] : [] });
    expect(defaultAnchor([mk('a', 'write'), mk('b', 'exec'), mk('c', 'write', true)])!.key).toBe('c');
    expect(defaultAnchor([mk('a', 'write'), mk('b', 'exec'), mk('c', 'exec')])!.key).toBe('b');
    expect(defaultAnchor([mk('a', 'write'), mk('b', 'create')])!.key).toBe('a');
    expect(defaultAnchor([])).toBeNull();
  });

  it('copes with a group too large to spread into Math.min (Safari tops out near 65k arguments)', () => {
    const many = Array.from({ length: 150_000 }, (_, i) => wr(`/tmp/m${i}`, 11, 10 + i));
    const cap = load([
      proc('100:1', [img({ token: '100:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 5)] }),
      proc('200:1', [img({ token: '200:1', time: at(1), seq: 2 })], { fileOps: many }),
    ]);
    const r = nearby(cap, ev(cap, '100:1:op:5'), 5_000);
    expect(r.total).toBe(150_000);
    expect(r.groups).toHaveLength(1);
  });

  it('offers three windows, 5 s by default', () => {
    expect(NEARBY_WINDOWS).toEqual([1_000, 5_000, 30_000]);
  });
});
