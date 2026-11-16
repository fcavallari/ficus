import { describe, expect, it } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import type { FileOp } from '../src/model/types';
import { analyze } from '../src/rules/engine';
import { allTimelineEvents, type TimelineEvent } from '../src/ui/timeline';
import { defaultAnchor, nearby, NEARBY_WINDOWS, pickShown } from '../src/ui/nearby';
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

  it('includes events exactly at either edge of the window, and nothing a millisecond past it', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(0), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 2)] }),
      proc('2:1', [img({ token: '2:1', time: at(0), seq: 3 })],
        { fileOps: [wr('/tmp/out-lo', 4.999, 4), wr('/tmp/lo', 5, 5), wr('/tmp/hi', 15, 6), wr('/tmp/out-hi', 15.001, 7)] }),
    ]);
    const r = nearby(cap, ev(cap, '1:1:op:2'), 5_000);
    expect(r.groups.flatMap(g => g.events).map(x => [x.e.path, x.offsetMs])).toEqual([['/tmp/lo', -5000], ['/tmp/hi', 5000]]);
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
    const link = Object.fromEntries(r.groups.map(g => [g.proc, g.link]));
    expect(link).toEqual({ '2:1': { kind: 'chain' }, '3:1': null });
    // A child of the anchor's process is linked too (the anchor process is in its ancestry).
    const cap2 = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 5)] }),
      proc('2:1', [img({ token: '2:1', time: at(1), seq: 2 })], { responsible: '1:1', fileOps: [wr('/tmp/p', 11, 6)] }),
    ]);
    expect(nearby(cap2, ev(cap2, '1:1:op:5'), 5_000).groups[0]!.link).toEqual({ kind: 'chain' });
  });

  it('a sibling under the same recorded parent shares it', () => {
    const cap = load([
      proc('100:1', [img({ token: '100:1', time: at(1), seq: 1, path: '/bin/zsh' })]),
      proc('200:1', [img({ token: '200:1', time: at(1), seq: 2 })], { originalParent: '100:1', fileOps: [wr('/tmp/a', 10, 5)] }),
      proc('300:1', [img({ token: '300:1', time: at(1), seq: 3 })], { originalParent: '100:1', fileOps: [wr('/tmp/b', 11, 6)] }),
    ]);
    expect(nearby(cap, ev(cap, '200:1:op:5'), 5_000).groups.find(g => g.proc === '300:1')!.link).toEqual({ kind: 'shared', via: '100:1' });
  });

  it('a common ancestor that is launchd, the kernel or a ghost is no link', () => {
    const cap = load([
      proc('1:1', [img({ token: '1:1', time: at(1), seq: 1, path: '/sbin/launchd' })]),
      proc('ghost:500', [], { ghost: true, pid: 500 }),
      proc('200:1', [img({ token: '200:1', time: at(1), seq: 2 })], { originalParent: '1:1', fileOps: [wr('/tmp/a', 10, 5)] }),
      proc('300:1', [img({ token: '300:1', time: at(1), seq: 3 })], { originalParent: '1:1', fileOps: [wr('/tmp/b', 11, 6)] }),
      proc('400:1', [img({ token: '400:1', time: at(1), seq: 4 })], { originalParent: 'ghost:500', fileOps: [wr('/tmp/c', 10, 7)] }),
      proc('600:1', [img({ token: '600:1', time: at(1), seq: 6 })], { originalParent: 'ghost:500', fileOps: [wr('/tmp/d', 11, 8)] }),
    ]);
    expect(nearby(cap, ev(cap, '200:1:op:5'), 5_000).groups.find(g => g.proc === '300:1')!.link).toBeNull();
    expect(nearby(cap, ev(cap, '400:1:op:7'), 5_000).groups.find(g => g.proc === '600:1')!.link).toBeNull();
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

  it('fork, spawn and exit entries do not count as the same path, though they carry the program path', () => {
    const zsh = (id: string, s: number, seq: number, o = {}) => proc(id, [img({ token: id, time: at(s), seq, path: '/bin/zsh', args: ['zsh'] })], o);
    const kid = (id: string, parent: string, seq: number) =>
      proc(id, [img({ token: id, time: at(11), seq, path: '/bin/zsh', inherited: true })], { forkParent: parent, originalParent: parent });
    const cap = load([
      zsh('100:1', 10, 1),
      zsh('200:1', 1, 2),
      kid('300:1', '200:1', 3),                       // a spawn entry of 200:1
      proc('ghost:9', [], { ghost: true, pid: 9 }),
      kid('400:1', 'ghost:9', 4),                     // a fork entry, kept: its parent is a ghost
      zsh('500:1', 12, 5, { exitTime: at(12.5), exitSeq: 6 }),
    ]);
    const same = (key: string) => Object.fromEntries(nearby(cap, ev(cap, key), 5_000).groups
      .flatMap(g => g.events).map(x => [x.e.key, x.samePath]));
    expect(same('100:1:img:0')).toEqual({ '200:1:spawn:300:1': false, '400:1:fork': false, '500:1:img:0': true, '500:1:exit': false });
    // And the other way round: a spawn anchor has no path of its own to share.
    expect(Object.values(same('200:1:spawn:300:1')).some(Boolean)).toBe(false);
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

  describe('pickShown', () => {
    /** One busy process with 300 events (299 at ±4 s) and 20 others with one event each at ±0.5 s, around a write at 10 s. */
    const busyWindow = () => {
      // The busy process also holds the event nearest the anchor, so its group is listed first.
      const busy = Array.from({ length: 300 }, (_, i) => wr(`/tmp/busy${i}`, i === 0 ? 10.1 : i % 2 ? 14 : 6, 100 + i));
      const singles = Array.from({ length: 20 }, (_, i) =>
        proc(`${300 + i}:1`, [img({ token: `${300 + i}:1`, time: at(1), seq: 10 + i })], { fileOps: [wr(`/tmp/s${i}`, i % 2 ? 10.5 : 9.5, 500 + i)] }));
      const cap = load([
        proc('100:1', [img({ token: '100:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 5)] }),
        proc('200:1', [img({ token: '200:1', time: at(1), seq: 2 })], { fileOps: busy }),
        ...singles,
      ]);
      return nearby(cap, ev(cap, '100:1:op:5'), 5_000);
    };

    it('takes the events nearest the anchor across all groups, not the first groups in order', () => {
      const r = busyWindow();
      const shown = pickShown(r, 200);
      expect(shown.size).toBe(200);
      const singles = r.groups.filter(g => g.proc !== '200:1');
      expect(singles).toHaveLength(20);
      for (const g of singles) expect(shown.has(g.events[0]!), g.proc).toBe(true);
      expect(r.groups.find(g => g.proc === '200:1')!.events.filter(x => shown.has(x))).toHaveLength(180);
    });

    it('a larger limit reveals more, up to everything', () => {
      const r = busyWindow();
      expect(pickShown(r, 400).size).toBe(320);
      const first = pickShown(r, 200);
      for (const x of first) expect(pickShown(r, 400).has(x)).toBe(true);
    });

    it('same-path events come first, however far', () => {
      const cap = load([
        proc('100:1', [img({ token: '100:1', time: at(1), seq: 1 })], { fileOps: [wr('/tmp/a', 10, 5)] }),
        proc('200:1', [img({ token: '200:1', time: at(1), seq: 2 })], { fileOps: [wr('/tmp/near', 10.1, 6), wr('/tmp/a', 14.9, 7)] }),
      ]);
      const r = nearby(cap, ev(cap, '100:1:op:5'), 5_000);
      expect([...pickShown(r, 1)].map(x => x.e.path)).toEqual(['/tmp/a']);
    });
  });

  it('offers three windows, 5 s by default', () => {
    expect(NEARBY_WINDOWS).toEqual([1_000, 5_000, 30_000]);
  });
});
