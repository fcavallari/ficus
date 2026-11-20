import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import { queueItemFor } from '../src/rules/group';
import type { CaptureModel, Image, PersistenceItem, Process } from '../src/model/types';
import { capture, img, persistenceItem, proc } from './synth';

// Runs of identical queued processes (a crash loop: the same helper started 500 times) are one queue row with all the
// processes as its members. The analysis still keeps every process's own findings.
const HELPER = '/Users/u/Downloads/sample/helper';

/** An unsigned program run from Downloads: `odd-location-exec` fires high for it. */
const helper = (args: string[], seq: number): Image => img({ path: HELPER, signingId: null, args: [HELPER, ...args], seq });
const parent = (): Process => proc('100:1', [img({ path: '/Users/u/Downloads/sample/main', signingId: null, args: ['main'], seq: 1 })]);
/** `n` children of the parent, each running `args`; ids `200:1`, `201:1`, … */
const children = (n: number, args: string[] = ['--dialog'], first = 200): Process[] =>
  Array.from({ length: n }, (_, i) => proc(`${first + i}:1`, [helper(args, 10 + i)], { originalParent: '100:1', ppid: 100, originalPpid: 100 }));
const world = (procs: Process[], persistence: PersistenceItem[] = []): CaptureModel => capture([parent(), ...procs], persistence);
const rowsOf = (m: CaptureModel, ...ids: string[]) =>
  analyze(m).queue.filter(q => q.procId !== null && ids.includes(q.procId));

describe('queue grouping', () => {
  test('three identical children are one row with three members, in sequence order', () => {
    const a = analyze(world(children(3)));
    const rows = a.queue.filter(q => q.members.includes('200:1'));
    expect(rows).toHaveLength(1);
    expect(rows[0]!.members).toEqual(['200:1', '201:1', '202:1']);
    expect(rows[0]!.procId).toBe('200:1');
    expect(rows[0]!.key).toBe('p:200:1');
    // The analysis keeps every process's own findings.
    for (const id of ['200:1', '201:1', '202:1']) expect(a.findings.get(id)?.length).toBeGreaterThan(0);
  });

  test('different arguments are different rows', () => {
    const m = world([...children(2, ['--dialog']), ...children(2, ['--other'], 300)]);
    const rows = analyze(m).queue.filter(q => q.members.some(id => id !== '100:1'));
    expect(rows.map(r => r.members)).toEqual([['200:1', '201:1'], ['300:1', '301:1']]);
  });

  test('a different program is a different row', () => {
    const odd = proc('250:1', [img({ path: '/Users/u/Downloads/sample/other', signingId: null, args: ['other', '--dialog'], seq: 20 })],
      { originalParent: '100:1', ppid: 100, originalPpid: 100 });
    const rows = rowsOf(world([...children(2), odd]), '200:1', '201:1', '250:1');
    expect(rows.map(r => r.members)).toEqual(expect.arrayContaining([['200:1', '201:1'], ['250:1']]));
    expect(rows).toHaveLength(2);
  });

  test('a child that also owns a persistence finding stays its own row', () => {
    const plist = '/Users/u/Library/LaunchAgents/com.evil.plist';
    const kids = children(2);
    kids[1]!.fileOps.push({ kind: 'create', path: plist, time: '2026-11-12T00:00:01.000Z', seq: 30 });
    const m = world(kids, [persistenceItem({ id: 'btm:1', plistPath: plist, executablePath: HELPER, creator: '201:1', itemType: 3, seq: 31 })]);
    const rows = rowsOf(m, '200:1', '201:1');
    expect(rows).toHaveLength(2);
    expect(rows.every(r => r.members.length === 1)).toBe(true);
  });

  test('a lone process has itself as its only member, and a persistence-only item has none', () => {
    const lone = analyze(world(children(1))).queue.find(q => q.procId === '200:1')!;
    expect(lone.members).toEqual(['200:1']);
    const item = persistenceItem({ id: 'btm:2', plistPath: '/Users/u/Library/LaunchAgents/x.plist', executablePath: '/tmp/x', itemType: 3, emitter: 'ghost:1' });
    const q = analyze(capture([], [item])).queue.find(x => x.kind === 'persistence');
    expect(q?.members).toEqual([]);
  });

  test('queueItemFor finds the row from any member, and nothing for a process that is not queued', () => {
    const a = analyze(world(children(3)));
    const row = a.queue.find(q => q.procId === '200:1')!;
    expect(queueItemFor(a, '202:1')).toBe(row);
    expect(queueItemFor(a, '999:1')).toBeUndefined();
  });

  test('5,000 identical children group in well under a second per thousand', () => {
    const m = world(children(5000));
    const t = Date.now();
    const a = analyze(m);
    expect(Date.now() - t).toBeLessThan(5000);
    expect(a.queue.find(q => q.procId === '200:1')!.members).toHaveLength(5000);
  });
});
