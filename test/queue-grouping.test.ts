import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import { queueItemFor } from '../src/rules/group';
import type { CaptureModel } from '../src/model/types';
import { buildReport } from '../src/report/report';
import { reportMarkdown } from '../src/report/markdown';
import { flaggedIds } from '../src/ui/lanes';
import { foldByRow } from '../src/ui/triage-model';
import { GEN, input, verdict } from './report-fixture';
import { children, HELPER, world } from './group-fixture';
import { capture, img, persistenceItem, proc } from './synth';

// Runs of identical queued processes (a crash loop: the same helper started 500 times) are one queue row with all the
// processes as its members. The analysis still keeps every process's own findings.
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

describe('everything that finds a process\'s queue row goes through its members', () => {
  const lab = (m: CaptureModel) => ({ fingerprint: 'fp', fileName: 'x.jsonl', size: 1, model: m, analysis: analyze(m) });

  test('the timeline lanes keep every member of a group', () => {
    const m = world(children(3));
    const ids = flaggedIds(lab(m), analyze(m).queue);
    expect(ids).toEqual(expect.arrayContaining(['200:1', '201:1', '202:1']));
  });

  test('a verdict on a member is a verdict on a queued process, not a user-marked extra', () => {
    const m = world(children(3));
    const report = buildReport(input({
      loaded: new Map([['fp', lab(m)]]), verdicts: [verdict('fp', '201:1', 'benign')],
    }), { redactArgs: false, generated: GEN });
    expect(report.captures[0]!.userMarked).toEqual([]);
  });

  test('the report names the repeat count on the row, and only on a grouped row', () => {
    const m = world(children(3));
    const r = buildReport(input({ loaded: new Map([['fp', lab(m)]]) }), { redactArgs: false, generated: GEN });
    const grouped = r.captures[0]!.rows!.find(x => x.process?.procId === '200:1')!;
    expect(grouped.repeats).toBe(3);
    expect(reportMarkdown(r)).toContain('×3');
    const alone = buildReport(input({ loaded: new Map([['fp', lab(world(children(1)))]]) }), { redactArgs: false, generated: GEN });
    expect(alone.captures[0]!.rows!.find(x => x.process?.procId === '200:1')!.repeats).toBe(1);
    expect(reportMarkdown(alone)).not.toContain('×');
  });
});

test('foldByRow folds the verdicts of one group, and leaves the rest alone', () => {
  const m = world([...children(3), ...children(1, ['--other'], 300)]);
  const cap = { fingerprint: 'fp', fileName: 'x.jsonl', size: 1, model: m, analysis: analyze(m) };
  const vs = ['200:1', '201:1', '202:1', '300:1', '999:1'].map(id => verdict('fp', id, 'confirmed'));
  const folded = foldByRow(vs, new Map([['fp', cap]]));
  expect(folded.map(f => [f.verdict.procKey, f.repeats])).toEqual([['200:1', 3], ['300:1', 1], ['999:1', 1]]);
  // A capture that is not loaded cannot be grouped: every verdict stands alone.
  expect(foldByRow(vs, new Map()).map(f => f.repeats)).toEqual([1, 1, 1, 1, 1]);
});
