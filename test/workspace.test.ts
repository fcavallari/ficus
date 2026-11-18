import { expect, test } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import { buildModel } from '../src/model/builder';
import { analyze } from '../src/rules/engine';
import type { Verdict } from '../src/session/store';
import { processTimeline, recordedSpan } from '../src/ui/timeline';
import { captureInfo, coverage, overview, verdictKey } from '../src/ui/triage-model';
import { readLines } from './fixtures';
import { procByPid, queued } from './helpers';

const lab = (): LoadedCapture => {
  const { m, a } = queued('synthetic-lab.jsonl');
  return { model: m, analysis: a } as LoadedCapture;
};

/** The lab's lines, each passed through `edit` (return null to drop the line). */
function labWith(edit: (o: Record<string, unknown>) => Record<string, unknown> | null): LoadedCapture {
  const lines = [...readLines('synthetic-lab.jsonl')].flatMap(l => {
    const o = edit(JSON.parse(l) as Record<string, unknown>);
    return o ? [JSON.stringify(o)] : [];
  });
  const model = buildModel(lines);
  return { model, analysis: analyze(model) } as LoadedCapture;
}

// --- model additions ----------------------------------------------------------------------------------------------

test('a fork child\'s inherited image carries the fork event\'s time; an exit carries its sequence number', () => {
  const m = lab().model;
  const forked = [...m.processes.values()].filter(p => p.images[0]?.inherited);
  expect(forked.length).toBeGreaterThan(0);
  for (const p of forked) expect(p.images[0]!.time).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  const exited = [...m.processes.values()].filter(p => p.exitTime !== null);
  expect(exited.length).toBeGreaterThan(0);
  for (const p of exited) expect(typeof p.exitSeq).toBe('number');
});

test('the stats count modelled events by eslogger type, apart from the types the viewer does not model', () => {
  const { stats } = lab().model;
  expect(stats.kinds!['exec']).toBeGreaterThan(0);
  expect(stats.kinds!['fork']).toBeGreaterThan(0);
  for (const t of Object.keys(stats.otherEvents)) expect(stats.kinds![t]).toBeUndefined();
  const modelled = Object.values(stats.kinds!).reduce((a, b) => a + b, 0);
  const other = Object.values(stats.otherEvents).reduce((a, b) => a + b, 0);
  expect(modelled + other).toBe(stats.events);
});

// --- timeline -----------------------------------------------------------------------------------------------------

test('a timeline is the process\'s own recorded events in capture order, with the finding on the exec it cites', () => {
  const cap = lab();
  const p = procByPid(cap.model, 7006);   // osascript display dialog
  const { events } = processTimeline(cap, p.id, false);
  expect(events.map(e => e.seq)).toEqual([...events.map(e => e.seq)].sort((a, b) => a - b));
  expect(events.every(e => e.proc === p.id)).toBe(true);
  const execs = events.filter(e => e.kind === 'exec');
  expect(execs.length).toBe(p.images.filter(i => !i.inherited && i.args !== null).length);
  const cited = execs.flatMap(e => e.findings.map(f => f.ruleId));
  expect(cited).toContain('fake-prompt');
  // A finding sits only on the event it names: no exec carries a finding from another image.
  for (const e of execs) for (const f of e.findings) expect(p.images[f.imgIndex!]!.seq).toBe(e.seq);
});

test('every timeline entry carries only times the capture recorded', () => {
  const cap = lab();
  const recorded = new Set<string>();
  for (const p of cap.model.processes.values()) {
    for (const i of p.images) if (i.time) recorded.add(i.time);
    for (const op of p.fileOps) recorded.add(op.time);
    if (p.exitTime) recorded.add(p.exitTime);
  }
  for (const it of cap.model.persistence) recorded.add(it.time);
  for (const p of cap.model.processes.values()) {
    for (const e of processTimeline(cap, p.id, false).events) if (e.time !== null) expect(recorded.has(e.time)).toBe(true);
  }
});

test('with descendants, a fork inside the subtree is listed once, on the parent that made it', () => {
  const cap = lab();
  const child = procByPid(cap.model, 7006);
  const parent = child.forkParent!;
  const own = processTimeline(cap, parent, false).events;
  const all = processTimeline(cap, parent, true);
  expect(all.processes).toBeGreaterThan(1);
  expect(all.events.length).toBeGreaterThan(own.length);
  expect(all.events.filter(e => e.kind === 'spawn' && e.other === child.id)).toHaveLength(1);
  expect(all.events.filter(e => e.kind === 'fork' && e.proc === child.id)).toHaveLength(0);
  expect(new Set(all.events.map(e => e.key)).size).toBe(all.events.length);
});

test('a process known only by pid has no timeline, and the recorded span of nothing is null', () => {
  const cap = lab();
  const ghost = [...cap.model.processes.values()].find(p => p.ghost)!;
  expect(processTimeline(cap, ghost.id, false).events).toEqual([]);
  expect(recordedSpan([])).toBeNull();
});

// --- overview -----------------------------------------------------------------------------------------------------

test('the overview splits the queue by severity and by verdict, and ranks the most flagged programs', () => {
  const cap = lab();
  const q = cap.analysis.queue;
  const first = q[0]!;
  const verdicts = new Map<string, Verdict>([[verdictKey(first), { status: 'confirmed' } as Verdict]]);
  const o = overview(cap, q, verdicts);
  const total = o.bySeverity.high.total + o.bySeverity.med.total + o.bySeverity.low.total;
  expect(total).toBe(q.length);
  expect(o.byVerdict.confirmed).toBe(1);
  expect(o.byVerdict.unreviewed).toBe(q.length - 1);
  expect(o.bySeverity[first.severity].open).toBe(o.bySeverity[first.severity].total - 1);
  expect(o.top.length).toBeGreaterThan(0);
  expect(o.top.map(t => t.count)).toEqual([...o.top.map(t => t.count)].sort((a, b) => b - a));
});

// --- coverage -----------------------------------------------------------------------------------------------------

test('a complete-looking v11 capture gets no stdin note; dropping the fds data names the checks it silences', () => {
  expect(coverage(lab().model).notes.find(n => n.id === 'stdin')).toBeUndefined();
  const old = labWith(o => {
    o['version'] = 6;
    const ev = o['event'] as Record<string, Record<string, unknown>>;
    if (ev['exec']) delete ev['exec']['fds'];
    return o;
  });
  const note = coverage(old.model).notes.find(n => n.id === 'stdin')!;
  expect(note.level).toBe('warn');
  expect(note.title).toMatch(/^No exec events carry file-descriptor data$/);
  expect(note.detail).toMatch(/schema v6 predates v11/);
  expect(note.checks).toEqual(['shell-from-pipe', 'osascript-script', 'reverse-shell']);
});

test('a missing event type is reported as missing, never as proof that nothing happened', () => {
  const cap = labWith(o => ('btm_launch_item_add' in (o['event'] as object) ? null : o));
  const note = coverage(cap.model).notes.find(n => n.id === 'none-btm_launch_item_add')!;
  expect(note.checks).toContain('persistence-item');
  expect(note.detail).toMatch(/Either none happened while it ran, or eslogger was not subscribed/);
  for (const n of coverage(cap.model).notes) expect(`${n.title} ${n.detail}`).not.toMatch(/\bcomplete\b|fully compatible/i);
});

test('processes known only by pid and unmodelled event types are counted in coverage', () => {
  const cov = coverage(lab().model);
  expect(cov.versions).toEqual([11]);
  expect(cov.notes.find(n => n.id === 'ghosts')?.title).toMatch(/known only by pid/);
  expect(cov.notes.find(n => n.id === 'other')?.detail).toMatch(/appear in no timeline/);
});

test('a launch item appears on the timeline of each process it names, with that process\'s role and the findings citing it', () => {
  const cap = lab();
  expect(cap.model.persistence.length).toBeGreaterThan(0);
  const cited = new Set([...cap.analysis.findings.values(), ...cap.analysis.queue.map(q => q.findings)].flat()
    .flatMap(f => (f.persistenceId ? [f.persistenceId] : [])));
  for (const item of cap.model.persistence) {
    const rows = processTimeline(cap, item.emitter, false).events.filter(e => e.persistenceId === item.id);
    expect(rows).toHaveLength(1);
    const role = item.app === item.emitter ? 'app' : item.instigator === item.emitter ? 'instigator' : 'emitter';
    expect(rows[0]!.role).toBe(role);
    expect(rows[0]!.kind).toBe(item.kind === 'add' ? 'btm_add' : 'btm_remove');
    expect(rows[0]!.findings.length > 0).toBe(cited.has(item.id));
  }
});

// --- events missing from the sequence ------------------------------------------------------------------------------

/** The lab with the events numbered in `drop` removed: what an eslogger that fell behind would have written. */
const without = (drop: number[]): LoadedCapture => labWith(o => (drop.includes(o['global_seq_num'] as number) ? null : o));

test('numbers missing from global_seq_num are counted, and the separate holes too', () => {
  const stats = without([5, 6, 7, 20]).model.stats;
  expect(stats.events).toBe(107);
  expect(stats.seqGaps).toBe(4);
  expect(stats.seqGapRuns).toBe(2);
});

test('a capture that lost nothing has no gap, and a late start, a repeated number and the last events are not gaps', () => {
  expect(lab().model.stats.seqGaps).toBe(0);
  expect(without([0, 1, 2]).model.stats.seqGaps).toBe(0);          // the capture simply started later
  expect(without([110]).model.stats.seqGaps).toBe(0);              // the end is not a hole
  const twice = labWith(o => ({ ...o, global_seq_num: Math.floor((o['global_seq_num'] as number) / 2) }));
  expect(twice.model.stats.seqGaps).toBe(0);                        // repeated numbers, nothing missing
  expect(coverage(lab().model).notes.some(n => n.id === 'seq-gaps')).toBe(false);
});

test('a record without a numeric global_seq_num takes no part in the count, and its placeholder 0 is no hole', () => {
  const cap = labWith(o => (o['global_seq_num'] === 30 ? { ...o, global_seq_num: undefined } : o));
  expect(cap.model.stats.events).toBe(111);
  // Only the number it should have carried is absent; the placeholder 0 it sorts under does not add anything.
  expect(cap.model.stats.seqGaps).toBe(1);
  expect(cap.model.stats.seqGapRuns).toBe(1);
});

test('the coverage note and the header line say how many events are missing, and what that can hide', () => {
  const m = without([5, 6, 7, 20]).model;
  const note = coverage(m).notes.find(n => n.id === 'seq-gaps')!;
  expect(note.level).toBe('warn');
  expect(note.title).toBe('4 events are missing from the sequence, in 2 places');
  expect(note.detail).toMatch(/drops events when the recorder falls behind/);
  expect(note.detail).toMatch(/lines were removed afterwards/);
  expect(note.detail).toMatch(/a count of what is missing, not a list/);
  expect(captureInfo(m.stats).line).toContain('4 events missing from the sequence');
  expect(coverage(without([5]).model).notes.find(n => n.id === 'seq-gaps')!.title).toBe('1 event is missing from the sequence');
});

test('a Mac Monitor trace is not checked: its sequence numbers restart per ES client', () => {
  // mach_time orders such a trace; with it present the numbers are renumbered and carry no gap information.
  const cap = labWith(o => ({ ...o, telemetry_version: '1', mach_time: 1000 + (o['global_seq_num'] as number) * 10, global_seq_num: (o['global_seq_num'] as number) * 3 }));
  expect(cap.model.stats.seqGaps).toBeUndefined();
  expect(coverage(cap.model).notes.some(n => n.id === 'seq-gaps')).toBe(false);
});
