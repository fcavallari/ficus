import { expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import { displayName } from '../src/model/relations';
import type { CaptureModel, Image } from '../src/model/types';
import { latestImage } from '../src/model/util';
import { buildReport, reportFileName, signatureOf, type Report, type ReportRow } from '../src/report/report';
import { keepReason, programKey } from '../src/session/routine';
import { coverage } from '../src/ui/triage-model';
import { readLines } from './fixtures';
import { procByPid, queued } from './helpers';
import { GEN, input, lab, strings, verdict } from './report-fixture';

const build = (over: Parameters<typeof input>[0] = {}, redactArgs = false): Report =>
  buildReport(input(over), { redactArgs, generated: GEN });
const rows = (r: Report): ReportRow[] => r.captures.flatMap(c => c.rows ?? []);
const rowOf = (r: Report, pid: number): ReportRow => rows(r).find(x => x.process?.pid === pid)!;
const { m, a } = queued('synthetic-lab.jsonl');

test('every queue row is in the report, in queue order', () => {
  const r = build();
  expect(r.format).toBe('ficus-report');
  expect(r.version).toBe(1);
  expect(r.generated).toBe(GEN);
  expect(r.session).toEqual({ id: 'sess-1', name: 'lab' });
  expect(r.captures[0]!.rows!.map(x => x.key)).toEqual(a.queue.map(q => q.key));
});

test('verdicts and notes are carried, and an untouched row has none', () => {
  const p6 = procByPid(m, 7006).id;
  const p1 = procByPid(m, 7001).id;
  const other = a.queue.find(q => q.procId !== null && q.procId !== p6 && q.procId !== p1)!;
  const r = build({ verdicts: [verdict('fp', p6, 'confirmed', 'n'), verdict('fp', p1, 'benign'), verdict('fp', other.procId!, 'unreviewed', '')] });
  expect(rowOf(r, 7006).verdict).toEqual({ status: 'confirmed', note: 'n', updated: 't' });
  expect(rowOf(r, 7001).verdict?.status).toBe('benign');
  expect(rows(r).find(x => x.key === other.key)!.verdict).toBeNull();
});

test('a routine-hidden row stays, marked; a high row marked routine is kept with its reason', () => {
  const hideable = a.queue.find(q => q.procId !== null && keepReason(q) === null)!;
  const high = a.queue.find(q => q.procId !== null && q.severity === 'high')!;
  const keys = new Set([hideable, high].map(q => programKey(latestImage(m.processes.get(q.procId!)!)!)));
  const r = build({ routineKeys: keys });
  const hidden = rows(r).find(x => x.key === hideable.key)!;
  expect(hidden.hiddenAsRoutine).toBe(true);
  expect(hidden.keptReason).toBeNull();
  const kept = rows(r).find(x => x.key === high.key)!;
  expect(kept.hiddenAsRoutine).toBe(false);
  expect(kept.keptReason).toBe(keepReason(high));
  expect(r.summary.hiddenAsRoutine).toBeGreaterThanOrEqual(1);
  expect(rows(r)).toHaveLength(a.queue.length);
});

test('process detail: pid, ancestry, images, no environment', () => {
  const r = build();
  const p = procByPid(m, 7006);
  const row = rowOf(r, 7006);
  expect(row.kind).toBe('process');
  expect(row.process!.procId).toBe(p.id);
  expect(row.process!.ancestry[0]!.name).toBe(displayName(m, p.originalParent!));
  expect(row.process!.images.length).toBeGreaterThan(0);
  expect(JSON.stringify(r)).not.toContain('"env"');
});

test('signatureOf names the signing state in fixed words', () => {
  const img = (o: Partial<Image>): Image => ({ token: 't', path: '/x', signingId: null, teamId: null, isPlatform: false, csFlags: 0,
    args: null, cwd: null, env: null, stdinIsPipe: null, script: null, time: null, seq: 0, inherited: false, ...o });
  expect(signatureOf(img({ isPlatform: true, signingId: 'com.apple.ls' }))).toBe('apple-platform');
  expect(signatureOf(img({}))).toBe('unsigned');
  expect(signatureOf(img({ signingId: 'a.out', csFlags: 0x2 }))).toBe('adhoc');
  expect(signatureOf(img({ signingId: 'com.x', teamId: 'ABCDE12345' }))).toBe('team-signed');
  expect(signatureOf(img({ signingId: 'com.x' }))).toBe('signed-no-team');
  expect(signatureOf(img({ path: null }))).toBe('unknown');
});

test('launch items: persistence findings carry their items', () => {
  const r = build();
  const withItem = rows(r).filter(x => x.findings.some(f => f.ruleId === 'persistence-item'));
  expect(withItem.length).toBeGreaterThan(0);
  for (const x of withItem) expect(x.launchItems.length).toBeGreaterThanOrEqual(1);
  const standalone = a.queue.filter(q => q.kind === 'persistence');
  for (const q of standalone) {
    const x = rows(r).find(y => y.key === q.key)!;
    expect(x.kind).toBe('persistence');
    expect(x.launchItems[0]!.id).toBe(q.persistenceId);
  }
});

test('file events are capped at 20 shown, with the total', () => {
  const fresh: CaptureModel = buildModel(readLines('synthetic-lab.jsonl'));
  const pid = rowOf(build(), 7006).process!.pid;
  const p = procByPid(fresh, pid);
  p.fileOps = Array.from({ length: 25 }, (_, i) => ({ kind: 'create' as const, path: `/tmp/f${i}`, time: 't', seq: i }));
  const r = build({ loaded: new Map([['fp', lab('fp', fresh)]]) });
  const ops = rowOf(r, pid).process!.fileOps;
  expect(ops.total).toBe(25);
  expect(ops.shown).toHaveLength(20);
  expect(ops.shown[0]!.path).toBe('/tmp/f0');
});

test('context-only findings are counted per rule', () => {
  const want: Record<string, number> = {};
  for (const f of [...a.contextOnly.values()].flat()) want[f.ruleId] = (want[f.ruleId] ?? 0) + 1;
  expect(build().captures[0]!.contextOnly).toEqual(want);
});

test('coverage and capture facts', () => {
  const c = build().captures[0]!;
  expect(c.loaded).toBe(true);
  expect(c.fileName).toBe('synthetic-lab.jsonl');
  expect(c.coverage!.map(x => x.id)).toEqual(coverage(m).notes.map(x => x.id));
  expect(c.schemaVersions).toEqual(m.stats.versions.filter(v => v > 0));
  expect(c.firstTime).toBe(m.stats.firstTime);
});

test('summary counts add up to the rows', () => {
  const r = build();
  const sum = (o: Record<string, number>): number => Object.values(o).reduce((x, y) => x + y, 0);
  expect(r.summary.rows).toBe(a.queue.length);
  expect(sum(r.summary.bySeverity)).toBe(r.summary.rows);
  expect(sum(r.summary.byVerdict)).toBe(r.summary.rows);
  expect(r.summary.capturesNotLoaded).toBe(0);
});

test('numbering follows the Markdown order: severity, then capture, then queue order', () => {
  const r = build({ loaded: new Map([['fp', lab('fp')], ['fp2', lab('fp2')]]),
    capRecs: [input().capRecs[0]!, { ...input().capRecs[0]!, fingerprint: 'fp2', fileName: 'z-second.jsonl' }] });
  const order = { high: 0, med: 1, low: 2 } as const;
  const expected = r.captures.flatMap((c, ci) => (c.rows ?? []).map((x, qi) => ({ x, ci, qi })))
    .sort((p, q) => order[p.x.severity!] - order[q.x.severity!] || p.ci - q.ci || p.qi - q.qi)
    .map(e => e.x.n);
  expect(expected).toEqual(expected.map((_, i) => i + 1));
});

test('a capture with an empty queue still reports its facts', () => {
  const cap = { ...lab(), analysis: { ...a, queue: [] } };
  const r = build({ loaded: new Map([['fp', cap]]) });
  expect(r.captures[0]!.rows).toEqual([]);
  expect(r.summary.rows).toBe(0);
  expect(r.captures[0]!.coverage).toBeDefined();
});

test('reportFileName follows the session save name', () => {
  expect(reportFileName({ id: 'sess-1', name: 'lab' }, 'md')).toMatch(/^lab\.[0-9a-f]{8}\.ficus-report\.md$/);
  expect(reportFileName({ id: 'sess-1', name: 'lab' }, 'json')).toMatch(/^lab\.[0-9a-f]{8}\.ficus-report\.json$/);
});

test('the report is deterministic', () => {
  expect(JSON.stringify(build())).toBe(JSON.stringify(build()));
});

// --- Task 2: captures not loaded, and processes the user marked ---------------------------------------------------

const gone = { ...input().capRecs[0]!, fingerprint: 'gone', fileName: 'gone.jsonl' };

test('a capture that is not loaded is listed with its verdicts', () => {
  const r = build({
    capRecs: [...input().capRecs, gone],
    verdicts: [verdict('gone', 'p1', 'confirmed', 'bad', { name: 'evil' }), verdict('gone', 'p2', 'unreviewed', '')],
  });
  const c = r.captures.find(x => x.fingerprint === 'gone')!;
  expect(c.loaded).toBe(false);
  expect(c.rows).toBeUndefined();
  expect(c.notLoaded).toEqual([{ procKey: 'p1', status: 'confirmed', note: 'bad', snapshot: expect.objectContaining({ name: 'evil' }) }]);
  expect(r.summary.capturesNotLoaded).toBe(1);
});

test('a verdict on a process the rules did not flag is reported as user-marked', () => {
  const queuedIds = new Set(a.queue.map(q => q.procId));
  const p = [...m.processes.values()].find(x => !queuedIds.has(x.id) && !x.ghost)!;
  const r = build({ verdicts: [verdict('fp', p.id, 'confirmed', 'odd')] });
  const marked = r.captures[0]!.userMarked!;
  expect(marked).toHaveLength(1);
  expect(marked[0]!.kind).toBe('user-marked');
  expect(marked[0]!.severity).toBeNull();
  expect(marked[0]!.verdict?.note).toBe('odd');
  expect(marked[0]!.findings.map(f => f.ruleId)).toEqual((a.contextOnly.get(p.id) ?? []).map(f => f.ruleId));
  expect(marked[0]!.process?.pid).toBe(p.pid);
  expect(r.summary.userMarked).toBe(1);
  expect(r.summary.rows).toBe(a.queue.length);
});

test('a verdict whose process is missing is reported from its snapshot', () => {
  const r = build({ verdicts: [verdict('fp', 'nope', 'confirmed', '', { name: 'ghosty' })] });
  const marked = r.captures[0]!.userMarked!;
  expect(marked).toHaveLength(1);
  expect(marked[0]!.name).toBe('ghosty');
  expect(marked[0]!.process).toBeUndefined();
});

test('user-marked rows are numbered after every queue row', () => {
  const r = build({ verdicts: [verdict('fp', 'nope', 'benign', '', { name: 'ghosty' })] });
  expect(r.captures[0]!.userMarked![0]!.n).toBe(a.queue.length + 1);
});

// --- Task 3: redaction --------------------------------------------------------------------------------------------

const values = (r: Report, skip: string[] = []): string[] => strings(r).filter(s => !skip.includes(s.key)).map(s => s.value);
const holds = (r: Report, needle: string, skip: string[] = []): boolean => values(r, skip).some(v => v.includes(needle));

test('redaction hides the dscl password everywhere', () => {
  expect(holds(build({}, true), 'labpass-not-real')).toBe(false);
  expect(holds(build({}, false), 'labpass-not-real')).toBe(true);
  const imgs = rowOf(build({}, true), 7016).process!.images;
  expect(imgs[imgs.length - 1]!.args).toEqual(['dscl', '[redacted]', '[redacted]', '[redacted]', '[redacted]']);
});

test('redaction reaches captures that are not loaded', () => {
  const over = { capRecs: [...input().capRecs, gone],
    verdicts: [verdict('gone', 'p1', 'confirmed', '', { args: ['dscl', '.', '-authonly', 'labuser', 'labpass-not-real'] })] };
  expect(holds(build(over, true), 'labpass-not-real')).toBe(false);
  expect(holds(build(over, false), 'labpass-not-real')).toBe(true);
});

/** Every value the capture records in a field of its own, joined: `holds` matches by substring, so an argument that sits inside one of them cannot be told from the field. */
function keptText(model: CaptureModel): string {
  const out: string[] = [];
  for (const p of model.processes.values()) {
    out.push(displayName(model, p.id));
    for (const i of p.images) out.push(i.path ?? '', i.cwd ?? '', i.script ?? '');
    for (const f of p.fileOps) out.push(f.path, f.toPath ?? '');
  }
  for (const i of model.persistence) out.push(i.plistPath ?? '', i.executablePath ?? '', i.appPath ?? '');
  return out.join('\n');
}

test('no argument survives redaction outside kept fields', () => {
  const kept = keptText(m);
  const args = new Set<string>();
  for (const p of m.processes.values()) for (const i of p.images) for (const x of i.args?.slice(1) ?? []) if (x.length >= 3 && !kept.includes(x)) args.add(x);
  expect([...args].some(x => x.includes('display dialog'))).toBe(true);
  const r = build({}, true);
  const leaked = [...args].filter(x => holds(r, x, ['ruleId', 'title', 'explanation', 'note']));
  expect(leaked).toEqual([]);
});

test('an argument that is only part of some path is still redacted', () => {
  const fresh = buildModel(readLines('synthetic-lab.jsonl'));
  const p = procByPid(fresh, 7016);
  const img = p.images.find(i => i.args?.[0] === 'dscl')!;
  // `tmp` occurs inside paths of the capture; typed as a password it is a secret, not repeated evidence.
  img.args = ['dscl', '.', '-authonly', 'labuser', 'tmp'];
  const cap = lab('fp', fresh);
  const q = cap.analysis.queue.find(x => x.procId === p.id)!;
  q.findings[0]!.evidence = 'checked the password tmp';
  const evidence = rowOf(build({ loaded: new Map([['fp', cap]]) }, true), 7016).findings[0]!.evidence;
  expect(evidence).toBe('checked the password [redacted]');
});

test('redacts a secret that the evidence limit cuts in half', () => {
  const fresh = buildModel(readLines('synthetic-lab.jsonl'));
  const p = procByPid(fresh, 7016);
  const img = p.images.find(i => i.args?.[0] === 'dscl')!;
  img.args = ['dscl', '.', '-authonly', 'labuser', 'x'.repeat(280) + 'SECRETSECRETSECRET'];
  const r = build({ loaded: new Map([['fp', lab('fp', fresh)]]) }, true);
  expect(holds(r, 'xxxxxxxxxx')).toBe(false);
  expect(holds(r, 'SECRET')).toBe(false);
});

test('notes are not redacted', () => {
  const r = build({ verdicts: [verdict('fp', procByPid(m, 7006).id, 'confirmed', 'pw is hunter22')] }, true);
  expect(holds(r, 'pw is hunter22')).toBe(true);
});

test('the report says whether it is redacted', () => {
  expect(build({}, true).redacted).toBe(true);
  expect(build({}, false).redacted).toBe(false);
});

// --- final review fixes --------------------------------------------------------------------------------------------

test('redaction hides a script path worked out from a relative argument', () => {
  for (const arg of ['./stealer.scpt', '../Shared/stealer.scpt', 'ab']) {
    const fresh = buildModel(readLines('synthetic-lab.jsonl'));
    const img = procByPid(fresh, 7006).images.find(i => i.args?.[0] === 'osascript')!;
    img.args = ['osascript', arg];
    img.cwd = '/Users/Shared';
    const cap = lab('fp', fresh);
    const plain = buildReport(input({ loaded: new Map([['fp', cap]]) }), { redactArgs: false, generated: GEN });
    const leaf = arg === 'ab' ? '/Users/Shared/ab' : 'stealer.scpt';
    expect(holds(plain, leaf), arg).toBe(true);   // the rule fired and quoted the resolved path
    const r = buildReport(input({ loaded: new Map([['fp', cap]]) }), { redactArgs: true, generated: GEN });
    expect(holds(r, leaf, ['ruleId', 'title', 'explanation', 'note']), arg).toBe(false);
  }
});
