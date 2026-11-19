// summarize-core.ts: turns a lab capture into findings, through Ficus's own model and rules, and compares them with what the
// public reports say the sample does. Pure functions plus one file reader; no console output, so tests can call them.
import fs from 'node:fs';
import { StringDecoder } from 'node:string_decoder';
import { buildModel } from '../src/model/builder';
import { ancestry } from '../src/model/relations';
import type { CaptureModel, ProcId } from '../src/model/types';
import { analyze, type Finding } from '../src/rules/engine';
import { RULES, type Severity } from '../src/rules/rules';

/**
 * One finding of one capture. `queued` is false for a context-only finding (it would not enter the triage queue by itself).
 * `lineage` is the programs of the process's ancestors, nearest first (empty for a launch-item finding), so a run can be
 * narrowed to the sample's own process tree with `filterUnder`.
 */
export interface FindingRow { ruleId: string; severity: Severity; process: string; evidence: string; mitre: string[]; queued: boolean; lineage: string[];
  /** How many times Ficus produced this same finding (same rule, program and evidence) for different processes; 1 for a single one. */
  count: number }

/**
 * Collects findings into rows. The same finding seen twice for one process (Ficus lists a flagged process's findings both in its
 * queue and per process) is one; the same finding for different processes (a loop that starts the same program hundreds of times)
 * is one row with a `count`, so the report stays readable and the repetition is still visible.
 */
export class FindingCollector {
  readonly rows: FindingRow[] = [];
  /** Findings Ficus produced, repeats included. */
  instances = 0;
  private readonly seenInstance = new Set<string>();
  private readonly byKey = new Map<string, FindingRow>();

  add(f: Pick<Finding, 'ruleId' | 'severity' | 'evidence' | 'mitre'>, process: string, queued: boolean, itemKey: string, lineage: string[]): void {
    const instance = [itemKey, f.ruleId, f.severity, f.evidence].join('\u0000');
    if (this.seenInstance.has(instance)) return;
    this.seenInstance.add(instance);
    this.instances++;
    const key = [f.ruleId, f.severity, process, f.evidence].join('\u0000');
    const existing = this.byKey.get(key);
    if (existing) {
      existing.count++;
      if (queued) existing.queued = true;
      return;
    }
    const row: FindingRow = { ruleId: f.ruleId, severity: f.severity, process, evidence: f.evidence, mitre: [...f.mitre], queued, lineage, count: 1 };
    this.byKey.set(key, row);
    this.rows.push(row);
  }
}

export interface Summary {
  badLines: number; events: number; processes: number; versions: number[];
  /** Counts of event types Ficus does not model, by eslogger event name. */
  otherEvents: Record<string, number>;
  /** Numbers missing from the capture's sequence: events the recorder dropped. */
  seqGaps: number;
  /** Items in Ficus's triage queue for this capture: what a person would have to go through. */
  queueItems: number;
  /** True when at least one exec event carried `fds`, which the stdin checks (shell-from-pipe, the reverse-shell socket check) read. */
  stdinVisible: boolean;
  /** Findings Ficus produced, counting repeats; `rows` has one row per distinct finding, each with a `count`. */
  instances: number;
  rows: FindingRow[];
}

/** A behavior a public report says the sample shows, and the Ficus rule that should catch it (`-`: none exists yet). */
export interface ExpectedRow { behavior: string; mitre: string; rule: string; source: string }

export interface Comparison { hit: ExpectedRow[]; miss: ExpectedRow[]; gap: ExpectedRow[]; review: FindingRow[] }

const EXPECTED_HEADER = 'behavior\tmitre\trule\tsource';

/** The program a finding is about: the image the finding points at, else the process's last image of its own. */
function processLabel(m: CaptureModel, id: ProcId | null, imgIndex: number | null = null): string {
  const p = id === null ? undefined : m.processes.get(id);
  if (!p) return id ?? 'unknown';
  const pointed = imgIndex === null ? undefined : p.images[imgIndex];
  if (pointed?.path) return pointed.path;
  const image = [...p.images].reverse().find(i => !i.inherited && i.path) ?? p.images[p.images.length - 1];
  return image?.path ?? `pid ${p.pid}`;
}

function persistenceLabel(m: CaptureModel, id: string | null): string {
  const item = m.persistence.find(x => x.id === id);
  return item?.plistPath ?? item?.executablePath ?? item?.appPath ?? id ?? 'unknown';
}

/** Builds the model and runs the rules. Queued findings come first; a finding seen both queued and plain is kept once, as queued. */
export function summarize(lines: Iterable<string>): Summary {
  const m = buildModel(lines);
  const a = analyze(m);
  const c = new FindingCollector();
  const lineageOf = (id: ProcId | null): string[] => (id === null ? [] : ancestry(m, id).map(p => processLabel(m, p)));
  for (const q of a.queue) {
    for (const f of q.findings) {
      if (q.kind === 'persistence') c.add(f, persistenceLabel(m, q.persistenceId), true, `item:${q.persistenceId}`, []);
      else c.add(f, processLabel(m, q.procId, f.imgIndex), true, `proc:${q.procId}`, lineageOf(q.procId));
    }
  }
  for (const [id, list] of a.findings) for (const f of list) c.add(f, processLabel(m, id, f.imgIndex), false, `proc:${id}`, lineageOf(id));
  for (const [id, list] of a.contextOnly) for (const f of list) c.add(f, processLabel(m, id, f.imgIndex), false, `proc:${id}`, lineageOf(id));
  return {
    badLines: m.stats.badLines, events: m.stats.events, processes: m.processes.size, versions: m.stats.versions,
    otherEvents: m.stats.otherEvents, seqGaps: m.stats.seqGaps ?? 0, queueItems: a.queue.length, instances: c.instances,
    stdinVisible: [...m.processes.values()].some(p => p.images.some(i => i.stdinIsPipe !== null)), rows: c.rows,
  };
}

/**
 * Events Endpoint Security dropped while recording, found from each event type's own `seq_num` (it counts that type's events
 * from 0 with no holes). Global sequence numbers cannot be used: the harness removes unmodified `close` events on purpose, which
 * leaves holes there, so `close` is not counted (a dropped modified `close` cannot be told from a removed one).
 */
export function countDrops(lines: Iterable<string>, ignore: string[] = ['close']): { total: number; byType: Record<string, number> } {
  const seen = new Map<string, { count: number; max: number }>();
  for (const line of lines) {
    if (line === '') continue;
    let rec: { event?: Record<string, unknown>; seq_num?: unknown };
    try { rec = JSON.parse(line) as typeof rec; } catch { continue; }
    const type = rec.event ? Object.keys(rec.event)[0] : undefined;
    if (type === undefined || typeof rec.seq_num !== 'number' || ignore.includes(type)) continue;
    const s = seen.get(type) ?? { count: 0, max: -1 };
    s.count++;
    if (rec.seq_num > s.max) s.max = rec.seq_num;
    seen.set(type, s);
  }
  const byType: Record<string, number> = {};
  let total = 0;
  for (const [type, s] of seen) {
    const holes = s.max + 1 - s.count;
    if (holes > 0) { byType[type] = holes; total += holes; }
  }
  return { total, byType };
}

/**
 * Only the findings about the sample itself: those whose process, or any ancestor, has NEEDLE in its program path. A lab capture
 * also holds the guest's own activity (macOS's crash reporter running system_profiler, a `tart exec` command, a background
 * service), and comparing every finding with a report would count that as the sample's behavior.
 */
export function filterUnder(rows: FindingRow[], needle: string): FindingRow[] {
  if (needle === '') throw new Error('--under needs a part of the sample\'s program path, not an empty string');
  return rows.filter(r => r.process.includes(needle) || r.lineage.some(p => p.includes(needle)));
}

/**
 * Which checks cannot fire on this capture. Ficus reads where a process's input comes from out of the `fds` list of an `exec` event
 * (`stdinIsPipe`, `stdinIsSocket`), not out of the version number: the macOS 26.6.2 guest reports version 10 and its exec events do
 * carry `fds`, and `shell-from-pipe` fires on its captures. So the note is about the `fds` being there, not about the version.
 */
export function schemaNotes(versions: number[], stdinVisible: boolean): string[] {
  if (stdinVisible) return [];
  const v = versions.length > 0 ? ` (schema ${versions.join('/')})` : '';
  return [`no exec event carries file descriptors${v}, so shell-from-pipe and the socket check in reverse-shell cannot fire; Ficus documents eslogger schema 11 for them`];
}

/** Reads an expected-behaviors file: tab-separated, header `behavior mitre rule source`, `#` comment lines allowed. */
export function parseExpected(tsv: string): ExpectedRow[] {
  const known = new Set(RULES.map(r => r.id));
  const rows: ExpectedRow[] = [];
  let headerSeen = false;
  tsv.split('\n').forEach((raw, i) => {
    const line = raw.replace(/\r$/, '');
    if (line.trim() === '' || line.startsWith('#')) return;
    if (!headerSeen) {
      if (line !== EXPECTED_HEADER) throw new Error(`the header must be: ${EXPECTED_HEADER.split('\t').join(' <tab> ')}`);
      headerSeen = true;
      return;
    }
    const cols = line.split('\t');
    if (cols.length < 4) throw new Error(`line ${i + 1}: expected 4 tab-separated columns (behavior, mitre, rule, source)`);
    const [behavior, mitre, rule, source] = cols as [string, string, string, string];
    if (rule !== '-' && !known.has(rule)) throw new Error(`line ${i + 1}: unknown rule id '${rule}' (use '-' when no rule exists yet)`);
    rows.push({ behavior, mitre, rule, source });
  });
  return rows;
}

/**
 * hit: the rule fired (queued or context only). miss: the rule exists and did not fire. gap: no rule exists yet.
 * review: a high finding whose rule no expected row names, which may be a false positive or a behavior nobody wrote down.
 */
export function compare(rows: FindingRow[], expected: ExpectedRow[]): Comparison {
  const fired = new Set(rows.map(r => r.ruleId));
  const named = new Set(expected.map(e => e.rule).filter(r => r !== '-'));
  return {
    hit: expected.filter(e => e.rule !== '-' && fired.has(e.rule)),
    miss: expected.filter(e => e.rule !== '-' && !fired.has(e.rule)),
    gap: expected.filter(e => e.rule === '-'),
    review: rows.filter(r => r.severity === 'high' && !named.has(r.ruleId)),
  };
}

const cell = (s: string) => s.replace(/\r?\n|\t/g, ' ').replace(/\|/g, '\\|');
function table(head: string[], body: string[][]): string {
  if (body.length === 0) return 'none\n';
  const line = (cols: string[]) => `| ${cols.map(cell).join(' | ')} |`;
  return [line(head), line(head.map(() => '---')), ...body.map(line)].join('\n') + '\n';
}

/** The gap report for one sample, in Markdown. `under`, when given, says the findings were limited to that sample's process tree. */
export function gapMarkdown(family: string, c: Comparison, under?: string): string {
  const expected = (list: ExpectedRow[]) => table(['behavior', 'MITRE', 'rule', 'source'], list.map(e => [e.behavior, e.mitre, e.rule, e.source]));
  return [
    `# ${family}`,
    '',
    `Hit ${c.hit.length}, miss ${c.miss.length}, gap ${c.gap.length}, review ${c.review.length}.`,
    '',
    under === undefined
      ? 'All findings in the capture were compared, including the guest\'s own activity.'
      : `Only findings about the process tree under \`${under.replace(/`/g, '')}\` were compared.`,
    '',
    '## Hit', '', 'A rule fired for a behavior the reports describe.', '', expected(c.hit),
    '## Miss', '', 'A rule exists for the behavior and did not fire. Check the capture: a rule to fix, or the sample did not do it here.', '', expected(c.miss),
    '## Gap', '', 'No rule exists for the behavior yet. Candidates for a new rule.', '', expected(c.gap),
    '## Review', '', 'High findings no expected row names. A false positive, or a behavior nobody wrote down.', '',
    table(['rule', 'severity', 'process', 'evidence'], c.review.map(r => [r.ruleId, r.severity, r.process, r.count > 1 ? `${r.evidence} (${r.count} times)` : r.evidence])),
  ].join('\n');
}

/** One line per distinct finding, six tab-separated columns (the last is how many times it repeated), whatever the evidence holds. */
export function findingsTsv(rows: FindingRow[]): string {
  const flat = (s: string) => s.replace(/\r?\n|\t/g, ' ');
  return ['queued\trule\tseverity\tcount\tprocess\tevidence',
    ...rows.map(r => [r.queued ? 'queued' : 'context', r.ruleId, r.severity, String(r.count), flat(r.process), flat(r.evidence)].join('\t'))].join('\n') + '\n';
}

/** The lines of a (possibly very large) file, read in chunks; multi-byte characters may straddle chunks. */
export function* linesOf(file: string, chunkBytes = 4 << 20): Generator<string> {
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(chunkBytes);
    const decoder = new StringDecoder('utf8');
    let carry = '';
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      const text = carry + (n === 0 ? decoder.end() : decoder.write(buf.subarray(0, n)));
      const parts = text.split('\n');
      carry = parts.pop() ?? '';
      for (const p of parts) yield p.replace(/\r$/, '');
      if (n === 0) break;
    }
    if (carry !== '') yield carry.replace(/\r$/, '');
  } finally {
    fs.closeSync(fd);
  }
}
