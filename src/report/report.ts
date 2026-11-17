import type { LoadedCapture } from '../ingest/load';
import { ancestry, childrenIndex, displayName, registrant } from '../model/relations';
import type { CaptureModel, FileOp, Image, PersistenceItem, ProcId, Process } from '../model/types';
import { itemTypeName, normPath, resolvePath } from '../model/util';
import type { Finding, QueueItem } from '../rules/engine';
import { cmdline, isAdhoc, isUnsigned, type Severity } from '../rules/rules';
import { idHash, REDACTED, redactArgv, slug } from '../session/export';
import { applyRoutine } from '../session/routine';
import type { CaptureRec, Session, Status, Verdict, VerdictSnapshot } from '../session/store';
import { coverage, itemName, verdictKey } from '../ui/triage-model';

/**
 * The report a self-service user sends to secops: every flagged row of the session's loaded captures, triaged or not,
 * with what a reader without the capture needs to judge it. The JSON file is this object; the Markdown is rendered
 * from it, so the two always agree. The shape is versioned: tools ingest it.
 */
export const REPORT_FORMAT = 'ficus-report';
export const FILE_OPS_SHOWN = 20;

export type Signature = 'apple-platform' | 'team-signed' | 'signed-no-team' | 'adhoc' | 'unsigned' | 'unknown';
export interface ReportInput {
  session: Pick<Session, 'id' | 'name'>;
  capRecs: CaptureRec[];
  loaded: Map<string, LoadedCapture>;
  /** Every verdict of the session. */
  verdicts: Verdict[];
  routineKeys: Set<string>;
}
export interface ReportOpts { redactArgs: boolean; generated: string }
export interface ProcRef { name: string; pid: number }
export interface ReportImage { path: string | null; args: string[] | null; cwd: string | null; signingId: string | null;
  teamId: string | null; isPlatform: boolean; signature: Signature; script: string | null; stdinIsPipe: boolean | null;
  time: string | null; inherited: boolean }
export interface ReportLaunchItem { id: string; type: number | null; typeName: string; plistPath: string | null;
  executablePath: string | null; appPath: string | null; time: string;
  registeredBy: (ProcRef & { via: 'app' | 'instigator' | 'creator' }) | null }
export type ReportFinding = Pick<Finding, 'ruleId' | 'severity' | 'title' | 'explanation' | 'mitre' | 'evidence' | 'trait'>;
export interface ReportRow {
  /** 1-based, across the whole report, in the order the Markdown prints rows. */
  n: number;
  key: string; kind: 'process' | 'persistence' | 'user-marked';
  name: string;
  /** Null only for a user-marked row. */
  severity: Severity | null;
  /** The user's view; null when they never touched the row. */
  verdict: { status: Status; note: string; updated: string } | null;
  inFlaggedChain: boolean; reconBurst: boolean;
  hiddenAsRoutine: boolean; keptReason: string | null;
  findings: ReportFinding[];
  process?: { procId: string; pid: number; startTime: string | null; exitTime: string | null; images: ReportImage[];
    ancestry: ProcRef[]; responsible: ProcRef | null; children: number;
    fileOps: { total: number; shown: FileOp[] } };
  launchItems: ReportLaunchItem[];
}
export interface ReportCapture {
  fingerprint: string; fileName: string; size: number; events: number; processes: number;
  firstTime: string | null; lastTime: string | null; schemaVersions: number[];
  loaded: boolean;
  coverage?: { id: string; level: 'warn' | 'info'; title: string; detail: string; checks: string[] }[];
  contextOnly?: Record<string, number>;
  rows?: ReportRow[];
  userMarked?: ReportRow[];
  notLoaded?: { procKey: string; status: Status; note: string; snapshot: VerdictSnapshot }[];
}
export interface Report {
  format: typeof REPORT_FORMAT; version: 1; generated: string;
  session: { id: string; name: string }; redacted: boolean;
  summary: { rows: number; bySeverity: Record<Severity, number>; byVerdict: Record<Status, number>;
    hiddenAsRoutine: number; userMarked: number; capturesNotLoaded: number };
  captures: ReportCapture[];
}

export function signatureOf(img: Image): Signature {
  if (img.path === null) return 'unknown';
  if (img.isPlatform) return 'apple-platform';
  if (isUnsigned(img)) return 'unsigned';
  if (isAdhoc(img)) return 'adhoc';
  return img.teamId ? 'team-signed' : 'signed-no-team';
}

export const reportFileName = (s: Pick<Session, 'id' | 'name'>, ext: 'md' | 'json'): string =>
  `${slug(s.name)}.${idHash(s.id)}.ficus-report.${ext}`;

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const SEV_ORDER: Record<Severity, number> = { high: 0, med: 1, low: 2 };

/** A verdict as the report shows it: null when nothing was set (unreviewed with no note counts as nothing). */
const userView = (v: Verdict | undefined): ReportRow['verdict'] =>
  v && (v.status !== 'unreviewed' || v.note !== '') ? { status: v.status, note: v.note, updated: v.updated } : null;

const ref = (m: CaptureModel, id: ProcId): ProcRef => ({ name: displayName(m, id), pid: m.processes.get(id)?.pid ?? -1 });

const reportFinding = ({ ruleId, severity, title, explanation, mitre, evidence, trait }: Finding): ReportFinding =>
  ({ ruleId, severity, title, explanation, mitre, evidence, trait });

/** Shortest argument redaction looks for in free text: one- and two-letter flags (-c, -w) occur in ordinary words. */
const MIN_REDACTED = 3;

/**
 * Every value the capture records in a field of its own (program and script paths, process names, working directories,
 * file-event paths, launch item paths). Redaction keeps an argument that is exactly one of these: they are evidence, and
 * an argument that repeats one is not a secret typed on a command line. A path also counts in its normalized form
 * (`/private/tmp/x` as `/tmp/x`) and as a folder above a recorded path. Whole values, not substrings: a password such
 * as `admin` or `bin` is part of some path in almost every capture, and must still be redacted.
 */
function keptValues(m: CaptureModel): Set<string> {
  const out = new Set<string>();
  const add = (v: string | null | undefined): void => {
    if (!v) return;
    out.add(v);
    if (!v.startsWith('/')) return;
    const n = normPath(v);
    out.add(n);
    // Each folder above it, so `/tmp/stage` is kept when `/tmp/stage/a.txt` was recorded; a bare word never matches.
    for (let i = n.lastIndexOf('/'); i > 0; i = n.lastIndexOf('/', i - 1)) out.add(n.slice(0, i));
  };
  for (const p of m.processes.values()) {
    add(displayName(m, p.id));
    for (const i of p.images) { add(i.path); add(i.cwd); add(i.script); }
    for (const f of p.fileOps) { add(f.path); add(f.toPath); }
  }
  for (const i of m.persistence) { add(i.plistPath); add(i.executablePath); add(i.appPath); }
  return out;
}

function launchItem(m: CaptureModel, item: PersistenceItem): ReportLaunchItem {
  const who = registrant(m, item);
  return {
    id: item.id, type: item.itemType, typeName: itemTypeName(item.itemType), plistPath: item.plistPath,
    executablePath: item.executablePath, appPath: item.appPath, time: item.time,
    registeredBy: who ? { ...ref(m, who.id), via: who.via } : null,
  };
}

/** Builds the per-capture parts: what a row says about its process and launch items. */
class CaptureRows {
  private readonly m: CaptureModel;
  private readonly children: Map<ProcId | null, ProcId[]>;
  private readonly items: Map<string, PersistenceItem>;
  private kept: Set<string> | null = null;
  constructor(readonly cap: LoadedCapture, private readonly redact: boolean) {
    this.m = cap.model;
    this.children = childrenIndex(this.m, 'original');
    this.items = new Map(this.m.persistence.map(i => [i.id, i]));
  }

  process(id: ProcId): ReportRow['process'] | undefined {
    const m = this.m;
    const p = m.processes.get(id);
    if (!p) return undefined;
    return {
      procId: p.id, pid: p.pid, startTime: p.startTime, exitTime: p.exitTime,
      images: p.images.map(i => ({
        path: i.path, args: this.redact ? redactArgv(i.args) : i.args, cwd: i.cwd, signingId: i.signingId, teamId: i.teamId, isPlatform: i.isPlatform,
        signature: signatureOf(i), script: i.script, stdinIsPipe: i.stdinIsPipe, time: i.time, inherited: i.inherited,
      })),
      ancestry: ancestry(m, p.id, 'original').map(a => ref(m, a)),
      responsible: p.responsible !== null && p.responsible !== p.id ? ref(m, p.responsible) : null,
      children: this.children.get(p.id)?.length ?? 0,
      fileOps: { total: p.fileOps.length, shown: p.fileOps.slice(0, FILE_OPS_SHOWN) },
    };
  }

  /**
   * A finding as the report shows it. Redacting, its evidence loses the command line it quotes: first the exact
   * `cmdline` text of the finding's image (so a line the evidence limit cut short is matched as cut), then any other
   * argument of the process, as typed or resolved against its working directory, that is not also a kept value.
   */
  finding(f: Finding, p: Process | undefined): ReportFinding {
    const out = reportFinding(f);
    if (!this.redact || !p) return out;
    let e = out.evidence;
    const img = f.imgIndex !== null ? p.images[f.imgIndex] : undefined;
    if (img?.args) e = e.split(cmdline(img)).join(cmdline({ ...img, args: redactArgv(img.args) }));
    this.kept ??= keptValues(this.m);
    // An argument as typed, and as a rule may have resolved it against the working directory (osascript's script path).
    const typed = p.images.flatMap(i => (i.args?.slice(1) ?? []).flatMap(a => [a, resolvePath(a, i.cwd)]));
    const args = [...new Set(typed)]
      .filter(a => a.length >= MIN_REDACTED && a !== REDACTED && !this.kept!.has(a) && !this.kept!.has(normPath(a)))
      .sort((a, b) => b.length - a.length);
    for (const a of args) e = e.split(a).join(REDACTED);
    return { ...out, evidence: e };
  }

  launchItems(ids: (string | null)[]): ReportLaunchItem[] {
    const seen = new Set<string>();
    const out: ReportLaunchItem[] = [];
    for (const id of ids) {
      const item = id !== null ? this.items.get(id) : undefined;
      if (!item || seen.has(item.id)) continue;
      seen.add(item.id);
      out.push(launchItem(this.m, item));
    }
    return out;
  }

  /** A process the user gave a verdict although the rules did not queue it; named from its snapshot when it is gone. */
  userMarkedRow(v: Verdict): ReportRow {
    const proc = this.process(v.procKey);
    return {
      n: 0, key: v.procKey, kind: 'user-marked', name: proc ? displayName(this.m, v.procKey) : v.snapshot.name,
      severity: null, verdict: userView(v), inFlaggedChain: false, reconBurst: false, hiddenAsRoutine: false, keptReason: null,
      findings: (this.cap.analysis.contextOnly.get(v.procKey) ?? []).map(f => this.finding(f, this.m.processes.get(v.procKey))),
      ...(proc ? { process: proc } : {}),
      launchItems: [],
    };
  }

  queueRow(q: QueueItem, verdict: Verdict | undefined, hidden: boolean, kept: string | null): ReportRow {
    return {
      n: 0, key: q.key, kind: q.kind, name: itemName(this.cap, q), severity: q.severity, verdict: userView(verdict),
      inFlaggedChain: q.inFlaggedChain, reconBurst: q.reconBurst, hiddenAsRoutine: hidden, keptReason: kept,
      findings: q.findings.map(f => this.finding(f, q.procId !== null ? this.m.processes.get(q.procId) : undefined)),
      ...(q.procId !== null ? { process: this.process(q.procId) } : {}),
      launchItems: this.launchItems(q.kind === 'persistence' ? [q.persistenceId] : q.findings.map(f => f.persistenceId)),
    };
  }
}

export function buildReport(input: ReportInput, opts: ReportOpts): Report {
  const recs = [...input.capRecs].sort((a, b) => cmp(a.fileName, b.fileName) || cmp(a.fingerprint, b.fingerprint));
  const byCapture = new Map<string, Verdict[]>();
  for (const v of input.verdicts) {
    const list = byCapture.get(v.fingerprint);
    if (list) list.push(v);
    else byCapture.set(v.fingerprint, [v]);
  }

  const captures: ReportCapture[] = recs.map(rec => {
    const cap = input.loaded.get(rec.fingerprint);
    const base = { fingerprint: rec.fingerprint, fileName: rec.fileName, size: rec.size, events: rec.events, processes: rec.processes };
    const stored = [...(byCapture.get(rec.fingerprint) ?? [])].filter(v => userView(v) !== null).sort((a, b) => cmp(a.procKey, b.procKey));
    if (!cap) {
      return { ...base, firstTime: null, lastTime: null, schemaVersions: [], loaded: false,
        notLoaded: stored.map(({ procKey, status, note, snapshot }) =>
          ({ procKey, status, note, snapshot: opts.redactArgs ? { ...snapshot, args: redactArgv(snapshot.args) } : snapshot })) };
    }
    const m = cap.model;
    const verdicts = new Map((byCapture.get(rec.fingerprint) ?? []).map(v => [v.procKey, v]));
    const routine = applyRoutine(cap.analysis, m, input.routineKeys);
    const shown = new Set(routine.queue.map(q => q.key));
    const queued = new Set(cap.analysis.queue.map(verdictKey));
    const build = new CaptureRows(cap, opts.redactArgs);
    const contextOnly: Record<string, number> = {};
    for (const f of [...cap.analysis.contextOnly.values()].flat()) contextOnly[f.ruleId] = (contextOnly[f.ruleId] ?? 0) + 1;
    return {
      ...base, events: m.stats.events, processes: m.processes.size,
      firstTime: m.stats.firstTime, lastTime: m.stats.lastTime, schemaVersions: m.stats.versions.filter(v => v > 0),
      loaded: true,
      coverage: coverage(m).notes.map(({ id, level, title, detail, checks }) => ({ id, level, title, detail, checks })),
      contextOnly,
      rows: cap.analysis.queue.map(q =>
        build.queueRow(q, verdicts.get(verdictKey(q)), !shown.has(q.key), routine.kept.get(q.key) ?? null)),
      userMarked: stored.filter(v => !queued.has(v.procKey)).map(v => build.userMarkedRow(v)),
    };
  });

  // Number the rows in the order the Markdown prints them: by severity, then capture, then queue order.
  const ordered = captures.flatMap((c, ci) => (c.rows ?? []).map((row, qi) => ({ row, ci, qi })))
    .sort((a, b) => SEV_ORDER[a.row.severity!] - SEV_ORDER[b.row.severity!] || a.ci - b.ci || a.qi - b.qi);
  let n = 0;
  for (const { row } of ordered) row.n = ++n;
  for (const c of captures) for (const row of c.userMarked ?? []) row.n = ++n;

  const all = captures.flatMap(c => c.rows ?? []);
  const bySeverity: Record<Severity, number> = { high: 0, med: 0, low: 0 };
  const byVerdict: Record<Status, number> = { unreviewed: 0, confirmed: 0, benign: 0 };
  for (const row of all) {
    bySeverity[row.severity!]++;
    byVerdict[row.verdict?.status ?? 'unreviewed']++;
  }
  return {
    format: REPORT_FORMAT, version: 1, generated: opts.generated,
    session: { id: input.session.id, name: input.session.name }, redacted: opts.redactArgs,
    summary: {
      rows: all.length, bySeverity, byVerdict, hiddenAsRoutine: all.filter(r => r.hiddenAsRoutine).length,
      userMarked: captures.reduce((k, c) => k + (c.userMarked?.length ?? 0), 0), capturesNotLoaded: captures.filter(c => !c.loaded).length,
    },
    captures,
  };
}
