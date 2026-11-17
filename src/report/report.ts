import type { LoadedCapture } from '../ingest/load';
import { ancestry, childrenIndex, displayName, registrant } from '../model/relations';
import type { CaptureModel, FileOp, Image, PersistenceItem, ProcId } from '../model/types';
import { itemTypeName } from '../model/util';
import type { Finding, QueueItem } from '../rules/engine';
import { isAdhoc, isUnsigned, type Severity } from '../rules/rules';
import { idHash, slug } from '../session/export';
import { applyRoutine } from '../session/routine';
import type { CaptureRec, Session, Status, Verdict, VerdictSnapshot } from '../session/store';
import { coverage, itemName, verdictKey } from '../ui/triage-model';

/**
 * The report a self-service user sends to secops: every flagged row of the session's loaded captures, triaged or not,
 * with what a reader without the capture needs to judge it. The JSON file is this object; the Markdown is rendered
 * from it, so the two always agree. The shape is versioned: tools ingest it.
 */
export const REPORT_FORMAT = 'gameleira-report';
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
  `${slug(s.name)}.${idHash(s.id)}.gameleira-report.${ext}`;

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const SEV_ORDER: Record<Severity, number> = { high: 0, med: 1, low: 2 };

/** A verdict as the report shows it: null when nothing was set (unreviewed with no note counts as nothing). */
const userView = (v: Verdict | undefined): ReportRow['verdict'] =>
  v && (v.status !== 'unreviewed' || v.note !== '') ? { status: v.status, note: v.note, updated: v.updated } : null;

const ref = (m: CaptureModel, id: ProcId): ProcRef => ({ name: displayName(m, id), pid: m.processes.get(id)?.pid ?? -1 });

const reportFinding = ({ ruleId, severity, title, explanation, mitre, evidence, trait }: Finding): ReportFinding =>
  ({ ruleId, severity, title, explanation, mitre, evidence, trait });

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
  constructor(readonly cap: LoadedCapture) {
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
        path: i.path, args: i.args, cwd: i.cwd, signingId: i.signingId, teamId: i.teamId, isPlatform: i.isPlatform,
        signature: signatureOf(i), script: i.script, stdinIsPipe: i.stdinIsPipe, time: i.time, inherited: i.inherited,
      })),
      ancestry: ancestry(m, p.id, 'original').map(a => ref(m, a)),
      responsible: p.responsible !== null && p.responsible !== p.id ? ref(m, p.responsible) : null,
      children: this.children.get(p.id)?.length ?? 0,
      fileOps: { total: p.fileOps.length, shown: p.fileOps.slice(0, FILE_OPS_SHOWN) },
    };
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

  queueRow(q: QueueItem, verdict: Verdict | undefined, hidden: boolean, kept: string | null): ReportRow {
    return {
      n: 0, key: q.key, kind: q.kind, name: itemName(this.cap, q), severity: q.severity, verdict: userView(verdict),
      inFlaggedChain: q.inFlaggedChain, reconBurst: q.reconBurst, hiddenAsRoutine: hidden, keptReason: kept,
      findings: q.findings.map(reportFinding),
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
    if (!cap) return { ...base, firstTime: null, lastTime: null, schemaVersions: [], loaded: false };
    const m = cap.model;
    const verdicts = new Map((byCapture.get(rec.fingerprint) ?? []).map(v => [v.procKey, v]));
    const routine = applyRoutine(cap.analysis, m, input.routineKeys);
    const shown = new Set(routine.queue.map(q => q.key));
    const build = new CaptureRows(cap);
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
    };
  });

  // Number the rows in the order the Markdown prints them: by severity, then capture, then queue order.
  const ordered = captures.flatMap((c, ci) => (c.rows ?? []).map((row, qi) => ({ row, ci, qi })))
    .sort((a, b) => SEV_ORDER[a.row.severity!] - SEV_ORDER[b.row.severity!] || a.ci - b.ci || a.qi - b.qi);
  let n = 0;
  for (const { row } of ordered) row.n = ++n;

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
      userMarked: 0, capturesNotLoaded: captures.filter(c => !c.loaded).length,
    },
    captures,
  };
}
