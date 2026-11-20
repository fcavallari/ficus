import type { LoadedCapture } from '../ingest/load';
import type { ParentMode } from '../model/relations';
import type { ProcId } from '../model/types';
import { basename, persistenceItem, timeMs } from '../model/util';
import type { QueueItem } from '../rules/engine';
import { SEVERITY_RANK, type Severity } from '../rules/rules';
import { processTimeline, type TimelineEvent, type TimelineKind } from './timeline';
import { forestOf, keepSet, ROOT, UNREACHABLE } from './tree-model';

/**
 * The Timeline tab's model: one lane per process, a bar from when the capture first shows it to its recorded exit, in
 * tree order, so the tree can be watched growing over time. Everything placed is a recorded event at its recorded time;
 * a bar end with nothing recorded (already running, still running) is marked as such, never drawn as an event.
 */

/** Which processes get a lane: the flagged ones with their lineage, the selected one with its lineage, or all of them. */
export type LaneScope = 'flagged' | 'selected' | 'all';

export interface LaneTick { key: string; ms: number; seq: number; kind: TimelineKind; severity: Severity | null;
  /** What it touched: the program, file or launch item path. */
  path?: string | null }

export interface Lane {
  id: ProcId;
  /** Depth among the lanes shown (a parent that has no lane does not count). */
  depth: number;
  /** Index of the lane it hangs from under the parent mode, or null at the top level. */
  parent: number | null;
  startMs: number;
  endMs: number;
  /** Running before the capture began: the bar's start is the capture's start, not an event. */
  before: boolean;
  /** No exit recorded: the bar's end is the capture's end, not an event. */
  after: boolean;
  /** Each program the process ran (exec, or an image first seen later), at the time it was recorded. */
  execs: { ms: number; name: string }[];
  /** Its timed events other than fork, spawn and exit, in time order. */
  ticks: LaneTick[];
  /** A flagged process: the triage queue holds it. */
  flagged: boolean;
  /**
   * A process the capture never saw, only referenced as a parent: it has a lane so the processes hanging from it stay
   * together, and no bar, since nothing about its lifetime was recorded.
   */
  ghost: boolean;
}

/** A step of the replay: an event worth stopping at, on the lane it belongs to. */
export interface Moment { ms: number; seq: number; lane: number; e: TimelineEvent }

export interface Lanes {
  lanes: Lane[];
  moments: Moment[];
  /** The capture's span: its first and last recorded times. */
  t0: number;
  t1: number;
  /** Events of the shown processes that carry no usable time, so are not placed. */
  untimed: number;
  /** More than MAX_LANES processes matched: the rest are left out. */
  truncated: boolean;
}

export const MAX_LANES = 20_000;

export interface LaneOptions { mode: ParentMode; scope: LaneScope; flagged: ProcId[]; selected: ProcId | null }

/**
 * The processes the triage queue holds. A launch item no process owns has a queue row of its own: its lane is the app
 * that registered it, else the caller that asked for it, else the process that reported it, so its event is on screen.
 */
export function flaggedIds(cap: LoadedCapture, queue: QueueItem[]): ProcId[] {
  const ids = new Set<ProcId>();
  for (const q of queue) {
    if (q.procId !== null) { for (const id of q.members) ids.add(id); continue; }
    const item = persistenceItem(cap.model, q.persistenceId);
    if (!item) continue;
    const who = [item.app, item.instigator, item.emitter].find(id => id !== null && cap.model.processes.get(id)?.ghost === false);
    if (who) ids.add(who);
  }
  return [...ids];
}

const STORY: ReadonlySet<TimelineKind> = new Set<TimelineKind>(['fork', 'exec', 'btm_add', 'btm_remove', 'exit']);

const worst = (e: TimelineEvent): Severity | null =>
  e.findings.reduce<Severity | null>((w, f) => (w === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[w] ? f.severity : w), null);

export function buildLanes(cap: LoadedCapture, o: LaneOptions): Lanes {
  const m = cap.model;
  const forest = forestOf(m, o.mode);
  const flaggedSet = new Set(o.flagged);
  const anchors = o.scope === 'flagged' ? o.flagged : o.scope === 'selected' && o.selected !== null ? [o.selected] : [];
  const anchorSet = new Set(anchors);
  const keep = keepSet(forest, anchors);

  // Tree order: depth first from the roots, children by first appearance (forestOf already sorts them).
  const order: { id: ProcId; parent: number | null; depth: number }[] = [];
  let truncated = false;
  const stack: { id: ProcId; parent: number | null; depth: number; under: boolean }[] = [];
  const pushKids = (key: string, parent: number | null, depth: number, under: boolean) => {
    const kids = forest.kids.get(key) ?? [];
    for (let i = kids.length - 1; i >= 0; i--) stack.push({ id: kids[i]!, parent, depth, under });
  };
  pushKids(UNREACHABLE, null, 0, false);
  pushKids(ROOT, null, 0, false);
  while (stack.length > 0) {
    const cur = stack.pop()!;
    const p = m.processes.get(cur.id);
    const under = cur.under || anchorSet.has(cur.id);
    const inScope = o.scope === 'all' || under || keep.has(cur.id);
    // A process never seen gets a lane only when something hangs from it.
    const shown = p !== undefined && inScope && (!p.ghost || (forest.kids.get(cur.id)?.length ?? 0) > 0);
    if (shown && order.length >= MAX_LANES) { truncated = true; break; }
    if (shown) {
      order.push({ id: cur.id, parent: cur.parent, depth: cur.depth });
      pushKids(cur.id, order.length - 1, cur.depth + 1, under);
    }
  }

  let lo = timeMs(m.stats.firstTime) ?? Infinity;
  let hi = timeMs(m.stats.lastTime) ?? -Infinity;
  let untimed = 0;
  const built: { lane: Omit<Lane, 'startMs' | 'endMs' | 'before' | 'after'>; events: TimelineEvent[] }[] = [];
  for (const { id, parent, depth } of order) {
    const events = m.processes.get(id)!.ghost ? [] : processTimeline(cap, id, false).events;
    const execs: Lane['execs'] = [];
    const ticks: LaneTick[] = [];
    for (const e of events) {
      if (e.kind === 'spawn') continue;
      const t = timeMs(e.time);
      // An image seen without its exec has no time of its own in the model (it is not a recorded event that was lost).
      if (t === null) { if (e.kind !== 'image') untimed++; continue; }
      if (t < lo) lo = t;
      if (t > hi) hi = t;
      if (e.kind === 'fork' || e.kind === 'exit') continue;
      if (e.kind === 'exec' || e.kind === 'image') execs.push({ ms: t, name: basename(e.path) || '?' });
      ticks.push({ key: e.key, ms: t, seq: e.seq, kind: e.kind, severity: worst(e), path: e.path });
    }
    ticks.sort((a, b) => a.ms - b.ms || a.seq - b.seq);
    execs.sort((a, b) => a.ms - b.ms);
    built.push({ lane: { id, parent, depth, execs, ticks, flagged: flaggedSet.has(id), ghost: m.processes.get(id)!.ghost }, events });
  }
  const t0 = Number.isFinite(lo) ? lo : 0;
  const t1 = Number.isFinite(hi) && hi > t0 ? hi : t0 + 1;

  const lanes: Lane[] = built.map(({ lane }) => {
    const p = m.processes.get(lane.id)!;
    const first = p.images[0];
    const appeared = first && (first.inherited || first.args !== null) ? timeMs(first.time) : null;
    let startMs: number;
    let before: boolean;
    if (appeared !== null) { startMs = appeared; before = false; }
    else {
      // Seen running: the audit token's start time places it when that falls inside the capture.
      const st = timeMs(p.startTime);
      before = st === null || st < t0;
      startMs = before ? t0 : st!;
    }
    const exit = timeMs(p.exitTime);
    const endMs = Math.max(startMs, exit ?? t1);
    return { ...lane, startMs, endMs, before, after: exit === null };
  });

  const moments: Moment[] = [];
  built.forEach(({ events }, lane) => {
    for (const e of events) {
      if (!STORY.has(e.kind) && e.findings.length === 0) continue;
      const t = timeMs(e.time);
      if (t !== null) moments.push({ ms: t, seq: e.seq, lane, e });
    }
  });
  moments.sort((a, b) => a.ms - b.ms || a.seq - b.seq);

  return { lanes, moments, t0, t1, untimed, truncated };
}

const KIND_WEIGHT: Partial<Record<TimelineKind, number>> = { exec: 2, image: 2, btm_add: 2, btm_remove: 2 };
const weight = (t: LaneTick): number => (t.severity ? SEVERITY_RANK[t.severity] * 10 : 0) + (KIND_WEIGHT[t.kind] ?? 1);

/**
 * The ticks inside [w0, w1] at a pixel x of a `width`-pixel axis, one per pixel: the most severe there, else a program
 * start over a file event. A lane can hold tens of thousands of events; it never draws more marks than pixels.
 */
export function binTicks(ticks: LaneTick[], w0: number, w1: number, width: number): (LaneTick & { x: number })[] {
  const span = w1 - w0;
  if (span <= 0 || width <= 0) return [];
  let a = 0, b = ticks.length;
  while (a < b) { const mid = (a + b) >>> 1; if (ticks[mid]!.ms < w0) a = mid + 1; else b = mid; }
  const out: (LaneTick & { x: number })[] = [];
  for (let i = a; i < ticks.length && ticks[i]!.ms <= w1; i++) {
    const t = ticks[i]!;
    const x = Math.round(((t.ms - w0) / span) * width);
    const last = out[out.length - 1];
    if (last && last.x === x) { if (weight(t) > weight(last)) out[out.length - 1] = { ...t, x }; }
    else out.push({ ...t, x });
  }
  return out;
}

const STEPS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 15_000, 30_000, 60_000, 120_000, 300_000,
  600_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000];

/** The step between ruler labels for a window: the smallest round step that leaves about 90 pixels between them. */
export function rulerStep(w0: number, w1: number, width: number): number {
  const want = ((w1 - w0) * 90) / Math.max(width, 1);
  return STEPS.find(s => s >= want) ?? STEPS[STEPS.length - 1]!;
}

/** Round times inside [w0, w1] to label the axis with. */
export function rulerTicks(w0: number, w1: number, width: number): number[] {
  const step = rulerStep(w0, w1, width);
  const out: number[] = [];
  for (let t = Math.ceil(w0 / step) * step; t <= w1; t += step) out.push(t);
  return out;
}

/**
 * A clock reading for a placed time, with milliseconds when `fine`. eslogger writes UTC (`utc`); a time written
 * without a zone was read as local time, so it is shown in local time to keep the digits the capture holds.
 */
export function clockOf(ms: number, utc: boolean, fine: boolean): string {
  const d = new Date(ms);
  const two = (n: number) => String(n).padStart(2, '0');
  const [h, mi, s, milli] = utc
    ? [d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMilliseconds()]
    : [d.getHours(), d.getMinutes(), d.getSeconds(), d.getMilliseconds()];
  return `${two(h)}:${two(mi)}:${two(s)}${fine ? `.${String(milli).padStart(3, '0')}` : ''}`;
}

/** A length of time in words a reader takes in at a glance: `420 ms`, `3.2 s`, `4 min 05 s`, `2 h 03 min`. */
export function fmtSpan(ms: number): string {
  if (ms < 1_000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  const s = Math.round(ms / 1000);
  if (s < 3600) return `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s`;
  const min = Math.round(s / 60);
  return `${Math.floor(min / 60)} h ${String(min % 60).padStart(2, '0')} min`;
}
