import type { LoadedCapture } from '../ingest/load';
import { ancestry, type ParentMode } from '../model/relations';
import type { CaptureModel, ProcId } from '../model/types';
import { timeMs } from '../model/util';
import { allTimelineEvents, type TimelineEvent } from './timeline';

/**
 * "What happened nearby": what other processes did within a window of one event. This is an inference from timing
 * alone; `link` says whether a recorded parent chain ties the process to the anchor's, nothing more.
 */

/** Window half-widths in ms; the middle one is the default. */
export const NEARBY_WINDOWS = [1_000, 5_000, 30_000] as const;

export interface NearbyEvent { e: TimelineEvent; offsetMs: number; samePath: boolean }
/**
 * How a recorded parent chain ties a process to the anchor's: one is the other's ancestor (`chain`), or both descend
 * from a recorded process (`shared`, the nearest one), or neither (null).
 */
export type NearbyLink = { kind: 'chain' } | { kind: 'shared'; via: ProcId } | null;
export interface NearbyGroup { proc: ProcId; link: NearbyLink; events: NearbyEvent[] }
export interface NearbyResult { groups: NearbyGroup[]; total: number; untimed: number }

const MODES: ParentMode[] = ['original', 'current', 'responsible'];

interface Index { events: TimelineEvent[]; ms: number[]; untimed: number }

const indexes = new WeakMap<LoadedCapture, Index>();

/** The capture's events that carry a parseable time, sorted by it (capture order breaks ties). */
function indexOf(cap: LoadedCapture): Index {
  let idx = indexes.get(cap);
  if (idx) return idx;
  const timed: { e: TimelineEvent; ms: number }[] = [];
  let untimed = 0;
  for (const e of allTimelineEvents(cap)) {
    const ms = timeMs(e.time);
    if (ms === null) untimed++;
    else timed.push({ e, ms });
  }
  timed.sort((a, b) => a.ms - b.ms || a.e.seq - b.e.seq);
  idx = { events: timed.map(t => t.e), ms: timed.map(t => t.ms), untimed };
  indexes.set(cap, idx);
  return idx;
}

/** First position in the sorted array whose value is >= `x` (`strict`: > `x`). */
function bound(ms: number[], x: number, strict: boolean): number {
  let lo = 0, hi = ms.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (strict ? ms[mid]! <= x : ms[mid]! < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * The paths an event touched: a file op's path and toPath, an exec's or image's program, a launch item's path. Not the
 * program path a fork, spawn or exit entry carries: that is inherited, and would make every shell event "same path".
 */
const pathsOf = (e: TimelineEvent): string[] =>
  e.kind === 'fork' || e.kind === 'spawn' || e.kind === 'exit' ? [] : [e.path, e.toPath].filter((p): p is string => !!p);

/**
 * The link between a process and the anchor's. A common ancestor counts only when it is a recorded process other than
 * the kernel or launchd (pid 0 or 1), which every process shares. Modes are tried in order; in each, the nearest.
 */
function linkOf(m: CaptureModel, id: ProcId, anchor: ProcId, ofAnchor: Set<ProcId>, anchorChains: Map<ParentMode, Set<ProcId>>): NearbyLink {
  if (ofAnchor.has(id) || MODES.some(mode => ancestry(m, id, mode).includes(anchor))) return { kind: 'chain' };
  for (const mode of MODES) {
    const theirs = anchorChains.get(mode)!;
    for (const a of ancestry(m, id, mode)) {
      if (!theirs.has(a)) continue;
      const q = m.processes.get(a);
      if (q && !q.ghost && q.pid !== 0 && q.pid !== 1) return { kind: 'shared', via: a };
    }
  }
  return null;
}

/**
 * Groups worth reading first come first: those holding an event on the anchor's own path, then by how close their nearest
 * event is to the anchor. Ties go to the group that began earlier, then to the process id, so the order never wobbles.
 * Events inside a group stay in time order. (By first-event time alone, a busy window buries the nearest events.)
 */
function orderGroups(groups: NearbyGroup[]): NearbyGroup[] {
  const key = (g: NearbyGroup) => {
    // A loop, not Math.min(...spread): a busy group can exceed the engine's argument limit (about 65k in Safari).
    let nearest = Infinity;
    for (const x of g.events) nearest = Math.min(nearest, Math.abs(x.offsetMs));
    return { same: g.events.some(x => x.samePath), nearest, first: g.events[0]!.offsetMs };
  };
  const keys = new Map(groups.map(g => [g, key(g)]));
  return groups.sort((a, b) => {
    const ka = keys.get(a)!, kb = keys.get(b)!;
    return Number(kb.same) - Number(ka.same) || ka.nearest - kb.nearest || ka.first - kb.first || (a.proc < b.proc ? -1 : a.proc > b.proc ? 1 : 0);
  });
}

export function nearby(cap: LoadedCapture, anchor: TimelineEvent, windowMs: number): NearbyResult {
  const idx = indexOf(cap);
  const at = timeMs(anchor.time);
  if (at === null) return { groups: [], total: 0, untimed: idx.untimed };
  const m = cap.model;
  const anchorChains = new Map(MODES.map(mode => [mode, new Set(ancestry(m, anchor.proc, mode))]));
  const ofAnchor = new Set<ProcId>([...anchorChains.values()].flatMap(c => [...c]));
  const anchorPaths = new Set(pathsOf(anchor));
  const groups = new Map<ProcId, NearbyGroup>();
  let total = 0;
  const end = bound(idx.ms, at + windowMs, true);
  for (let i = bound(idx.ms, at - windowMs, false); i < end; i++) {
    const e = idx.events[i]!;
    if (e.proc === anchor.proc) continue;
    total++;
    let g = groups.get(e.proc);
    if (!g) {
      g = { proc: e.proc, link: linkOf(m, e.proc, anchor.proc, ofAnchor, anchorChains), events: [] };
      groups.set(e.proc, g);
    }
    g.events.push({ e, offsetMs: idx.ms[i]! - at, samePath: pathsOf(e).some(p => anchorPaths.has(p)) });
  }
  return { groups: orderGroups([...groups.values()]), total, untimed: idx.untimed };
}

/**
 * Which events to show when only `limit` fit: same-path events first, then the ones nearest the anchor, whichever process
 * they belong to (ties: the earlier, then capture order). Picking group by group instead lets one busy process fill
 * every row and hide the processes that did one thing close by.
 */
export function pickShown(r: NearbyResult, limit: number): Set<NearbyEvent> {
  const all: NearbyEvent[] = [];
  for (const g of r.groups) for (const x of g.events) all.push(x);
  all.sort((a, b) => Number(b.samePath) - Number(a.samePath) || Math.abs(a.offsetMs) - Math.abs(b.offsetMs)
    || a.offsetMs - b.offsetMs || a.e.seq - b.e.seq || a.e.key.localeCompare(b.e.key));
  return new Set(all.length > limit ? all.slice(0, limit) : all);
}

/** Where to start: the first event with a finding, else the first exec, else the first event. */
export function defaultAnchor(events: TimelineEvent[]): TimelineEvent | null {
  return events.find(e => e.findings.length > 0) ?? events.find(e => e.kind === 'exec') ?? events[0] ?? null;
}
