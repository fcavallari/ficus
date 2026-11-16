import type { LoadedCapture } from '../ingest/load';
import { ancestry, type ParentMode } from '../model/relations';
import type { ProcId } from '../model/types';
import { timeMs } from '../model/util';
import { allTimelineEvents, type TimelineEvent } from './timeline';

/**
 * "What happened nearby": what other processes did within a window of one event. This is an inference from timing
 * alone; `linked` says whether a recorded parent chain ties the process to the anchor's, nothing more.
 */

/** Window half-widths in ms; the middle one is the default. */
export const NEARBY_WINDOWS = [1_000, 5_000, 30_000] as const;

export interface NearbyEvent { e: TimelineEvent; offsetMs: number; samePath: boolean }
export interface NearbyGroup { proc: ProcId; linked: boolean; events: NearbyEvent[] }
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

const pathsOf = (e: TimelineEvent): string[] => [e.path, e.toPath].filter((p): p is string => !!p);

export function nearby(cap: LoadedCapture, anchor: TimelineEvent, windowMs: number): NearbyResult {
  const idx = indexOf(cap);
  const at = timeMs(anchor.time);
  if (at === null) return { groups: [], total: 0, untimed: idx.untimed };
  const m = cap.model;
  const ofAnchor = new Set<ProcId>(MODES.flatMap(mode => ancestry(m, anchor.proc, mode)));
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
      const linked = ofAnchor.has(e.proc) || MODES.some(mode => ancestry(m, e.proc, mode).includes(anchor.proc));
      g = { proc: e.proc, linked, events: [] };
      groups.set(e.proc, g);
    }
    g.events.push({ e, offsetMs: idx.ms[i]! - at, samePath: pathsOf(e).some(p => anchorPaths.has(p)) });
  }
  // Map insertion order is the order each process first appeared in the window, i.e. by its first event's time.
  return { groups: [...groups.values()], total, untimed: idx.untimed };
}

/** Where to start: the first event with a finding, else the first exec, else the first event. */
export function defaultAnchor(events: TimelineEvent[]): TimelineEvent | null {
  return events.find(e => e.findings.length > 0) ?? events.find(e => e.kind === 'exec') ?? events[0] ?? null;
}
