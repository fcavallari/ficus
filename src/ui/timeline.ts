import type { LoadedCapture } from '../ingest/load';
import type { CaptureModel, FileOp, PersistenceItem, ProcId, Process } from '../model/types';
import type { Finding } from '../rules/engine';
import { forestOf } from './tree-model';

/**
 * What a process did, as the capture recorded it, in the order the events happened. Every entry is one recorded event:
 * nothing is inferred, and an entry carries only the time the event itself carried.
 *
 * Ordering is by sequence number, never by time: a Mac Monitor trace is renumbered by mach_time when it is loaded, so
 * the sequence is the capture's own order for both formats.
 */
export type TimelineKind =
  | 'fork'        // this process was forked (the event its parent emitted)
  | 'exec'        // an exec event: a new program, with its arguments
  | 'image'       // a new program seen on a later event, without its exec event
  | 'spawn'       // this process forked a child
  | FileOp['kind']
  | 'btm_add' | 'btm_remove'
  | 'exit';

export interface TimelineEvent {
  key: string;
  seq: number;
  time: string | null;
  kind: TimelineKind;
  /** The process the event belongs to. */
  proc: ProcId;
  /** Program path (exec, image), file path (file ops), plist or program (launch items). */
  path: string | null;
  toPath?: string;
  xattr?: string;
  args?: string[];
  /** The other process of a fork: the parent (fork) or the child (spawn). */
  other?: ProcId;
  persistenceId?: string;
  /** For a launch item: how this process figures in it (several processes can, for one registration). */
  role?: 'emitter' | 'instigator' | 'app';
  /** Findings that cite exactly this event: an exec by its image, a launch item by its id. */
  findings: Finding[];
}

/** The eslogger event type each kind came from, as the capture names it. */
export const RAW_TYPE: Record<TimelineKind, string> = {
  fork: 'fork', exec: 'exec', image: 'exec not captured', spawn: 'fork', exit: 'exit',
  create: 'create', rename: 'rename', unlink: 'unlink', copy: 'clone / copyfile', write: 'write', setextattr: 'setextattr',
  btm_add: 'btm_launch_item_add', btm_remove: 'btm_launch_item_remove',
};

const forkKids = new WeakMap<CaptureModel, Map<ProcId, ProcId[]>>();

/** Children per process by the fork event that made them (not by a parent mode): who emitted the fork. */
function forkChildren(m: CaptureModel): Map<ProcId, ProcId[]> {
  let idx = forkKids.get(m);
  if (idx) return idx;
  idx = new Map();
  for (const p of m.processes.values()) {
    if (p.forkParent === null || !p.images[0]?.inherited) continue;
    const list = idx.get(p.forkParent);
    if (list) list.push(p.id);
    else idx.set(p.forkParent, [p.id]);
  }
  forkKids.set(m, idx);
  return idx;
}

const itemsOf = new WeakMap<CaptureModel, Map<ProcId, PersistenceItem[]>>();

/** Launch items per process that emitted, asked for or registered them, in capture order; built once per capture. */
function launchItemsOf(m: CaptureModel): Map<ProcId, PersistenceItem[]> {
  let idx = itemsOf.get(m);
  if (idx) return idx;
  idx = new Map();
  for (const item of m.persistence) {
    for (const id of new Set([item.emitter, item.instigator, item.app])) {
      if (id === null) continue;
      const list = idx.get(id);
      if (list) list.push(item);
      else idx.set(id, [item]);
    }
  }
  itemsOf.set(m, idx);
  return idx;
}

const byItem = new WeakMap<LoadedCapture['analysis'], Map<string, Finding[]>>();

/** Findings per launch item id, wherever they were attached (the owning process, or the item's own queue row). */
function itemFindings(cap: LoadedCapture): Map<string, Finding[]> {
  let idx = byItem.get(cap.analysis);
  if (idx) return idx;
  idx = new Map();
  const seen = new Set<Finding>();
  const all = [...cap.analysis.findings.values(), ...cap.analysis.contextOnly.values(), ...cap.analysis.queue.map(q => q.findings)];
  for (const list of all) {
    for (const f of list) {
      if (f.persistenceId === null || seen.has(f)) continue;
      seen.add(f);
      const l = idx.get(f.persistenceId);
      if (l) l.push(f);
      else idx.set(f.persistenceId, [f]);
    }
  }
  byItem.set(cap.analysis, idx);
  return idx;
}

function eventsOf(cap: LoadedCapture, p: Process, out: TimelineEvent[]): void {
  const m = cap.model;
  const findings = [...(cap.analysis.findings.get(p.id) ?? []), ...(cap.analysis.contextOnly.get(p.id) ?? [])];
  const first = p.images[0];
  if (first?.inherited && p.forkParent !== null) {
    out.push({ key: `${p.id}:fork`, seq: first.seq, time: first.time, kind: 'fork', proc: p.id, path: first.path, other: p.forkParent, findings: [] });
  }
  p.images.forEach((img, i) => {
    if (img.inherited) return;
    const exec = img.args !== null;
    out.push({
      key: `${p.id}:img:${i}`, seq: img.seq, time: img.time, kind: exec ? 'exec' : 'image', proc: p.id, path: img.path,
      ...(exec ? { args: img.args! } : {}),
      findings: findings.filter(f => f.imgIndex === i),
    });
  });
  for (const kid of forkChildren(m).get(p.id) ?? []) {
    const k = m.processes.get(kid)!;
    const img = k.images[0]!;
    out.push({ key: `${p.id}:spawn:${kid}`, seq: img.seq, time: img.time, kind: 'spawn', proc: p.id, path: img.path, other: kid, findings: [] });
  }
  for (const op of p.fileOps) {
    const e: TimelineEvent = { key: `${p.id}:op:${op.seq}`, seq: op.seq, time: op.time, kind: op.kind, proc: p.id, path: op.path, findings: [] };
    if (op.toPath !== undefined) e.toPath = op.toPath;
    if (op.xattr !== undefined) e.xattr = op.xattr;
    out.push(e);
  }
  // Launch items the process emitted, asked for, or registered. Findings about an item may sit on another process (its
  // owner) or on the persistence-only queue row: they are matched by the item's id.
  for (const item of launchItemsOf(m).get(p.id) ?? []) {
    const role = item.app === p.id ? 'app' : item.instigator === p.id ? 'instigator' : 'emitter';
    out.push({ role,
      key: `${p.id}:btm:${item.id}`, seq: item.seq, time: item.time, kind: item.kind === 'add' ? 'btm_add' : 'btm_remove', proc: p.id,
      path: item.plistPath ?? item.executablePath ?? item.appPath, persistenceId: item.id,
      findings: itemFindings(cap).get(item.id) ?? [],
    });
  }
  if (p.exitTime !== null) {
    // An exit captured before this build recorded its sequence number sorts last, after everything that has one.
    out.push({ key: `${p.id}:exit`, seq: p.exitSeq ?? Number.MAX_SAFE_INTEGER, time: p.exitTime, kind: 'exit', proc: p.id, path: null, findings: [] });
  }
}

/** Upper bound on the processes a "with descendants" timeline walks; past it the result says it stopped short. */
export const MAX_SUBTREE = 2000;

/**
 * The recorded events of a process, and with `descendants` those of every process under it (original parent), in
 * capture order. `truncated` is set when the subtree had more than MAX_SUBTREE processes.
 */
export function processTimeline(cap: LoadedCapture, id: ProcId, descendants: boolean): { events: TimelineEvent[]; processes: number; truncated: boolean } {
  const m = cap.model;
  const ids: ProcId[] = [id];
  let truncated = false;
  if (descendants) {
    const kids = forestOf(m, 'original').kids;
    for (let i = 0; i < ids.length; i++) {
      for (const k of kids.get(ids[i]!) ?? []) {
        if (ids.length >= MAX_SUBTREE) { truncated = true; break; }
        ids.push(k);
      }
      if (truncated) break;
    }
  }
  const events: TimelineEvent[] = [];
  for (const pid of ids) {
    const p = m.processes.get(pid);
    if (p && !p.ghost) eventsOf(cap, p, events);
  }
  // Within one subtree a spawn and the child's own fork entry are the same event: keep the parent's (it names the child).
  const shown = descendants ? new Set(ids) : null;
  const deduped = shown ? events.filter(e => !(e.kind === 'fork' && e.other !== undefined && shown.has(e.other))) : events;
  deduped.sort((a, b) => a.seq - b.seq || a.key.localeCompare(b.key));
  return { events: deduped, processes: ids.length, truncated };
}

/**
 * Every recorded event of every captured process, in capture order. A fork entry is dropped when its parent is a
 * captured process too: that parent's spawn entry is the same event and names the child.
 */
export function allTimelineEvents(cap: LoadedCapture): TimelineEvent[] {
  const m = cap.model;
  const events: TimelineEvent[] = [];
  for (const p of m.processes.values()) if (!p.ghost) eventsOf(cap, p, events);
  const kept = events.filter(e => !(e.kind === 'fork' && e.other !== undefined && m.processes.get(e.other)?.ghost === false));
  kept.sort((a, b) => a.seq - b.seq || a.key.localeCompare(b.key));
  return kept;
}

/**
 * The times of the first and the last event that carried one, in capture order (the events come sorted by sequence),
 * or null when none did. Taken by position, not by comparing time strings, which differ in format between captures.
 */
export function recordedSpan(events: TimelineEvent[]): { first: string; last: string } | null {
  const first = events.find(e => e.time)?.time;
  let last: string | null | undefined;
  for (let i = events.length - 1; i >= 0 && !last; i--) last = events[i]!.time;
  return first && last ? { first, last } : null;
}

/** Counts of what was recorded, by kind, for the summary line. */
export function recordedCounts(events: TimelineEvent[]): Partial<Record<TimelineKind, number>> {
  const c: Partial<Record<TimelineKind, number>> = {};
  for (const e of events) c[e.kind] = (c[e.kind] ?? 0) + 1;
  return c;
}
