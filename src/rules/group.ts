import type { CaptureModel, ProcId } from '../model/types';
import { latestImage } from '../model/util';
import { originalParentImage } from './context';
import type { Analysis, QueueItem } from './engine';

/**
 * What makes two queued processes "the same run again": the same program (path and signature), the same arguments, the
 * same parent program, and the same findings. Pids, times and evidence text are left out: a loop differs in nothing else.
 * A launch item no process owns is never grouped (null).
 */
export function groupKey(m: CaptureModel, q: QueueItem): string | null {
  if (q.kind !== 'process' || q.procId === null) return null;
  const p = m.processes.get(q.procId);
  const img = p ? latestImage(p) : undefined;
  if (!p || !img) return null;
  const parent = originalParentImage(m, p)?.path ?? '-';
  const findings = q.findings.map(f => `${f.ruleId}|${f.severity}|${f.title}`).sort();
  return JSON.stringify([img.path, img.signingId, img.teamId, img.args, parent, findings, q.inFlaggedChain, q.reconBurst]);
}

/**
 * One row per run of identical queued processes: the first (earliest) keeps the row, and every member, itself included,
 * is listed in `members`. Everything else keeps its place. Linear in the queue.
 */
export function groupQueue(m: CaptureModel, queue: QueueItem[]): QueueItem[] {
  const byKey = new Map<string, QueueItem>();
  const out: QueueItem[] = [];
  for (const q of queue) {
    const key = groupKey(m, q);
    const first = key === null ? undefined : byKey.get(key);
    if (first) { first.members.push(q.procId!); continue; }
    if (key !== null) byKey.set(key, q);
    out.push(q);
  }
  return out;
}

const index = new WeakMap<Analysis, Map<ProcId, QueueItem>>();

/** The queue row that holds `id` as one of its members (the row itself, or a row it was grouped into). */
export function queueItemFor(a: Analysis, id: ProcId): QueueItem | undefined {
  let map = index.get(a);
  if (!map) {
    map = new Map();
    for (const q of a.queue) for (const member of q.members) map.set(member, q);
    index.set(a, map);
  }
  return map.get(id);
}
