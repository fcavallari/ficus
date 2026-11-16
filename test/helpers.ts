import { buildModel } from '../src/model/builder';
import type { CaptureModel, Process } from '../src/model/types';
import { analyze, type Analysis, type Finding, type QueueItem } from '../src/rules/engine';
import { RULES, type Severity } from '../src/rules/rules';
import { readLines, type FixtureName } from './fixtures';

const cache = new Map<FixtureName, CaptureModel>();

/** Model built from a fixture, memoized per fixture. */
export function model(name: FixtureName): CaptureModel {
  let m = cache.get(name);
  if (!m) {
    m = buildModel(readLines(name));
    cache.set(name, m);
  }
  return m;
}

/** The nth process (by firstSeq) with this pid; throws when there is none. */
export function procByPid(m: CaptureModel, pid: number, nth = 0): Process {
  const ps = [...m.processes.values()].filter(p => p.pid === pid).sort((a, b) => a.firstSeq - b.firstSeq);
  const p = ps[nth];
  if (!p) throw new Error(`no process #${nth} with pid ${pid} (found ${ps.length})`);
  return p;
}

export function imagePaths(p: Process): (string | null)[] {
  return p.images.map(i => i.path);
}

export interface QueuedRow { item: QueueItem; p: Process | null; paths: (string | null)[]; args: string }
export interface Queued { m: CaptureModel; a: Analysis; items: QueuedRow[] }

const analyses = new Map<FixtureName, Queued>();

/** The fixture's triage queue, each row with its process, image paths and joined args of all images. */
export function queued(name: FixtureName): Queued {
  let q = analyses.get(name);
  if (!q) {
    const m = model(name);
    const a = analyze(m);
    const items = a.queue.map(item => {
      const p = item.procId !== null ? m.processes.get(item.procId) ?? null : null;
      return {
        item, p,
        paths: p ? imagePaths(p) : [],
        args: p ? p.images.map(i => (i.args ?? []).join(' ')).join(' ') : '',
      };
    });
    q = { m, a, items };
    analyses.set(name, q);
  }
  return q;
}

export function item(name: FixtureName, pred: (x: QueuedRow) => boolean): QueueItem | undefined {
  return queued(name).items.find(pred)?.item;
}

export function hasQueued(name: FixtureName, pred: (x: QueuedRow) => boolean): boolean {
  return queued(name).items.some(pred);
}

/** Rule ids of the first matching queue row; empty when nothing matches. */
export function rules(name: FixtureName, pred: (x: QueuedRow) => boolean): string[] {
  return item(name, pred)?.findings.map(f => f.ruleId) ?? [];
}

export function sev(name: FixtureName, pred: (x: QueuedRow) => boolean): Severity | undefined {
  return item(name, pred)?.severity;
}

export function count(name: FixtureName, pred: (x: QueuedRow) => boolean): number {
  return queued(name).items.filter(pred).length;
}

const GATE = new Map(RULES.map(r => [r.id, r.gated]));
const isGated = (f: Finding): boolean => {
  const g = GATE.get(f.ruleId);
  return g === 'always' || (g === 'when-low' && f.severity === 'low');
};

/** How a process shows in the queue, by the spec's precedence: own finding, then burst, then chain; else context. */
export function queueStatus(a: Analysis, p: Process): 'queued' | 'burst' | 'in-chain' | 'context' {
  const item = a.queue.find(q => q.procId === p.id);
  if (!item) return 'context';
  if (item.findings.some(f => !isGated(f))) return 'queued';
  if (item.reconBurst) return 'burst';
  if (item.inFlaggedChain) return 'in-chain';
  throw new Error(`pid ${p.pid} is queued for no reason the key knows`);
}

/**
 * What a capture makes the rule engine say, keyed by process id (`pid:pidversion`) and by persistence item id. Each
 * value lists `rule:severity:queue` sorted, one per finding; a queued process with no findings of its own (a burst
 * or chain member) lists `-:-:queue`. A cleaned capture must give the same map as the raw one.
 */
export function findingSignature(m: CaptureModel): Map<string, string[]> {
  const a = analyze(m);
  const sig = new Map<string, string[]>();
  const add = (id: string, v: string): void => { sig.set(id, [...(sig.get(id) ?? []), v].sort()); };
  for (const [id, list] of [...a.findings, ...a.contextOnly]) {
    const p = m.processes.get(id);
    for (const f of list) add(id, `${f.ruleId}:${f.severity}:${p ? queueStatus(a, p) : 'context'}`);
  }
  for (const q of a.queue) {
    if (q.kind === 'persistence' && q.persistenceId !== null) {
      for (const f of q.findings) add(q.persistenceId, `${f.ruleId}:${f.severity}:item`);
    } else if (q.procId !== null && !sig.has(q.procId)) {
      const p = m.processes.get(q.procId);
      add(q.procId, `-:-:${p ? queueStatus(a, p) : 'context'}`);
    }
  }
  return sig;
}
