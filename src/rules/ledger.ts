import type { CaptureModel, ProcId } from '../model/types';
import { normPath, timeMs } from '../model/util';

/** A file that appeared at `path`: created there, renamed into place, or copied there (clone or copyfile). */
export interface DropRecord { path: string; writer: ProcId; seq: number; ms: number | null }
export interface UnlinkRecord { seq: number; ms: number | null }
/** What the capture saw happen to files, by `normPath(path).toLowerCase()`; each list is in capture order. */
export interface FileLedger { drops: Map<string, DropRecord[]>; unlinks: Map<string, UnlinkRecord[]> }

const ledgers = new WeakMap<CaptureModel, FileLedger>();

function push<T>(map: Map<string, T[]>, path: string, record: T): void {
  const key = normPath(path).toLowerCase();
  const list = map.get(key);
  if (list) list.push(record); else map.set(key, [record]);
}

/** Every file drop and unlink in the capture, built once per model. */
export function fileLedger(m: CaptureModel): FileLedger {
  const cached = ledgers.get(m);
  if (cached) return cached;
  const ledger: FileLedger = { drops: new Map(), unlinks: new Map() };
  for (const p of m.processes.values()) {
    for (const op of p.fileOps) {
      const ms = timeMs(op.time);
      if (op.kind === 'unlink') push(ledger.unlinks, op.path, { seq: op.seq, ms });
      else if (op.kind === 'create') push(ledger.drops, op.path, { path: op.path, writer: p.id, seq: op.seq, ms });
      else if ((op.kind === 'rename' || op.kind === 'copy') && op.toPath !== undefined) push(ledger.drops, op.toPath, { path: op.toPath, writer: p.id, seq: op.seq, ms });
    }
  }
  ledgers.set(m, ledger);
  return ledger;
}
