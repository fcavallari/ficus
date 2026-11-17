import type { LoadedCapture } from '../src/ingest/load';
import type { CaptureModel } from '../src/model/types';
import { analyze } from '../src/rules/engine';
import type { CaptureRec, Status, Verdict, VerdictSnapshot } from '../src/session/store';
import type { ReportInput } from '../src/report/report';
import { queued } from './helpers';

export const GEN = '2026-11-16T12:00:00.000Z';
export const SESSION = { id: 'sess-1', name: 'lab' };

export const capRec = (fingerprint: string, fileName: string): CaptureRec => ({
  sessionId: SESSION.id, fingerprint, fileName, size: 1, events: 1, processes: 1, flagged: 1, added: 't',
});

/** A loaded capture of the synthetic lab under fingerprint `fp`; pass a model to use a modified one. */
export function lab(fp = 'fp', m?: CaptureModel): LoadedCapture {
  if (m) return { fingerprint: fp, fileName: 'synthetic-lab.jsonl', size: 1, model: m, analysis: analyze(m) };
  const q = queued('synthetic-lab.jsonl');
  return { fingerprint: fp, fileName: 'synthetic-lab.jsonl', size: 1, model: q.m, analysis: q.a };
}

const SNAP: VerdictSnapshot = { name: 'x', path: null, args: null, ruleIds: [], severity: null, startTime: null };

export function verdict(fingerprint: string, procKey: string, status: Status, note = '', snapshot: Partial<VerdictSnapshot> = {}): Verdict {
  return { sessionId: SESSION.id, fingerprint, procKey, status, note, updated: 't', snapshot: { ...SNAP, ...snapshot } };
}

/** The lab capture loaded as `fp`, no verdicts, no routine marks; override any part. */
export function input(over: Partial<ReportInput> = {}): ReportInput {
  const cap = over.loaded?.get('fp') ?? lab();
  return {
    session: SESSION,
    capRecs: [capRec('fp', 'synthetic-lab.jsonl')],
    loaded: new Map([['fp', cap]]),
    verdicts: [],
    routineKeys: new Set(),
    ...over,
  };
}

/** Every string value in a JSON-like object (keys skipped), with the key each sits under. */
export function strings(x: unknown, key = '', out: { key: string; value: string }[] = []): { key: string; value: string }[] {
  if (typeof x === 'string') out.push({ key, value: x });
  else if (Array.isArray(x)) for (const v of x) strings(v, key, out);
  else if (x && typeof x === 'object') for (const [k, v] of Object.entries(x)) strings(v, k, out);
  return out;
}
