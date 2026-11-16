import type { ReactNode } from 'react';
import type { LoadedCapture } from '../ingest/load';
import { displayName } from '../model/relations';
import type { ProcId } from '../model/types';
import { SEVERITY_RANK, type Severity } from '../rules/rules';
import { RAW_TYPE, type TimelineEvent } from './timeline';
import { fmtArgs, fmtClock, fmtTime, SEVERITY_LABEL } from './triage-model';

/** Small pieces shared by the detail pane's timeline and the nearby panel. */

export const plural = (n: number, one: string, many = `${one}s`): string => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;

/** A severity badge: the short form in lists, the full word (`full`) where there is room. */
export function Sev({ s, full }: { s: Severity; full?: boolean }) {
  return <span className={`badge sev-${s}${full ? ' full' : ''}`} title={`Severity: ${SEVERITY_LABEL[s]}`}>{full ? SEVERITY_LABEL[s] : s}</span>;
}

/** A process link with its pid, or the bare pid when the capture has no process for it. */
export function ProcLink({ cap, id, onSelect }: { cap: LoadedCapture; id: ProcId | null; onSelect(id: ProcId): void }) {
  if (id === null) return <span className="muted">not recorded</span>;
  const q = cap.model.processes.get(id);
  return (
    <span>
      <button className="link" onClick={() => { onSelect(id); }}>{displayName(cap.model, id)}</button>
      {q && !q.ghost && <span className="muted small"> pid {q.pid}</span>}
    </span>
  );
}

/** A signed offset from the anchor, as `+2.000 s` or `−0.420 s` (a real minus sign). */
export const fmtOffset = (ms: number): string => `${ms < 0 ? '\u2212' : '+'}${(Math.abs(ms) / 1000).toFixed(3)} s`;

/**
 * One timeline entry: when, which event, what it touched, and the finding it carries, if one cites exactly this event.
 * `onAnchor` adds the "nearby" button (`anchored`: this row is the one the nearby panel is built around). `nearby`
 * replaces the clock with the offset from that anchor, and says whether the event touched the same path.
 */
export function TimelineRow({ cap, e, self, multiDay, onSelect, onAnchor, anchored, nearby }: {
  cap: LoadedCapture; e: TimelineEvent; self: ProcId; multiDay: boolean; onSelect(id: ProcId): void;
  onAnchor?(e: TimelineEvent): void; anchored?: boolean; nearby?: { offsetMs: number; samePath: boolean };
}) {
  const link = (id: ProcId) => <ProcLink cap={cap} id={id} onSelect={onSelect} />;
  let body: ReactNode;
  switch (e.kind) {
    case 'fork': body = <>forked by {link(e.other!)}</>; break;
    case 'spawn': body = <>forked {link(e.other!)}</>; break;
    case 'exec': body = <code className="mono wrap">{e.args && e.args.length > 0 ? fmtArgs(e.args) : (e.path ?? '?')}</code>; break;
    case 'image': body = <><code className="mono wrap">{e.path ?? '?'}</code> <span className="muted small">(its exec is not in the capture)</span></>; break;
    case 'rename': body = <code className="mono wrap">{e.path} <span className="muted">→</span> {e.toPath ?? '?'}</code>; break;
    case 'setextattr': body = <code className="mono wrap">{e.path}{e.xattr !== undefined && <span className="muted"> ({e.xattr})</span>}</code>; break;
    case 'btm_add': case 'btm_remove': {
      const verb = e.kind === 'btm_add' ? 'added' : 'removed';
      const role = e.role === 'app' ? `its app: launch item ${verb}` : e.role === 'instigator' ? `asked for: launch item ${verb}` : `reported: launch item ${verb}`;
      body = <><span className="muted small">{role}</span> <code className="mono wrap">{e.path ?? '(no path recorded)'}</code></>;
      break;
    }
    case 'exit': body = <span className="muted">exited</span>; break;
    default: body = <code className="mono wrap">{e.path}</code>;
  }
  const worst = e.findings.reduce<Severity | null>((w, f) => (w === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[w] ? f.severity : w), null);
  return (
    <li className={`tl-row k-${e.kind}${worst ? ` flagged sev-border-${worst}` : ''}${onAnchor ? ' anchorable' : ''}${anchored ? ' anchored' : ''}${nearby?.samePath ? ' same-path' : ''}`}>
      <time className="tl-t mono" dateTime={e.time ?? undefined} title={e.time ? fmtTime(e.time) : 'no time recorded'}>
        {nearby ? fmtOffset(nearby.offsetMs) : e.time ? `${multiDay ? `${e.time.slice(5, 10)} ` : ''}${fmtClock(e.time)}` : '—'}
      </time>
      <span className="tl-k">{RAW_TYPE[e.kind]}</span>
      <span className="tl-body">
        {e.proc !== self && <span className="tl-who">{link(e.proc)}</span>}
        {body}
        {nearby?.samePath && <span className="tl-same small">same path</span>}
        {e.findings.length > 0 && (
          <span className="tl-why">
            {e.findings.map((f, i) => <span key={i} className="row"><Sev s={f.severity} /><span className="small">{f.title}</span></span>)}
          </span>
        )}
      </span>
      {onAnchor && (
        <button className="tl-near" aria-label="Show what happened near this event" aria-pressed={!!anchored} onClick={() => { onAnchor(e); }}>nearby</button>
      )}
    </li>
  );
}
