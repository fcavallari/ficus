import { useMemo, useState } from 'react';
import type { LoadedCapture } from '../ingest/load';
import { displayName } from '../model/relations';
import type { ProcId } from '../model/types';
import { timeMs } from '../model/util';
import type { Severity } from '../rules/rules';
import { nearby, NEARBY_WINDOWS, pickShown, type NearbyEvent, type NearbyGroup, type NearbyLink } from './nearby';
import { plural, ProcLink, Sev, TimelineRow } from './shared';
import { RAW_TYPE, type TimelineEvent } from './timeline';
import { fmtTime } from './triage-model';

const NEARBY_FIRST = 200;
const NEARBY_STEP = 200;
const label = (ms: number): string => `±${ms / 1000} s`;
const n = (x: number): string => x.toLocaleString('en-US');

/** How a recorded parent chain ties the group's process to the anchor's; no link at all is the case worth a look. */
function LinkNote({ cap, link, onSelect }: { cap: LoadedCapture; link: NearbyLink; onSelect(id: ProcId): void }) {
  if (link === null) return <span className="nb-unlinked small">no recorded link</span>;
  if (link.kind === 'chain') return <span className="muted small">linked by parent chain</span>;
  return <span className="muted small">shares <ProcLink cap={cap} id={link.via} onSelect={onSelect} /></span>;
}

/**
 * One process's events in the window: who it is, how it is (not) tied to the anchor's process, then the rows picked to
 * show (in time order) and how many of its events are not shown yet.
 */
function Group({ cap, g, shown, severity, onSelect }: {
  cap: LoadedCapture; g: NearbyGroup; shown: NearbyEvent[]; severity: Map<ProcId, Severity>; onSelect(id: ProcId): void;
}) {
  const sev = severity.get(g.proc);
  const hidden = g.events.length - shown.length;
  return (
    <div className="nb-group">
      <h5 className="nb-head">
        {sev && <Sev s={sev} />}
        <ProcLink cap={cap} id={g.proc} onSelect={onSelect} />
        <LinkNote cap={cap} link={g.link} onSelect={onSelect} />
      </h5>
      <ol className="tl" aria-label={`Events of ${displayName(cap.model, g.proc)} near the anchor`}>
        {shown.map(x => (
          <TimelineRow key={x.e.key} cap={cap} e={x.e} self={g.proc} multiDay={false} onSelect={onSelect}
            nearby={{ offsetMs: x.offsetMs, samePath: x.samePath }} />
        ))}
      </ol>
      {hidden > 0 && <p className="muted small nb-more">+{n(hidden)} more in this process</p>}
    </div>
  );
}

/**
 * The result for one anchor and window. Shown in steps (the lookup is uncapped and a busy window can hold thousands of
 * events), the events nearest the anchor first whichever process they belong to; keyed by anchor and window by the
 * caller, so a new choice starts again at the first rows.
 */
function Results({ cap, anchor, windowMs, severity, onSelect }: {
  cap: LoadedCapture; anchor: TimelineEvent; windowMs: number; severity: Map<ProcId, Severity>; onSelect(id: ProcId): void;
}) {
  const [limit, setLimit] = useState(NEARBY_FIRST);
  // Memoised so "Show more" (which re-renders this component) and the parent's re-renders do not redo the lookup. The
  // dependency is anchor.key, not the anchor object: the Timeline hands over a fresh object for the same event.
  const r = useMemo(() => nearby(cap, anchor, windowMs), [cap, anchor.key, windowMs]);
  const shown = useMemo(() => pickShown(r, limit), [r, limit]);
  const note = r.untimed > 0 ? ` · ${plural(r.untimed, 'event')} in this capture ${r.untimed === 1 ? 'has' : 'have'} no time and ${r.untimed === 1 ? 'is' : 'are'} not placed` : '';
  const left = r.total - shown.size;
  return (
    <>
      <p className="muted small tl-meta">
        {r.total === 0 ? `Nothing else recorded within ${label(windowMs)}.` : `${plural(r.total, 'event')} in other processes within ${label(windowMs)}`}{note}
      </p>
      {r.groups.map(g => {
        const mine = g.events.filter(x => shown.has(x));
        return mine.length > 0 && <Group key={g.proc} cap={cap} g={g} shown={mine} severity={severity} onSelect={onSelect} />;
      })}
      {left > 0 && (
        <button onClick={() => { setLimit(l => l + NEARBY_STEP); }}>
          Show {n(Math.min(NEARBY_STEP, left))} more ({n(left)} left)
        </button>
      )}
    </>
  );
}

/**
 * What other processes did close in time to one event. This is inference from timing alone: the capture does not say
 * these events are related, only that they sit near each other, so each process says whether a parent chain ties it in.
 */
export function NearbyPanel({ cap, anchor, severity, onSelect }: {
  cap: LoadedCapture; anchor: TimelineEvent; severity: Map<ProcId, Severity>; onSelect(id: ProcId): void;
}) {
  const [win, setWin] = useState<number>(NEARBY_WINDOWS[1]);
  const timed = timeMs(anchor.time) !== null;
  return (
    <section aria-labelledby="d-nearby" className="nearby">
      <div className="row tl-tools">
        <h4 id="d-nearby">What happened nearby</h4>
        {timed && (
          <div className="row" role="radiogroup" aria-label="Nearby window">
            {NEARBY_WINDOWS.map(w => (
              <label key={w} className="inline small">
                <input type="radio" name="nearby-window" checked={w === win} onChange={() => { setWin(w); }} />{label(w)}
              </label>
            ))}
          </div>
        )}
      </div>
      <p className="muted small tl-meta">
        Inferred from timing: these events are close in time, not recorded as related.
      </p>
      <p className="small nb-anchor">
        <span className="muted">Around </span><span className="mono">{anchor.time ? fmtTime(anchor.time) : 'no time'}</span>
        <span className="muted"> · {RAW_TYPE[anchor.kind]} · </span><code className="mono wrap">{anchor.path ?? '(no path)'}</code>
      </p>
      {timed
        ? <Results key={`${anchor.key}|${win}`} cap={cap} anchor={anchor} windowMs={win} severity={severity} onSelect={onSelect} />
        : <p className="muted small">This event has no recorded time, so nothing can be placed near it.</p>}
    </section>
  );
}
