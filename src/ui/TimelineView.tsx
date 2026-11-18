import { useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent, type PointerEvent } from 'react';
import type { LoadedCapture } from '../ingest/load';
import { displayName, type ParentMode } from '../model/relations';
import type { ProcId } from '../model/types';
import type { QueueItem } from '../rules/engine';
import { SEVERITY_RANK, type Severity } from '../rules/rules';
import { DetailPane } from './DetailPane';
import { binTicks, buildLanes, flaggedIds, clockOf, fmtSpan, rulerStep, rulerTicks, type Lane, type LaneScope, type Lanes } from './lanes';
import { useSession } from './session-context';
import { plural, Sev, TimelineRow } from './shared';
import { RAW_TYPE } from './timeline';
import { SEVERITY_LABEL } from './triage-model';
import { useVirtualRows } from './virtual';

/**
 * The Timeline tab: every process as a lane on one time axis, in tree order. A bar runs from when the capture first
 * shows the process to its recorded exit; a root drops from the parent's bar to the child's at the moment it appeared.
 * Replay walks the recorded moments in order, so the tree can be watched growing.
 */

const ROW_H = 28;
const LABEL_W = 240;
const BAR_Y = 14;
const BAR_H = 7;
const MAX_INDENT = 16;
const OPEN = 16;
const BUCKETS = 240;
const MIN_SPAN = 5;
/** Moments per second while replaying. */
const SPEEDS = [{ label: 'Slow', n: 1.5 }, { label: 'Normal', n: 5 }, { label: 'Fast', n: 20 }] as const;
const MODES: { value: ParentMode; label: string }[] = [
  { value: 'original', label: 'Original parent' },
  { value: 'current', label: 'Current parent' },
  { value: 'responsible', label: 'Responsible' },
];
const SCOPES: { value: LaneScope; label: string }[] = [
  { value: 'flagged', label: 'Flagged processes and their lineage' },
  { value: 'selected', label: 'Selected process and its lineage' },
  { value: 'all', label: 'Every process' },
];

type Win = readonly [number, number];

/** Event density over the whole capture, and where the flagged events sit, for the overview strip. */
function overviewOf(L: Lanes): { counts: number[]; max: number; flags: { at: number; s: Severity }[] } {
  const counts = new Array<number>(BUCKETS).fill(0);
  const worst = new Map<number, Severity>();
  const bucket = (ms: number) => Math.min(BUCKETS - 1, Math.max(0, Math.floor(((ms - L.t0) / (L.t1 - L.t0)) * BUCKETS)));
  for (const lane of L.lanes) {
    if (!lane.before) counts[bucket(lane.startMs)]!++;
    for (const t of lane.ticks) {
      const b = bucket(t.ms);
      counts[b]!++;
      if (t.severity && (!worst.has(b) || SEVERITY_RANK[t.severity] > SEVERITY_RANK[worst.get(b)!])) worst.set(b, t.severity);
    }
  }
  return { counts, max: Math.max(1, ...counts), flags: [...worst].map(([at, s]) => ({ at, s })) };
}

const clamp = (w: Win, t0: number, t1: number): Win => {
  const span = Math.min(Math.max(w[1] - w[0], MIN_SPAN), t1 - t0);
  const a = Math.min(Math.max(w[0], t0), t1 - span);
  return [a, a + span];
};

function LaneBar({ lane, w, width, now }: { lane: Lane; w: Win; width: number; now: number | null }) {
  const span = w[1] - w[0];
  const X = (ms: number) => ((ms - w[0]) / span) * width;
  if (lane.endMs < w[0] || lane.startMs > w[1]) return <svg className="lane-svg" width={width} height={ROW_H} aria-hidden="true" />;
  // Never seen, only referenced as a parent: a faint dotted guide to hang the roots from, not a lifetime.
  if (lane.ghost) {
    return <svg className="lane-svg" width={width} height={ROW_H} aria-hidden="true"><line className="lane-ghost" x1={0} x2={width} y1={BAR_Y} y2={BAR_Y} /></svg>;
  }
  const x0 = Math.max(0, X(lane.startMs));
  const x1 = Math.min(width, X(lane.endMs));
  // The open ends take OPEN pixels each, when the bar's own end is on screen and the bar is long enough to spare them.
  const openStart = lane.before && X(lane.startMs) >= 0 && x1 - x0 > OPEN * 3;
  const openEnd = lane.after && X(lane.endMs) <= width && x1 - x0 > OPEN * 3;
  const s0 = openStart ? x0 + OPEN : x0;
  const s1 = openEnd ? x1 - OPEN : x1;
  const sev = lane.ticks.reduce<Severity | null>((s, t) => (t.severity && (s === null || SEVERITY_RANK[t.severity] > SEVERITY_RANK[s]) ? t.severity : s), null);
  const ticks = binTicks(lane.ticks, w[0], w[1], width);
  const execs = lane.execs.filter(e => e.ms >= w[0] && e.ms <= w[1]);
  return (
    <svg className="lane-svg" width={width} height={ROW_H} aria-hidden="true">
      {/* No start or no exit recorded: that end of the bar is a dashed run instead of solid, so it reads as open. */}
      <rect className={`lane-bar${lane.flagged ? ' flagged' : ''}${sev ? ` sev-${sev}` : ''}`} x={s0} y={BAR_Y - BAR_H / 2} width={Math.max(2, s1 - s0)} height={BAR_H} rx={1.5} />
      {s0 > x0 && <line className="lane-open" x1={x0} x2={s0} y1={BAR_Y} y2={BAR_Y} />}
      {s1 < x1 && <line className="lane-open" x1={s1} x2={x1} y1={BAR_Y} y2={BAR_Y} />}
      {now !== null && now > lane.startMs && now < lane.endMs && (
        <rect className="lane-past" x={x0} y={BAR_Y - BAR_H / 2} width={Math.max(0, Math.min(x1, X(now)) - x0)} height={BAR_H} rx={1.5} />
      )}
      {!lane.after && X(lane.endMs) <= width && <line className="lane-exit" x1={x1} x2={x1} y1={BAR_Y - 6} y2={BAR_Y + 6} />}
      {execs.map((e, i) => {
        const x = X(e.ms);
        const next = execs[i + 1];
        const room = (next ? X(next.ms) : x1) - x;
        return (
          <g key={i}>
            <line className="lane-exec" x1={x} x2={x} y1={BAR_Y - 7} y2={BAR_Y + 7} />
            {room > 44 && <text className="lane-prog" x={x + 3} y={BAR_Y - 6}>{e.name}</text>}
          </g>
        );
      })}
      {ticks.map(t => {
        const tip = `${RAW_TYPE[t.kind]}${t.path ? ` ${t.path}` : ''}${t.severity ? ` · flagged ${SEVERITY_LABEL[t.severity].toLowerCase()}` : ''}`;
        if (t.severity) return <circle key={t.key} className={`lane-flag sev-${t.severity}`} cx={t.x} cy={BAR_Y} r={4}><title>{tip}</title></circle>;
        if (t.kind === 'btm_add' || t.kind === 'btm_remove') {
          return <path key={t.key} className="lane-btm" d={`M${t.x} ${BAR_Y - 5}l4 5-4 5-4-5z`}><title>{tip}</title></path>;
        }
        if (t.kind === 'exec' || t.kind === 'image') return null;
        return <line key={t.key} className="lane-tick" x1={t.x} x2={t.x} y1={BAR_Y + 4} y2={BAR_Y + 9}><title>{tip}</title></line>;
      })}
    </svg>
  );
}

function TimelineInner({ cap, queue }: { cap: LoadedCapture; queue: QueueItem[] }) {
  const c = useSession();
  const { selected } = c;
  const noteRef = useRef<HTMLTextAreaElement>(null);
  const flagged = useMemo(() => flaggedIds(cap, queue), [cap, queue]);
  const [scope, setScope] = useState<LaneScope>(() => (flagged.length > 0 ? 'flagged' : 'all'));
  /** The process the "selected" scope is built around: fixed when chosen, so clicking a lane does not rebuild the view. */
  const [focusRoot, setFocusRoot] = useState<ProcId | null>(null);
  const [mode, setMode] = useState<ParentMode>('original');
  const L = useMemo(() => buildLanes(cap, { mode, scope, flagged, selected: focusRoot }), [cap, mode, scope, flagged, focusRoot]);
  const badge = useMemo(() => {
    const m = new Map<ProcId, Severity>();
    for (const q of cap.analysis.queue) if (q.procId !== null) m.set(q.procId, q.severity);
    return m;
  }, [cap]);
  const laneOf = useMemo(() => new Map(L.lanes.map((l, i) => [l.id, i])), [L]);
  const overview = useMemo(() => overviewOf(L), [L]);
  const utc = cap.model.stats.firstTime?.endsWith('Z') ?? true;

  const [win, setWin] = useState<Win>([L.t0, L.t1]);
  const w = clamp(win, L.t0, L.t1);
  const [at, setAt] = useState<number | null>(null);   // index into L.moments
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  useEffect(() => { setAt(null); setPlaying(false); }, [L]);
  const moment = at !== null ? L.moments[at] ?? null : null;
  const now = moment?.ms ?? null;

  const { scroller, mode: vmode, v } = useVirtualRows(L.lanes.length, ROW_H);
  const [chartW, setChartW] = useState(640);
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const measure = () => { if (el.clientWidth > 0) setChartW(Math.max(120, el.clientWidth - LABEL_W - 12)); };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => { ro.disconnect(); };
  }, [scroller]);

  const scrollToLane = (i: number) => {
    if (vmode === 'virtual') v.scrollToIndex(i, { align: 'auto' });
    else scroller.current?.querySelector(`[data-lane="${i}"]`)?.scrollIntoView?.({ block: 'nearest' });
  };
  // A step of the replay keeps its moment on screen: the lane scrolls in, and the window pans to the time.
  const goTo = (i: number) => {
    const mo = L.moments[i];
    if (!mo) return;
    setAt(i);
    setWin(cur => {
      const cw = clamp(cur, L.t0, L.t1);
      if (mo.ms >= cw[0] && mo.ms <= cw[1]) return cur;
      const span = cw[1] - cw[0];
      return clamp([mo.ms - span * 0.15, mo.ms + span * 0.85], L.t0, L.t1);
    });
    scrollToLane(mo.lane);
  };
  useEffect(() => {
    if (!playing) return;
    const n = SPEEDS[speed]!.n;
    const t = setInterval(() => {
      setAt(cur => {
        const next = cur === null ? 0 : cur + 1;
        if (next >= L.moments.length) { setPlaying(false); return cur; }
        return next;
      });
    }, 1000 / n);
    return () => { clearInterval(t); };
  }, [playing, speed, L]);
  // While playing, follow the moment (the interval only moves the index).
  useEffect(() => { if (playing && at !== null) goTo(at); }, [at, playing]);

  const selLane = selected !== null ? laneOf.get(selected) ?? -1 : -1;
  useEffect(() => { if (selLane >= 0 && !playing) scrollToLane(selLane); }, [selLane, vmode]);

  const select = (id: ProcId) => { c.selectProc(id); scroller.current?.focus({ preventScroll: true }); };
  const togglePlay = () => {
    if (L.moments.length === 0) return;
    if (!playing && (at === null || at >= L.moments.length - 1)) goTo(0);
    setPlaying(p => !p);
  };
  const step = (d: number) => {
    setPlaying(false);
    const i = at === null ? (d > 0 ? 0 : L.moments.length - 1) : Math.min(L.moments.length - 1, Math.max(0, at + d));
    goTo(i);
  };
  /** Puts the replay at the last moment at or before `ms` (the first one when `ms` is before all of them). */
  const seek = (ms: number) => {
    setPlaying(false);
    let lo = 0, hi = L.moments.length;
    while (lo < hi) { const mid = (lo + hi) >>> 1; if (L.moments[mid]!.ms <= ms) lo = mid + 1; else hi = mid; }
    if (L.moments.length > 0) goTo(Math.max(0, lo - 1));
  };
  const zoom = (f: number) => {
    const mid = now !== null && now >= w[0] && now <= w[1] ? now : (w[0] + w[1]) / 2;
    const span = (w[1] - w[0]) * f;
    const k = (mid - w[0]) / (w[1] - w[0]);
    setWin(clamp([mid - span * k, mid + span * (1 - k)], L.t0, L.t1));
  };
  const fitSelected = () => {
    if (selLane < 0) return;
    const l = L.lanes[selLane]!;
    const pad = Math.max((l.endMs - l.startMs) * 0.06, MIN_SPAN);
    setWin(clamp([l.startMs - pad, l.endMs + pad], L.t0, L.t1));
  };

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.metaKey || e.ctrlKey || e.altKey || e.target !== e.currentTarget) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (L.lanes.length === 0) return;
      e.preventDefault();
      const i = selLane < 0 ? (e.key === 'ArrowDown' ? 0 : L.lanes.length - 1) : Math.min(L.lanes.length - 1, Math.max(0, selLane + (e.key === 'ArrowDown' ? 1 : -1)));
      c.selectProc(L.lanes[i]!.id);
    } else if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { e.preventDefault(); step(e.key === 'ArrowRight' ? 1 : -1); }
    else if (e.key === ' ') { e.preventDefault(); togglePlay(); }
  };

  // The overview strip: drag across it to zoom to that stretch, click to centre the window there.
  const brush = useRef<{ x0: number; x1: number } | null>(null);
  const [brushBox, setBrushBox] = useState<{ x0: number; x1: number } | null>(null);
  const ovX = (ms: number) => ((ms - L.t0) / (L.t1 - L.t0)) * chartW;
  const ovMs = (x: number) => L.t0 + (Math.min(Math.max(x, 0), chartW) / chartW) * (L.t1 - L.t0);
  const localX = (e: PointerEvent<SVGSVGElement>) => e.clientX - e.currentTarget.getBoundingClientRect().left;
  const onBrushDown = (e: PointerEvent<SVGSVGElement>) => {
    e.currentTarget.setPointerCapture?.(e.pointerId);
    brush.current = { x0: localX(e), x1: localX(e) };
    setBrushBox(brush.current);
  };
  const onBrushMove = (e: PointerEvent<SVGSVGElement>) => {
    if (!brush.current) return;
    brush.current = { ...brush.current, x1: localX(e) };
    setBrushBox(brush.current);
  };
  const onBrushUp = () => {
    const b = brush.current;
    brush.current = null;
    setBrushBox(null);
    if (!b) return;
    if (Math.abs(b.x1 - b.x0) < 4) {
      const mid = ovMs(b.x0);
      const span = w[1] - w[0];
      setWin(clamp([mid - span / 2, mid + span / 2], L.t0, L.t1));
    } else setWin(clamp([ovMs(Math.min(b.x0, b.x1)), ovMs(Math.max(b.x0, b.x1))], L.t0, L.t1));
  };

  const X = (ms: number) => ((ms - w[0]) / (w[1] - w[0])) * chartW;
  const fine = rulerStep(w[0], w[1], chartW) < 1000;
  const whole = w[0] <= L.t0 && w[1] >= L.t1;

  // Which rows are drawn: the virtual window, or every row where the list is not laid out (no virtualization).
  const items = vmode === 'virtual' ? v.getVirtualItems().map(vi => ({ i: vi.index, top: vi.start })) : vmode === 'plain' ? L.lanes.map((_, i) => ({ i, top: i * ROW_H })) : [];
  const first = items[0]?.i ?? 0;
  const last = items[items.length - 1]?.i ?? -1;
  const top = items[0]?.top ?? 0;
  const roots = useMemo(() => {
    const out: { from: number; to: number; ms: number }[] = [];
    L.lanes.forEach((l, i) => { if (l.parent !== null && !l.before) out.push({ from: l.parent, to: i, ms: l.startMs }); });
    return out;
  }, [L]);

  const renderRow = (i: number, style: CSSProperties) => {
    const lane = L.lanes[i]!;
    const p = cap.model.processes.get(lane.id);
    const name = displayName(cap.model, lane.id);
    const sev = badge.get(lane.id);
    const future = now !== null && lane.startMs > now;
    const said = [
      name, p && !lane.ghost ? `pid ${p.pid}` : '',
      ...(lane.ghost ? ['never seen in the capture, only named as a parent'] : [
        lane.before ? 'running when the capture began' : `appeared ${clockOf(lane.startMs, utc, true)}`,
        lane.after ? 'still running at the end' : `exited ${clockOf(lane.endMs, utc, true)}`,
      ]),
      plural(lane.ticks.length, 'event'), sev ? `flagged ${SEVERITY_LABEL[sev].toLowerCase()}` : '',
    ].filter(Boolean).join(', ');
    return (
      <div key={lane.id} role="option" aria-selected={lane.id === selected} aria-label={said} data-lane={i} style={style}
        className={`lrow${lane.ghost ? ' ghost' : ''}${lane.id === selected ? ' sel' : ''}${future ? ' future' : ''}${moment?.lane === i ? ' now' : ''}`}
        onClick={() => { select(lane.id); }}>
        <div className="llabel" style={{ paddingLeft: 8 + Math.min(lane.depth, MAX_INDENT) * 12 }} title={name}>
          {sev && <Sev s={sev} />}
          <span className="truncate lname">{name}</span>
          {p && !lane.ghost && <span className="muted small lpid">{p.pid}</span>}
        </div>
        <LaneBar lane={lane} w={w} width={chartW} now={now} />
      </div>
    );
  };

  const scopeNote = selected !== null && selLane < 0 && cap.model.processes.get(selected)?.ghost === false;

  return (
    <div className="triage timeline">
      <section className="queue" aria-label="Process timeline">
        <div className="qtools">
          <div className="row">
            <label className="inline">Show{' '}
              <select value={scope} onChange={e => {
                const s = e.target.value as LaneScope;
                if (s === 'selected' && selected !== null) setFocusRoot(selected);
                setScope(s);
              }}>
                {SCOPES.map(s => <option key={s.value} value={s.value} disabled={s.value === 'selected' && selected === null && focusRoot === null}>{s.label}</option>)}
              </select>
            </label>
            {scope === 'selected' && selected !== null && selected !== focusRoot && laneOf.has(selected) && (
              <button className="small-btn" onClick={() => { setFocusRoot(selected); }}>Focus on the selected lane</button>
            )}
            <label className="inline">Parent mode{' '}
              <select value={mode} onChange={e => { setMode(e.target.value as ParentMode); }}>
                {MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </label>
          </div>
          <div className="tl-overview">
            <span className="tl-win muted small" style={{ width: LABEL_W - 12 }}>
              {whole ? `Whole capture, ${fmtSpan(L.t1 - L.t0)}` : `${clockOf(w[0], utc, fine)} to ${clockOf(w[1], utc, fine)}, ${fmtSpan(w[1] - w[0])}`}{utc ? ' UTC' : ''}
              <span className="tl-zoom">
                <button className="small-btn" onClick={() => { zoom(2); }} disabled={whole} aria-label="Zoom out" title="Zoom out">−</button>
                <button className="small-btn" onClick={() => { zoom(0.5); }} aria-label="Zoom in" title="Zoom in (or drag across the strip)">+</button>
                <button className="small-btn" onClick={() => { setWin([L.t0, L.t1]); }} disabled={whole}>Whole</button>
                <button className="small-btn" onClick={fitSelected} disabled={selLane < 0} title="Zoom to the selected process's lifetime">Fit selected</button>
              </span>
            </span>
            <svg width={chartW} height={34} className="ov-svg" role="img" aria-label="Activity over the whole capture: drag across it to zoom to that stretch"
              onPointerDown={onBrushDown} onPointerMove={onBrushMove} onPointerUp={onBrushUp} onPointerCancel={onBrushUp}>
              {overview.counts.map((n, b) => n > 0 && (
                <rect key={b} className="ov-bar" x={(b / BUCKETS) * chartW} width={Math.max(1, chartW / BUCKETS - 0.5)}
                  y={30 - Math.max(1.5, Math.sqrt(n / overview.max) * 24)} height={Math.max(1.5, Math.sqrt(n / overview.max) * 24)} />
              ))}
              {overview.flags.map(f => <rect key={f.at} className={`ov-flag sev-${f.s}`} x={(f.at / BUCKETS) * chartW} y={0} width={2} height={6} />)}
              {!whole && <rect className="ov-win" x={ovX(w[0])} y={0.5} width={Math.max(2, ovX(w[1]) - ovX(w[0]))} height={33} />}
              {now !== null && <line className="ov-now" x1={ovX(now)} x2={ovX(now)} y1={0} y2={34} />}
              {brushBox && <rect className="ov-brush" x={Math.min(brushBox.x0, brushBox.x1)} y={0} width={Math.abs(brushBox.x1 - brushBox.x0)} height={34} />}
            </svg>
          </div>
          <div className="row tl-replay">
            <button className="small-btn" onClick={() => { step(-1); }} disabled={L.moments.length === 0 || at === 0} aria-label="Previous moment">◀</button>
            <button className="small-btn primary" onClick={togglePlay} disabled={L.moments.length === 0} aria-pressed={playing}>{playing ? 'Pause' : 'Replay'}</button>
            <button className="small-btn" onClick={() => { step(1); }} disabled={L.moments.length === 0 || at === L.moments.length - 1} aria-label="Next moment">▶</button>
            <label className="inline small">Speed{' '}
              <select value={speed} onChange={e => { setSpeed(Number(e.target.value)); }}>
                {SPEEDS.map((s, i) => <option key={s.label} value={i}>{s.label}</option>)}
              </select>
            </label>
            <span className="muted small num" aria-live="off">{at !== null ? `${(at + 1).toLocaleString('en-US')} of ${L.moments.length.toLocaleString('en-US')}` : plural(L.moments.length, 'moment')}</span>
            {at !== null && <button className="link small" onClick={() => { setPlaying(false); setAt(null); }}>Show all</button>}
          </div>
          {/* One slot, always there, so stepping through the replay never moves the lanes. */}
          <div className="tl-now-slot">
            {moment ? (
              <ol className="tl tl-now" aria-label="Current moment" aria-live={playing ? 'off' : 'polite'}>
                <TimelineRow cap={cap} e={moment.e} self="" multiDay={false} onSelect={select} />
              </ol>
            ) : (
              <p className="muted small">Replay steps through the recorded moments in order. With the lanes focused, ← → step and Space plays.</p>
            )}
          </div>
        </div>
        <div className="tl-ruler" style={{ paddingLeft: LABEL_W }}>
          <svg width={chartW} height={20} aria-label="Time axis: click to move the replay there" role="img"
            onClick={e => { seek(w[0] + ((e.clientX - e.currentTarget.getBoundingClientRect().left) / chartW) * (w[1] - w[0])); }}>
            {rulerTicks(w[0], w[1], chartW).map(t => (
              <g key={t}>
                <line className="ruler-tick" x1={X(t)} x2={X(t)} y1={14} y2={20} />
                <text className="ruler-label" x={X(t) + 3} y={11}>{clockOf(t, utc, fine)}</text>
              </g>
            ))}
            {now !== null && now >= w[0] && now <= w[1] && <path className="ruler-now" d={`M${X(now) - 5} 12h10l-5 8z`} />}
          </svg>
        </div>
        <div ref={scroller} role="listbox" aria-label="Process lanes" tabIndex={0} className={`qscroll lscroll roots-${mode}`} onKeyDown={onKey}>
          <div style={{ height: L.lanes.length * ROW_H, position: 'relative' }}>
            {items.map(({ i, top: y }) => renderRow(i, { position: 'absolute', top: 0, left: 0, right: 0, height: ROW_H, transform: `translateY(${y}px)` }))}
            {last >= first && (
              <svg className="lane-roots" aria-hidden="true" width={chartW} height={(last - first + 1) * ROW_H}
                style={{ position: 'absolute', left: LABEL_W, top }}>
                {roots.map(r => {
                  if (r.to < first || r.from > last || r.ms < w[0] || r.ms > w[1]) return null;
                  const x = X(r.ms);
                  const y1 = (r.from - first) * ROW_H + BAR_Y + BAR_H / 2;
                  const y2 = (r.to - first) * ROW_H + BAR_Y - BAR_H / 2;
                  const future = now !== null && r.ms > now;
                  return <path key={r.to} className={`lane-root${future ? ' future' : ''}`} d={`M${x} ${y1}V${y2}`} />;
                })}
                {now !== null && now >= w[0] && now <= w[1] && <line className="lane-now" x1={X(now)} x2={X(now)} y1={0} y2={(last - first + 1) * ROW_H} />}
              </svg>
            )}
          </div>
        </div>
        {L.lanes.length === 0 && (
          <p className="muted qempty">{scope === 'flagged' ? 'No flagged processes in this capture. Show every process to see them all.' : scope === 'selected' ? 'Select a process first.' : 'No processes.'}</p>
        )}
        <div className="qfoot small muted">
          <span>
            {plural(L.lanes.length, 'process', 'processes')}
            {L.truncated && <span className="warn"> · stopped at the first {L.lanes.length.toLocaleString('en-US')}</span>}
            {L.untimed > 0 && ` · ${plural(L.untimed, 'event')} with no usable time, not placed`}
            {scopeNote && <> · the selected process has no lane here: <button className="link" onClick={() => { setFocusRoot(selected); setScope('selected'); }}>show its lineage</button></>}
          </span>
          <span className="tl-legend" aria-label="Legend">
            <span><i className="lg-bar" aria-hidden="true" />alive</span>
            <span><i className="lg-root" aria-hidden="true" />appeared under</span>
            <span><i className="lg-exec" aria-hidden="true" />new program</span>
            <span><i className="lg-flag" aria-hidden="true" />flagged</span>
            <span><i className="lg-btm" aria-hidden="true" />launch item</span>
            <span><i className="lg-open" aria-hidden="true" />no start or exit recorded</span>
          </span>
        </div>
      </section>
      <section className="detail" aria-label="Selected process">
        {selected !== null
          ? <DetailPane selKey={selected} onSelectProc={c.selectProc} noteRef={noteRef} />
          : <p className="muted detail-empty">Select a lane to see what that process is and what it did. Replay walks through the recorded moments in order: each new process drops from its parent at the moment it appeared.</p>}
      </section>
    </div>
  );
}

export function TimelineView() {
  const { capture, triage, active } = useSession();
  if (!capture || !triage) return null;
  return <TimelineInner key={active} cap={capture} queue={triage.queue} />;
}
