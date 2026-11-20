import { useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react';
import type { LoadedCapture } from '../ingest/load';
import { ancestry, childrenIndex, displayName, type ParentMode } from '../model/relations';
import type { ProcId, Process } from '../model/types';
import { basename, latestImage, persistenceItem } from '../model/util';
import type { Finding, QueueItem } from '../rules/engine';
import { queueItemFor } from '../rules/group';
import { MITRE_NAMES } from '../rules/mitre';
import type { Severity } from '../rules/rules';
import { NO_IDENTITY, programKey } from '../session/routine';
import type { Status } from '../session/store';
import { LaunchItem } from './LaunchItem';
import { defaultAnchor } from './nearby';
import { NearbyPanel } from './NearbyPanel';
import { STATUS_ICON } from './QueueList';
import { useSession } from './session-context';
import { plural, ProcLink, Sev, TimelineRow } from './shared';
import { processTimeline, recordedCounts, recordedSpan, type TimelineEvent, type TimelineKind } from './timeline';
import {
  coverage, fmtArgs, fmtClock, fmtTime, overview, SEVERITY_LABEL, TRIAGE_KEYS, VERDICT_LABEL, verdictKey,
} from './triage-model';
import { ReportOffer } from './ReportButton';

const SHOW_FIRST = 40;
const TIMELINE_FIRST = 60;
const TIMELINE_STEP = 200;
const yesNo = (b: boolean): string => (b ? 'yes' : 'no');

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} className="dsec">
      <h3 id={id} tabIndex={-1}>{title}</h3>
      {children}
    </section>
  );
}

/** One finding, written for a learner: what it means first, then the technique, then the evidence. */
function FindingBlock({ f }: { f: Finding }) {
  return (
    <article className={`why sev-border-${f.severity}`}>
      <div className="row"><Sev s={f.severity} /><strong>{f.title}</strong></div>
      <p className="explain">{f.explanation}</p>
      <div className="row mitre">
        {f.mitre.map(id => (
          <span key={id} className="chip" title="MITRE ATT&CK technique">{MITRE_NAMES[id] ? `${id} · ${MITRE_NAMES[id]}` : id}</span>
        ))}
        {f.trait && f.mitre.length === 0 && (
          <span className="chip trait" title="A property common in malware, but also in harmless software: it says how suspicious a binary looks, not what an attacker did.">trait, not an attack technique</span>
        )}
      </div>
      <div className="evidence"><span className="muted small">Evidence</span><code className="mono wrap">{f.evidence}</code></div>
    </article>
  );
}

function Why({ findings, item }: { findings: Finding[]; item?: QueueItem }) {
  return (
    <Section id="d-why" title="Why flagged">
      {findings.length > 0
        ? findings.map((f, i) => <FindingBlock key={`${f.ruleId}:${i}`} f={f} />)
        : <p className="muted">Not flagged on its own. You are looking at it because of where it sits in a chain or tree.</p>}
      {item?.reconBurst && (
        <p className="small"><span className="chain-mark">recon burst</span>{' '}
          <span className="muted">Queued because it was one of 3 or more different reconnaissance tools run under the same parent within 60 seconds. Each one is common on its own; together they look like someone sizing up the machine.</span></p>
      )}
      {item?.inFlaggedChain && (
        <p className="small"><span className="chain-mark">in chain</span>{' '}
          <span className="muted">Queued because it ran under, or as part of, something that was flagged.</span></p>
      )}
    </Section>
  );
}

function Step({ cap, id, onSelect }: { cap: LoadedCapture; id: ProcId; onSelect(id: ProcId): void }) {
  const p = cap.model.processes.get(id);
  return (
    <li>
      <button className="link" onClick={() => { onSelect(id); }}>{displayName(cap.model, id)}</button>
      {p && !p.ghost && <span className="muted small"> pid {p.pid}</span>}
    </li>
  );
}

const ROOTS: { mode: ParentMode; name: string; label: string }[] = [
  { mode: 'original', name: 'Original parent', label: 'Launch chain, oldest first' },
  { mode: 'current', name: 'Current parent', label: 'Current-parent chain, oldest first' },
  { mode: 'responsible', name: 'Responsible', label: 'Responsible chain, oldest first' },
];
const same = (a: ProcId[], b: ProcId[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Every root of a process, the way a gameleira grows: each way of tracing where it came from hangs as its own column,
 * oldest first, and they all come down into one trunk, the process itself. A root that agrees with the original parent
 * is not drawn twice; the line under the trunk says so.
 */
function LaunchedBy({ cap, p, onSelect }: { cap: LoadedCapture; p: Process; onSelect(id: ProcId): void }) {
  const chains = useMemo(() => ROOTS.map(r => ({ ...r, chain: ancestry(cap.model, p.id, r.mode).reverse() })), [cap, p.id]);
  const original = chains[0]!.chain;
  const shown = chains.filter((r, i) => i === 0 || (r.chain.length > 0 && !same(r.chain, original)));
  const agree = chains.filter((r, i) => i > 0 && r.chain.length > 0 && same(r.chain, original)).map(r => r.name.toLowerCase());
  const selfResponsible = p.responsible === p.id;
  const unknown = chains.filter((r, i) => i > 0 && r.chain.length === 0 && !(r.mode === 'responsible' && selfResponsible))
    .map(r => r.name.toLowerCase());
  return (
    <Section id="d-launch" title="Launched by">
      <div className="roots">
        {shown.map(r => (
          <div key={r.mode} className={`root ${r.mode}`}>
            <span className="root-name">{r.name}</span>
            <ol className="chain" aria-label={r.label}>
              {r.chain.map(id => <Step key={id} cap={cap} id={id} onSelect={onSelect} />)}
              {r.chain.length === 0 && <li className="same">No parent is known for this process.</li>}
            </ol>
          </div>
        ))}
      </div>
      <div className="trunk"><span className="self">{displayName(cap.model, p.id)}</span>{!p.ghost && <span className="muted small">pid {p.pid}</span>}</div>
      {(agree.length > 0 || unknown.length > 0 || selfResponsible) && (
        <p className="muted small roots-agree">
          {agree.length > 0 && `The ${agree.join(' and ')} ${agree.length === 1 ? 'is' : 'are'} the same chain. `}
          {selfResponsible && 'It is its own responsible process. '}
          {unknown.length > 0 && `No ${unknown.join(' or ')} recorded.`}
        </p>
      )}
    </Section>
  );
}

function Dl({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="dl">
      {rows.map(([k, v]) => <div key={k} className="dlrow"><dt>{k}</dt><dd>{v}</dd></div>)}
    </dl>
  );
}

const COUNT_WORDS: [TimelineKind[], string][] = [
  [['exec'], 'exec'], [['image'], 'program change without exec'], [['spawn'], 'fork'],
  [['create', 'rename', 'unlink', 'write', 'setextattr'], 'file event'], [['btm_add', 'btm_remove'], 'launch item event'], [['exit'], 'exit'],
];

function Details({ cap, p, own, onSelect }: { cap: LoadedCapture; p: Process; own: TimelineEvent[]; onSelect(id: ProcId): void }) {
  const img = latestImage(p);
  const exec = [...p.images].reverse().find(i => i.args !== null);
  const history = p.images.filter(i => !i.inherited);
  const shown = history.length > 0 ? history : p.images;
  if (!img) {
    return (
      <Section id="d-details" title="Details">
        <p className="muted">This process started before the capture began, so only its pid is known. Its program, arguments and signature were never logged.</p>
      </Section>
    );
  }
  const span = recordedSpan(own);
  const counts = recordedCounts(own);
  const countText = COUNT_WORDS.map(([kinds, word]) => [kinds.reduce((a, k) => a + (counts[k] ?? 0), 0), word] as const)
    .filter(([n]) => n > 0).map(([n, w]) => plural(n, w)).join(' · ');
  const ppid = p.originalPpid !== null && p.ppid !== null && p.originalPpid !== p.ppid
    ? `${p.originalPpid} at launch, ${p.ppid} later` : String(p.originalPpid ?? p.ppid ?? '');
  const rows: [string, ReactNode][] = [
    ['PID', <span className="mono">{p.pid}</span>],
    ['Parent PID', ppid ? <span className="mono">{ppid}</span> : <span className="muted">not recorded</span>],
    ['Parent', <ProcLink cap={cap} id={p.originalParent} onSelect={onSelect} />],
    ['Last captured exec command line', exec?.args ? <code className="mono wrap">{fmtArgs(exec.args)}</code> : <span className="muted">no exec event captured</span>],
    ['Working dir', exec?.cwd ? <code className="mono wrap">{exec.cwd}</code> : <span className="muted">unknown</span>],
    ['Program', <code className="mono wrap">{img.path ?? 'unknown'}</code>],
  ];
  if (shown.length > 1) rows.push(['Image history', <code className="mono wrap">{shown.map(i => i.path ?? '?').join(' → ')}</code>]);
  rows.push(
    ['Signing ID', img.signingId ?? <span className="muted">none</span>],
    ['Team ID', img.teamId ?? <span className="muted">none</span>],
    ['Apple platform binary', yesNo(img.isPlatform)],
    ['Ad-hoc signed', yesNo((img.csFlags & 0x2) !== 0)],
    ['Started', <span className="mono">{fmtTime(p.startTime)}</span>],
    ['Exited', <span className="mono">{p.exitTime ? fmtTime(p.exitTime) : 'not seen (still running, or the capture ended first)'}</span>],
    ['Recorded activity', span
      ? <span className="mono">{span.first === span.last ? fmtTime(span.first)
        : `${fmtTime(span.first)} → ${span.first.slice(0, 10) === span.last.slice(0, 10) ? fmtClock(span.last) : fmtTime(span.last)}`}</span>
      : <span className="muted">no timed events</span>],
    ['Recorded events', countText || <span className="muted">none of its own</span>],
  );
  return <Section id="d-details" title="Details"><Dl rows={rows} /></Section>;
}

/**
 * What the process did, in capture order: every recorded event that belongs to it (and, on request, to every process
 * under it). Built from the capture alone; event types the viewer does not model are counted elsewhere, never placed.
 */
function Timeline({ cap, p, anchor, onAnchor, onSelect }: {
  cap: LoadedCapture; p: Process; anchor: TimelineEvent | null; onAnchor(e: TimelineEvent): void; onSelect(id: ProcId): void;
}) {
  const [withKids, setWithKids] = useState(false);
  const [limit, setLimit] = useState(TIMELINE_FIRST);
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const tl = useMemo(() => processTimeline(cap, p.id, withKids), [cap, p.id, withKids]);
  const list = flaggedOnly ? tl.events.filter(e => e.findings.length > 0 || e.kind === 'exec' || e.kind === 'btm_add') : tl.events;
  const shown = list.slice(0, limit);
  const span = recordedSpan(tl.events);
  const multiDay = span !== null && span.first.slice(0, 10) !== span.last.slice(0, 10);
  // eslogger writes UTC (a trailing Z); only then is the zone named.
  const utc = tl.events.every(e => !e.time || e.time.endsWith('Z'));
  return (
    <>
      <div className="row tl-tools">
        <h4>Timeline</h4>
        <label className="inline small"><input type="checkbox" checked={withKids} onChange={e => { setWithKids(e.target.checked); setLimit(TIMELINE_FIRST); }} />Include descendants</label>
        <label className="inline small"><input type="checkbox" checked={flaggedOnly} onChange={e => { setFlaggedOnly(e.target.checked); setLimit(TIMELINE_FIRST); }} />Execs, launch items and flagged events only</label>
      </div>
      <p className="muted small tl-meta">
        {plural(list.length, 'event')}{withKids && ` across ${plural(tl.processes, 'process', 'processes')}`}
        {span && ` · ${multiDay ? `${span.first.slice(0, 10)} to ${span.last.slice(0, 10)}` : span.first.slice(0, 10)}${utc ? ', UTC' : ''}`}
        {tl.truncated && <span className="warn"> · stopped at the first {tl.processes.toLocaleString('en-US')} processes of the subtree</span>}
      </p>
      {list.length === 0 ? <p className="muted small">No events recorded{flaggedOnly ? ' of these kinds' : ''}.</p> : (
        <ol className="tl" aria-label={`Timeline of ${displayName(cap.model, p.id)}`}>
          {shown.map(e => <TimelineRow key={e.key} cap={cap} e={e} self={p.id} multiDay={multiDay} onSelect={onSelect} onAnchor={onAnchor} anchored={e.key === anchor?.key} />)}
        </ol>
      )}
      {/* In steps: a subtree can hold tens of thousands of events, and mounting them all at once stalls the pane. */}
      {list.length > shown.length && (
        <button onClick={() => { setLimit(l => l + TIMELINE_STEP); }}>
          Show {Math.min(TIMELINE_STEP, list.length - shown.length).toLocaleString('en-US')} more ({(list.length - shown.length).toLocaleString('en-US')} left)
        </button>
      )}
    </>
  );
}

/**
 * For a row that stands for several identical processes (a loop): says so and lists them, so any one can be opened. The
 * findings and the verdict above and below are the same for all of them.
 */
function Repeats({ cap, item, current, onSelect }: { cap: LoadedCapture; item: QueueItem; current: ProcId; onSelect(id: ProcId): void }) {
  const [all, setAll] = useState(false);
  if (item.members.length < 2) return null;
  const shown = all ? item.members : item.members.slice(0, SHOW_FIRST);
  return (
    <Section id="d-repeats" title={`Repeated ${item.members.length} times`}>
      <p className="muted small">
        {item.members.length} identical processes (same program, arguments, parent and findings) are listed as one row. A verdict you
        set on the row applies to all of them; open one to see what it did.
      </p>
      <ul className="kids">
        {shown.map(id => {
          const proc = cap.model.processes.get(id);
          const at = proc ? latestImage(proc)?.time ?? proc.startTime : null;
          return (
            <li key={id}>
              <button className="link" aria-current={id === current ? 'true' : undefined} onClick={() => { onSelect(id); }}>
                pid {proc?.pid ?? id}{at ? ` · ${fmtClock(at)}` : ''}
              </button>
            </li>
          );
        })}
      </ul>
      {item.members.length > SHOW_FIRST && !all && <button onClick={() => { setAll(true); }}>Show all {item.members.length}</button>}
    </Section>
  );
}

function DidWhat({ cap, p, own, onSelect }: { cap: LoadedCapture; p: Process; own: TimelineEvent[]; onSelect(id: ProcId): void }) {
  const [allKids, setAllKids] = useState(false);
  // The event the nearby panel is built around: one the person picked on the Timeline, else the most telling own event.
  const [picked, setPicked] = useState<TimelineEvent | null>(null);
  const fallback = defaultAnchor(own);
  const anchor = picked ?? fallback;
  // Offered only when it would change the anchor: picking the default row itself leaves nothing to reset.
  const reset = picked !== null && picked.key !== fallback?.key ? () => { setPicked(null); } : undefined;
  const kids = useMemo(() => childrenIndex(cap.model, 'original').get(p.id) ?? [], [cap, p.id]);
  const severity = useMemo(() => {
    const m = new Map<ProcId, Severity>();
    for (const q of cap.analysis.queue) if (q.procId !== null) for (const id of q.members) m.set(id, q.severity);
    return m;
  }, [cap]);
  const kidsShown = allKids ? kids : kids.slice(0, SHOW_FIRST);
  return (
    <Section id="d-did" title="What it did">
      <h4>Started {kids.length} {kids.length === 1 ? 'process' : 'processes'}</h4>
      {kids.length === 0 ? <p className="muted small">None.</p> : (
        <ul className="kids">
          {kidsShown.map(id => {
            const sev = severity.get(id);
            const kid = cap.model.processes.get(id);
            return (
              <li key={id}>
                {sev && <Sev s={sev} />}
                <button className="link" onClick={() => { onSelect(id); }}>{displayName(cap.model, id)}</button>
                {kid && !kid.ghost && <span className="muted small"> pid {kid.pid}</span>}
              </li>
            );
          })}
        </ul>
      )}
      {kids.length > SHOW_FIRST && !allKids && <button onClick={() => { setAllKids(true); }}>Show all {kids.length}</button>}
      <Timeline key={p.id} cap={cap} p={p} anchor={anchor} onAnchor={setPicked} onSelect={onSelect} />
      {anchor && <NearbyPanel key={`nearby-${p.id}`} cap={cap} anchor={anchor} severity={severity} onSelect={onSelect} onReset={reset} />}
    </Section>
  );
}

function ContextOnly({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <Section id="d-ctx" title="Low-signal observations">
      <p className="muted small">These were noticed but are common on their own, so they did not put this process in the queue.</p>
      {findings.map((f, i) => <FindingBlock key={`${f.ruleId}:${i}`} f={f} />)}
    </Section>
  );
}

const NOTE_DEBOUNCE_MS = 500;

/**
 * The note saves while typing (debounced), on blur, when the pane goes away and when the page is hidden. The save always
 * goes to the capture and process the note was opened on (`fingerprint`, `vkey`), never to whatever is active by then:
 * a capture that finishes loading switches the active capture and unmounts this field while the user is still typing.
 */
function Note({ vkey, fingerprint, saved, noteRef }: {
  vkey: string; fingerprint: string; saved: string; noteRef: RefObject<HTMLTextAreaElement | null>;
}) {
  const { setNote } = useSession();
  const [text, setText] = useState(saved);
  const textRef = useRef(saved);
  const savedRef = useRef(saved);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // The latest saver, read when a save fires. The note never carries a status: setNote keeps whatever verdict is current
  // when the write runs (a click on Confirm may have come after the first keystroke, and its write may still be open).
  const live = useRef({ setNote });
  live.current = { setNote };
  // The saved note changing from outside (another save) is not a local edit.
  useEffect(() => { savedRef.current = saved; }, [saved]);

  const flush = useRef(() => {
    clearTimeout(timer.current);
    timer.current = undefined;
    if (textRef.current === savedRef.current) return;
    savedRef.current = textRef.current;
    void live.current.setNote(vkey, textRef.current, fingerprint);
  });

  useEffect(() => {
    const f = flush.current;
    window.addEventListener('pagehide', f);
    return () => { window.removeEventListener('pagehide', f); f(); };
  }, []);

  return (
    <label className="note-label">Note
      <textarea ref={noteRef} rows={3} value={text}
        onChange={e => {
          setText(e.target.value);
          textRef.current = e.target.value;
          clearTimeout(timer.current);
          timer.current = setTimeout(flush.current, NOTE_DEBOUNCE_MS);
        }}
        onBlur={flush.current} />
    </label>
  );
}

function Actions({ vkey, p, noteRef }: { vkey: string; p: Process | null; noteRef: RefObject<HTMLTextAreaElement | null> }) {
  const c = useSession();
  const fingerprint = c.active ?? '';
  const verdict = c.verdicts.get(vkey);
  const status: Status = verdict?.status ?? 'unreviewed';
  const img = p ? latestImage(p) : undefined;
  const pkey = img ? programKey(img) : null;
  const noIdentity = pkey === null || pkey === NO_IDENTITY;
  const keptWhy = pkey !== null && c.routineKeys.has(pkey) ? c.triage?.kept.get(`p:${vkey}`) : undefined;
  return (
    <Section id="d-actions" title="Actions">
      <p className="small status-line"><span className="muted">Verdict: </span><strong className={`st-${status}`}>{VERDICT_LABEL[status]}</strong></p>
      <div className="row">
        <button className="primary" aria-pressed={status === 'confirmed'} onClick={() => { void c.toggleVerdict(vkey, 'confirmed'); }}>Mark suspicious <kbd>c</kbd></button>
        <button aria-pressed={status === 'benign'} onClick={() => { void c.toggleVerdict(vkey, 'benign'); }}>Mark benign <kbd>b</kbd></button>
        {p && (pkey !== null && c.routineKeys.has(pkey)
          ? <button onClick={() => { void c.removeRoutine(pkey); }}>Stop treating as routine</button>
          : <button disabled={noIdentity} title={noIdentity ? 'No signing ID, team ID or path: it cannot be told apart from other programs' : undefined}
              onClick={() => { if (img) void c.addRoutine(img); }}>Treat as routine</button>)}
        {p && <button onClick={() => { c.showInTree(p.id, c.view === 'triage' ? vkey : undefined); }}>Show in tree <kbd>t</kbd></button>}
      </div>
      {p && <p className="muted small">“Treat as routine” hides every run of this program, in every capture of this session, except rows with a high or persistence finding.</p>}
      {keptWhy && <p className="small warn">This program is marked routine, but this row stays visible: {keptWhy}.</p>}
      <Note key={`${fingerprint}:${vkey}`} vkey={vkey} fingerprint={fingerprint} saved={verdict?.note ?? ''} noteRef={noteRef} />
      <p className="muted small">Press <kbd>n</kbd> to jump to the note. Pressing the verdict it already has takes it back to unreviewed; <kbd>u</kbd> undoes the last verdict you set.</p>
    </Section>
  );
}

function PersistenceDetail({ cap, q, onSelect, noteRef }: {
  cap: LoadedCapture; q: QueueItem; onSelect(id: ProcId): void; noteRef: RefObject<HTMLTextAreaElement | null>;
}) {
  const item = persistenceItem(cap.model, q.persistenceId);
  const status = useSession().verdicts.get(q.key)?.status ?? 'unreviewed';
  return (
    <>
      <header className="dhead">
        <h2>{`persistence: ${basename(item?.plistPath ?? null) || q.key}`}</h2>
        <p className="muted small">A launch item registered while the capture ran. No captured process is tied to it, so there is no launch chain.</p>
        <div className="row assess">
          <span className="assess-chip">Severity <Sev s={q.severity} full /></span>
          <span className="assess-chip">Verdict <strong className={`st-${status}`}>{VERDICT_LABEL[status]}</strong></span>
        </div>
      </header>
      <Why findings={q.findings} item={q} />
      <Section id="d-details" title="Details">
        {item ? <LaunchItem cap={cap} item={item} current={null} onSelect={onSelect} /> : <p className="muted">Launch item details are not available.</p>}
      </Section>
      <Actions vkey={q.key} p={null} noteRef={noteRef} />
    </>
  );
}

/** The launch items a process's findings are about: the process registered one, or wrote the plist of one. */
function LaunchItems({ cap, p, findings, onSelect }: { cap: LoadedCapture; p: Process; findings: Finding[]; onSelect(id: ProcId): void }) {
  const ids = [...new Set(findings.map(f => f.persistenceId).filter((x): x is string => x !== null))];
  const items = ids.flatMap(id => persistenceItem(cap.model, id) ?? []);
  if (items.length === 0) return null;
  return (
    <Section id="d-launch-item" title={items.length === 1 ? 'Launch item' : 'Launch items'}>
      {items.map(item => <LaunchItem key={item.id} cap={cap} item={item} current={p.id} onSelect={onSelect} />)}
    </Section>
  );
}

/**
 * The unreviewed rows as one bar split by severity, each part as wide as its share, its count printed above it. The
 * label and the bar share one column template, so each count stands over its own part.
 */
function SeverityBar({ counts }: { counts: (readonly [Severity, number])[] }) {
  const parts = counts.filter(([, n]) => n > 0);
  const cols = parts.map(([, n]) => `minmax(64px, ${n}fr)`).join(' ');
  return (
    <div className="sev-split" role="img" aria-label={`Unreviewed by severity: ${counts.map(([s, n]) => `${SEVERITY_LABEL[s]} ${n}`).join(', ')}`}>
      <div className="sevbar-labels" style={{ gridTemplateColumns: cols }}>
        {parts.map(([s, n]) => <span key={s} className={`sev-${s}`}><span>{SEVERITY_LABEL[s]}</span> <b className="num">{n}</b></span>)}
      </div>
      <div className="sevbar" style={{ gridTemplateColumns: cols }}>
        {parts.map(([s]) => <span key={s} className={`seg ${s}`} />)}
      </div>
    </div>
  );
}

const SEVERITIES: Severity[] = ['high', 'med', 'low'];
const VERDICTS: Status[] = ['unreviewed', 'confirmed', 'benign'];

/** A count with a bar as wide as its share of `of`; the button narrows the queue to it. */
function DistRow({ label, n, of, cls, title, onPick }: { label: ReactNode; n: number; of: number; cls: string; title: string; onPick(): void }) {
  return (
    <li>
      <button className="dist-row" onClick={onPick} title={title}>
        <span className="dist-label">{label}</span>
        <span className="dist-bar" aria-hidden="true"><span className={cls} style={{ width: of > 0 ? `${(n / of) * 100}%` : 0 }} /></span>
        <b className="num">{n.toLocaleString('en-US')}</b>
      </button>
    </li>
  );
}

/** Before anything is selected: where the investigation stands, what the capture can show, and the keys. */
function NothingSelected() {
  const c = useSession();
  const { capture: cap, triage, verdicts } = c;
  const queue = triage?.queue ?? [];
  const o = useMemo(() => (cap ? overview(cap, queue, verdicts) : null), [cap, queue, verdicts]);
  const cov = useMemo(() => (cap ? coverage(cap.model) : null), [cap]);
  if (!cap || !o || !cov) return null;
  const open = o.byVerdict.unreviewed;
  const set = c.updateTriageFilters;
  const warns = cov.notes.filter(x => x.level === 'warn');
  return (
    <div className="detail-empty overview">
      <p className="lead-figure"><span className="num">{open}</span> of {queue.length} flagged {queue.length === 1 ? 'row is' : 'rows are'} unreviewed</p>
      {open > 0 && <SeverityBar counts={SEVERITIES.map(s => [s, o.bySeverity[s].open] as const)} />}
      <p className="muted">Select a flagged process on the left to see why it was flagged, where it came from and what it did. Rows run high first, then by time.</p>

      <ReportOffer />

      {queue.length > 0 && (
        <div className="ov-grid">
          <section aria-labelledby="ov-sev">
            <h3 id="ov-sev">Severity <span className="muted small">what the rules found</span></h3>
            <ul className="dist">
              {SEVERITIES.map(s => (
                <DistRow key={s} label={SEVERITY_LABEL[s]} n={o.bySeverity[s].total} of={queue.length} cls={`seg ${s}`}
                  title={`Show only ${SEVERITY_LABEL[s].toLowerCase()} severity rows`} onPick={() => { set({ sev: new Set([s]) }); }} />
              ))}
            </ul>
          </section>
          <section aria-labelledby="ov-verdict">
            <h3 id="ov-verdict">Verdict <span className="muted small">what you decided</span></h3>
            <ul className="dist">
              {VERDICTS.map(v => (
                <DistRow key={v} label={<><span className={`status st-${v}`} aria-hidden="true">{STATUS_ICON[v]}</span> {VERDICT_LABEL[v]}</>}
                  n={o.byVerdict[v]} of={queue.length} cls={`vseg ${v}`}
                  title={`Show only ${VERDICT_LABEL[v].toLowerCase()} rows`} onPick={() => { set({ status: v }); }} />
              ))}
            </ul>
          </section>
        </div>
      )}

      {o.top.length > 0 && (
        <section aria-labelledby="ov-top">
          <h3 id="ov-top">Most flagged</h3>
          <ol className="top-list">
            {o.top.map(t => (
              <li key={t.name}>
                <Sev s={t.severity} />
                <button className="link" title={`Search the queue for ${t.name}`} onClick={() => { set({ search: t.name }); }}>{t.name}</button>
                <span className="muted small num">{plural(t.count, 'row')}</span>
              </li>
            ))}
          </ol>
        </section>
      )}

      <section aria-labelledby="ov-cov">
        <h3 id="ov-cov">Capture coverage</h3>
        <p className="small">
          {cov.versions.length > 0 ? `eslogger schema ${cov.versions.map(v => `v${v}`).join(', ')}` : 'No schema version recorded'}
          {' · '}{cap.model.stats.events.toLocaleString('en-US')} events read
        </p>
        {cov.notes.length > 0 ? (
          <ul className="cov-brief">
            {cov.notes.map(x => <li key={x.id} className={`lvl-${x.level}`}>{x.title}</li>)}
          </ul>
        ) : <p className="muted small">Nothing to flag about the file itself.</p>}
        <p className="muted small">
          {warns.length > 0 ? `${plural(warns.length, 'note')} above can hide findings. ` : ''}
          <button className="link" onClick={() => { openCoverage(); }}>What this capture can and cannot show</button>
        </p>
      </section>

      <section aria-labelledby="ov-keys">
        <h3 id="ov-keys">Keys</h3>
        <dl className="keys">
          {TRIAGE_KEYS.map(k => <div key={k.key}><dt><kbd>{k.key}</kbd></dt><dd>{k.what}</dd></div>)}
        </dl>
      </section>
    </div>
  );
}

/** Opens the capture coverage panel under the session header and brings it into view. */
function openCoverage(): void {
  const d = document.getElementById('coverage') as HTMLDetailsElement | null;
  if (!d) return;
  d.open = true;
  d.scrollIntoView?.({ block: 'nearest' });
  d.querySelector('summary')?.focus();
}

/** Jump links for a long pane: the three questions in the order the pane answers them. */
const JUMPS: [string, string][] = [['d-why', 'Why flagged'], ['d-launch', 'Where it came from'], ['d-did', 'What it did'], ['d-actions', 'Verdict']];

function Jumps() {
  return (
    <nav className="jumps small" aria-label="Sections">
      {JUMPS.map(([id, label]) => (
        <button key={id} className="link" onClick={() => {
          const el = document.getElementById(id);
          // The heading takes focus too, so Tab carries on from the section rather than from the link.
          el?.focus({ preventScroll: true });
          el?.scrollIntoView?.({ block: 'start' });
        }}>{label}</button>
      ))}
    </nav>
  );
}

function ProcessDetail({ cap, p, onSelectProc, noteRef }: {
  cap: LoadedCapture; p: Process; onSelectProc(id: ProcId): void; noteRef: RefObject<HTMLTextAreaElement | null>;
}) {
  const { verdicts } = useSession();
  const img = latestImage(p);
  const findings = cap.analysis.findings.get(p.id) ?? [];
  const item = queueItemFor(cap.analysis, p.id);
  const own = useMemo(() => processTimeline(cap, p.id, false).events, [cap, p.id]);
  const execArgs = [...p.images].reverse().find(i => i.args !== null)?.args ?? null;
  const commandLine = execArgs && execArgs.length > 0 ? fmtArgs(execArgs) : null;
  const observed = recordedSpan(own);
  const status = verdicts.get(p.id)?.status ?? 'unreviewed';
  return (
    <>
      <header className="dhead">
        <h2>{displayName(cap.model, p.id)}</h2>
        <p className="muted small">
          {p.ghost ? 'started before the capture' : `pid ${p.pid}`}
          {!p.ghost && (p.originalPpid ?? p.ppid) !== null ? ` · parent pid ${p.originalPpid ?? p.ppid}` : ''}
          {img?.signingId ? ` · ${img.signingId}` : ''}
          {img?.isPlatform ? ' · Apple platform binary' : ''}
        </p>
        {img?.path && <p className="dpath mono">{img.path}</p>}
        {commandLine && <p className="dcommand"><span className="muted small">Last captured exec command line</span><code className="mono wrap">{commandLine}</code></p>}
        {own.length > 0 && (
          <p className="dactivity muted small">
            {observed && <><span>Observed </span><span className="mono">{fmtTime(observed.first)}{observed.first !== observed.last && <> → {fmtTime(observed.last)}</>}</span><span> · </span></>}
            {plural(own.length, 'recorded event')}
          </p>
        )}
        <div className="row assess">
          {item
            ? <span className="assess-chip">Severity <Sev s={item.severity} full /></span>
            : <span className="assess-chip muted">Not in the queue</span>}
          <span className="assess-chip">Verdict <strong className={`st-${status}`}>{VERDICT_LABEL[status]}</strong></span>
        </div>
        <Jumps />
      </header>
      <Why findings={findings} item={item} />
      {item && <Repeats key={item.key} cap={cap} item={item} current={p.id} onSelect={onSelectProc} />}
      <LaunchItems cap={cap} p={p} findings={findings} onSelect={onSelectProc} />
      <LaunchedBy cap={cap} p={p} onSelect={onSelectProc} />
      <Details cap={cap} p={p} own={own} onSelect={onSelectProc} />
      <DidWhat cap={cap} p={p} own={own} onSelect={onSelectProc} />
      <ContextOnly findings={cap.analysis.contextOnly.get(p.id) ?? []} />
      <Actions vkey={p.id} p={p} noteRef={noteRef} />
    </>
  );
}

/** The right-hand pane. `selKey` is the selected process id, or the queue key of a persistence-only item. */
export function DetailPane({ selKey, onSelectProc, noteRef }: {
  selKey: string | null; onSelectProc(id: ProcId): void; noteRef: RefObject<HTMLTextAreaElement | null>;
}) {
  const { capture: cap } = useSession();
  if (!cap) return null;
  if (selKey === null) return <NothingSelected />;
  const p = cap.model.processes.get(selKey);
  if (!p) {
    const q = cap.analysis.queue.find(x => x.key === selKey && x.kind === 'persistence');
    return q ? <PersistenceDetail cap={cap} q={q} onSelect={onSelectProc} noteRef={noteRef} /> : null;
  }
  return <ProcessDetail key={p.id} cap={cap} p={p} onSelectProc={onSelectProc} noteRef={noteRef} />;
}
