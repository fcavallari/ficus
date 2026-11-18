import type { LoadedCapture } from '../ingest/load';
import { displayName } from '../model/relations';
import type { CaptureModel, CaptureStats, Process } from '../model/types';
import { basename, persistenceItem } from '../model/util';
import type { QueueItem } from '../rules/engine';
import { RULES, SEVERITY_RANK, type Severity } from '../rules/rules';
import type { Status, Verdict } from '../session/store';

export interface TriageFilters {
  status: 'all' | Status;
  sev: Set<Severity>;
  search: string;
  showHidden: boolean;
  /** Only rows queued because they sit under, or in, a flagged chain. */
  chainOnly: boolean;
}
export const DEFAULT_FILTERS: TriageFilters = { status: 'all', sev: new Set<Severity>(['high', 'med', 'low']), search: '', showHidden: false, chainOnly: false };

/** Verdicts are keyed by the process id; a persistence-only item has none, so it uses its queue key (`i:<id>`). */
export const verdictKey = (q: QueueItem): string => q.procId ?? q.key;

/** Pressing the verdict a queue item already has takes it back to unreviewed (the note is kept). */
export const toggleStatus = (current: Status, pressed: 'confirmed' | 'benign'): Status => (current === pressed ? 'unreviewed' : pressed);

/**
 * Two different questions, kept apart in every label. Severity is what the rules think of the evidence (set by the
 * capture); the verdict is what the researcher decided (set by you). The stored values stay as they always were
 * (`med`, `confirmed`), so saved sessions and exports read the same; only the words on screen are these.
 */
export const SEVERITY_LABEL: Record<Severity, string> = { high: 'High', med: 'Medium', low: 'Low' };
export const VERDICT_LABEL: Record<Status, string> = { unreviewed: 'Unreviewed', confirmed: 'Suspicious', benign: 'Benign' };

/** The Triage shortcuts: the key handler and the legend in the empty detail pane both read this table. */
export type TriageAction = 'next' | 'prev' | 'confirm' | 'benign' | 'note' | 'tree' | 'undo' | 'search';
export const TRIAGE_KEYS: { key: string; also?: string; action: TriageAction; what: string }[] = [
  { key: 'j', also: 'ArrowDown', action: 'next', what: 'next row' },
  { key: 'k', also: 'ArrowUp', action: 'prev', what: 'previous row' },
  { key: 'c', action: 'confirm', what: 'verdict: suspicious' },
  { key: 'b', action: 'benign', what: 'verdict: benign' },
  { key: 'u', action: 'undo', what: 'undo the last verdict' },
  { key: 'n', action: 'note', what: 'write a note' },
  { key: 't', action: 'tree', what: 'show in the tree' },
  { key: '/', action: 'search', what: 'search the queue' },
];
export const triageAction = (key: string): TriageAction | undefined => TRIAGE_KEYS.find(k => k.key === key || k.also === key)?.action;

/** Name shown for a queue item: the process name, or `persistence: <plist>` for a persistence-only item. */
export function itemName(cap: LoadedCapture, q: QueueItem): string {
  if (q.procId !== null) return displayName(cap.model, q.procId);
  const item = persistenceItem(cap.model, q.persistenceId);
  return `persistence: ${basename(item?.plistPath ?? null) || q.persistenceId || 'launch item'}`;
}

/**
 * What a row shows after its name (the latest image's program): the arguments of the latest exec that was captured,
 * without argv[0]. When the latest image itself has no captured args (its exec was not seen), the args come from an
 * earlier image and are prefixed with that image's program, so they are not read as the arguments of the name beside them.
 */
export function rowArgs(p: Process): string {
  let i = p.images.length - 1;
  while (i >= 0 && p.images[i]!.args === null) i--;
  const img = p.images[i];
  if (!img?.args) return '';
  const args = img.args.slice(1).join(' ');
  if (i === p.images.length - 1) return args;
  return [basename(img.path), args].filter(Boolean).join(' ');
}

/** What the row shows after the name: args, or the launched program for a persistence item. */
export function itemArgs(cap: LoadedCapture, q: QueueItem): string {
  if (q.procId !== null) {
    const p = cap.model.processes.get(q.procId);
    const args = p ? rowArgs(p) : '';
    return args || (q.findings[0]?.title ?? '');
  }
  const item = persistenceItem(cap.model, q.persistenceId);
  return item?.executablePath ?? item?.appPath ?? '';
}

/** Lower-cased text the search box matches against: name, paths, args, signing and team IDs. */
export function haystack(cap: LoadedCapture, q: QueueItem): string {
  const parts: (string | null)[] = [itemName(cap, q)];
  if (q.procId !== null) {
    const p = cap.model.processes.get(q.procId);
    for (const i of p?.images ?? []) parts.push(i.path, i.signingId, i.teamId, i.script, ...(i.args ?? []));
  } else {
    const item = persistenceItem(cap.model, q.persistenceId);
    parts.push(item?.plistPath ?? null, item?.executablePath ?? null, item?.appPath ?? null);
  }
  return parts.filter(Boolean).join('\n').toLowerCase();
}

/** `2026-11-12T16:43:52.123456789Z` → `2026-11-12 16:43:52.123Z`. */
export const fmtTime = (t: string | null): string =>
  t ? t.replace('T', ' ').replace(/(\.\d{3})\d*Z$/, '$1Z') : 'n/a';

/** `2026-11-12T16:43:52.123456789Z` → `16:43:52.123`: the clock part, for a list whose date is shown once above it. */
export const fmtClock = (t: string | null): string => {
  const m = t ? /T(\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)/.exec(t) : null;
  return m ? m[1]! : (t ?? '');
};

/** Command line for display: elements with spaces (or empty ones) are quoted so the boundaries stay visible. */
export const fmtArgs = (args: string[]): string =>
  args.map(a => (a === '' || /\s/.test(a) ? `"${a}"` : a)).join(' ');

/** The first schema version with the exec stdin data the `shell-from-pipe` rule needs. */
export const MODERN_SCHEMA = 11;
const MAX_OTHER_SHOWN = 5;

/**
 * What the loader skipped or could not use, so nothing is dropped silently: unreadable lines, event types the viewer
 * does not model, and the eslogger schema version(s). `line` is null when there is nothing to say.
 */
export function captureInfo(stats: CaptureStats): { line: string | null; older: boolean } {
  const parts: string[] = [];
  const unit = stats.layout === 'objects' ? 'record' : 'line';
  if (stats.badLines > 0) parts.push(`${stats.badLines.toLocaleString('en-US')} unreadable ${unit}${stats.badLines === 1 ? '' : 's'}`);
  if (stats.seqGaps) parts.push(`${stats.seqGaps.toLocaleString('en-US')} ${stats.seqGaps === 1 ? 'event' : 'events'} missing from the sequence`);
  const other = Object.entries(stats.otherEvents).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  if (other.length > 0) {
    const shown = other.slice(0, MAX_OTHER_SHOWN).map(([t, n]) => `${t} ×${n.toLocaleString('en-US')}`);
    if (other.length > MAX_OTHER_SHOWN) shown.push(`${other.length - MAX_OTHER_SHOWN} more`);
    parts.push(`other events: ${shown.join(', ')}`);
  }
  const versions = stats.versions.filter(v => v > 0);
  if (versions.length > 0) parts.push(`schema ${versions.map(v => `v${v}`).join(', ')}`);
  return { line: parts.length > 0 ? parts.join(' · ') : null, older: versions.length > 0 && versions.every(v => v < MODERN_SCHEMA) };
}

// --- the overview shown before a row is picked ------------------------------------------------------------------

export interface Overview {
  /** Every row of the queue the filters start from (routine-hidden rows left out), and how many of those are still open. */
  bySeverity: Record<Severity, { total: number; open: number }>;
  byVerdict: Record<Status, number>;
  /** Programs with the most queued rows: name, rows, the highest severity among them. */
  top: { name: string; count: number; severity: Severity }[];
}

const TOP_PROGRAMS = 5;

export function overview(cap: LoadedCapture, queue: QueueItem[], verdicts: Map<string, Verdict>): Overview {
  const bySeverity: Overview['bySeverity'] = { high: { total: 0, open: 0 }, med: { total: 0, open: 0 }, low: { total: 0, open: 0 } };
  const byVerdict: Overview['byVerdict'] = { unreviewed: 0, confirmed: 0, benign: 0 };
  const groups = new Map<string, { count: number; severity: Severity }>();
  for (const q of queue) {
    const st = verdicts.get(verdictKey(q))?.status ?? 'unreviewed';
    bySeverity[q.severity].total++;
    if (st === 'unreviewed') bySeverity[q.severity].open++;
    byVerdict[st]++;
    const name = itemName(cap, q);
    const g = groups.get(name);
    if (!g) groups.set(name, { count: 1, severity: q.severity });
    else {
      g.count++;
      if (SEVERITY_RANK[q.severity] > SEVERITY_RANK[g.severity]) g.severity = q.severity;
    }
  }
  const top = [...groups].map(([name, g]) => ({ name, ...g }))
    .sort((a, b) => b.count - a.count || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (a.name < b.name ? -1 : 1))
    .slice(0, TOP_PROGRAMS);
  return { bySeverity, byVerdict, top };
}

// --- capture coverage -------------------------------------------------------------------------------------------

/**
 * What a capture can and cannot show. Every note is read off the capture itself (counts of what is there or missing);
 * none says the capture is complete, because that cannot be known from the file: eslogger records only the event types
 * it was asked for, only while it ran.
 */
export interface CoverageNote { id: string; level: 'warn' | 'info'; title: string; detail: string; checks: string[] }

/**
 * The event types the capture command subscribes to, what only that type gives the viewer, and the checks that cannot
 * fire without it. Programs and signatures are not on the list: every event carries its process's executable and
 * signature, so they are known without exec events; command lines, working directories and script paths are not.
 */
const ARG_CHECKS = ['fake-prompt', 'osascript-script', 'keychain-access', 'security-setting-change', 'dscl-authonly', 'launchctl-load',
  'quarantine-strip', 'payload-decode', 'shell-from-pipe', 'download', 'archive-staging', 'recon', 'known-indicator'];
const EXPECTED: { type: string; gives: string; checks: string[]; level?: 'warn' | 'info' }[] = [
  { type: 'exec', gives: 'command lines, working directories or script paths (programs and signatures still come from every event\'s process, so the location and signature checks can fire)',
    checks: [...ARG_CHECKS, 'odd-location-exec'] },
  { type: 'fork', gives: 'which process instance forked each child, or when. Each process is still tied to its parent through its own parent pid and token, which can point at the wrong process when a pid was reused, and a child that ran nothing of its own may be missing',
    checks: [], level: 'warn' },
  { type: 'exit', gives: 'when processes ended', checks: [] },
  { type: 'create', gives: 'files written', checks: ['persistence-plist', 'download', 'known-indicator'] },
  { type: 'rename', gives: 'files moved into place', checks: ['persistence-plist', 'known-indicator'] },
  { type: 'unlink', gives: 'files deleted', checks: [] },
  { type: 'setextattr', gives: 'extended attributes set on files', checks: [] },
  { type: 'btm_launch_item_add', gives: 'launch items, login items, agents and daemons registered', checks: ['persistence-item', 'persistence-plist'] },
  { type: 'btm_launch_item_remove', gives: 'launch items removed', checks: [] },
];

const ruleTitle = (id: string): string => RULES.find(r => r.id === id)?.title ?? id;
const n = (x: number): string => x.toLocaleString('en-US');

export function coverage(m: CaptureModel): { versions: number[]; notes: CoverageNote[] } {
  const stats = m.stats;
  const notes: CoverageNote[] = [];
  const versions = stats.versions.filter(v => v > 0);

  // exec events without file-descriptor data: the piped-shell checks cannot tell a pipe from a file there.
  let execs = 0;
  let noFds = 0;
  let missedExec = 0;
  let ghosts = 0;
  for (const p of m.processes.values()) {
    if (p.ghost) ghosts++;
    p.images.forEach((img, i) => {
      if (img.inherited) return;
      // A process's first image with no args is a program that was already running when the capture began (or the
      // emitter's pre-exec image): nothing changed, so nothing is missing. Only a later image without args is a change
      // whose exec was not captured.
      if (img.args === null) { if (i > 0) missedExec++; }
      else { execs++; if (img.stdinIsPipe === null) noFds++; }
    });
  }
  if (noFds > 0) {
    const all = noFds === execs;
    notes.push({
      id: 'stdin', level: 'warn', title: `${all ? 'No' : `${n(noFds)} of ${n(execs)}`} exec events carry file-descriptor data`,
      detail: `${versions.length > 0 && versions.every(v => v < MODERN_SCHEMA) ? `eslogger schema ${versions.map(v => `v${v}`).join(', ')} predates v${MODERN_SCHEMA}, the first with an exec event's open file descriptors. ` : ''}Without them a shell reading from a pipe looks the same as one reading a file, so these checks cannot fire on ${all ? 'any exec' : 'those execs'}.`,
      checks: ['shell-from-pipe', 'osascript-script'],
    });
  } else if (execs > 0 && versions.length > 0 && versions.every(v => v < MODERN_SCHEMA)) {
    // The header flags the old schema by its number; the data itself says whether the piped-shell checks lost anything.
    notes.push({
      id: 'stdin-present', level: 'info', title: `Schema ${versions.map(v => `v${v}`).join(', ')}, yet every exec event carries file-descriptor data`,
      detail: 'The schema number predates v11, but this file (a Mac Monitor trace, for example) records each exec\'s open file descriptors, so the piped-shell checks can run on it.',
      checks: [],
    });
  }
  if (stats.kinds) {
    for (const e of EXPECTED) {
      if ((stats.kinds[e.type] ?? 0) > 0) continue;
      notes.push({
        id: `none-${e.type}`, level: e.level ?? (e.checks.length > 0 ? 'warn' : 'info'),
        title: `No ${e.type} events`,
        detail: `This capture has none, so it cannot show ${e.gives}. Either none happened while it ran, or eslogger was not subscribed to ${e.type}; the file cannot say which.`,
        checks: e.checks,
      });
    }
  }
  // write and close are left out of the recommended capture (both are noisy); without either, a plist that already
  // existed and was overwritten in place leaves no trace.
  if (stats.kinds && !(stats.kinds.write ?? 0) && !(stats.kinds.close ?? 0) && !(stats.otherEvents.close ?? 0)) {
    notes.push({
      id: 'none-write-close', level: 'info', title: 'No write or close events',
      detail: 'A launch agent or daemon plist that already existed and was overwritten in place shows only as a write, or a close marked modified. This capture has neither, so such an overwrite cannot be seen; a plist created or renamed into place still is. Both event types are optional and noisy, so the recommended capture leaves them out.',
      checks: ['persistence-plist'],
    });
  }
  if (missedExec > 0) {
    notes.push({
      id: 'missed-exec', level: 'info', title: `${n(missedExec)} program ${missedExec === 1 ? 'change' : 'changes'} without an exec event`,
      detail: 'A process was seen running a new program, but the exec that started it is not in the capture (it happened before the capture began, or was dropped). Its arguments and working directory are unknown, and the checks that read a command line skip it.',
      checks: [],
    });
  }
  if (ghosts > 0) {
    notes.push({
      id: 'ghosts', level: 'info', title: `${n(ghosts)} ${ghosts === 1 ? 'process' : 'processes'} known only by pid`,
      detail: 'They started before the capture and emitted nothing themselves; they appear as parents of processes that did. Their program, arguments and signature were never logged.',
      checks: [],
    });
  }
  if (stats.badLines > 0) {
    const unit = stats.layout === 'objects' ? 'record' : 'line';
    notes.push({
      id: 'bad', level: 'warn', title: `${n(stats.badLines)} unreadable ${unit}${stats.badLines === 1 ? '' : 's'}`,
      detail: `They were not JSON, or not an eslogger event, and were skipped. Whatever they held is missing from the tree, the queue and every timeline.`,
      checks: [],
    });
  }
  if (stats.seqGaps) {
    const gaps = stats.seqGaps;
    const runs = stats.seqGapRuns ?? 1;
    notes.push({
      id: 'seq-gaps', level: 'warn',
      title: `${n(gaps)} ${gaps === 1 ? 'event is' : 'events are'} missing from the sequence${runs > 1 ? `, in ${n(runs)} places` : ''}`,
      detail: `Endpoint Security numbers every event it delivers to the recorder (global_seq_num), so a capture that lost nothing counts up without a break. These numbers are absent: it drops events when the recorder falls behind (a busy Mac, a slow disk or terminal), or lines were removed afterwards (an unreadable line above, or a cleaner that dropped an event). A missing fork or exec can leave a process without its parent or its program, and a missing event of any other kind is something that happened and is not shown. This is a count of what is missing, not a list of it.`,
      checks: [],
    });
  }
  const other = Object.entries(stats.otherEvents).sort((a, b) => b[1] - a[1]);
  if (other.length > 0) {
    notes.push({
      id: 'other', level: 'info', title: `${n(other.length)} event ${other.length === 1 ? 'type' : 'types'} the viewer does not model`,
      detail: `${other.map(([t, c]) => `${t} ×${n(c)}`).join(', ')}. They are counted but not read: they appear in no timeline and no check looks at them. Each still places its process in the tree.`,
      checks: [],
    });
  }
  return { versions, notes };
}

/** Rule titles for a coverage note, in the order the note lists them. */
export const checkTitles = (ids: string[]): string[] => ids.map(ruleTitle);
