import { basename, normPath } from '../model/util';
import data from './indicators.json';
import type { Severity } from './rules';

/**
 * Indicators vendors published for named macOS malware families, in the forms a process capture can show. The data is in
 * indicators.json (its `about` and `pathSyntax` fields say what is in it and what is left out); the same file feeds the
 * am-i-pwned skill's reference page and triage script (scripts/gen-indicators.mjs), so there is one list to keep.
 */
export type IndicatorKind = 'team-id' | 'signing-id' | 'path' | 'plist' | 'argv';
export type Confidence = 'high' | 'medium';
export interface Indicator {
  familyId: string; family: string; actor: string; attribution: string;
  kind: IndicatorKind; value: string; severity: Severity; confidence: Confidence; source: string; note: string;
}
/** What matched: the indicator, and the text of the capture it matched (a path, an ID, an argument). */
export interface IndicatorHit { indicator: Indicator; found: string; mitre: string[] }

interface RawIndicator { kind: IndicatorKind; value: string; severity: Severity; confidence: Confidence; source: string; note?: string }
interface RawFamily { id: string; name: string; actor: string; attribution: string; summary: string; indicators: RawIndicator[] }
const FAMILIES = (data as unknown as { families: RawFamily[] }).families;

export const INDICATOR_FAMILIES: { id: string; name: string; actor: string; attribution: string; summary: string }[] =
  FAMILIES.map(({ id, name, actor, attribution, summary }) => ({ id, name, actor, attribution, summary }));
export const INDICATORS: Indicator[] = FAMILIES.flatMap(f => f.indicators.map(i => ({
  familyId: f.id, family: f.name, actor: f.actor, attribution: f.attribution, kind: i.kind, value: i.value,
  severity: i.severity, confidence: i.confidence, source: i.source, note: i.note ?? '',
})));

// ---------------------------------------------------------------------------------------------------------------------
// Compiling the patterns once

/** The launch folders a plist indicator is looked for in: where a user or an installer puts one, never /System. */
const LAUNCH_PLIST_DIR = /^(?:\/library\/launch(agents|daemons)|\/users\/[^/]+\/library\/launchagents)$/;

const escapeRe = (s: string): string => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

/**
 * A path pattern as a lower-case regex: `~/` any home folder, `**\/` any folders (or none), `*` inside one segment, a
 * trailing `/` the folder and everything in it. A pattern without a slash (a plist file name) matches a whole name.
 */
function pathRegex(pattern: string): RegExp {
  let p = pattern.toLowerCase();
  const dir = p.endsWith('/');
  if (dir) p = p.slice(0, -1);
  let prefix = '';
  if (p.startsWith('~/')) { prefix = '/users/[^/]+/'; p = p.slice(2); }
  else if (p.startsWith('**/')) { prefix = '/(?:.*/)?'; p = p.slice(3); }
  else if (p.startsWith('/')) { prefix = '/'; p = p.slice(1); }
  const body = p.split('/').map(seg => escapeRe(seg).replace(/\*/g, '[^/]*')).join('/');
  return new RegExp(`^${prefix}${body}${dir ? '(?:/.*)?' : ''}$`);
}

const hasWild = (v: string): boolean => v.includes('*');

const byTeam = new Map<string, Indicator>();
const bySigning = new Map<string, Indicator>();
const exactPaths = new Map<string, Indicator[]>();       // literal file or folder path, lower-case; `~/` kept as written
const dirPaths = new Map<string, Indicator[]>();         // a folder: anything inside matches
const wildPaths: { re: RegExp; indicator: Indicator }[] = [];
const exactPlists = new Map<string, Indicator[]>();      // by lower-case file name
const wildPlists: { re: RegExp; indicator: Indicator }[] = [];
const argvWords: { re: RegExp; indicator: Indicator }[] = [];

const add = (m: Map<string, Indicator[]>, key: string, i: Indicator): void => {
  const list = m.get(key);
  if (list) list.push(i); else m.set(key, [i]);
};

/**
 * The value as a whole word: not part of a longer name, address or domain (`23.254.226.90` is not in `123.254.226.90`).
 * A value that starts with `/` is a URL path, and is looked for only in a URL argument: `/task/mac` is the staging
 * server's path in `http://host/task/mac`, but also a folder in a developer's `~/dev/task/mac/run.js`.
 * No lookbehind (older Safari lacks it): the leading character is part of the match instead.
 */
const wordRegex = (v: string): RegExp =>
  new RegExp(`${/^\w/.test(v) ? '(?:^|[^\\w.-])' : ''}${escapeRe(v)}${/\w$/.test(v) ? (v.startsWith('/') ? '(?![\\w/-]|\\.\\w)' : '(?![\\w-]|\\.\\w)') : ''}`);
const URL_ARG = /^[a-z][a-z0-9+.-]*:\/\//i;

for (const i of INDICATORS) {
  if (i.kind === 'team-id') byTeam.set(i.value, i);
  else if (i.kind === 'signing-id') bySigning.set(i.value, i);
  else if (i.kind === 'argv') argvWords.push({ re: wordRegex(i.value), indicator: i });
  else if (i.kind === 'plist') {
    if (hasWild(i.value)) wildPlists.push({ re: pathRegex(i.value), indicator: i });
    else add(exactPlists, i.value.toLowerCase(), i);
  } else if (hasWild(i.value) || i.value.startsWith('**/')) wildPaths.push({ re: pathRegex(i.value), indicator: i });
  else if (i.value.endsWith('/')) add(dirPaths, i.value.toLowerCase().replace(/\/$/, ''), i);
  else add(exactPaths, i.value.toLowerCase(), i);
}

// ---------------------------------------------------------------------------------------------------------------------
// Matching

const HOME = /^\/users\/[^/]+(\/.*)$/;

/** The keys a path is looked up under: itself, and the same path under `~/` when it sits in a home folder. */
function pathKeys(path: string): string[] {
  const p = normPath(path).toLowerCase().replace(/\/+$/, '');
  const home = HOME.exec(p);
  return home ? [p, `~${home[1]!}`] : [p];
}

/** Indicators a file or program path matches: a named file, a folder it is in, a wildcard pattern. */
export function matchPath(path: string): Indicator[] {
  const hits: Indicator[] = [];
  const keys = pathKeys(path);
  for (const key of keys) {
    const exact = exactPaths.get(key);
    if (exact) hits.push(...exact);
    // Every folder above the path, for a folder indicator.
    for (let i = key.lastIndexOf('/'); i > 0; i = key.lastIndexOf('/', i - 1)) {
      const dir = dirPaths.get(key.slice(0, i));
      if (dir) hits.push(...dir);
    }
    // A folder indicator also matches the folder itself.
    const self = dirPaths.get(key);
    if (self) hits.push(...self);
  }
  const lower = keys[0]!;
  for (const w of wildPaths) if (w.re.test(lower)) hits.push(w.indicator);
  return [...new Set(hits)];
}

/** Launch plist indicators a file path matches: the file name, in a launch folder a user or installer writes to. */
export function matchPlist(path: string): { hit: Indicator; mitre: string } [] {
  const p = normPath(path).toLowerCase();
  const slash = p.lastIndexOf('/');
  const dir = LAUNCH_PLIST_DIR.exec(p.slice(0, slash));
  if (!dir) return [];
  const name = basename(p);
  const mitre = dir[1] === 'daemons' ? 'T1543.004' : 'T1543.001';
  const hits = [...(exactPlists.get(name) ?? []), ...wildPlists.filter(w => w.re.test(name)).map(w => w.indicator)];
  return hits.map(hit => ({ hit, mitre }));
}

export const matchTeam = (teamId: string | null): Indicator | undefined => (teamId === null ? undefined : byTeam.get(teamId));
export const matchSigning = (signingId: string | null): Indicator | undefined => (signingId === null ? undefined : bySigning.get(signingId));

/** Indicators a command line names; argv[0] is the program, which the path and ID checks already cover. */
export function matchArgs(args: string[] | null): { indicator: Indicator; arg: string }[] {
  if (!args) return [];
  const out: { indicator: Indicator; arg: string }[] = [];
  for (let k = 1; k < args.length; k++) {
    const arg = args[k]!;
    for (const w of argvWords) if ((!w.indicator.value.startsWith('/') || URL_ARG.test(arg)) && w.re.test(arg)) out.push({ indicator: w.indicator, arg });
  }
  return out;
}
