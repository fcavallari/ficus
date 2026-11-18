// Where Ficus keeps its files on the Mac, and the one gate every capture read goes through:
// only captures the Ficus cleaner wrote (a key exists for them) and that are no longer being written.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface FicusPaths {
  home: string;
  captures: string;
  keys: string;
  /** Where the cleaner puts its keys when it is told nothing: under the user's home, whatever FICUS_HOME says. */
  defaultKeys: string;
  bin: string;
  exportRoot: string;
}

export function ficusPaths(env: NodeJS.ProcessEnv = process.env): FicusPaths {
  const user = env.HOME || os.homedir();
  const home = env.FICUS_HOME || path.join(user, 'Library', 'Application Support', 'Ficus');
  return {
    home,
    captures: path.join(home, 'captures'),
    keys: path.join(home, 'keys'),
    defaultKeys: path.join(user, 'Library', 'Application Support', 'Ficus', 'keys'),
    bin: path.join(home, 'bin'),
    exportRoot: env.FICUS_EXPORT_DIR || path.join(user, 'Desktop'),
  };
}

export class CaptureRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CaptureRefused';
  }
}

/** A name from the agent as it is echoed back in a message: the first 120 characters, so a huge name stays small. */
export function shortName(name: string): string {
  return name.length > 120 ? `${name.slice(0, 120)}…` : name;
}

export const STILL_WRITING_MS = 10_000;

const KEY_SUFFIX = '.key.tsv';

function isPlainFileName(name: string): boolean {
  return (
    name !== '' &&
    name !== '.' &&
    name !== '..' &&
    !/[\\/\0]/.test(name) &&
    path.basename(name) === name
  );
}

function keyPath(p: FicusPaths, name: string): string {
  return path.join(p.keys, `${name}${KEY_SUFFIX}`);
}

// Existence check only: the key file itself is never opened.
function hasKey(p: FicusPaths, name: string): boolean {
  try {
    return fs.statSync(keyPath(p, name)).isFile();
  } catch {
    return false;
  }
}

export function cleanedCapturePath(p: FicusPaths, name: string, now: number = Date.now()): string {
  if (!isPlainFileName(name)) {
    throw new CaptureRefused(
      `"${shortName(name)}" is not a plain file name. Give only the name of a file in the Ficus captures folder, as ficus_list_captures shows it.`,
    );
  }
  const notThere = new CaptureRefused(
    `"${shortName(name)}" is not in the Ficus captures folder. Use ficus_list_captures to see what is there.`,
  );
  // The name must be an entry of the folder exactly as spelled. On a case- or normalization-insensitive file system
  // (APFS) a variant spelling opens the same file, and the consent record is kept per name: one file, two names would
  // split it.
  let entries: string[];
  try {
    entries = fs.readdirSync(p.captures);
  } catch {
    throw notThere;
  }
  if (!entries.includes(name)) throw notThere;
  const file = path.join(p.captures, name);
  let st: fs.Stats;
  try {
    st = fs.lstatSync(file); // lstat: a symlink pointing elsewhere is not a capture in this folder
  } catch {
    throw notThere;
  }
  if (!st.isFile()) {
    throw new CaptureRefused(`"${shortName(name)}" is not a regular file in the Ficus captures folder.`);
  }
  if (!hasKey(p, name)) {
    throw new CaptureRefused(
      `"${shortName(name)}" was not made by the Ficus cleaner (no key for it). Ask the person to record a new capture with the command from ficus_record_command. ` +
        `To clean a capture they already have, see docs/cleaning-captures.md in the Ficus repository.`,
    );
  }
  if (now - st.mtimeMs < STILL_WRITING_MS) {
    throw new CaptureRefused(`"${shortName(name)}" is still being recorded; wait until Terminal shows the summary.`);
  }
  return file;
}

export interface CaptureEntry {
  name: string;
  size: number;
  modified: string;
  hasKey: boolean;
  stillWriting: boolean;
}

export function listCaptures(p: FicusPaths, now: number = Date.now()): CaptureEntry[] {
  let names: string[];
  try {
    names = fs.readdirSync(p.captures);
  } catch {
    return [];
  }
  const entries: Array<CaptureEntry & { mtimeMs: number }> = [];
  for (const name of names) {
    if (name.endsWith(KEY_SUFFIX)) continue;
    let st: fs.Stats;
    try {
      st = fs.lstatSync(path.join(p.captures, name));
    } catch {
      continue;
    }
    if (!st.isFile()) continue;
    entries.push({
      name,
      size: st.size,
      modified: new Date(st.mtimeMs).toISOString(),
      hasKey: hasKey(p, name),
      stillWriting: now - st.mtimeMs < STILL_WRITING_MS,
      mtimeMs: st.mtimeMs,
    });
  }
  entries.sort((a, b) => b.mtimeMs - a.mtimeMs || (a.name < b.name ? -1 : 1));
  return entries.map(({ mtimeMs: _m, ...e }) => e);
}
