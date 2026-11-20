import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import { MASS_RENAME_MIN_FILES, MASS_RENAME_WINDOW_MS, TEMP_EXTENSIONS } from '../src/rules/rules';
import type { CaptureModel, FileOp } from '../src/model/types';
import { capture, img, proc } from './synth';

// mass-rename: one process renaming many files to one new extension in a few seconds, the way ransomware encrypts in place.
const RULE = 'mass-rename';
const T0 = Date.parse('2026-11-12T00:00:00.000Z');

const rename = (from: string, to: string, ms: number, seq = 2): FileOp =>
  ({ kind: 'rename', path: from, toPath: to, time: new Date(T0 + ms).toISOString(), seq });

/** `n` files `/Users/u/Documents/fileN.txt` renamed by `rename(i)`, `gap` ms apart. */
const burst = (n: number, gap: number, to: (i: number) => string, from: (i: number) => string = i => `/Users/u/Documents/file${i}.txt`): FileOp[] =>
  Array.from({ length: n }, (_, i) => rename(from(i), to(i), i * gap, 2 + i));

/** The same renames, each preceded by the process creating its source file: how a daemon saves (write a temporary file, move it into place). */
const createdFirst = (ops: FileOp[]): FileOp[] => ops.flatMap(o => [{ kind: 'create' as const, path: o.path, time: new Date(Date.parse(o.time) - 5).toISOString(), seq: o.seq - 1 }, o]);

const story = (fileOps: FileOp[]): CaptureModel =>
  capture([proc('100:1', [img({ path: '/Users/u/Downloads/h/locker', signingId: null, args: ['locker'], seq: 1 })], { fileOps })]);
const hits = (m: CaptureModel) =>
  analyze(m).queue.flatMap(q => q.findings.filter(f => f.ruleId === RULE));

describe('mass-rename', () => {
  test('the thresholds are named constants', () => {
    expect(MASS_RENAME_MIN_FILES).toBe(10);
    expect(MASS_RENAME_WINDOW_MS).toBe(10_000);
    expect([...TEMP_EXTENSIONS].sort()).toEqual(['bak', 'crdownload', 'download', 'part', 'partial', 'swp', 'tmp']);
  });

  test('15 files renamed to .heartbreaker in 1.3 s fires, high, T1486', () => {
    const f = hits(story(burst(15, 87, i => `/Users/u/Documents/file${i}.txt.heartbreaker`)));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1486']);
    expect(f[0]!.evidence).toContain('15 files');
    expect(f[0]!.evidence).toContain('.heartbreaker');
    expect(f[0]!.evidence).toContain('file0.txt.heartbreaker');
  });

  test('9 files do not fire; 10 do', () => {
    const to = (i: number) => `/Users/u/Documents/file${i}.txt.locked`;
    expect(hits(story(burst(9, 100, to)))).toHaveLength(0);
    expect(hits(story(burst(10, 100, to)))).toHaveLength(1);
  });

  test('10 files spread over 30 seconds do not fire', () => {
    expect(hits(story(burst(10, 3_000, i => `/Users/u/Documents/file${i}.txt.locked`)))).toHaveLength(0);
  });

  test('a burst at the end of a longer, slower run fires on the burst', () => {
    const slow = burst(2, 30_000, i => `/Users/u/Documents/slow${i}.txt.locked`, i => `/Users/u/Documents/slow${i}.txt`);
    const fast = burst(10, 100, i => `/Users/u/Documents/file${i}.txt.locked`).map(o => ({ ...o, time: new Date(Date.parse(o.time) + 120_000).toISOString() }));
    const f = hits(story([...slow, ...fast]));
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toContain('10 files');
  });

  test('ten different new extensions do not fire', () => {
    expect(hits(story(burst(10, 100, i => `/Users/u/Documents/file${i}.txt.ext${i}`)))).toHaveLength(0);
  });

  test('temporary extensions do not count', () => {
    for (const ext of ['tmp', 'part', 'download', 'crdownload', 'swp', 'bak', 'partial', 'TMP']) {
      expect(hits(story(burst(12, 100, i => `/Users/u/Documents/file${i}.txt.${ext}`))), ext).toHaveLength(0);
    }
  });

  test('renaming away from a temporary name (write, then rename into place) does not count', () => {
    const f = hits(story(burst(12, 100, i => `/Users/u/Library/Caches/out${i}.o`, i => `/Users/u/Library/Caches/out${i}.o.tmp`)));
    expect(f).toHaveLength(0);
  });

  test('a file moved to another folder is not encrypted in place', () => {
    // How an Apple daemon saves: write under a temporary name in a temporary folder, then move the file into place.
    const f = hits(story(burst(12, 100,
      i => `/Users/u/Library/Caches/com.apple.chrono/${i}.relevancecache`,
      i => `/private/var/folders/p7/T/NSIRD_chronod_x/${i}-UUID`)));
    expect(f).toHaveLength(0);
  });

  test('files the process created itself and then moved into place do not count', () => {
    // How cfprefsd saves: create `name.plist.a1B2c3`, then rename it to `name.plist`; and iconservicesagent: create `tmp.PHod7U`, rename it to a `.car`.
    const suffix = burst(12, 100, i => `/Users/u/Library/Preferences/com.example.app${i}.plist`, i => `/Users/u/Library/Preferences/com.example.app${i}.plist.a1B2c${i}`);
    expect(hits(story(createdFirst(suffix)))).toHaveLength(0);
    const unrelated = burst(12, 100, i => `/Users/u/Library/Caches/coreui-${i}.car`, i => `/Users/u/Library/Caches/tmp.PHod7${i}`);
    expect(hits(story(createdFirst(unrelated)))).toHaveLength(0);
  });

  test('the same renames of files that already existed do count: names unrelated to each other do not matter', () => {
    // A cleaned capture gives every name its own placeholder, so the rule cannot lean on how two names relate.
    const f = hits(story(burst(12, 100, i => `/Users/u/Documents/name${i + 100}.locked`, i => `/Users/u/Documents/name${i}.docx`)));
    expect(f).toHaveLength(1);
  });

  test('a rename that keeps the extension does not count', () => {
    expect(hits(story(burst(12, 100, i => `/Users/u/Documents/renamed${i}.txt`)))).toHaveLength(0);
  });

  test('the extension is compared without regard to case', () => {
    const ops = burst(12, 100, i => `/Users/u/Documents/file${i}.txt.${i % 2 ? 'LOCKED' : 'locked'}`);
    expect(hits(story(ops))).toHaveLength(1);
  });

  test('only the extension that reaches the threshold is reported', () => {
    const big = burst(12, 100, i => `/Users/u/Documents/file${i}.txt.locked`);
    const small = burst(4, 100, i => `/Users/u/Pictures/pic${i}.jpg.other`, i => `/Users/u/Pictures/pic${i}.jpg`);
    const f = hits(story([...big, ...small]));
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toContain('.locked');
    expect(f[0]!.evidence).not.toContain('.other');
  });

  test('a rename with no destination is ignored, and a process with no renames never fires', () => {
    expect(hits(story([]))).toHaveLength(0);
    const odd: FileOp[] = Array.from({ length: 12 }, (_, i) => ({ kind: 'rename', path: `/Users/u/a${i}`, time: new Date(T0 + i).toISOString(), seq: 2 + i }));
    expect(hits(story(odd))).toHaveLength(0);
  });
});
