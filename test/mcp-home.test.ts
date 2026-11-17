import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { expect, test } from 'vitest';
import { CaptureRefused, STILL_WRITING_MS, cleanedCapturePath, ficusPaths, listCaptures } from '../src/mcp/home';

const MTIME = 1_700_000_000; // seconds
const MTIME_MS = MTIME * 1000;

function freshHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-home-'));
  const p = ficusPaths({ HOME: '/nowhere', FICUS_HOME: home } as NodeJS.ProcessEnv);
  fs.mkdirSync(p.captures, { recursive: true });
  fs.mkdirSync(p.keys, { recursive: true });
  return p;
}

function writeCapture(p: ReturnType<typeof freshHome>, name: string, opts: { key?: boolean; mtime?: number; body?: string } = {}) {
  const file = path.join(p.captures, name);
  fs.writeFileSync(file, opts.body ?? '{}\n');
  fs.utimesSync(file, opts.mtime ?? MTIME, opts.mtime ?? MTIME);
  if (opts.key !== false) fs.writeFileSync(path.join(p.keys, `${name}.key.tsv`), 'k\tv\n');
  return file;
}

test('ficusPaths defaults and overrides', () => {
  const p = ficusPaths({ HOME: '/Users/x' } as NodeJS.ProcessEnv);
  expect(p.home).toBe('/Users/x/Library/Application Support/Ficus');
  expect(p.captures).toBe('/Users/x/Library/Application Support/Ficus/captures');
  expect(p.keys).toBe('/Users/x/Library/Application Support/Ficus/keys');
  expect(p.bin).toBe('/Users/x/Library/Application Support/Ficus/bin');
  expect(p.exportRoot).toBe('/Users/x/Desktop');
  expect(ficusPaths({ HOME: '/Users/x', FICUS_HOME: '/t/f', FICUS_EXPORT_DIR: '/t/d' } as NodeJS.ProcessEnv))
    .toMatchObject({ home: '/t/f', captures: '/t/f/captures', exportRoot: '/t/d' });
});

test('a capture with its key, written over 10 s ago, is accepted', () => {
  const p = freshHome();
  writeCapture(p, 'a.cleaned.jsonl');
  expect(STILL_WRITING_MS).toBe(10_000);
  expect(cleanedCapturePath(p, 'a.cleaned.jsonl', MTIME_MS + 10_001)).toBe(path.join(p.captures, 'a.cleaned.jsonl'));
});

test.each(['../a.jsonl', 'sub/a.jsonl', '.', '..', '', '/etc/passwd', 'a\\b.jsonl', 'a\0b.jsonl'])('name %j is refused', (n) => {
  const p = freshHome();
  writeCapture(p, 'a.jsonl');
  expect(() => cleanedCapturePath(p, n, MTIME_MS + 60_000)).toThrow(CaptureRefused);
});

test('a capture without its key is refused, and the message says to record with ficus_record_command', () => {
  const p = freshHome();
  writeCapture(p, 'a.jsonl', { key: false });
  expect(() => cleanedCapturePath(p, 'a.jsonl', MTIME_MS + 60_000)).toThrow(/ficus_record_command/);
  expect(() => cleanedCapturePath(p, 'a.jsonl', MTIME_MS + 60_000)).toThrow(CaptureRefused);
});

test('a capture modified less than 10 s ago is refused as still recording', () => {
  const p = freshHome();
  writeCapture(p, 'a.jsonl');
  expect(() => cleanedCapturePath(p, 'a.jsonl', MTIME_MS + 9_999)).toThrow(/still being recorded/);
  expect(() => cleanedCapturePath(p, 'a.jsonl', MTIME_MS + 10_000)).not.toThrow();
});

test('a missing capture is refused', () => {
  const p = freshHome();
  expect(() => cleanedCapturePath(p, 'nope.jsonl', MTIME_MS)).toThrow(CaptureRefused);
  fs.rmSync(p.captures, { recursive: true });
  expect(() => cleanedCapturePath(p, 'nope.jsonl', MTIME_MS)).toThrow(CaptureRefused);
});

test('a folder, or a symlink to a file elsewhere, is refused', () => {
  const p = freshHome();
  fs.mkdirSync(path.join(p.captures, 'dir.jsonl'));
  fs.writeFileSync(path.join(p.keys, 'dir.jsonl.key.tsv'), 'k\n');
  expect(() => cleanedCapturePath(p, 'dir.jsonl', MTIME_MS + 60_000)).toThrow(CaptureRefused);
  const outside = path.join(os.tmpdir(), `outside-${process.pid}.jsonl`);
  fs.writeFileSync(outside, '{}\n');
  fs.utimesSync(outside, MTIME, MTIME);
  fs.symlinkSync(outside, path.join(p.captures, 'link.jsonl'));
  fs.writeFileSync(path.join(p.keys, 'link.jsonl.key.tsv'), 'k\n');
  expect(() => cleanedCapturePath(p, 'link.jsonl', MTIME_MS + 60_000)).toThrow(CaptureRefused);
  fs.rmSync(outside);
});

test('listCaptures: newest first, key and still-writing flags, ignores folders and key files', () => {
  const p = freshHome();
  writeCapture(p, 'old.jsonl', { mtime: MTIME - 1000, body: 'abc' });
  writeCapture(p, 'new.jsonl', { mtime: MTIME, key: false, body: '{}\n' });
  writeCapture(p, 'live.jsonl', { mtime: MTIME + 100 });
  fs.mkdirSync(path.join(p.captures, 'a-folder'));
  fs.writeFileSync(path.join(p.captures, 'stray.key.tsv'), 'k\n');
  const now = (MTIME + 100) * 1000 + 5_000;
  expect(listCaptures(p, now)).toEqual([
    { name: 'live.jsonl', size: 3, modified: new Date((MTIME + 100) * 1000).toISOString(), hasKey: true, stillWriting: true },
    { name: 'new.jsonl', size: 3, modified: new Date(MTIME * 1000).toISOString(), hasKey: false, stillWriting: false },
    { name: 'old.jsonl', size: 3, modified: new Date((MTIME - 1000) * 1000).toISOString(), hasKey: true, stillWriting: false },
  ]);
});

test('listCaptures on a missing captures folder is empty', () => {
  const p = freshHome();
  fs.rmSync(p.captures, { recursive: true });
  expect(listCaptures(p, MTIME_MS)).toEqual([]);
});
