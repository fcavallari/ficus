import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import { esCreate, esExec, esExit, esFork, esProc } from './clean-fixture';
import { fixture } from './fixtures';
import { findingSignature } from './helpers';

// scripts/gameleira-clean.sh pseudonymizes a capture. Run with /bin/bash so macOS's bash 3.2 is what gets tested there.
const SCRIPT = path.resolve(__dirname, '..', 'scripts', 'gameleira-clean.sh');
const JQ = '/usr/bin/jq';
const SYNTHETIC = fixture('synthetic-lab.jsonl');

const tmpDirs: string[] = [];
function tmpDir(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'clean-'));
  tmpDirs.push(d);
  return d;
}
afterAll(() => { for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true }); });

export interface KeyRow { kind: string; placeholder: string; real: string }

/** The key file: a header line, then `kind<TAB>placeholder<TAB>real as a JSON string` per line. */
export function parseKey(tsv: string): KeyRow[] {
  const lines = tsv.split('\n').filter(l => l !== '');
  expect(lines[0]).toBe('kind\tplaceholder\treal');
  return lines.slice(1).map(l => {
    const [kind, placeholder, real] = l.split('\t');
    return { kind: kind!, placeholder: placeholder!, real: JSON.parse(real!) as string };
  });
}

export interface CleanRun {
  /** The cleaned capture: standard output with `-o -`, else the output file (empty when none was written). */
  out: string;
  /** The key file's content, empty when none was made. */
  key: string;
  /** The summary on stderr, `name: value` lines. */
  summary: Record<string, string>;
  stderr: string;
  status: number;
}

/**
 * Runs the script in a fresh folder, with its own key folder unless `-k` is passed, and this Mac's accounts left out.
 * Without `-o` the capture goes to `out.jsonl` in that folder. `input` is written to a file and passed as `-i`.
 */
export function runClean(args: string[], opts: { input?: string; env?: Record<string, string> } = {}): CleanRun {
  const dir = tmpDir();
  const argv = [...args];
  if (opts.input !== undefined) {
    fs.writeFileSync(path.join(dir, 'input'), opts.input);
    if (!argv.includes('-i')) argv.push('-i', path.join(dir, 'input'));
  }
  if (argv[0] === 'clean' && !argv.includes('-o')) argv.push('-o', path.join(dir, 'out.jsonl'));
  const keyDir = path.join(dir, 'keys');
  const r = spawnSync('/bin/bash', [SCRIPT, ...argv], {
    cwd: dir, maxBuffer: 64 << 20, input: '',
    env: { ...process.env, GAMELEIRA_CLEAN_KEY_DIR: keyDir, GAMELEIRA_CLEAN_NO_LOCAL_SEEDS: '1', ...opts.env },
  });
  const stderr = r.stderr.toString('utf8');
  const summary: Record<string, string> = {};
  for (const l of stderr.split('\n')) {
    const i = l.indexOf(': ');
    if (i > 0) summary[l.slice(0, i)] = l.slice(i + 2);
  }
  const oi = argv.indexOf('-o');
  const outFile = oi >= 0 && argv[oi + 1] !== '-' ? argv[oi + 1]! : null;
  const out = outFile === null ? r.stdout.toString('utf8') : fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : '';
  const keyFile = summary['key'];
  const key = keyFile && fs.existsSync(keyFile) ? fs.readFileSync(keyFile, 'utf8') : '';
  return { out, key, summary, stderr, status: r.status ?? -1 };
}

const synthLines = (): string[] => fs.readFileSync(SYNTHETIC, 'utf8').split('\n').filter(l => l !== '');
const lines = (s: string): string[] => s.split('\n').filter(l => l !== '');

describe.skipIf(!fs.existsSync(JQ))('plumbing', () => {
  test('an unknown argument exits 2', () => {
    expect(runClean(['clean', '--nope']).status).toBe(2);
    expect(runClean(['clean', '-i', SYNTHETIC, '--nope']).status).toBe(2);
    expect(runClean(['frobnicate']).status).toBe(2);
    expect(runClean(['clean', '-i']).status).toBe(2);
  });

  test('clean without -i exits 2', () => {
    const r = runClean(['clean']);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/-i/);
  });

  test('record is accepted and says it is not built yet', () => {
    const r = runClean(['record', '-t', '5']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/record mode is not built yet/);
    expect(runClean(['record', '--nope']).status).toBe(2);
  });

  test('every event comes out as JSON, one per line', () => {
    const r = runClean(['clean', '-i', SYNTHETIC, '-o', '-']);
    expect(r.status).toBe(0);
    const out = lines(r.out);
    expect(out).toHaveLength(synthLines().length);
    for (const l of out) expect(() => JSON.parse(l)).not.toThrow();
    expect(r.summary['events in']).toBe(String(out.length));
    expect(r.summary['events out']).toBe(String(out.length));
    expect(r.summary['unreadable lines dropped']).toBe('0');
    expect(r.summary['events dropped by Endpoint Security']).toBe('0');
    expect(r.summary['placeholders user']).toBe('0');
    expect(r.summary['redacted']).toBe('0');
    expect(r.summary['capture']).toBe('(standard output)');
  });

  test('a broken line is dropped and counted, never copied', () => {
    const good = synthLines();
    const input = [
      good[0], good[1], good[2],
      '{"event":{"exec":{"args":["SECRETFRAG',
      'not json SECRETFRAG2',
      good[3],
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status).toBe(0);
    expect(lines(r.out)).toHaveLength(4);
    expect(r.summary['unreadable lines dropped']).toBe('2');
    expect(r.out).not.toContain('SECRETFRAG');
    expect(r.stderr).not.toContain('SECRETFRAG');
  });

  test('a line that is JSON but not an event object is dropped too, and blank lines are skipped', () => {
    const good = synthLines();
    const r = runClean(['clean', '-o', '-'], { input: [good[0], '', '42', '"SECRETFRAG"', 'null', '[1,2]', '   ', good[1]].join('\n') + '\n' });
    expect(lines(r.out)).toHaveLength(2);
    expect(r.summary['unreadable lines dropped']).toBe('4');
    expect(r.out).not.toContain('SECRETFRAG');
  });

  test('a pretty-printed export and a JSON array are read', () => {
    const events = synthLines().slice(0, 12).map(l => JSON.parse(l) as unknown);
    const jsonl = runClean(['clean', '-o', '-'], { input: events.map(e => JSON.stringify(e)).join('\n') + '\n' });
    const objects = runClean(['clean', '-o', '-'], { input: events.map(e => JSON.stringify(e, null, 2)).join('\n') + '\n' });
    const array = runClean(['clean', '-o', '-'], { input: JSON.stringify(events, null, 2) + '\n' });
    expect(lines(jsonl.out)).toHaveLength(12);
    expect(objects.out).toBe(jsonl.out);
    expect(array.out).toBe(jsonl.out);
    expect(objects.summary['input ended with a parse error']).toBeUndefined();
  });

  test('an export cut short says it ended with a parse error, and keeps what was read before', () => {
    const events = synthLines().slice(0, 5).map(l => JSON.parse(l) as unknown);
    const input = events.map(e => JSON.stringify(e, null, 2)).join('\n') + '\n{\n  "event": {"exec": {"args": ["SECRETFRAG';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status).toBe(0);
    expect(lines(r.out)).toHaveLength(5);
    expect(r.summary['input ended with a parse error']).toBe('yes');
    expect(r.stderr).not.toContain('SECRETFRAG');
  });

  test('sequence gaps are reported', () => {
    const p = esProc({ pid: 100, path: '/bin/zsh', platform: true });
    const c = esProc({ pid: 101, path: '/bin/zsh', platform: true, ppid: 100 });
    const input = [esFork(p, c, 1), esExit(c, 2), esExit(p, 5), esFork(p, c, 6)].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(lines(r.out)).toHaveLength(4);
    expect(r.summary['events dropped by Endpoint Security']).toBe('2');
  });

  test('a capture that arrives out of order or starts late has no gaps to report', () => {
    const p = esProc({ pid: 100, path: '/bin/zsh', platform: true });
    const input = [esExit(p, 40), esExit(p, 41), esExit(p, 39), esExit(p, 42)].join('\n') + '\n';
    expect(runClean(['clean', '-o', '-'], { input }).summary['events dropped by Endpoint Security']).toBe('0');
  });

  test('the key is 0600, in the key folder, with a header', () => {
    const dir = tmpDir();
    const keyDir = path.join(dir, 'k');
    const out = path.join(dir, 'x.cleaned.jsonl');
    const r = runClean(['clean', '-i', SYNTHETIC, '-o', out], { env: { GAMELEIRA_CLEAN_KEY_DIR: keyDir } });
    expect(r.status).toBe(0);
    const keyFile = path.join(keyDir, 'x.cleaned.jsonl.key.tsv');
    expect(r.summary['key']).toBe(keyFile);
    expect(fs.statSync(keyFile).mode & 0o777).toBe(0o600);
    expect(fs.readFileSync(keyFile, 'utf8').split('\n')[0]).toBe('kind\tplaceholder\treal');
    expect(parseKey(r.key)).toEqual([]);
    expect(r.summary['capture']).toBe(out);
    expect(r.summary['raw capture, left as it was']).toBe(SYNTHETIC);
  });

  test('-o into a folder that does not exist creates it', () => {
    const dir = tmpDir();
    const out = path.join(dir, 'a', 'b', 'c.jsonl');
    const r = runClean(['clean', '-i', SYNTHETIC, '-o', out]);
    expect(r.status).toBe(0);
    expect(lines(fs.readFileSync(out, 'utf8'))).toHaveLength(synthLines().length);
  });

  test('with -o -, the default key is stdout.key.tsv, and it is not overwritten by a second run', () => {
    const dir = tmpDir();
    const keyDir = path.join(dir, 'keys');
    const first = runClean(['clean', '-i', SYNTHETIC, '-o', '-'], { env: { GAMELEIRA_CLEAN_KEY_DIR: keyDir } });
    expect(first.status).toBe(0);
    expect(first.summary['key']).toBe(path.join(keyDir, 'stdout.key.tsv'));
    const second = runClean(['clean', '-i', SYNTHETIC, '-o', '-'], { env: { GAMELEIRA_CLEAN_KEY_DIR: keyDir } });
    expect(second.status).toBe(1);
    expect(second.stderr).toMatch(/already exists/);
    expect(second.stderr).toMatch(/-k/);
    expect(second.out).toBe('');
  });

  test('an existing default key is refused without -k, and the earlier capture is left alone', () => {
    const dir = tmpDir();
    const keyDir = path.join(dir, 'keys');
    const out = path.join(dir, 'cap.jsonl');
    expect(runClean(['clean', '-i', SYNTHETIC, '-o', out], { env: { GAMELEIRA_CLEAN_KEY_DIR: keyDir } }).status).toBe(0);
    const before = fs.readFileSync(out, 'utf8');
    const again = runClean(['clean', '-i', SYNTHETIC, '-o', out], { env: { GAMELEIRA_CLEAN_KEY_DIR: keyDir } });
    expect(again.status).toBe(1);
    expect(again.stderr).toMatch(/pass -k to reuse it/);
    expect(again.stderr).toMatch(/another -o/);
    expect(fs.readFileSync(out, 'utf8')).toBe(before);
  });

  test('-k names where the key goes; an existing key is loaded and appended to, not replaced', () => {
    const dir = tmpDir();
    const key = path.join(dir, 'mine', 'my.key.tsv');
    const first = runClean(['clean', '-i', SYNTHETIC, '-o', '-', '-k', key]);
    expect(first.status).toBe(0);
    expect(first.summary['key']).toBe(key);
    expect(fs.statSync(key).mode & 0o777).toBe(0o600);
    fs.appendFileSync(key, 'user\tuser1\t"alice"\n');
    fs.chmodSync(key, 0o644);
    const second = runClean(['clean', '-i', SYNTHETIC, '-o', '-', '-k', key]);
    expect(second.status).toBe(0);
    expect(second.key).toBe('kind\tplaceholder\treal\nuser\tuser1\t"alice"\n');
    expect(fs.statSync(key).mode & 0o777).toBe(0o600);
  });

  test('a file that is not a key is refused', () => {
    const dir = tmpDir();
    const key = path.join(dir, 'notakey.tsv');
    fs.writeFileSync(key, 'something else\n');
    const r = runClean(['clean', '-i', SYNTHETIC, '-o', '-', '-k', key]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not a Gameleira key file/);
    expect(fs.readFileSync(key, 'utf8')).toBe('something else\n');
  });

  test('a seed file with a bad line, and a key with a bad line, are refused', () => {
    const dir = tmpDir();
    const seeds = path.join(dir, 'seeds.tsv');
    fs.writeFileSync(seeds, 'user\talice\nnonsense\n');
    const r = runClean(['clean', '-i', SYNTHETIC, '-o', '-', '-S', seeds]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/line 2 of the seed file/);
    const key = path.join(dir, 'bad.key.tsv');
    fs.writeFileSync(key, 'kind\tplaceholder\treal\nuser\tuser1\talice\n');
    const k = runClean(['clean', '-i', SYNTHETIC, '-o', '-', '-k', key]);
    expect(k.status).toBe(1);
    expect(k.stderr).toMatch(/line 2 of the key file/);
  });

  test('a run that fails before it starts leaves no key behind, so the same command works once fixed', () => {
    const dir = tmpDir();
    const keyDir = path.join(dir, 'keys');
    const out = path.join(dir, 'cap.jsonl');
    const seeds = path.join(dir, 'seeds.tsv');
    const env = { GAMELEIRA_CLEAN_KEY_DIR: keyDir };
    fs.writeFileSync(seeds, 'nonsense\n');
    const bad = runClean(['clean', '-i', SYNTHETIC, '-o', out, '-S', seeds], { env });
    expect(bad.status).toBe(1);
    expect(fs.existsSync(path.join(keyDir, 'cap.jsonl.key.tsv'))).toBe(false);
    fs.writeFileSync(seeds, 'user\talice\n');
    expect(runClean(['clean', '-i', SYNTHETIC, '-o', out, '-S', seeds], { env }).status).toBe(0);
  });

  test('numbers pass through unchanged, big ones and ones with a decimal point', () => {
    const e = JSON.parse(synthLines()[0]!) as Record<string, unknown>;
    const raw = JSON.stringify(e).slice(0, -1) + ',"big":18446744073709551615,"dec":1.0,"exp":1e3}';
    const r = runClean(['clean', '-o', '-'], { input: raw + '\n' });
    expect(r.out).toContain('"big":18446744073709551615');
    expect(r.out).toContain('"dec":1.0');
  });

  test('a good seed file and -D domains are accepted', () => {
    const dir = tmpDir();
    const seeds = path.join(dir, 'seeds.tsv');
    fs.writeFileSync(seeds, 'user\talice\nhost\tbox.corp.example\n');
    const r = runClean(['clean', '-i', SYNTHETIC, '-o', '-', '-S', seeds, '-D', 'Corp.Example', '-D', 'other.example']);
    expect(r.status).toBe(0);
  });

  test('-o cannot be the capture being read', () => {
    const dir = tmpDir();
    const raw = path.join(dir, 'raw.jsonl');
    fs.copyFileSync(SYNTHETIC, raw);
    const r = runClean(['clean', '-i', raw, '-o', raw]);
    expect(r.status).toBe(1);
    expect(fs.readFileSync(raw, 'utf8')).toBe(fs.readFileSync(SYNTHETIC, 'utf8'));
  });

  test('findingSignature of raw and cleaned synthetic-lab captures match', () => {
    const r = runClean(['clean', '-i', SYNTHETIC, '-o', '-']);
    const raw = findingSignature(buildModel(synthLines()));
    const cleaned = findingSignature(buildModel(lines(r.out)));
    expect(raw.size).toBeGreaterThan(5);
    expect(cleaned).toEqual(raw);
  });

  test('the fixture builders make a capture the viewer reads', () => {
    const sh = esProc({ pid: 200, path: '/bin/zsh', platform: true, signingId: 'com.apple.zsh' });
    const ls = esProc({ pid: 200, pidversion: 1201, path: '/bin/ls', platform: true, signingId: 'com.apple.ls' });
    const m = buildModel([
      esExec(sh, ls, { args: ['ls', '-l'], cwd: '/tmp', seq: 1 }),
      esCreate(ls, { dir: '/tmp', filename: 'a.txt' }, 2),
      esCreate(ls, { path: '/tmp/b.txt' }, 3),
    ]);
    expect(m.stats.badLines).toBe(0);
    expect(m.stats.events).toBe(3);
  });
});

describe.skipIf(!fs.existsSync(JQ))('the stream between jq and the files', () => {
  // A stand-in for jq that says what the real program says on stderr, so the plumbing is tested on its own.
  test('key lines reach the key file as they come, the stats line the stats file, anything else stderr, and stdout is only the capture', () => {
    const dir = tmpDir();
    const fakeJq = path.join(dir, 'fake-jq');
    fs.writeFileSync(fakeJq, [
      '#!/bin/bash',
      'while IFS= read -r l; do',
      '  printf "K\\tname\\tname1\\t%s\\n" "\\"real $l\\"" >&2',
      '  echo "a diagnostic about $l" >&2',
      '  echo "{\\"cleaned\\":\\"$l\\"}"',
      'done',
      'printf \'S\\t{"eventsIn":2}\\n\' >&2',
    ].join('\n'), { mode: 0o755 });
    const key = path.join(dir, 'key');
    const stats = path.join(dir, 'stats');
    fs.writeFileSync(key, 'kind\tplaceholder\treal\n');
    const r = spawnSync('/bin/bash', ['-c', `GAMELEIRA_CLEAN_SOURCE_ONLY=1 . "${SCRIPT}"; run_cleaner "${dir}/cfg" "${key}" "${stats}"; echo "status $?" >&2`], {
      input: 'one\ntwo\n', env: { ...process.env, GAMELEIRA_CLEAN_JQ: fakeJq },
    });
    expect(r.stdout.toString()).toBe('{"cleaned":"one"}\n{"cleaned":"two"}\n');
    expect(fs.readFileSync(key, 'utf8')).toBe('kind\tplaceholder\treal\nname\tname1\t"real one"\nname\tname1\t"real two"\n');
    expect(fs.readFileSync(stats, 'utf8')).toBe('{"eventsIn":2}\n');
    const err = r.stderr.toString();
    expect(err).toContain('a diagnostic about one');
    expect(err).not.toMatch(/^K\t/m);
    expect(err).toContain('status 0');
  });

  test('write_config turns -D, -S and a loaded key into the config the program reads', () => {
    const dir = tmpDir();
    const seeds = path.join(dir, 'seeds.tsv');
    const key = path.join(dir, 'in.key.tsv');
    fs.writeFileSync(seeds, 'user\talice\nhost\tbox.corp.example\n');
    fs.writeFileSync(key, 'kind\tplaceholder\treal\nname\tname7\t"a\\tb\\nc"\nrealname\tPerson 2\t"Alice A"\n');
    const cfg = path.join(dir, 'cfg.json');
    const r = spawnSync('/bin/bash', ['-c',
      `GAMELEIRA_CLEAN_SOURCE_ONLY=1 . "${SCRIPT}"; DOMAINS=(Corp.Example .other.example); SEED_FILE="${seeds}"; LOADED_KEY="${key}"; write_config "${cfg}"`]);
    expect(r.status, r.stderr.toString()).toBe(0);
    expect(JSON.parse(fs.readFileSync(cfg, 'utf8'))).toEqual({
      seeds: [{ kind: 'user', value: 'alice' }, { kind: 'host', value: 'box.corp.example' }],
      domains: ['corp.example', 'other.example'],
      key: [{ kind: 'name', placeholder: 'name7', real: 'a\tb\nc' }, { kind: 'realname', placeholder: 'Person 2', real: 'Alice A' }],
      keep: [],
    });
  });
});
