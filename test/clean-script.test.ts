import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import { esBtm, esCreate, esExec, esExit, esFork, esProc } from './clean-fixture';
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
    const noValue = runClean(['clean', '-o', '-', '-i']);
    expect(noValue.status).toBe(2);
    expect(noValue.stderr).toMatch(/-i needs a value/);
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
    expect(r.summary['placeholders user']).toBe('1');   // alice
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
    expect(parseKey(r.key)[0]).toEqual({ kind: 'user', placeholder: 'user1', real: 'alice' });
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
    const p = esProc({ pid: 100, path: '/bin/zsh', platform: true });
    const c = esProc({ pid: 101, path: '/bin/zsh', platform: true, ppid: 100 });
    const quiet = [esFork(p, c, 1), esExit(c, 2)].join('\n') + '\n';   // nothing in it to clean
    const first = runClean(['clean', '-o', '-', '-k', key], { input: quiet });
    expect(first.status).toBe(0);
    expect(first.summary['key']).toBe(key);
    expect(fs.statSync(key).mode & 0o777).toBe(0o600);
    fs.appendFileSync(key, 'user\tuser1\t"alice"\n');
    fs.chmodSync(key, 0o644);
    const second = runClean(['clean', '-o', '-', '-k', key], { input: quiet + esCreate(p, { path: '/Users/alice/x' }, 3) + '\n' });
    expect(second.status).toBe(0);
    expect(second.key).toBe('kind\tplaceholder\treal\nuser\tuser1\t"alice"\nname\tname1\t"x"\n');
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
  test('with a stand-in jq: K lines go to the key file, the S line to the stats file, anything else to stderr, and stdout is only the capture', () => {
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

  // The real program, with only the cleaning swapped for a minting stand-in: the call in `step` is renamed, so the real
  // state, numbering, K lines and S line run under the real jq, whatever clean_event grows into.
  test('the real program writes a K line per placeholder, numbers on from a loaded key, and ends with the stats', () => {
    const dir = tmpDir();
    const program = fs.readFileSync(path.resolve(__dirname, '..', 'scripts', 'gameleira-clean.jq'), 'utf8');
    expect(program).toContain('clean_event($seen)');
    const mint = [
      'def mint_event($state):',
      '  .who as $w',
      '  | if $state.map.user[$w] != null then {event: (.who = $state.map.user[$w]), state: $state, new: []}',
      '    else ($state.next.user // 1) as $n | "user\\($n)" as $p',
      '      | {event: (.who = $p), state: ($state | .map.user[$w] = $p | .next.user = $n + 1), new: [{kind: "user", placeholder: $p, real: $w}]}',
      '    end;',
    ].join('\n');
    const scratch = path.join(dir, 'mint.jq');
    fs.writeFileSync(scratch, mint + '\n' + program.replace('clean_event($seen)', 'mint_event($seen)'));
    const loadedKey = path.join(dir, 'loaded.key.tsv');
    fs.writeFileSync(loadedKey, 'kind\tplaceholder\treal\nuser\tuser4\t"known"\n');
    const key = path.join(dir, 'run.key.tsv');
    fs.writeFileSync(key, 'kind\tplaceholder\treal\n');
    const stats = path.join(dir, 'stats');
    const nasty = 'a\tb\n"c"\\d';
    const input = [nasty, 'known', nasty, 'fresh'].map(w => JSON.stringify({ who: w, global_seq_num: 1 })).join('\n') + '\n'
      + 'not json\n' + JSON.stringify({ who: 'late', global_seq_num: 4 }) + '\n';
    const r = spawnSync('/bin/bash', ['-c', [
      `GAMELEIRA_CLEAN_SOURCE_ONLY=1 . "${SCRIPT}"`,
      `CLEAN_PROGRAM="${scratch}"; DOMAINS=(); SEED_FILE=; LOADED_KEY="${loadedKey}"`,
      `write_config "${dir}/cfg.json" && run_cleaner "${dir}/cfg.json" "${key}" "${stats}"`,
    ].join('\n')], { input, env: process.env });
    expect(r.status, r.stderr.toString()).toBe(0);
    // `known` keeps its loaded placeholder; new values continue at user5, and a repeat reuses its placeholder.
    expect(lines(r.stdout.toString()).map(l => (JSON.parse(l) as { who: string }).who))
      .toEqual(['user5', 'user4', 'user5', 'user6', 'user7']);
    expect(parseKey(fs.readFileSync(key, 'utf8'))).toEqual([
      { kind: 'user', placeholder: 'user5', real: nasty },
      { kind: 'user', placeholder: 'user6', real: 'fresh' },
      { kind: 'user', placeholder: 'user7', real: 'late' },
    ]);
    // Each real value is one JSON string on one line, so tabs, newlines and quotes survive.
    expect(fs.readFileSync(key, 'utf8').split('\n')[1]).toBe(`user\tuser5\t${JSON.stringify(nasty)}`);
    expect(JSON.parse(fs.readFileSync(stats, 'utf8'))).toEqual({
      eventsIn: 6, eventsOut: 5, unreadable: 1, seqGaps: 2, redacted: 0, placeholders: { user: 3 },
    });
    expect(r.stderr.toString()).not.toMatch(/^[KS]\t/m);
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

// ---- paths ------------------------------------------------------------------------------------------------------
// A Mac whose user is jdoe (uid 501). The environment is given explicitly: bare account names outside paths (USER=jdoe)
// are cleaned by a later step, so none is planted here.
const JDOE_ENV = ['HOME=/Users/jdoe', 'LANG=C.UTF-8', 'PATH=/usr/bin:/bin:/Users/jdoe/.pyenv/shims', 'SHELL=/bin/zsh', 'TMPDIR=/var/folders/ab/cdef/T/'];
const zsh = esProc({ pid: 300, path: '/bin/zsh', platform: true, signingId: 'com.apple.zsh' });
const sysProc = (pid: number, p: string): ReturnType<typeof esProc> =>
  esProc({ pid, path: p, platform: true, signingId: `com.apple.${p.split('/').pop()!}`, ppid: 300 });
const userProc = (pid: number, p: string, extra: Partial<Parameters<typeof esProc>[0]> = {}): ReturnType<typeof esProc> =>
  esProc({ pid, path: p, signingId: null, ppid: 300, ...extra });

/** The events of a cleaned capture, parsed. */
const events = (out: string): Record<string, any>[] => lines(out).map(l => JSON.parse(l) as Record<string, any>);
/** The real values of a key of one kind. */
const keyed = (key: string, kind: string): Map<string, string> =>
  new Map(parseKey(key).filter(r => r.kind === kind).map(r => [r.real, r.placeholder]));

describe.skipIf(!fs.existsSync(JQ))('paths', () => {
  const planted = [
    '/Users/jdoe/Documents/Board – Q3 "final"/Q3-acquisition.pdf',
    '/Users/jdoe/Desktop/Merger/notes.txt',
    '/Users/jdoe/Library/Application Support/Microsoft/Office/AutoRecovery/Offer.docx',
    '/Users/jdoe/Library/Group Containers/UBF8T346G9.Office/Budget.xlsx',
    '/Users/Shared/Payroll.xlsx',
    '/Volumes/Jdoe Passport/Clients/acme.pdf',
    '/tmp/Board.key',
    '/var/folders/ab/cdef/T/TemporaryItems/Notes.txt',
    '/System/Volumes/Data/Users/jdoe/Desktop/Merger/notes.txt',
  ];
  const open = sysProc(310, '/usr/bin/open');
  const leakInput = [
    ...planted.map((p, i) => esCreate(zsh, { path: p }, i + 1)),
    esCreate(zsh, { dir: '/Users/jdoe/Documents/Board', filename: 'Minutes.pages' }, 20),
    esExec(zsh, open, { args: ['open', '~/Documents/Offsite.txt', '--out=/Users/jdoe/Desktop/Merger/plan.key'], cwd: '/Users/jdoe/Desktop/Merger', env: JDOE_ENV, seq: 21 }),
  ].join('\n') + '\n';

  test('home, shared, volume and temp names become placeholders', () => {
    const r = runClean(['clean', '-o', '-'], { input: leakInput });
    expect(r.status, r.stderr).toBe(0);
    const out = r.out.toLowerCase();
    for (const s of ['jdoe', 'board', 'q3', 'acquisition', 'merger', 'notes.txt', 'offer', 'budget', 'payroll', 'passport',
      'clients', 'acme', 'minutes', 'offsite', 'plan.key']) expect(out, s).not.toContain(s);
    expect(keyed(r.key, 'user')).toEqual(new Map([['jdoe', 'user1']]));
    expect(keyed(r.key, 'volume')).toEqual(new Map([['Jdoe Passport', 'vol1']]));
    const names = keyed(r.key, 'name');
    for (const n of ['Board – Q3 "final"', 'Q3-acquisition.pdf', 'Merger', 'notes.txt', 'Offer.docx', 'Budget.xlsx', 'Payroll.xlsx',
      'Clients', 'acme.pdf', 'Board.key', 'Notes.txt', 'Board', 'Minutes.pages', 'Offsite.txt', 'plan.key']) expect(names.has(n), n).toBe(true);
    expect(names.get('Q3-acquisition.pdf')).toMatch(/^name\d+\.pdf$/);
    expect(names.get('Board – Q3 "final"')).toMatch(/^name\d+$/);
    const ev = events(r.out);
    const paths = ev.slice(0, planted.length).map(e => e.event.create.destination.existing_file.path as string);
    expect(paths[0]).toBe(`/Users/user1/Documents/${names.get('Board – Q3 "final"')}/${names.get('Q3-acquisition.pdf')}`);
    expect(paths[2]).toMatch(/^\/Users\/user1\/Library\/Application Support\/name\d+\/name\d+\/name\d+\/name\d+\.docx$/);
    expect(paths[3]).toMatch(/^\/Users\/user1\/Library\/Group Containers\/UBF8T346G9\.Office\/name\d+\.xlsx$/);
    expect(paths[4]).toMatch(/^\/Users\/Shared\/name\d+\.xlsx$/);
    expect(paths[5]).toMatch(/^\/Volumes\/vol1\/name\d+\/name\d+\.pdf$/);
    expect(paths[6]).toMatch(/^\/tmp\/name\d+\.key$/);
    expect(paths[7]).toMatch(/^\/var\/folders\/ab\/cdef\/T\/TemporaryItems\/name\d+\.txt$/);
    expect(paths[8]).toBe(`/System/Volumes/Data${paths[1]}`);
    // A new file's separate name is cleaned as the last name of its folder.
    const np = ev[planted.length]!.event.create.destination.new_path;
    expect(np.dir.path).toBe(`/Users/user1/Documents/${names.get('Board')}`);
    expect(np.filename).toBe(names.get('Minutes.pages'));
    expect(ev[planted.length]!.event.create).not.toHaveProperty('acl');
    // ~/ paths and paths after = are cleaned too; arguments keep their count and order.
    const exec = ev[planted.length + 1]!.event.exec;
    expect(exec.args).toEqual(['open', `~/Documents/${names.get('Offsite.txt')}`, `--out=/Users/user1/Desktop/${names.get('Merger')}/${names.get('plan.key')}`]);
    expect(exec.cwd.path).toBe(`/Users/user1/Desktop/${names.get('Merger')}`);
  });

  test('the same name gets the same placeholder in every field', () => {
    const backup = userProc(320, '/usr/local/bin/backup');
    const btmd = sysProc(330, '/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Resources/backgroundtaskmanagementd');
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/Q3-acquisition.pdf' }, 1),
      esExec(zsh, backup, { args: ['backup', '/tmp/Q3-acquisition.pdf', 'sh', '-c', 'cp "/Users/jdoe/Board Q3/Q3-acquisition.pdf" /tmp/x'], cwd: '/Volumes/Jdoe Passport/Q3-acquisition.pdf', env: JDOE_ENV, seq: 2 }),
      esBtm(btmd, { itemUrl: 'file:///Users/jdoe/Library/LaunchAgents/Q3-acquisition.pdf', executablePath: '/usr/local/bin/backup', itemType: 1 }, 3),
      esCreate(zsh, { path: '/Users/jdoe/Board Q3/notes.txt' }, 4),
      esBtm(btmd, { itemUrl: 'file:///Users/jdoe/Board%20Q3/notes.txt', executablePath: '/usr/local/bin/backup', itemType: 1 }, 5),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const rows = parseKey(r.key).filter(k => k.real === 'Q3-acquisition.pdf');
    expect(rows).toHaveLength(1);
    const ph = rows[0]!.placeholder;
    expect(ph).toMatch(/^name\d+\.pdf$/);
    const board = keyed(r.key, 'name').get('Board Q3')!;
    const ev = events(r.out);
    expect(ev[0]!.event.create.destination.existing_file.path).toBe(`/Users/user1/Documents/${ph}`);
    expect(ev[1]!.event.exec.cwd.path).toBe(`/Volumes/vol1/${ph}`);
    expect(ev[1]!.event.exec.args).toEqual(['backup', `/tmp/${ph}`, 'sh', '-c', `cp "/Users/user1/${board}/${ph}" /tmp/${keyed(r.key, 'name').get('x')}`]);
    expect(ev[2]!.event.btm_launch_item_add.item.item_url).toBe(`file:///Users/user1/Library/LaunchAgents/${ph}`);
    // A file URL is read name by name with its %-escapes undone, so a name in it matches the same name in a path.
    expect(ev[4]!.event.btm_launch_item_add.item.item_url).toBe(`file:///Users/user1/${board}/${keyed(r.key, 'name').get('notes.txt')}`);
    expect(r.out).not.toContain('Q3');
  });

  test('shapes the rules need survive', () => {
    const agent = userProc(340, '/Users/jdoe/Applications/Foo.app/Contents/MacOS/Foo', { teamId: 'ABCDE12345', signingId: 'com.foo.Foo' });
    const translocated = '/private/var/folders/ab/cdef/T/AppTranslocation/0E7A1C2B-5D4F-4A3B-9C8D-112233445566/d/Foo.app/Contents/MacOS/Foo';
    const moved = userProc(341, translocated, { teamId: 'ABCDE12345', signingId: 'com.foo.Foo' });
    const btmd = sysProc(330, '/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Resources/backgroundtaskmanagementd');
    const curl = sysProc(342, '/usr/bin/curl');
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Downloads/setup.pkg' }, 1),
      esCreate(zsh, { path: '/Users/Shared/drop.txt' }, 2),
      esCreate(zsh, { path: '/Users/jdoe/Projects/.hidden/x' }, 3),
      esCreate(zsh, { path: '/Users/jdoe/Projects/node_modules/.bin/tool' }, 4),
      esCreate(zsh, { path: '/Users/jdoe/Projects/.git/hooks/pre-commit' }, 5),
      esCreate(zsh, { path: '/Users/jdoe/Library/LaunchAgents/com.jdoe.agent.plist' }, 6),
      esBtm(btmd, { itemUrl: 'file:///Users/jdoe/Library/LaunchAgents/com.jdoe.agent.plist', executablePath: '/Users/jdoe/Applications/Foo.app/Contents/MacOS/Foo', itemType: 1 }, 7),
      esExec(zsh, agent, { args: ['/Users/jdoe/Applications/Foo.app/Contents/MacOS/Foo'], cwd: '/var/folders/ab/cdef/T/', env: JDOE_ENV, seq: 8 }),
      esExec(zsh, moved, { args: [translocated], cwd: '/', env: JDOE_ENV, seq: 9 }),
      // Names that look like bundle IDs, but in Documents: a person's files, not an app's.
      esCreate(zsh, { path: '/Users/jdoe/Documents/first.last.resume.pdf' }, 10),
      esCreate(zsh, { path: '/Users/jdoe/Documents/com.acme.secret-plan.docx' }, 11),
      // Home folders named like system ones do not change system paths.
      esCreate(zsh, { path: '/Users/jdoe/homebrew/bin/tool' }, 12),
      esCreate(zsh, { path: '/Users/jdoe/Projects/usr/lib/System/x' }, 13),
      esExec(zsh, curl, { args: ['curl', '-o', '/usr/lib/libz.dylib'], cwd: '/System/Library/Frameworks', env: JDOE_ENV, seq: 14 }),
      esCreate(zsh, { path: '/Users/jdoe/Library/Developer/Xcode/DerivedData/App-abc/Build/x' }, 15),
    ].join('\n') + '\n';
    const raw = lines(input);
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const ev = events(r.out);
    const created = (i: number): string => ev[i]!.event.create.destination.existing_file.path as string;
    expect(created(0)).toMatch(/^\/Users\/user1\/Downloads\/name\d+\.pkg$/);
    expect(created(1)).toMatch(/^\/Users\/Shared\/name\d+\.txt$/);
    expect(created(2)).toMatch(/^\/Users\/user1\/name\d+\/\.name\d+\/name\d+$/);
    expect(created(3)).toMatch(/^\/Users\/user1\/name\d+\/node_modules\/\.name\d+\/name\d+$/);
    expect(created(4)).toMatch(/^\/Users\/user1\/name\d+\/\.git\/name\d+\/name\d+$/);
    expect(created(5)).toBe('/Users/user1/Library/LaunchAgents/com.user1.agent.plist');
    expect(ev[6]!.event.btm_launch_item_add.item.item_url).toBe('file:///Users/user1/Library/LaunchAgents/com.user1.agent.plist');
    expect(ev[6]!.event.btm_launch_item_add.executable_path).toBe('/Users/user1/Applications/Foo.app/Contents/MacOS/Foo');
    expect(ev[7]!.event.exec.target.executable.path).toBe('/Users/user1/Applications/Foo.app/Contents/MacOS/Foo');
    expect(ev[7]!.event.exec.cwd.path).toBe('/var/folders/ab/cdef/T/');
    expect(ev[8]!.event.exec.target.executable.path).toBe(translocated);
    expect(ev[8]!.event.exec.args).toEqual([translocated]);
    expect(created(9)).toMatch(/^\/Users\/user1\/Documents\/name\d+\.pdf$/);
    expect(created(10)).toMatch(/^\/Users\/user1\/Documents\/name\d+\.docx$/);
    expect(created(11)).toMatch(/^\/Users\/user1\/name\d+\/bin\/name\d+$/);
    expect(created(12)).toMatch(/^\/Users\/user1\/name\d+\/usr\/lib\/System\/name\d+$/);
    expect(ev[13]!.event.exec.args).toEqual(['curl', '-o', '/usr/lib/libz.dylib']);
    expect(ev[13]!.event.exec.cwd.path).toBe('/System/Library/Frameworks');
    expect(created(14)).toMatch(/^\/Users\/user1\/Library\/Developer\/name\d+\/DerivedData\/name\d+\/name\d+\/name\d+$/);
    // PATH lists are cleaned entry by entry.
    expect(ev[7]!.event.exec.env).toContain('HOME=/Users/user1');
    expect(ev[7]!.event.exec.env.find((e: string) => e.startsWith('PATH='))).toMatch(/^PATH=\/usr\/bin:\/bin:\/Users\/user1\/\.name\d+\/shims$/);
    expect(findingSignature(buildModel(lines(r.out)))).toEqual(findingSignature(buildModel(raw)));
  });

  test('programs that ran keep their names', () => {
    // Each program runs in its own process: a shell child (pid N) execs it (pid N, a new pidversion).
    const child = (pid: number): ReturnType<typeof esProc> => esProc({ pid, path: '/bin/zsh', platform: true, signingId: 'com.apple.zsh', ppid: 300 });
    const image = (pid: number, p: string): ReturnType<typeof esProc> => userProc(pid, p, { pidversion: pid + 2000 });
    const input = [
      esExec(child(400), image(400, '/Users/jdoe/homebrew/bin/curl'), { args: ['curl', '-o', 'x', 'https://example.com/a.py'], cwd: '/Users/jdoe/Downloads', env: JDOE_ENV, seq: 1 }),
      esExec(child(401), image(401, '/Users/jdoe/.pyenv/shims/python3'), { args: ['python3'], cwd: '/Users/jdoe/Downloads', env: JDOE_ENV, stdinPipe: true, seq: 2 }),
      esExec(child(402), image(402, '/Users/jdoe/.nvm/versions/node/v22.0.0/bin/node'), { args: ['node', '-e', 'require("child_process")'], cwd: '/Users/jdoe/Projects', env: JDOE_ENV, seq: 3 }),
      esExec(child(403), image(403, '/Users/jdoe/Downloads/Zoom_Installer'), { args: ['/Users/jdoe/Downloads/Zoom_Installer'], cwd: '/Users/jdoe/Downloads', env: JDOE_ENV, seq: 4 }),
      // From now on these names stay, in any path.
      esCreate(zsh, { path: '/Users/jdoe/Documents/Zoom_Installer' }, 5),
      esCreate(zsh, { path: '/Users/jdoe/Documents/curl/node' }, 6),
    ].join('\n') + '\n';
    const raw = lines(input);
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const ev = events(r.out);
    expect(ev.map(e => e.event.exec?.target.executable.path)).toEqual([
      '/Users/user1/homebrew/bin/curl'.replace('homebrew', keyed(r.key, 'name').get('homebrew')!),
      expect.stringMatching(/^\/Users\/user1\/\.name\d+\/shims\/python3$/),
      expect.stringMatching(/^\/Users\/user1\/\.name\d+\/versions\/node\/name\d+\.0\/bin\/node$/),
      '/Users/user1/Downloads/Zoom_Installer',
      undefined, undefined,
    ]);
    expect(ev[3]!.event.exec.args).toEqual(['/Users/user1/Downloads/Zoom_Installer']);
    expect(ev[4]!.event.create.destination.existing_file.path).toBe('/Users/user1/Documents/Zoom_Installer');
    expect(ev[5]!.event.create.destination.existing_file.path).toBe('/Users/user1/Documents/curl/node');
    const sig = findingSignature(buildModel(raw));
    expect(sig.size).toBeGreaterThan(2);
    expect(findingSignature(buildModel(lines(r.out)))).toEqual(sig);
  });

  test('a name that had a placeholder before its program ran keeps it in the key, and is kept from then on', () => {
    const child = esProc({ pid: 410, path: '/bin/zsh', platform: true, signingId: 'com.apple.zsh', ppid: 300 });
    const dropper = userProc(410, '/Users/jdoe/Downloads/Zoom_Installer', { pidversion: 2410 });
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Downloads/Zoom_Installer' }, 1),
      esExec(child, dropper, { args: ['/Users/jdoe/Downloads/Zoom_Installer'], cwd: '/Users/jdoe/Downloads', env: JDOE_ENV, seq: 2 }),
      esCreate(zsh, { path: '/Users/jdoe/Downloads/Zoom_Installer' }, 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    const ph = keyed(r.key, 'name').get('Zoom_Installer');
    expect(ph).toMatch(/^name\d+$/);
    const ev = events(r.out);
    expect(ev[0]!.event.create.destination.existing_file.path).toBe(`/Users/user1/Downloads/${ph}`);
    expect(ev[1]!.event.exec.target.executable.path).toBe('/Users/user1/Downloads/Zoom_Installer');
    expect(ev[2]!.event.create.destination.existing_file.path).toBe('/Users/user1/Downloads/Zoom_Installer');
  });

  test('a launch agent plist with a space in its name is matched to its registration as in the raw capture', () => {
    const btmd = sysProc(330, '/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Resources/backgroundtaskmanagementd');
    const sh = sysProc(350, '/bin/sh');
    const input = [
      esCreate(sh, { path: '/Users/jdoe/Library/LaunchAgents/My Agent.plist' }, 1),
      esBtm(btmd, { itemUrl: 'file:///Users/jdoe/Library/LaunchAgents/My%20Agent.plist', executablePath: '/Users/jdoe/Downloads/Zoom_Installer', itemType: 1 }, 2),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    const ph = keyed(r.key, 'name').get('My Agent.plist');
    expect(ph).toMatch(/^name\d+\.plist$/);
    expect(events(r.out)[1]!.event.btm_launch_item_add.item.item_url).toBe(`file:///Users/user1/Library/LaunchAgents/${ph}`);
    expect(findingSignature(buildModel(lines(r.out)))).toEqual(findingSignature(buildModel(lines(input))));
  });

  test('same findings: the synthetic-lab fixture and the lab script\'s synthetic capture', () => {
    const lab = spawnSync('/bin/bash', [path.resolve(__dirname, '..', 'scripts', 'gameleira-lab.sh'), 'synthetic', '--stdout']).stdout.toString('utf8');
    for (const [input, user] of [[fs.readFileSync(SYNTHETIC, 'utf8'), 'alice'], [lab, 'learner']] as const) {
      const r = runClean(['clean', '-o', '-'], { input });
      expect(r.status, r.stderr).toBe(0);
      expect(keyed(r.key, 'user').get(user)).toBe('user1');
      const raw = findingSignature(buildModel(lines(input)));
      expect(raw.size).toBeGreaterThan(5);
      expect(findingSignature(buildModel(lines(r.out)))).toEqual(raw);
    }
  });

  test('same output every run, for the same input and a fresh key', () => {
    const a = runClean(['clean', '-o', '-'], { input: leakInput });
    const b = runClean(['clean', '-o', '-'], { input: leakInput });
    expect(a.out).not.toBe('');
    expect(b.out).toBe(a.out);
    expect(b.key).toBe(a.key);
  });

  test('a loaded key keeps its placeholders, and new names are numbered after it', () => {
    const dir = tmpDir();
    const key = path.join(dir, 'shared.key.tsv');
    fs.writeFileSync(key, 'kind\tplaceholder\treal\nuser\tuser1\t"jdoe"\nname\tname4.pdf\t"Q3-acquisition.pdf"\n');
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/Q3-acquisition.pdf' }, 1),
      esCreate(zsh, { path: '/Users/jdoe/Documents/Merger.key' }, 2),
      esCreate(zsh, { path: '/Users/kim/Desktop/x' }, 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-', '-k', key], { input });
    expect(r.status, r.stderr).toBe(0);
    expect(events(r.out).map(e => e.event.create.destination.existing_file.path)).toEqual([
      '/Users/user1/Documents/name4.pdf', '/Users/user1/Documents/name5.key', '/Users/user2/Desktop/name6',
    ]);
    expect(parseKey(r.key).slice(2)).toEqual([
      { kind: 'name', placeholder: 'name5.key', real: 'Merger.key' },
      { kind: 'user', placeholder: 'user2', real: 'kim' },
      { kind: 'name', placeholder: 'name6', real: 'x' },
    ]);
    expect(r.summary['placeholders name']).toBe('2');
    expect(r.summary['placeholders user']).toBe('1');
  });
});
