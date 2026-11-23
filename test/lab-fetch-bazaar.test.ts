import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';

// lab/fetch-bazaar.sh searches MalwareBazaar and downloads one sample. It needs the user's abuse.ch Auth-Key in ABUSE_CH_KEY, must
// never put it on a command line, in a file or in its output, and must never extract what it downloads. A stub curl (LAB_CURL)
// stands in for the API, so nothing here touches the network.
const SCRIPT = path.resolve(__dirname, '..', 'lab', 'fetch-bazaar.sh');
const KEY = 'TESTKEY0123456789abcdefTESTKEY0123456789abcdef';
const SHA = 'fdcd5d218a0cc440c6da0e7e4189d92f9d6792db48bedcf07137991f965ebc96';
const HEADER = 'family\tzip\tsha256\trecipe\twindow_s\tnotes\tsource';

const INFO = JSON.stringify({ query_status: 'ok', data: [{ file_name: 'u78676388', file_size: 442752, file_type: 'macho', first_seen: '2026-11-16 10:22:14',
  signature: 'AMOS', tags: ['AMOS', 'macho'], sha256_hash: SHA }] });
const SEARCH = JSON.stringify({ query_status: 'ok', data: [
  { first_seen: '2026-11-16 10:22:14', sha256_hash: SHA, file_size: 442752, file_arch: 'X86_64', signature: 'AMOS', file_type: 'macho', tags: ['AMOS', 'macho'], file_name: 'u78676388' },
  { first_seen: '2026-11-15 01:00:00', sha256_hash: 'b'.repeat(64), file_size: 34627, file_arch: null, signature: null, file_type: 'macho', tags: null, file_name: 'tab\there\nnewline' },
] });

// The stub reads the curl config from stdin (the key goes there, not on the command line), logs what it was asked, and answers by query.
const CURL = `#!/bin/bash
echo "curl $*" >> "$STUB_LOG"
cfg=$(cat)
case "$cfg" in *"Auth-Key: $STUB_KEY"*) echo "AUTH_OK" >> "$STUB_LOG" ;; *) echo "AUTH_BAD" >> "$STUB_LOG" ;; esac
out=""; prev=""; q=""
for a in "$@"; do [ "$prev" = "-o" ] && out=$a; case "$a" in query=*) q=\${a#query=} ;; esac; prev=$a; done
case "$q" in
  get_info) printf '%s' "$STUB_INFO" > "$out" ;;
  get_file) printf '%b' "$STUB_FILE" > "$out" ;;
  get_file_type|get_taginfo) printf '%s' "$STUB_SEARCH" > "$out" ;;
esac
exit "\${STUB_EXIT:-0}"
`;

let dir: string;
let log: string;
const manifest = () => path.join(dir, 'manifest.tsv');
const calls = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
const rows = () => fs.readFileSync(manifest(), 'utf8').replace(/\n$/, '').split('\n');

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-bazaar-'));
  log = path.join(dir, 'log.txt');
  fs.mkdirSync(path.join(dir, 'bin'));
  fs.writeFileSync(path.join(dir, 'bin', 'curl'), CURL, { mode: 0o755 });
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function run(args: string[], extra: Record<string, string> = {}, withKey = true) {
  const r = spawnSync('/bin/bash', [SCRIPT, ...args], {
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH ?? '', HOME: '/home/x', STUB_LOG: log, STUB_KEY: KEY, STUB_INFO: INFO, STUB_SEARCH: SEARCH, STUB_FILE: 'PK\\003\\004fake aes zip bytes',
      FICUS_LAB_DATA: path.join(dir, 'data'), LAB_MANIFEST: manifest(), LAB_CURL: path.join(dir, 'bin', 'curl'), ...(withKey ? { ABUSE_CH_KEY: KEY } : {}), ...extra,
    },
  });
  return r;
}
/** Every place the key could have leaked to: output, the stub's log of its command lines, the manifest, the samples folder. */
function leaks(r: { stdout: string; stderr: string }): string[] {
  const found: string[] = [];
  if (r.stdout.includes(KEY)) found.push('stdout');
  if (r.stderr.includes(KEY)) found.push('stderr');
  if (calls().some(c => c.includes(KEY))) found.push('command line');
  if (fs.existsSync(manifest()) && fs.readFileSync(manifest(), 'utf8').includes(KEY)) found.push('manifest');
  const samples = path.join(dir, 'data', 'samples');
  if (fs.existsSync(samples)) for (const f of fs.readdirSync(samples)) if (fs.readFileSync(path.join(samples, f)).includes(KEY)) found.push(`samples/${f}`);
  return found;
}

describe('lab/fetch-bazaar.sh', () => {
  test('parses under bash', () => {
    expect(spawnSync('/bin/bash', ['-n', SCRIPT]).status).toBe(0);
  });

  test('without ABUSE_CH_KEY it exits 2, names the variable and calls nothing', () => {
    const r = run(['search'], {}, false);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('ABUSE_CH_KEY');
    expect(calls()).toEqual([]);
  });

  test('no command, an unknown command or an unknown option exits 2', () => {
    expect(run([]).status).toBe(2);
    expect(run(['frobnicate']).status).toBe(2);
    expect(run(['search', '--nope']).status).toBe(2);
    expect(calls()).toEqual([]);
  });

  describe('search', () => {
    test('asks for recent Mach-O files by default and prints one tab-separated line each, whatever a field holds', () => {
      const r = run(['search']);
      expect(r.status, r.stderr).toBe(0);
      expect(calls().some(c => c.includes('query=get_file_type') && c.includes('file_type=macho') && c.includes('limit=30'))).toBe(true);
      const lines = r.stdout.trimEnd().split('\n');
      expect(lines[0]).toBe('first_seen\tsha256\tsize\tarch\tsignature\ttype\ttags\tname');
      expect(lines).toHaveLength(3);
      for (const l of lines) expect(l.split('\t')).toHaveLength(8);
      expect(lines[1]).toContain(`2026-11-16\t${SHA}\t442752\tX86_64\tAMOS\tmacho\tAMOS,macho\tu78676388`);
    });

    test('--type, --tag and --limit change the query; a tag uses get_taginfo', () => {
      expect(run(['search', '--type', 'dmg', '--limit', '5']).status).toBe(0);
      expect(calls().some(c => c.includes('file_type=dmg') && c.includes('limit=5'))).toBe(true);
      fs.rmSync(log);
      expect(run(['search', '--tag', 'AMOS']).status).toBe(0);
      expect(calls().some(c => c.includes('query=get_taginfo') && c.includes('tag=AMOS'))).toBe(true);
    });

    test('a bad value for --type, --tag or --limit exits 2 and calls nothing', () => {
      for (const args of [['--limit', 'ten'], ['--limit', '0'], ['--limit', '5000'], ['--type', 'a b'], ['--type', 'x&y=z'], ['--tag', '../x']]) {
        expect(run(['search', ...args]).status, args.join(' ')).toBe(2);
      }
      expect(calls()).toEqual([]);
    });

    test('a refusal from the API is reported with its status, and the key is not in the message', () => {
      const r = run(['search'], { STUB_SEARCH: JSON.stringify({ query_status: 'unknown_auth_key' }) });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('unknown_auth_key');
      expect(leaks(r)).toEqual([]);
    });

    test('the key goes to curl on standard input, not on the command line', () => {
      const r = run(['search']);
      expect(calls()).toContain('AUTH_OK');
      expect(calls().find(c => c.startsWith('curl'))).toContain('-K -');
      expect(leaks(r)).toEqual([]);
    });
  });

  describe('get', () => {
    test('downloads by sha256, saves the zip, records a manifest row with source bazaar and the sample hash, and never leaks the key', () => {
      const r = run(['get', SHA]);
      expect(r.status, r.stderr).toBe(0);
      const label = 'Bazaar-AMOS-fdcd5d21';
      const zip = path.join(dir, 'data', 'samples', `${label}.zip`);
      expect(fs.existsSync(zip)).toBe(true);
      expect(calls().some(c => c.includes('query=get_info') && c.includes(`hash=${SHA}`))).toBe(true);
      expect(calls().some(c => c.includes('query=get_file') && c.includes(`sha256_hash=${SHA}`))).toBe(true);
      expect(rows()[0]).toBe(HEADER);
      expect(rows()).toHaveLength(2);
      const [family, file, sha, recipe, window, notes, source] = rows()[1]!.split('\t');
      expect([family, file, recipe, window, source]).toEqual([label, `${label}.zip`, 'manual', '600', 'bazaar']);
      expect(notes).toBe(`bazaar:${SHA} AMOS`);
      expect(sha).toBe(spawnSync('shasum', ['-a', '256', zip], { encoding: 'utf8' }).stdout.split(' ')[0]);
      expect(r.stdout).toContain('AMOS');
      expect(leaks(r)).toEqual([]);
    });

    test('a label given on the command line names the sample; an upper-case hash is accepted', () => {
      const r = run(['get', SHA.toUpperCase(), 'Amos-Nov16']);
      expect(r.status, r.stderr).toBe(0);
      expect(fs.existsSync(path.join(dir, 'data', 'samples', 'Amos-Nov16.zip'))).toBe(true);
      expect(rows()[1]!.split('\t')[0]).toBe('Amos-Nov16');
    });

    test('a second call neither downloads again nor adds a second row', () => {
      expect(run(['get', SHA]).status).toBe(0);
      expect(run(['get', SHA]).status).toBe(0);
      expect(calls().filter(c => c.includes('query=get_file') && !c.includes('get_file_type'))).toHaveLength(1);
      expect(rows()).toHaveLength(2);
    });

    test('a hash that is not 64 hex digits, or a bad label, exits 2 and calls nothing', () => {
      for (const args of [['get'], ['get', 'abc'], ['get', 'z'.repeat(64)], ['get', SHA, 'a/b'], ['get', SHA, '..'], ['get', SHA, '-rf']]) {
        expect(run(args).status, args.join(' ')).toBe(2);
      }
      expect(calls()).toEqual([]);
    });

    test('a sample the API does not have is reported with its status and leaves nothing behind', () => {
      const r = run(['get', SHA], { STUB_INFO: JSON.stringify({ query_status: 'hash_not_found' }) });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('hash_not_found');
      expect(fs.existsSync(manifest())).toBe(false);
      expect(fs.existsSync(path.join(dir, 'data', 'samples')) ? fs.readdirSync(path.join(dir, 'data', 'samples')) : []).toEqual([]);
    });

    test('an answer that is JSON, not a zip (an error from get_file), is removed and recorded nowhere', () => {
      const r = run(['get', SHA], { STUB_FILE: '{"query_status":"file_not_found"}' });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('file_not_found');
      expect(fs.existsSync(manifest())).toBe(false);
      const samples = path.join(dir, 'data', 'samples');
      expect(fs.readdirSync(samples)).toEqual([]);
      expect(leaks(r)).toEqual([]);
    });

    test('a failed curl leaves no zip, no partial file and no row', () => {
      const r = run(['get', SHA], { STUB_EXIT: '28' });
      expect(r.status).toBe(1);
      expect(fs.existsSync(manifest())).toBe(false);
      const samples = path.join(dir, 'data', 'samples');
      expect(fs.existsSync(samples) ? fs.readdirSync(samples) : []).toEqual([]);
    });

    test('it never extracts or opens what it fetched', () => {
      for (const t of ['unzip', 'ditto', 'open', '7zz', '7z', 'tar']) fs.writeFileSync(path.join(dir, 'bin', t), `#!/bin/bash\necho "${t}" >> "$STUB_LOG"\n`, { mode: 0o755 });
      const r = spawnSync('/bin/bash', [SCRIPT, 'get', SHA], {
        encoding: 'utf8',
        env: { PATH: `${path.join(dir, 'bin')}:${process.env.PATH ?? ''}`, HOME: '/home/x', STUB_LOG: log, STUB_KEY: KEY, STUB_INFO: INFO, STUB_FILE: 'PK\\003\\004x', ABUSE_CH_KEY: KEY,
          FICUS_LAB_DATA: path.join(dir, 'data'), LAB_MANIFEST: manifest(), LAB_CURL: path.join(dir, 'bin', 'curl') },
      });
      expect(r.status, r.stderr).toBe(0);
      expect(calls().filter(c => ['unzip', 'ditto', 'open', '7zz', '7z', 'tar'].includes(c))).toEqual([]);
    });
  });
});
