import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';

// lab/fetch-sample.sh downloads one zip from the objective-see/malware repository and records its hash. It must never
// extract or open what it fetched. These tests use a stub curl (LAB_CURL) so nothing is downloaded.
const SCRIPT = path.resolve(__dirname, '..', 'lab', 'fetch-sample.sh');
const HEADER = 'family\tzip\tsha256\trecipe\twindow_s\tnotes';

const CURL_STUB = `#!/bin/bash
echo "curl $*" >> "$STUB_LOG"
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out=$a; prev=$a; done
printf '%b' "\${STUB_CURL_BODY-PK\\\\003\\\\004fake zip bytes}" > "$out"
exit "\${STUB_CURL_EXIT:-0}"
`;
const TOOL_STUB = `#!/bin/bash\necho "$(basename "$0") $*" >> "$STUB_LOG"\n`;

let dir: string;
let log: string;
const manifest = () => path.join(dir, 'manifest.tsv');
const rows = () => fs.readFileSync(manifest(), 'utf8').replace(/\n$/, '').split('\n'); // not trim(): the last column is empty
const calls = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-fetch-'));
  log = path.join(dir, 'log.txt');
  fs.mkdirSync(path.join(dir, 'bin'));
  fs.writeFileSync(path.join(dir, 'bin', 'curl'), CURL_STUB, { mode: 0o755 });
  for (const t of ['unzip', 'ditto', 'open', 'tar']) fs.writeFileSync(path.join(dir, 'bin', t), TOOL_STUB, { mode: 0o755 });
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function fetch(args: string[], extra: Record<string, string> = {}) {
  return spawnSync('/bin/bash', [SCRIPT, ...args], {
    encoding: 'utf8',
    env: {
      PATH: `${path.join(dir, 'bin')}:${process.env.PATH ?? ''}`, HOME: '/home/x', STUB_LOG: log,
      FICUS_LAB_DATA: path.join(dir, 'data'), LAB_MANIFEST: manifest(), LAB_CURL: path.join(dir, 'bin', 'curl'), ...extra,
    },
  });
}

describe('lab/fetch-sample.sh', () => {
  test('parses under bash', () => {
    expect(spawnSync('/bin/bash', ['-n', SCRIPT]).status).toBe(0);
  });

  test('downloads the encoded URL, saves the zip, and records one manifest row with its sha256', () => {
    const r = fetch(['BlackHole (Musminim)']);
    expect(r.status, r.stderr).toBe(0);
    const zip = path.join(dir, 'data', 'samples', 'BlackHole (Musminim).zip');
    expect(fs.existsSync(zip)).toBe(true);
    expect(calls()).toHaveLength(1);
    expect(calls()[0]).toContain('https://github.com/objective-see/malware/raw/main/BlackHole%20%28Musminim%29.zip');
    expect(calls()[0]).toContain('-fL');
    expect(rows()[0]).toBe(HEADER);
    expect(rows()).toHaveLength(2);
    const [family, file, sha, recipe, window, notes] = rows()[1]!.split('\t');
    expect([family, file, recipe, window, notes]).toEqual(['BlackHole (Musminim)', 'BlackHole (Musminim).zip', 'manual', '600', '']);
    const expected = spawnSync('shasum', ['-a', '256', zip], { encoding: 'utf8' }).stdout.split(' ')[0];
    expect(sha).toBe(expected);
  });

  test('a second call neither downloads again nor adds a second row', () => {
    expect(fetch(['Banshee']).status).toBe(0);
    expect(fetch(['Banshee']).status).toBe(0);
    expect(calls()).toHaveLength(1);
    expect(rows()).toHaveLength(2);
  });

  test('a zip that is already on disk but missing from the manifest gets its row without a download', () => {
    fs.mkdirSync(path.join(dir, 'data', 'samples'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'data', 'samples', 'Banshee.zip'), 'PK\u0003\u0004already here');
    expect(fetch(['Banshee']).status).toBe(0);
    expect(calls()).toEqual([]);
    expect(rows()).toHaveLength(2);
  });

  test('names that could leave the folder or act as an option exit 1 and run no curl', () => {
    for (const bad of ['a/b', '..', 'x..y', '-rf']) {
      expect(fetch([bad]).status, bad).toBe(1);
    }
    expect(calls()).toEqual([]);
    expect(fs.existsSync(manifest())).toBe(false);
  });

  test('a download that is not a zip (an HTML error page) is removed and recorded nowhere', () => {
    const r = fetch(['Banshee'], { STUB_CURL_BODY: '<html>404</html>' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('not a zip');
    expect(fs.existsSync(path.join(dir, 'data', 'samples', 'Banshee.zip'))).toBe(false);
    expect(fs.existsSync(path.join(dir, 'data', 'samples', 'Banshee.zip.part'))).toBe(false);
    expect(fs.existsSync(manifest())).toBe(false);
  });

  test('a failed curl leaves no zip, no partial file and no row', () => {
    const r = fetch(['Banshee'], { STUB_CURL_EXIT: '22' });
    expect(r.status).toBe(1);
    expect(fs.existsSync(path.join(dir, 'data', 'samples', 'Banshee.zip'))).toBe(false);
    expect(fs.existsSync(path.join(dir, 'data', 'samples', 'Banshee.zip.part'))).toBe(false);
    expect(fs.existsSync(manifest())).toBe(false);
  });

  test('it never extracts or opens what it fetched', () => {
    expect(fetch(['Banshee']).status).toBe(0);
    expect(calls().filter(c => /^(unzip|ditto|open|tar) /.test(c))).toEqual([]);
  });

  test('no name, or two names, exit 2', () => {
    expect(fetch([]).status).toBe(2);
    expect(fetch(['A', 'B']).status).toBe(2);
  });

  test('a name with a tab is refused, since the manifest is tab-separated', () => {
    expect(fetch(['A\tB']).status).toBe(1);
  });
});
