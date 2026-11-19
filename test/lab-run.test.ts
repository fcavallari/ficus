import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';

// lab/lab-run.sh runs one sample (or a baseline) end to end. Here it runs against a stub `tart`, a stub launcher and a stub
// isolation check, so no VM starts. The stubs log every call to one file, so the tests can check the order of the steps.
const SCRIPT = path.resolve(__dirname, '..', 'lab', 'lab-run.sh');
const HEADER = 'family\tzip\tsha256\trecipe\twindow_s\tnotes\tsource';
const SHA = 'a'.repeat(64);

// A stub tart. `exec` looks at the command text; STUB_FAIL_ON makes any command containing that text fail; STUB_ES picks how
// the eslogger stand-in behaves: "stay" (prints a few events, then waits to be killed by the pkill call), "short" (prints and exits),
// "big" (prints many bytes, then waits).
const TART = `#!/bin/bash
echo "tart $*" >> "$STUB_LOG"
sub=$1; shift
case "$sub" in
  clone|stop|delete) exit 0 ;;
  exec)
    stdin=0; [ "$1" = "-i" ] && { stdin=1; shift; }
    name=$1; shift
    all="$*"
    if [ -n "\${STUB_FAIL_ON:-}" ] && printf '%s' "$all" | grep -q -- "$STUB_FAIL_ON"; then [ $stdin = 1 ] && cat >/dev/null; exit 1; fi
    if [ $stdin = 1 ]; then cat > /dev/null; exit 0; fi
    case "$all" in
      *pkill*) [ -f "$STUB_DIR/es.pid" ] && kill "$(cat "$STUB_DIR/es.pid")" 2>/dev/null; exit 0 ;;
      *eslogger*)
        echo '{"event":{"exec":{"target":{"executable":{"path":"/usr/bin/true"}}}}}'
        echo '{"event":{"close":{"modified":true,"target":{"path":"/tmp/kept"}}}}'
        echo '{"event":{"close":{"modified":false,"target":{"path":"/tmp/dropped"}}}}'
        case "\${STUB_ES:-stay}" in
          short) exit 0 ;;
          big) i=0; while [ $i -lt 300 ]; do echo '{"event":{"exec":{"pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}}'; i=$((i+1)); done ;;
        esac
        echo $$ > "$STUB_DIR/es.pid"
        exec sleep 300 ;;
      *golden-image*) printf 'macos=26.6.2\\n'; exit 0 ;;
      *gateway.pcap*) printf 'PCAPDATA'; exit 0 ;;
      *guest-collect.sh*) printf '=== btm ===\\nbtm text\\n=== processes ===\\nps text\\n'; exit 0 ;;
    esac
    exit 0 ;;
  *) exit 0 ;;
esac
`;

const NET = `#!/bin/bash
echo "launcher $*" >> "$STUB_LOG"
[ -n "\${STUB_NET_FAIL:-}" ] && exit 1
trap 'echo "launcher stopped" >> "$STUB_LOG"; exit 0' TERM INT
echo READY
while true; do sleep 0.1; done
`;

const ISO = `#!/bin/bash
echo "isolation $*" >> "$STUB_LOG"
[ -n "\${STUB_ISO_FAIL:-}" ] && { echo "FAIL public-ip: stub"; exit 1; }
exit 0
`;

let dir: string;
let data: string;
let log: string;
const started: number[] = [];
const calls = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : []);
const index = (needle: string | RegExp) => calls().findIndex(c => (typeof needle === 'string' ? c.includes(needle) : needle.test(c)));
const runDirs = (name: string) => (fs.existsSync(path.join(data, 'runs', name)) ? fs.readdirSync(path.join(data, 'runs', name)).sort() : []);
const meta = (name: string, id: string) => JSON.parse(fs.readFileSync(path.join(data, 'runs', name, id, 'meta.json'), 'utf8')) as Record<string, unknown>;

function manifestRow(family: string, recipe = 'exec:run.sh', window = '1', zip = `${family}.zip`, source?: string) {
  // The source column is optional: a row without it is an objective-see sample.
  fs.appendFileSync(path.join(dir, 'manifest.tsv'), `${family}\t${zip}\t${SHA}\t${recipe}\t${window}\t${source === undefined ? '' : `\t${source}`}\n`);
  fs.mkdirSync(path.join(data, 'samples'), { recursive: true });
  fs.writeFileSync(path.join(data, 'samples', zip), 'PK\u0003\u0004zip bytes');
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-run-'));
  data = path.join(dir, 'data');
  log = path.join(dir, 'log.txt');
  fs.mkdirSync(path.join(dir, 'bin'));
  fs.writeFileSync(path.join(dir, 'bin', 'tart'), TART, { mode: 0o755 });
  fs.writeFileSync(path.join(dir, 'bin', 'net'), NET, { mode: 0o755 });
  fs.writeFileSync(path.join(dir, 'bin', 'iso'), ISO, { mode: 0o755 });
  fs.writeFileSync(path.join(dir, 'manifest.tsv'), `${HEADER}\n`);
});
afterEach(() => {
  try { process.kill(Number(fs.readFileSync(path.join(dir, 'es.pid'), 'utf8')), 'SIGKILL'); } catch { /* already gone */ }
  for (const p of started) try { process.kill(p, 'SIGKILL'); } catch { /* done */ }
  fs.rmSync(dir, { recursive: true, force: true });
});

const baseEnv = (extra: Record<string, string> = {}) => ({
  PATH: process.env.PATH ?? '', HOME: '/home/x', STUB_LOG: log, STUB_DIR: dir, FICUS_LAB_DATA: data, LAB_MANIFEST: path.join(dir, 'manifest.tsv'),
  LAB_TART: path.join(dir, 'bin', 'tart'), LAB_NET: path.join(dir, 'bin', 'net'), LAB_ISOLATION: path.join(dir, 'bin', 'iso'),
  LAB_POLL: '0.2', LAB_AGENT_SLEEP: '0.1', LAB_ISOLATION_TRIES: '2', LAB_ISOLATION_SLEEP: '0.1', LAB_READY_SLEEP: '0.1', LAB_STOP_SLEEP: '0.1',
  ...extra,
});
function run(args: string[], extra: Record<string, string> = {}, input = '') {
  return spawnSync('/bin/bash', [SCRIPT, ...args], { encoding: 'utf8', env: baseEnv(extra), input, timeout: 60_000 });
}

// Each run takes a second or two (the recording window and the clean-up), and some tests make several: allow for a loaded machine.
describe('lab/lab-run.sh', { timeout: 60_000 }, () => {
  test('parses under bash', () => {
    expect(spawnSync('/bin/bash', ['-n', SCRIPT]).status).toBe(0);
  });

  test('a good run: the steps happen in order, both clones are deleted, and meta.json is complete', () => {
    manifestRow('Banshee');
    const r = run(['Banshee'], { LAB_RUN_ID: 'fixed' });
    expect(r.status, r.stdout + r.stderr).toBe(0);
    const order = [
      index('tart clone lab-gold run-fixed'), index('tart clone lab-gw gw-fixed'), index('launcher --gateway gw-fixed --guest run-fixed'),
      index('isolation run-fixed'), index('eslogger'), index('cat > /tmp/sample.zip'), index('-P infect3d'), index('FICUS_LAB_START fixed'),
      index('FICUS_LAB_END fixed'), index('guest-collect.sh'), index('pkill'), index('gateway.pcap'), index('launcher stopped'),
      index('tart delete run-fixed'),
    ];
    expect(order.every(i => i >= 0), JSON.stringify(order) + calls().join('\n')).toBe(true);
    expect([...order].sort((a, b) => a - b).slice(0, 9)).toEqual(order.slice(0, 9)); // up to the end marker, in this order
    expect(index('tart delete gw-fixed')).toBeGreaterThan(index('launcher stopped'));
    // eslogger is stopped before the post-state is collected, so the collecting does not enter the capture
    expect(index('pkill')).toBeLessThan(index('guest-collect.sh'));
    const m = meta('banshee', 'fixed');
    expect(m).toMatchObject({ run_id: 'fixed', family: 'Banshee', sample_sha256: SHA, source: 'objective-see', guest_image: 'lab-gold', guest_macos: '26.6.2', network_mode: 'fake-internet',
      recipe: 'exec:run.sh', window_s: 1, status: 'ok', eslogger_exited_early: false });
    const capture = path.join(data, 'runs', 'banshee', 'fixed', 'capture.jsonl');
    expect(m.capture_bytes).toBe(fs.statSync(capture).size);
    expect(m.eslogger_events).toEqual(expect.arrayContaining(['exec', 'close', 'xp_malware_detected']));
    expect(m.started_utc).toMatch(/^\d{4}-\d\d-\d\dT/);
    expect(m.ended_utc).toMatch(/^\d{4}-\d\d-\d\dT/);
    expect(fs.readFileSync(path.join(data, 'runs', 'banshee', 'fixed', 'gateway.pcap'), 'utf8')).toBe('PCAPDATA');
    expect(fs.readFileSync(path.join(data, 'runs', 'banshee', 'fixed', 'post-state', 'btm.txt'), 'utf8')).toContain('btm text');
    expect(fs.readFileSync(path.join(data, 'runs', 'banshee', 'fixed', 'post-state', 'processes.txt'), 'utf8')).toContain('ps text');
  });

  test('the capture keeps modified closes and everything else, and drops unmodified closes', () => {
    manifestRow('Banshee');
    expect(run(['Banshee'], { LAB_RUN_ID: 'fixed' }).status).toBe(0);
    const text = fs.readFileSync(path.join(data, 'runs', 'banshee', 'fixed', 'capture.jsonl'), 'utf8');
    expect(text).toContain('/tmp/kept');
    expect(text).not.toContain('/tmp/dropped');
    expect(text).toContain('"exec"');
  });

  test('the start marker is an exec of /usr/bin/true with FICUS_LAB_START and the run id', () => {
    manifestRow('Banshee');
    run(['Banshee'], { LAB_RUN_ID: 'fixed' });
    expect(calls()).toContain('tart exec run-fixed /usr/bin/true FICUS_LAB_START fixed');
    expect(calls()).toContain('tart exec run-fixed /usr/bin/true FICUS_LAB_END fixed');
  });

  test('a failing isolation check stops the run before the zip is copied, and leaves no VM or launcher behind', () => {
    manifestRow('Banshee');
    const r = run(['Banshee'], { LAB_RUN_ID: 'fixed', STUB_ISO_FAIL: '1' });
    expect(r.status).toBe(1);
    expect(index('cat > /tmp/sample.zip')).toBe(-1);
    expect(index('eslogger')).toBe(-1);
    expect(index('launcher stopped')).toBeGreaterThan(-1);
    expect(index('tart delete run-fixed')).toBeGreaterThan(-1);
    expect(index('tart delete gw-fixed')).toBeGreaterThan(-1);
    const m = meta('banshee', 'fixed');
    expect(m.status).toBe('failed');
    expect(String(m.reason)).toMatch(/isolation/i);
  });

  test('a launcher that never says READY stops the run before anything runs in the guest, and both clones go', () => {
    manifestRow('Banshee');
    const r = run(['Banshee'], { LAB_RUN_ID: 'fixed', STUB_NET_FAIL: '1' });
    expect(r.status).toBe(1);
    expect(calls().some(c => c.startsWith('tart exec'))).toBe(false);
    expect(index('tart delete run-fixed')).toBeGreaterThan(-1);
    expect(index('tart delete gw-fixed')).toBeGreaterThan(-1);
    expect(meta('banshee', 'fixed').status).toBe('failed');
  });

  test('a step that fails mid-run still deletes both clones, keeps the capture and records the reason', () => {
    manifestRow('Banshee');
    const r = run(['Banshee'], { LAB_RUN_ID: 'fixed', STUB_FAIL_ON: '-P infect3d' });
    expect(r.status).toBe(1);
    const m = meta('banshee', 'fixed');
    expect(m.status).toBe('failed');
    expect(String(m.reason)).toMatch(/unzip/);
    expect(fs.existsSync(path.join(data, 'runs', 'banshee', 'fixed', 'capture.jsonl'))).toBe(true);
    expect(index('tart delete run-fixed')).toBeGreaterThan(-1);
    expect(index('tart delete gw-fixed')).toBeGreaterThan(-1);
    expect(index('launcher stopped')).toBeGreaterThan(-1);
  });

  test('if eslogger exits by itself the flag is set, the capture is kept and the run still finishes', () => {
    manifestRow('Banshee', 'exec:run.sh', '3');
    const r = run(['Banshee'], { LAB_RUN_ID: 'fixed', STUB_ES: 'short' });
    expect(r.status, r.stderr).toBe(0);
    const m = meta('banshee', 'fixed');
    expect(m.eslogger_exited_early).toBe(true);
    expect(m.capture_bytes).toBeGreaterThan(0);
    expect(String(m.reason)).toMatch(/eslogger/);
  });

  test('a capture larger than --max-bytes aborts the run with status aborted-size and keeps the partial capture', () => {
    manifestRow('Banshee', 'exec:run.sh', '30');
    const r = run(['--max-bytes', '2000', 'Banshee'], { LAB_RUN_ID: 'fixed', STUB_ES: 'big' });
    expect(r.status).toBe(1);
    const m = meta('banshee', 'fixed');
    expect(m.status).toBe('aborted-size');
    expect(m.capture_bytes).toBeGreaterThan(2000);
    expect(index('tart delete run-fixed')).toBeGreaterThan(-1);
  });

  test('an unknown family, a missing zip or a bad name exit 2 and start nothing', () => {
    manifestRow('Banshee');
    for (const args of [['Nope'], ['a/b'], ['..']]) {
      expect(run(args).status, args.join(' ')).toBe(2);
    }
    fs.rmSync(path.join(data, 'samples', 'Banshee.zip'));
    expect(run(['Banshee']).status).toBe(2);
    expect(calls()).toEqual([]);
  });

  test('usage errors exit 2: no arguments, an unknown option, a bad number', () => {
    manifestRow('Banshee');
    expect(run([]).status).toBe(2);
    expect(run(['--nope', 'Banshee']).status).toBe(2);
    expect(run(['--window', 'ten', 'Banshee']).status).toBe(2);
    expect(run(['--window']).status).toBe(2);
    expect(calls()).toEqual([]);
  });

  test('two runs with the same run id get different folders, and the first is never touched', () => {
    manifestRow('Banshee');
    expect(run(['Banshee'], { LAB_RUN_ID: 'same' }).status).toBe(0);
    const before = fs.readFileSync(path.join(data, 'runs', 'banshee', 'same', 'meta.json'), 'utf8');
    expect(run(['Banshee'], { LAB_RUN_ID: 'same' }).status).toBe(0);
    expect(runDirs('banshee')).toEqual(['same', 'same-2']);
    expect(fs.readFileSync(path.join(data, 'runs', 'banshee', 'same', 'meta.json'), 'utf8')).toBe(before);
  });

  test('--baseline idle records the guest alone: no manifest, no zip, family baseline-idle', () => {
    const r = run(['--baseline', 'idle', '--window', '1'], { LAB_RUN_ID: 'fixed', LAB_MANIFEST: path.join(dir, 'does-not-exist.tsv') });
    expect(r.status, r.stderr).toBe(0);
    expect(index('cat > /tmp/sample.zip')).toBe(-1);
    expect(index('guest-benign.sh')).toBe(-1);
    expect(index('FICUS_LAB_START fixed')).toBeGreaterThan(-1);
    expect(meta('baseline-idle', 'fixed')).toMatchObject({ family: 'baseline-idle', sample_sha256: '', recipe: 'none', status: 'ok', window_s: 1 });
  });

  test('--baseline benign copies the activity script into the guest and runs it after the start marker', () => {
    const r = run(['--baseline', 'benign', '--window', '1'], { LAB_RUN_ID: 'fixed' });
    expect(r.status, r.stderr).toBe(0);
    expect(index('cat > /tmp/guest-benign.sh')).toBeGreaterThan(index('FICUS_LAB_START fixed'));
    expect(index('bash /tmp/guest-benign.sh')).toBeGreaterThan(index('cat > /tmp/guest-benign.sh'));
    expect(index('bash /tmp/guest-benign.sh')).toBeLessThan(index('FICUS_LAB_END fixed'));
    expect(index('cat > /tmp/sample.zip')).toBe(-1);
    expect(meta('baseline-benign', 'fixed')).toMatchObject({ family: 'baseline-benign', recipe: 'script:guest-benign.sh', status: 'ok' });
    expect(fs.existsSync(path.join(data, 'runs', 'baseline-benign', 'fixed', 'benign.log'))).toBe(true);
  });

  test('the baseline windows default to 600 s (idle) and 120 s (benign)', () => {
    expect(run(['--baseline', 'idle'], { LAB_RUN_ID: 'a', STUB_NET_FAIL: '1' }).status).toBe(1); // stops early; only the recorded window matters
    expect(meta('baseline-idle', 'a').window_s).toBe(600);
    expect(run(['--baseline', 'benign'], { LAB_RUN_ID: 'b', STUB_NET_FAIL: '1' }).status).toBe(1);
    expect(meta('baseline-benign', 'b').window_s).toBe(120);
  });

  test('a benign script that cannot run fails the run', () => {
    const r = run(['--baseline', 'benign', '--window', '1'], { LAB_RUN_ID: 'fixed', STUB_FAIL_ON: 'bash /tmp/guest-benign.sh' });
    expect(r.status).toBe(1);
    expect(String(meta('baseline-benign', 'fixed').reason)).toMatch(/benign script/);
    expect(index('tart delete run-fixed')).toBeGreaterThan(-1);
  });

  test('a baseline takes no family, and an unknown baseline or a missing value is a usage error', () => {
    manifestRow('Banshee');
    expect(run(['--baseline', 'idle', 'Banshee']).status).toBe(2);
    expect(run(['--baseline', 'nope']).status).toBe(2);
    expect(run(['--baseline']).status).toBe(2);
    expect(calls()).toEqual([]);
  });

  test('an objective-see row (the source column empty or absent) is opened with unzip and the password infect3d', () => {
    manifestRow('Banshee', 'exec:run.sh', '1', 'Banshee.zip', 'objective-see');
    expect(run(['Banshee'], { LAB_RUN_ID: 'a' }).status).toBe(0);
    expect(calls().some(c => c.includes('/usr/bin/unzip') && c.includes('-P infect3d'))).toBe(true);
    expect(calls().some(c => c.includes('7zz'))).toBe(false);
  });

  test('a bazaar row is opened with 7zz and the password infected, never with unzip, and meta.json says bazaar', () => {
    manifestRow('Bazaar-AMOS-fdcd5d21', 'manual', '1', 'Bazaar-AMOS-fdcd5d21.zip', 'bazaar');
    const r = run(['Bazaar-AMOS-fdcd5d21'], { LAB_RUN_ID: 'fixed' }, '\n');
    expect(r.status, r.stderr).toBe(0);
    expect(calls().some(c => c.includes('7zz x') && c.includes('-pinfected'))).toBe(true);
    expect(calls().some(c => c.includes('/usr/bin/unzip') || c.includes('infect3d'))).toBe(false);
    expect(index('7zz x')).toBeLessThan(index('FICUS_LAB_START fixed'));
    expect(meta('bazaar-amos-fdcd5d21', 'fixed')).toMatchObject({ source: 'bazaar', status: 'ok' });
  });

  test('a bazaar zip that 7zz cannot open (or a guest without 7zz) fails the run and says to use the main image', () => {
    manifestRow('Bazaar-X', 'manual', '1', 'Bazaar-X.zip', 'bazaar');
    const r = run(['Bazaar-X'], { LAB_RUN_ID: 'fixed', STUB_FAIL_ON: '7zz x' }, '\n');
    expect(r.status).toBe(1);
    expect(String(meta('bazaar-x', 'fixed').reason)).toMatch(/7zz.*main image/);
    expect(index('tart delete run-fixed')).toBeGreaterThan(-1);
  });

  test('an unknown source in the manifest is refused with exit 2 and starts nothing', () => {
    manifestRow('Odd', 'exec:run.sh', '1', 'Odd.zip', 'carrier-pigeon');
    const r = run(['Odd']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('carrier-pigeon');
    expect(calls()).toEqual([]);
  });

  test('--image clones that guest image instead of lab-gold, and meta.json records it', () => {
    manifestRow('Banshee');
    const r = run(['--image', 'lab-gold-lean', 'Banshee'], { LAB_RUN_ID: 'fixed' });
    expect(r.status, r.stderr).toBe(0);
    expect(calls()).toContain('tart clone lab-gold-lean run-fixed');
    expect(calls()).not.toContain('tart clone lab-gold run-fixed');
    expect(meta('banshee', 'fixed').guest_image).toBe('lab-gold-lean');
  });

  test('the image is lab-gold by default, LAB_GUEST_IMAGE changes the default, and the flag beats the variable', () => {
    manifestRow('Banshee');
    expect(run(['Banshee'], { LAB_RUN_ID: 'a' }).status).toBe(0);
    expect(calls()).toContain('tart clone lab-gold run-a');
    expect(run(['Banshee'], { LAB_RUN_ID: 'b', LAB_GUEST_IMAGE: 'from-env' }).status).toBe(0);
    expect(calls()).toContain('tart clone from-env run-b');
    expect(run(['--image', 'from-flag', 'Banshee'], { LAB_RUN_ID: 'c', LAB_GUEST_IMAGE: 'from-env' }).status).toBe(0);
    expect(calls()).toContain('tart clone from-flag run-c');
    expect(calls()).not.toContain('tart clone from-env run-c');
  });

  test('--image works with a baseline too', () => {
    expect(run(['--baseline', 'idle', '--window', '1', '--image', 'lab-gold-lean'], { LAB_RUN_ID: 'fixed' }).status).toBe(0);
    expect(meta('baseline-idle', 'fixed').guest_image).toBe('lab-gold-lean');
  });

  test('--image with no value, an empty one, an option, a path or a name with a space is a usage error and starts nothing', () => {
    manifestRow('Banshee');
    expect(run(['Banshee', '--image']).status).toBe(2);
    for (const bad of ['', '-x', 'ghcr.io/org/img:latest', 'a/b', 'a b']) {
      expect(run(['--image', bad, 'Banshee']).status, JSON.stringify(bad)).toBe(2);
    }
    expect(run(['Banshee'], { LAB_GUEST_IMAGE: 'bad/name' }).status).toBe(2);
    expect(calls()).toEqual([]);
  });

  test('--keep-vm leaves both clones in place', () => {
    manifestRow('Banshee');
    expect(run(['--keep-vm', 'Banshee'], { LAB_RUN_ID: 'fixed' }).status).toBe(0);
    expect(index('tart delete')).toBe(-1);
  });

  test('--window overrides the manifest window', () => {
    manifestRow('Banshee', 'exec:run.sh', '900');
    expect(run(['--window', '1', 'Banshee'], { LAB_RUN_ID: 'fixed' }).status).toBe(0);
    expect(meta('banshee', 'fixed').window_s).toBe(1);
  });

  test('the recipe kinds run the right command in the guest', () => {
    const cases: Array<[string, RegExp]> = [
      ['app:Foo.app', /open "\$HOME\/Downloads\/sample\/\$1"/],
      ['pkg:Foo.pkg', /installer -pkg/],
      ['dmg:Foo.dmg', /hdiutil attach/],
      ['exec:bin/foo', /p=\.\/\$1 ;; esac && chmod \+x "\$p" && \(nohup "\$p"/], // ./ for a bare name: nohup would search PATH
    ];
    for (const [recipe, re] of cases) {
      fs.rmSync(log, { force: true });
      fs.writeFileSync(path.join(dir, 'manifest.tsv'), `${HEADER}\n`);
      manifestRow('Fam', recipe);
      expect(run(['Fam'], { LAB_RUN_ID: recipe.replace(/\W/g, '') }).status, recipe).toBe(0);
      expect(calls().some(c => re.test(c) && c.includes(recipe.split(':')[1]!)), recipe + '\n' + calls().join('\n')).toBe(true);
    }
  });

  test('a manifest row whose recipe is "manual" behaves like --manual: a guest window, no launch, wait for Enter', () => {
    manifestRow('Fam', 'manual');
    const r = run(['Fam'], { LAB_RUN_ID: 'fixed' }, '\n');
    expect(r.status, r.stderr).toBe(0);
    expect(calls().some(c => c.startsWith('launcher') && c.includes('--guest-window'))).toBe(true);
    expect(calls().some(c => c.includes('nohup') || c.includes('installer') || c.includes('hdiutil'))).toBe(false);
    expect(index('-P infect3d')).toBeGreaterThan(-1); // still unzipped in the guest
    expect(meta('fam', 'fixed')).toMatchObject({ status: 'ok', recipe: 'manual' });
  });

  test('an unknown recipe kind fails the run with a clear reason', () => {
    manifestRow('Fam', 'teleport:x');
    const r = run(['Fam'], { LAB_RUN_ID: 'fixed' });
    expect(r.status).toBe(1);
    expect(String(meta('fam', 'fixed').reason)).toMatch(/recipe/);
  });

  test('--manual opens a guest window, skips the recipe and waits for Enter', async () => {
    manifestRow('Banshee', 'exec:run.sh', '600');
    const child = spawn('/bin/bash', [SCRIPT, '--manual', 'Banshee'], { env: baseEnv({ LAB_RUN_ID: 'fixed' }), stdio: ['pipe', 'pipe', 'pipe'] });
    started.push(child.pid!);
    const done = new Promise<number | null>(res => child.on('exit', c => res(c)));
    const end = Date.now() + 20_000;
    while (index('FICUS_LAB_START') < 0 && Date.now() < end) await new Promise(r => setTimeout(r, 100));
    expect(calls().some(c => c.startsWith('launcher') && c.includes('--guest-window'))).toBe(true);
    expect(calls().some(c => c.includes('nohup'))).toBe(false); // the recipe is not run
    expect(index('guest-collect.sh')).toBe(-1); // still waiting
    child.stdin.write('\n');
    expect(await done).toBe(0);
    expect(index('guest-collect.sh')).toBeGreaterThan(-1);
    expect(meta('banshee', 'fixed').status).toBe('ok');
  });
});
