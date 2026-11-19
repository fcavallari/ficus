import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

// lab/lib.sh is sourced by the other lab scripts. Each test runs one of its functions in a fresh /bin/bash (macOS's 3.2).
const LIB = path.resolve(__dirname, '..', 'lab', 'lib.sh');

function call(fn: string, ...args: string[]) {
  const r = spawnSync('/bin/bash', ['-c', `. "${LIB}"; ${fn} "$@"`, '_', ...args], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: '/home/x' } });
  return { status: r.status, out: r.stdout, err: r.stderr };
}

describe('lab/lib.sh', () => {
  test('parses under bash', () => {
    expect(spawnSync('/bin/bash', ['-n', LIB]).status).toBe(0);
  });

  test('lab_slug makes a lowercase dashed name', () => {
    expect(call('lab_slug', 'BlackHole (Musminim)').out.trim()).toBe('blackhole-musminim');
    expect(call('lab_slug', 'Crisis (Morcut)').out.trim()).toBe('crisis-morcut');
    expect(call('lab_slug', 'AtomicStealer').out.trim()).toBe('atomicstealer');
    expect(call('lab_slug', '  Odd -- name!! ').out.trim()).toBe('odd-name');
  });

  test('lab_sample_url percent-encodes the family name', () => {
    expect(call('lab_sample_url', 'BlackHole (Musminim)').out.trim())
      .toBe('https://github.com/objective-see/malware/raw/main/BlackHole%20%28Musminim%29.zip');
    expect(call('lab_sample_url', 'AtomicStealer').out.trim()).toBe('https://github.com/objective-see/malware/raw/main/AtomicStealer.zip');
    expect(call('lab_sample_url', 'Chilly, Hell').out.trim()).toContain('Chilly%2C%20Hell.zip');
  });

  test('lab_events is one line holding the Ficus set and the research set, and none of the noisy events', () => {
    const r = call('lab_events');
    expect(r.status).toBe(0);
    expect(r.out.trim().split('\n')).toHaveLength(1);
    const events = r.out.trim().split(' ');
    for (const want of ['fork', 'exec', 'exit', 'create', 'rename', 'unlink', 'setextattr', 'btm_launch_item_add', 'btm_launch_item_remove',
      'close', 'signal', 'tcc_modify', 'xp_malware_detected', 'openssh_login']) expect(events, want).toContain(want);
    for (const noisy of ['write', 'open', 'lookup', 'stat', 'readdir', 'getattrlist', 'mmap', 'mprotect']) expect(events, noisy).not.toContain(noisy);
    expect(new Set(events).size).toBe(events.length);
  });

  test('every event in events.txt is a real eslogger event on this Mac', () => {
    const listed = spawnSync('eslogger', ['--list-events'], { encoding: 'utf8' });
    if (listed.status !== 0) return; // not macOS, or no eslogger: nothing to compare with
    const real = new Set(listed.stdout.split(/\s+/).filter(Boolean));
    expect(call('lab_events').out.trim().split(' ').filter(e => !real.has(e))).toEqual([]);
  });

  test('lab_check_name accepts a family name and refuses anything that could leave the folder or act as an option', () => {
    expect(call('lab_check_name', 'AtomicStealer').status).toBe(0);
    expect(call('lab_check_name', 'BlackHole (Musminim)').status).toBe(0);
    for (const bad of ['', 'a/b', '..', 'x..y', '-rf', 'a\nb', 'a\tb']) {
      const r = call('lab_check_name', bad);
      expect(r.status, JSON.stringify(bad)).not.toBe(0);
      expect(r.err, JSON.stringify(bad)).toContain('error');
    }
  });

  test('lab_run_id is the slug, a UTC time and the process id; two processes differ', () => {
    const a = call('lab_run_id', 'Banshee').out.trim();
    expect(a).toMatch(/^banshee-\d{8}T\d{6}Z-\d+$/);
    expect(call('lab_run_id', 'Banshee').out.trim()).not.toBe(a);
  });

  test('lab_data_dir honours FICUS_LAB_DATA and otherwise ends in ficus-lab-data', () => {
    const r = spawnSync('/bin/bash', ['-c', `. "${LIB}"; lab_data_dir`], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: '/home/x', FICUS_LAB_DATA: '/x y' } });
    expect(r.stdout.trim()).toBe('/x y');
    expect(call('lab_data_dir').out.trim()).toBe('/home/x/WORK/investigation/MacOSThreats/ficus-lab-data');
  });

  test('lab_sha256 prints the SHA-256 of a file', () => {
    const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lab-lib-')), 'x');
    fs.writeFileSync(f, 'abc');
    expect(call('lab_sha256', f).out.trim()).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    fs.rmSync(path.dirname(f), { recursive: true, force: true });
  });

  test('lab_die prints the message to stderr and exits 1', () => {
    const r = call('lab_die', 'it broke');
    expect(r.status).toBe(1);
    expect(r.err).toContain('error: it broke');
    expect(r.out).toBe('');
  });
});
