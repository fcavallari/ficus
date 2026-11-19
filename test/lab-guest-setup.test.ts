import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

// lab/guest-setup.sh prepares the Tart guest. It must never touch a real Mac, so every test here either only prints
// (--dry-run) or plants bait under a temporary HOME (--bait-only with FICUS_LAB_ASSUME_VM=1, which skips every system step).
const SCRIPT = path.resolve(__dirname, '..', 'lab', 'guest-setup.sh');

function run(args: string[], env: Record<string, string> = {}) {
  return spawnSync('/bin/bash', [SCRIPT, ...args], { env: { PATH: process.env.PATH ?? '', ...env }, encoding: 'utf8' });
}

function walk(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
}

describe('lab/guest-setup.sh', () => {
  test('parses under bash', () => {
    execFileSync('/bin/bash', ['-n', SCRIPT]);
  });

  test('--help exits 0 and says it runs inside the guest', () => {
    const r = run(['--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('inside the Tart guest');
  });

  test('an unknown argument exits 2', () => {
    expect(run(['--nope']).status).toBe(2);
  });

  test('--dry-run changes nothing and lists the steps', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-guest-'));
    try {
      const r = run(['--dry-run'], { HOME: home });
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('Rosetta');
      expect(r.stdout).toContain('Chrome Safe Storage');
      expect(r.stdout).toContain('/etc/lab-golden-image');
      expect(fs.readdirSync(home)).toEqual([]);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('refuses to change anything when this is not a VM', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-guest-'));
    try {
      // No FICUS_LAB_ASSUME_VM: on a real Mac or a CI Linux box this must stop before any step.
      const r = run(['--bait-only'], { HOME: home });
      if (r.status !== 0) {
        expect(r.stderr).toContain('not a virtual machine');
        expect(fs.readdirSync(home)).toEqual([]);
      } // Run inside an actual VM, it is allowed to proceed; the other tests cover that path.
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('--bait-only plants the stealer targets, every file marked LAB-BAIT, and is safe to run twice', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-guest-'));
    try {
      const env = { HOME: home, FICUS_LAB_ASSUME_VM: '1' };
      const first = run(['--bait-only'], env);
      expect(first.status, first.stderr).toBe(0);
      const files = walk(home);
      const rel = files.map(f => path.relative(home, f));
      for (const want of [
        'Library/Application Support/Google/Chrome/Default/Login Data',
        'Library/Application Support/Google/Chrome/Default/Cookies',
        'Library/Application Support/Google/Chrome/Local State',
        'Library/Application Support/Firefox/Profiles/lab.default/key4.db',
        'Library/Application Support/Firefox/Profiles/lab.default/logins.json',
        'Library/Application Support/Exodus/exodus.wallet/seed.seco',
        '.aws/credentials',
        'Documents/passwords.txt',
      ]) expect(rel, want).toContain(want);
      for (const f of files) expect(fs.readFileSync(f).includes('LAB-BAIT'), f).toBe(true);
      const second = run(['--bait-only'], env);
      expect(second.status, second.stderr).toBe(0);
      expect(second.stdout).toContain('exists');
      expect(walk(home).sort()).toEqual(files.sort());
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
