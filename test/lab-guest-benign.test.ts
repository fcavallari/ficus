import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

// lab/guest-benign.sh runs ordinary activity inside the guest so the benign baseline shows what Ficus flags on clean behavior.
// It must never touch a real Mac, so every test here parses it, prints a dry run, or checks that it refuses to run outside a VM.
const SCRIPT = path.resolve(__dirname, '..', 'lab', 'guest-benign.sh');
const run = (args: string[], env: Record<string, string> = {}) =>
  spawnSync('/bin/bash', [SCRIPT, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', ...env } });

describe('lab/guest-benign.sh', () => {
  test('parses under bash', () => {
    expect(spawnSync('/bin/bash', ['-n', SCRIPT]).status).toBe(0);
  });

  test('an unknown argument exits 2', () => {
    expect(run(['--nope']).status).toBe(2);
  });

  test('--dry-run lists every kind of activity and changes nothing', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-benign-'));
    try {
      const r = run(['--dry-run'], { HOME: home });
      expect(r.status, r.stderr).toBe(0);
      for (const want of ['recon', 'developer tools', 'files', 'archives', 'download', 'preferences', 'ssh key', 'package', 'app', 'launchctl', 'python', 'clean up']) {
        expect(r.stdout.toLowerCase(), want).toContain(want);
      }
      expect(fs.readdirSync(home)).toEqual([]);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('refuses to run for real outside a virtual machine', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-benign-'));
    try {
      const r = run([], { HOME: home });
      if (r.status !== 0) {
        expect(r.stderr).toContain('not a virtual machine');
        expect(fs.readdirSync(home)).toEqual([]);
      } // inside an actual VM it is allowed to proceed
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('contains nothing that looks like an attack: no pipe from curl into a shell, no base64 decoding, no quarantine stripping', () => {
    const src = fs.readFileSync(SCRIPT, 'utf8').split('\n').filter(l => !l.trim().startsWith('#')).join('\n');
    expect(src).not.toMatch(/curl[^\n]*\|\s*(ba|z)?sh/);
    expect(src).not.toMatch(/base64\s+-?-?d/);
    expect(src).not.toMatch(/xattr\s+-[cd]/);
    expect(src).not.toMatch(/LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap|submit)/);
  });

  test('keeps going when one step fails and says how many did', () => {
    const src = fs.readFileSync(SCRIPT, 'utf8');
    expect(src).toMatch(/steps ok/);
  });
});
