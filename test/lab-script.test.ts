import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';

// scripts/gameleira-lab.sh writes a teaching capture. Run with /bin/bash so macOS's bash 3.2 is what gets tested there.
const SCRIPT = path.resolve(__dirname, '..', 'scripts', 'gameleira-lab.sh');

function runLab(...args: string[]): string {
  return execFileSync('/bin/bash', [SCRIPT, ...args], { maxBuffer: 16 << 20, stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8');
}

describe('the script', () => {
  test('synthetic --stdout is a clean schema 11 capture', () => {
    const m = buildModel(runLab('synthetic', '--stdout').split('\n'));
    expect(m.stats.badLines).toBe(0);
    expect(m.stats.versions).toEqual([11]);
    expect(m.stats.events).toBeGreaterThan(0);
  });
  test('synthetic output is the same on every run', () => {
    expect(runLab('synthetic', '--stdout')).toBe(runLab('synthetic', '--stdout'));
  });
  test('json_str escapes quotes, backslashes and control characters', () => {
    const out = execFileSync('/bin/bash', ['-c', `GAMELEIRA_LAB_SOURCE_ONLY=1 . "${SCRIPT}"; json_str "$1"`, '_', 'a"b\\c\td\ne\u0001'])
      .toString('utf8');
    expect(JSON.parse(out)).toBe('a"b\\c\td\ne\u0001');
  });
  test('-o writes the capture and the answer key, creating the folder', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-'));
    try {
      runLab('synthetic', '-o', path.join(dir, 'sub', 'x.jsonl'));
      expect(fs.readFileSync(path.join(dir, 'sub', 'x.jsonl'), 'utf8')).toBe(runLab('synthetic', '--stdout'));
      expect(fs.readFileSync(path.join(dir, 'sub', 'x.answers.tsv'), 'utf8')).toBe(runLab('synthetic', '--answers'));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  test('an unknown argument exits 2', () => {
    let status: number | null = null;
    try {
      runLab('synthetic', '--nope');
    } catch (e) {
      status = (e as { status: number }).status;
    }
    expect(status).toBe(2);
  });
});
