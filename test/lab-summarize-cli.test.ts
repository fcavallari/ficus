import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

// The command line of the lab's summarizer, built to a temporary folder with the same Vite config `npm run build:lab` uses.
const ROOT = path.resolve(__dirname, '..');
let tmp: string;
let bundle: string;
let runDir: string;

const run = (...args: string[]) => spawnSync('node', [bundle, ...args], { encoding: 'utf8' });

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-sum-cli-'));
  execFileSync(path.join(ROOT, 'node_modules', '.bin', 'vite'), ['build', '-c', 'vite.lab.config.ts', '--outDir', path.join(tmp, 'dist')], { cwd: ROOT, stdio: 'pipe' });
  bundle = path.join(tmp, 'dist', 'lab-summarize.mjs');
  runDir = path.join(tmp, 'run');
  fs.mkdirSync(runDir);
  const synthetic = execFileSync('/bin/bash', [path.join(ROOT, 'scripts', 'ficus-lab.sh'), 'synthetic', '--stdout'], { maxBuffer: 16 << 20 });
  fs.writeFileSync(path.join(runDir, 'capture.jsonl'), synthetic);
  fs.writeFileSync(path.join(runDir, 'meta.json'), JSON.stringify({ family: 'Synthetic Family' }));
  fs.writeFileSync(path.join(tmp, 'expected.tsv'),
    'behavior\tmitre\trule\tsource\nStrips the quarantine flag\tT1553.001\tquarantine-strip\ttest\nEncrypts files\tT1486\t-\ttest\n');
}, 120_000);
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe('lab-summarize.mjs', () => {
  test('prints the findings as a table on stdout and the facts on stderr', () => {
    const r = run(runDir);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout.split('\n')[0]).toBe('queued\trule\tseverity\tprocess\tevidence');
    expect(r.stdout).toContain('\tquarantine-strip\thigh\t');
    expect(r.stderr).toMatch(/events \d+, processes \d+, schema 11, bad lines 0, dropped events \d+, findings \d+/);
  });

  test('with an expected file it writes gap.md, headed with the family from meta.json', () => {
    const r = run(runDir, path.join(tmp, 'expected.tsv'));
    expect(r.status, r.stderr).toBe(0);
    const md = fs.readFileSync(path.join(runDir, 'gap.md'), 'utf8');
    expect(md).toContain('# Synthetic Family');
    expect(md).toContain('Strips the quarantine flag');
    expect(md).toContain('Encrypts files');
    expect(r.stderr).toMatch(/hit 1, miss 0, gap 1, review \d+/);
  });

  test('accepts a capture file as well as a run folder', () => {
    const r = run(path.join(runDir, 'capture.jsonl'));
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('quarantine-strip');
  });

  test('exits 2 on a usage error and 1 on a missing capture or a bad expected file', () => {
    expect(run().status).toBe(2);
    expect(run('--nope', runDir).status).toBe(2);
    expect(run(path.join(tmp, 'nothing-here')).status).toBe(1);
    fs.writeFileSync(path.join(tmp, 'bad.tsv'), 'behavior\tmitre\trule\tsource\nx\tT1\tno-such-rule\ts\n');
    const bad = run(runDir, path.join(tmp, 'bad.tsv'));
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain('no-such-rule');
  });

  test('--under keeps only the findings about that program and its descendants, and says so in gap.md', () => {
    const all = run(runDir);
    const some = run('--under', 'xattr', runDir, path.join(tmp, 'expected.tsv'));
    expect(some.status, some.stderr).toBe(0);
    const lines = some.stdout.trimEnd().split('\n');
    expect(lines.length).toBeGreaterThan(1);
    expect(lines.length).toBeLessThan(all.stdout.trimEnd().split('\n').length);
    expect(some.stderr).toMatch(/kept \d+ of \d+ findings: the process tree under "xattr"/);
    expect(fs.readFileSync(path.join(runDir, 'gap.md'), 'utf8')).toContain('process tree under `xattr`');
    expect(run('--under=xattr', runDir).stdout).toBe(some.stdout);
  });

  test('--under with no value, or with an empty value, is a usage error', () => {
    expect(run(runDir, '--under').status).toBe(2);
    expect(run('--under', '', runDir).status).toBe(2);
  });

  test('says when the capture is of an older schema', () => {
    const old = path.join(tmp, 'old');
    fs.mkdirSync(old);
    const lines = fs.readFileSync(path.join(runDir, 'capture.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => l.replace('"version":11', '"version":10'));
    fs.writeFileSync(path.join(old, 'capture.jsonl'), lines.join('\n') + '\n');
    expect(run(old).stderr).toMatch(/schema 10.*shell-from-pipe/);
  });
});
