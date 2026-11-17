import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { expect, test } from 'vitest';
import { cleanedCapturePath, ficusPaths } from '../src/mcp/home';
import { CLEANER_FILES, recordCommand } from '../src/mcp/record';
import { Workspace } from '../src/mcp/workspace';
import { fixture } from './fixtures';

const SCRIPTS = path.resolve(__dirname, '../scripts');
const NOW = new Date(2026, 10, 17, 10, 30, 12);

function freshPaths() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-record-'));
  return ficusPaths({ HOME: tmp, FICUS_HOME: path.join(tmp, 'Application Support', 'Ficus') } as NodeJS.ProcessEnv);
}

/** Paths in the default place under HOME, as a person who has not set FICUS_HOME has them. */
function defaultPaths() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-record-'));
  return ficusPaths({ HOME: tmp } as NodeJS.ProcessEnv);
}

test('the command records to captures/ with absolute quoted paths', () => {
  const p = defaultPaths();
  const r = recordCommand(p, SCRIPTS, { domains: ['example.com'] }, NOW);
  expect(r.capture).toBe('capture-2026-11-17-103012.cleaned.jsonl');
  expect(r.command).toBe(`"${p.bin}/ficus-clean.sh" record -o "${p.captures}/${r.capture}" -t 600 -D example.com`);
  expect(r.command).not.toContain('~');
});

test('with FICUS_HOME the command tells the cleaner where the keys go, so the guard finds them', () => {
  const p = freshPaths();
  const r = recordCommand(p, SCRIPTS, {}, NOW);
  expect(r.command).toBe(
    `FICUS_CLEAN_KEY_DIR="${p.keys}" "${p.bin}/ficus-clean.sh" record -o "${p.captures}/${r.capture}" -t 600`,
  );
  expect(r.command).not.toContain(' -k ');
});

test('a keys folder with a character unsafe in quotes is refused', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-record-'));
  const p = ficusPaths({ HOME: tmp, FICUS_HOME: path.join(tmp, 'a$b') } as NodeJS.ProcessEnv);
  expect(() => recordCommand(p, SCRIPTS, {}, NOW)).toThrow(RangeError);
  const bang = ficusPaths({ HOME: tmp, FICUS_HOME: path.join(tmp, 'a!b') } as NodeJS.ProcessEnv);
  expect(() => recordCommand(bang, SCRIPTS, {}, NOW)).toThrow(RangeError);
});

const JQ = '/usr/bin/jq';
// The handed-out command, run as the person would run it (no sudo here: the cleaner's stand-in recorder prints the
// synthetic lab and ends), must leave a capture and a key where the guard looks, with FICUS_HOME set.
test.skipIf(!fs.existsSync(JQ))('the handed-out command, run with FICUS_HOME set, makes a capture the guard accepts', async () => {
  const p = freshPaths();
  const r = recordCommand(p, SCRIPTS, {}, NOW);
  const run = spawnSync('/bin/bash', ['-c', r.command], {
    maxBuffer: 64 << 20,
    env: {
      ...process.env,
      HOME: path.dirname(p.home), // not where the keys are: only FICUS_CLEAN_KEY_DIR in the command can lead the cleaner to p.keys
      FICUS_CLEAN_NO_LOCAL_SEEDS: '1',
      FICUS_CLEAN_FAKE_OS: 'Darwin',
      FICUS_CLEAN_RECORDER: `cat '${fixture('synthetic-lab.jsonl')}'`,
    },
  });
  expect(run.status, run.stderr.toString('utf8').replace(/^short or common account names: .*$/gm, '')).toBe(0);
  const file = path.join(p.captures, r.capture);
  expect(fs.existsSync(file)).toBe(true);
  expect(fs.existsSync(path.join(p.keys, `${r.capture}.key.tsv`))).toBe(true);
  // Just written: refused as still recording. Ten seconds on: accepted.
  expect(() => cleanedCapturePath(p, r.capture)).toThrow(/still being recorded/);
  const past = (Date.now() - 60_000) / 1000;
  fs.utimesSync(file, past, past);
  expect(cleanedCapturePath(p, r.capture)).toBe(file);
  const view = await new Workspace(p, () => NOW).analyze(r.capture);
  expect(view.rows.length).toBeGreaterThan(0);
});

test('the cleaner is copied to bin/, executable, and replaced when it differs', () => {
  const p = freshPaths();
  recordCommand(p, SCRIPTS, {}, NOW);
  const same = () => {
    for (const f of CLEANER_FILES) {
      expect(fs.readFileSync(path.join(p.bin, f)).equals(fs.readFileSync(path.join(SCRIPTS, f)))).toBe(true);
    }
  };
  same();
  expect(fs.statSync(path.join(p.bin, 'ficus-clean.sh')).mode & 0o111).toBeTruthy();
  for (const f of CLEANER_FILES) fs.writeFileSync(path.join(p.bin, f), 'junk');
  recordCommand(p, SCRIPTS, {}, NOW);
  same();
  expect(fs.statSync(path.join(p.bin, 'ficus-clean.sh')).mode & 0o111).toBeTruthy();
});

test('captures/ is created', () => {
  const p = freshPaths();
  expect(fs.existsSync(p.captures)).toBe(false);
  recordCommand(p, SCRIPTS, {}, NOW);
  expect(fs.statSync(p.captures).isDirectory()).toBe(true);
});

test.each([59, 1801, 1.5, NaN])('seconds %s is refused', (s) => {
  expect(() => recordCommand(freshPaths(), SCRIPTS, { seconds: s }, NOW)).toThrow(RangeError);
});

test.each([60, 1800])('seconds %s is allowed', (s) => {
  expect(recordCommand(freshPaths(), SCRIPTS, { seconds: s }, NOW).command).toContain(` -t ${s}`);
});

test.each(['x.com; rm -rf ~', '$(id)', '`id`', 'a b.com', '"x.com"', '-D', '', 'x'.repeat(254), 'x.com\n', 'x.com\r', 'x.com\u0000', '-a.com', 'a.'.repeat(127) + 'com'])('domain %j is refused', (d) => {
  expect(() => recordCommand(freshPaths(), SCRIPTS, { domains: [d] }, NOW)).toThrow(RangeError);
});

test('a refused domain writes nothing', () => {
  const p = freshPaths();
  expect(() => recordCommand(p, SCRIPTS, { domains: ['$(id)'] }, NOW)).toThrow(RangeError);
  expect(fs.existsSync(p.home)).toBe(false);
});

test('several domains each get -D', () => {
  const p = freshPaths();
  const r = recordCommand(p, SCRIPTS, { domains: ['a.example', 'b-c.example.org'] }, NOW);
  expect(r.command.endsWith(' -t 600 -D a.example -D b-c.example.org')).toBe(true);
});

test('instructions mention Terminal, the Mac password, Full Disk Access and waiting for the summary', () => {
  const text = recordCommand(freshPaths(), SCRIPTS, { seconds: 300 }, NOW).instructions.join('\n');
  expect(text).toContain('Terminal');
  expect(text).toMatch(/Mac password/);
  expect(text).toContain('Full Disk Access');
  expect(text).toContain('eslogger stopped before recording anything');
  expect(text).toContain('5 minutes');
  expect(text).toMatch(/summary/);
});

test('instructions say macOS 15 is needed and that a stopped or failed recording needs a new command', () => {
  const text = recordCommand(freshPaths(), SCRIPTS, {}, NOW).instructions.join('\n');
  expect(text).toMatch(/macOS 15 or later/);
  expect(text).toMatch(/stopped early or fails/);
  expect(text).toMatch(/new command/);
  expect(text).toMatch(/key already exists/);
});
