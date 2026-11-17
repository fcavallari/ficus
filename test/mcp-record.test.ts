import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { expect, test } from 'vitest';
import { ficusPaths } from '../src/mcp/home';
import { CLEANER_FILES, recordCommand } from '../src/mcp/record';

const SCRIPTS = path.resolve(__dirname, '../scripts');
const NOW = new Date(2026, 10, 17, 10, 30, 12);

function freshPaths() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-record-'));
  return ficusPaths({ HOME: tmp, FICUS_HOME: path.join(tmp, 'Application Support', 'Ficus') } as NodeJS.ProcessEnv);
}

test('the command records to captures/ with absolute quoted paths', () => {
  const p = freshPaths();
  const r = recordCommand(p, SCRIPTS, { domains: ['example.com'] }, NOW);
  expect(r.capture).toBe('capture-2026-11-17-103012.cleaned.jsonl');
  expect(r.command).toBe(`"${p.bin}/ficus-clean.sh" record -o "${p.captures}/${r.capture}" -t 600 -D example.com`);
  expect(r.command).not.toContain('~');
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

test.each(['x.com; rm -rf ~', '$(id)', '`id`', 'a b.com', '"x.com"', '-D', '', 'x'.repeat(254)])('domain %j is refused', (d) => {
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
