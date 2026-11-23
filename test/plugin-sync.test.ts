import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { DEFAULT_TARGET, replaceBlock, replaceTooling, renderBlock, scriptEntries, stampOf, toolingDirs } from '../scripts/gen-indicators.mjs';

/**
 * Ficus owns src/rules/indicators.json and the list of tooling folders in src/rules/locations.ts; the am-i-pwned plugin
 * (Automattic/claude-code-plugins, plugins/am-i-pwned) holds generated copies. These tests keep the copies from drifting.
 * The sync test runs wherever a plugin checkout exists (the default path, or $AM_I_PWNED_DIR) and is skipped where none does,
 * such as the GitHub Pages build; .githooks/pre-commit covers the commit that changes a source.
 */
const TARGET = process.env.AM_I_PWNED_DIR ? path.resolve(process.env.AM_I_PWNED_DIR) : DEFAULT_TARGET;
const present = fs.existsSync(path.join(TARGET, 'lib/indicators.sh'));
const GEN = path.resolve(__dirname, '..', 'scripts', 'gen-indicators.mjs');

describe.skipIf(!present)('the am-i-pwned plugin copy', () => {
  test('is what indicators.json and locations.ts generate (run: node scripts/gen-indicators.mjs, then commit in the plugin repo)', () => {
    const r = spawnSync('node', [GEN, '--check'], { encoding: 'utf8', env: { ...process.env, AM_I_PWNED_DIR: TARGET } });
    expect(r.stderr, 'the plugin copy is behind').toBe('');
    expect(r.status).toBe(0);
  });

  test('is committed there too: the generated files as the plugin repo has them at HEAD are current', () => {
    const prefix = spawnSync('git', ['-C', TARGET, 'rev-parse', '--show-prefix'], { encoding: 'utf8' });
    if (prefix.status !== 0) return;   // not a git checkout (an export): nothing to compare
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-head-'));
    try {
      for (const f of ['lib/indicators.sh', 'lib/signatures.sh', 'references/known-indicators.md']) {
        const show = spawnSync('git', ['-C', TARGET, 'show', `HEAD:${prefix.stdout.trim()}${f}`], { encoding: 'utf8' });
        expect(show.status, `${f} is not committed in the claude-code-plugins repo: commit the generated copy there`).toBe(0);
        fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
        fs.writeFileSync(path.join(dir, f), show.stdout);
      }
      const r = spawnSync('node', [GEN, '--check'], { encoding: 'utf8', env: { ...process.env, AM_I_PWNED_DIR: dir } });
      expect(r.stderr, 'the committed copy in the plugin repo is behind: run the generator and commit there').toBe('');
      expect(r.status).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('the generator', () => {
  const data = { about: 'a', updated: 'x', pathSyntax: 'p', families: [{ name: 'F', actor: 'a', attribution: 'b', summary: 's', indicators: [{ kind: 'team-id', value: 'ABC', severity: 'high', confidence: 'high', source: 'u' }] }] };

  test('stamps a copy with the hash of its source, so any change to the source shows', () => {
    expect(stampOf('a')).not.toBe(stampOf('b'));
    expect(renderBlock(data, stampOf('a'))).toContain(`sha256 ${stampOf('a')}`);
    expect(renderBlock(data, stampOf('a'))).not.toBe(renderBlock(data, stampOf('b')));
  });

  test('replaces its block whatever the marker line says, and refuses a script without one', () => {
    const script = 'before\n# BEGIN GENERATED INDICATORS (old words)\nold\n# END GENERATED INDICATORS\nafter\n';
    const out = replaceBlock(script, renderBlock(data, 'abc'));
    expect(out.startsWith('before\n')).toBe(true);
    expect(out.endsWith('# END GENERATED INDICATORS\nafter\n')).toBe(true);
    expect(out).toContain('team|F|high|ABC');
    expect(() => replaceBlock('nothing here', 'x')).toThrow(/no generated-indicators block/);
  });

  test('carries the paths published without a folder (**/) in their own list, and refuses a ** it cannot look for', () => {
    const path_ = (value: string, severity = 'med') => ({ kind: 'path', value, severity, confidence: 'high', source: 'u' });
    const withPaths = (...indicators: object[]) => ({ ...data, families: [{ ...data.families[0], indicators }] });
    const e = scriptEntries(withPaths(path_('~/Library/x'), path_('**/Lure.app/', 'high'), path_('**/Contents/MacOS/.macos')));
    expect(e.paths).toEqual(['F|med|~/Library/x']);
    expect(e.anywhere).toEqual(['F|high|**/Lure.app/', 'F|med|**/Contents/MacOS/.macos']);
    const block = renderBlock(withPaths(path_('**/Lure.app/', 'high')), 'abc');
    expect(block).toContain("KNOWN_ANYWHERE='F|high|**/Lure.app/'");
    expect(renderBlock(data, 'abc')).toContain("KNOWN_ANYWHERE=''");
    for (const bad of ['/Users/**/x', '**/a/**/b', '**/']) {
      expect(() => scriptEntries(withPaths(path_(bad))), bad).toThrow(/cannot be looked for/);
    }
  });

  test('looks for every path of indicators.json: none is dropped', () => {
    const real = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', 'src', 'rules', 'indicators.json'), 'utf8'));
    const e = scriptEntries(real);
    const inScript = new Set([...e.paths, ...e.anywhere].map(l => l.split('|')[2]));
    const published = real.families.flatMap((f: { indicators: { kind: string; value: string }[] }) => f.indicators.filter(i => i.kind === 'path').map(i => i.value));
    expect(published.filter((v: string) => !inScript.has(v))).toEqual([]);
    expect(e.anywhere.length).toBeGreaterThan(0);
  });

  test('copies the tooling folders of locations.ts into the script\'s awk list, and refuses if either side changes shape', () => {
    const ts = readLocations();
    const dirs = toolingDirs(ts);
    expect(dirs).toContain('node_modules');
    expect(dirs.every(d => d === d.toLowerCase())).toBe(true);
    const out = replaceTooling('x\nBEGIN { split("old list", a, " "); for (k in a) T[a[k]] = 1 }\n', dirs);
    expect(out).toContain(`split("${dirs.join(' ')}", a, " ")`);
    expect(() => replaceTooling('no list here', dirs)).toThrow(/no tooling-folder list/);
    expect(() => toolingDirs('const OTHER = 1;')).toThrow(/TOOLING_DIRS/);
  });

  test('--check reports a copy that is behind and changes nothing; a plain run brings it up to date', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-sync-'));
    try {
      fs.mkdirSync(path.join(dir, 'references'));
      fs.mkdirSync(path.join(dir, 'lib'));
      const indicators = 'x\n# BEGIN GENERATED INDICATORS (old)\nold\n# END GENERATED INDICATORS\n';
      const signatures = 'awk \'BEGIN { split("old list", a, " ") }\'\n';
      fs.writeFileSync(path.join(dir, 'lib', 'indicators.sh'), indicators);
      fs.writeFileSync(path.join(dir, 'lib', 'signatures.sh'), signatures);
      fs.writeFileSync(path.join(dir, 'references', 'known-indicators.md'), 'old page\n');
      fs.writeFileSync(path.join(dir, 'mac-triage.sh'), 'untouched\n');
      const run = (...args: string[]) => spawnSync('node', [GEN, ...args], { encoding: 'utf8', env: { ...process.env, AM_I_PWNED_DIR: dir } });
      const read = (f: string) => fs.readFileSync(path.join(dir, f), 'utf8');

      const behind = run('--check');
      expect(behind.status).toBe(1);
      expect(behind.stderr).toMatch(/out of date .*lib\/indicators\.sh, lib\/signatures\.sh, references\/known-indicators\.md/);
      expect(read('lib/indicators.sh')).toBe(indicators);   // --check wrote nothing
      expect(read('lib/signatures.sh')).toBe(signatures);
      expect(read('references/known-indicators.md')).toBe('old page\n');

      expect(run().status).toBe(0);
      expect(run('--check').status).toBe(0);
      const page = read('references/known-indicators.md');
      expect(page).toMatch(/sha256 [0-9a-f]{16}\) by scripts\/gen-indicators\.mjs/);
      expect(page).toMatch(/The `indicators` check/);
      expect(page).not.toMatch(/section 10/);
      expect(read('lib/indicators.sh')).toMatch(/sha256 [0-9a-f]{16}; edit the source there/);
      expect(read('lib/signatures.sh')).toMatch(/split\("[^"]*node_modules[^"]*", a, " "\)/);
      expect(read('mac-triage.sh')).toBe('untouched\n');   // the generator writes only the three copies

      // A hand edit of a generated file is caught as well.
      fs.appendFileSync(path.join(dir, 'references', 'known-indicators.md'), 'hand edit\n');
      expect(run('--check').status).toBe(1);
      // And with no checkout at all, the generator says so (exit 2) rather than passing.
      expect(spawnSync('node', [GEN, '--check', '--to', path.join(dir, 'nope')], { encoding: 'utf8' }).status).toBe(2);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('says which file or marker is missing, and writes nothing, rather than guessing', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-missing-'));
    try {
      fs.mkdirSync(path.join(dir, 'lib'));
      const run = (...args: string[]) => spawnSync('node', [GEN, ...args], { encoding: 'utf8', env: { ...process.env, AM_I_PWNED_DIR: dir } });
      const block = '# BEGIN GENERATED INDICATORS (old)\nold\n# END GENERATED INDICATORS\n';
      const list = 'awk \'BEGIN { split("old list", a, " ") }\'\n';

      fs.writeFileSync(path.join(dir, 'lib', 'signatures.sh'), list);
      for (const mode of [[], ['--check']]) {
        const r = run(...mode);
        expect(r.status).toBe(3);
        expect(r.stderr).toMatch(/lib\/indicators\.sh.*missing/);
      }
      fs.writeFileSync(path.join(dir, 'lib', 'indicators.sh'), block);
      fs.rmSync(path.join(dir, 'lib', 'signatures.sh'));
      expect(run().stderr).toMatch(/lib\/signatures\.sh.*missing/);
      fs.writeFileSync(path.join(dir, 'lib', 'signatures.sh'), 'no list here\n');
      expect(run().stderr).toMatch(/lib\/signatures\.sh has no tooling-folder list/);
      fs.writeFileSync(path.join(dir, 'lib', 'signatures.sh'), list);
      fs.writeFileSync(path.join(dir, 'lib', 'indicators.sh'), 'no markers\n');
      const r = run();
      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/lib\/indicators\.sh has no generated-indicators block/);
      expect(fs.readFileSync(path.join(dir, 'lib', 'signatures.sh'), 'utf8')).toBe(list);   // nothing was written
      expect(fs.existsSync(path.join(dir, 'references'))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

function readLocations(): string {
  return fs.readFileSync(path.resolve(__dirname, '..', 'src', 'rules', 'locations.ts'), 'utf8');
}
