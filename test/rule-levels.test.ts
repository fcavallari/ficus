import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import { analyze } from '../src/rules/engine';
import { RULES, ruleLevels, SEVERITY_RANK, type Severity } from '../src/rules/rules';
import { hasRealCaptures, readLines, REAL_FIXTURES, type FixtureName } from './fixtures';

// Each rule says which severities its findings can have. The guide filters on that range, and the README's rules
// table states it in words, so the two must agree.

test('a rule\'s range holds its own severity, highest first, with no repeats', () => {
  for (const r of RULES) {
    const levels = ruleLevels(r);
    expect(levels, r.id).toContain(r.severity);
    expect(levels, r.id).toEqual([...new Set(levels)].sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a]));
  }
});

test('a range is only spelled out when it has more than one level', () => {
  for (const r of RULES) if (r.levels !== undefined) expect(r.levels.length, r.id).toBeGreaterThan(1);
});

const CAPTURES: FixtureName[] = ['synthetic-lab.jsonl', ...(hasRealCaptures ? REAL_FIXTURES : [])];

test.each(CAPTURES)('every finding in %s has a severity its rule says it can reach', name => {
  const a = analyze(buildModel(readLines(name)));
  const all = [...a.findings.values(), ...a.contextOnly.values(), ...a.queue.map(q => q.findings)].flat();
  expect(all.length).toBeGreaterThan(0);
  for (const f of all) expect(ruleLevels(RULES.find(r => r.id === f.ruleId)!), `${f.ruleId}: ${f.evidence}`).toContain(f.severity);
});

test('the README\'s rules table states the same range for every rule', () => {
  const readme = fs.readFileSync(path.resolve(__dirname, '..', 'README.md'), 'utf8');
  const stated = new Map<string, Severity[]>();
  for (const m of readme.matchAll(/^\| `([a-z-]+)` \| ([a-z, ]+?) \|/gm)) {
    stated.set(m[1]!, m[2]!.split(/, | or /).map(s => s.trim() as Severity));
  }
  for (const r of RULES) {
    expect(stated.has(r.id), `${r.id} is missing from the README's rules table`).toBe(true);
    expect([...stated.get(r.id)!].sort(), r.id).toEqual([...ruleLevels(r)].sort());
  }
});
