import { expect, test } from 'vitest';
import { RULES, ruleLevels, type Severity } from '../src/rules/rules';
import { STAGES } from '../src/ui/GuideScreen';
import { listRules, SEVERITIES } from '../src/ui/guide-rules';

const ALL = new Set(SEVERITIES);
const STAGE_ORDER = STAGES.flatMap(s => s.rules);
const ids = (show: ReadonlySet<Severity>, order: 'severity' | 'stage' | 'name') => listRules(RULES, show, order, STAGE_ORDER).map(r => r.id);

test('every severity ticked lists every rule once', () => {
  for (const order of ['severity', 'stage', 'name'] as const) expect(ids(ALL, order).sort()).toEqual(RULES.map(r => r.id).sort());
});

test('a rule is kept when it can reach any ticked severity, not only its usual one', () => {
  const low = ids(new Set<Severity>(['low']), 'name');
  expect(low).toContain('odd-location-exec');   // usually med, can be low
  expect(low).toContain('keychain-access');     // usually high, can be low
  expect(low).not.toContain('download');        // always med
  expect(low.sort()).toEqual(RULES.filter(r => ruleLevels(r).includes('low')).map(r => r.id).sort());
  const high = ids(new Set<Severity>(['high']), 'name');
  expect(high).toContain('dropped-then-executed');   // usually med, can be high
  expect(high).not.toContain('recon');
});

test('nothing ticked lists nothing', () => {
  expect(ids(new Set(), 'severity')).toEqual([]);
});

test('by severity: highest reachable level first, and a rule that is always high before one that can drop', () => {
  const list = listRules(RULES, ALL, 'severity', STAGE_ORDER);
  const tops = list.map(r => ruleLevels(r)[0]);
  expect(tops.indexOf('med')).toBeGreaterThan(tops.lastIndexOf('high'));
  expect(tops.indexOf('low')).toBeGreaterThan(tops.lastIndexOf('med'));
  const order = list.map(r => r.id);
  expect(order.indexOf('fake-prompt')).toBeLessThan(order.indexOf('apple-masquerade'));          // high before high or med
  expect(order.indexOf('apple-masquerade')).toBeLessThan(order.indexOf('odd-location-exec'));    // high or med before high, med or low
});

test('by stage: the stages\' order; by name: the titles A to Z', () => {
  expect(ids(ALL, 'stage')).toEqual(STAGE_ORDER);
  const titles = listRules(RULES, ALL, 'name', STAGE_ORDER).map(r => r.title);
  expect(titles).toEqual([...titles].sort((a, b) => a.localeCompare(b)));
});
