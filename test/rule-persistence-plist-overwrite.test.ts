import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import type { CaptureModel, FileOp } from '../src/model/types';
import { coverage } from '../src/ui/triage-model';
import { apple, capture, op, proc } from './synth';

const findings = (m: CaptureModel) =>
  [...analyze(m).findings.values()].flat().filter(f => f.ruleId === 'persistence-plist');
const writer = (...ops: FileOp[]): CaptureModel =>
  capture([proc('100:1', [apple('/bin/cat', ['cat'], { seq: 1 })], { fileOps: ops })]);
const viaClose = (path: string, seq = 2): FileOp => ({ ...op('write', path, seq), via: 'close' });

describe('persistence-plist: plists overwritten in place', () => {
  test('a write to an existing LaunchDaemons plist is high, "modified in place"', () => {
    const f = findings(writer(op('write', '/Library/LaunchDaemons/com.google.chromeplugin.plist')));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: 'high', mitre: ['T1543.004'] });
    expect(f[0]!.evidence).toContain('modified in place /Library/LaunchDaemons/com.google.chromeplugin.plist');
    expect(f[0]!.evidence).not.toContain('seen at close');
  });

  test('a modified close to ~/Library/LaunchAgents/x.plist is high and says seen at close', () => {
    const f = findings(writer(viaClose('/Users/u/Library/LaunchAgents/x.plist')));
    expect(f.map(x => x.severity)).toEqual(['high']);
    expect(f[0]!.evidence).toContain('modified in place /Users/u/Library/LaunchAgents/x.plist (seen at close)');
  });

  test('create then write of the same plist by one process: one entry, says wrote', () => {
    const plist = '/Users/u/Library/LaunchAgents/x.plist';
    const f = findings(writer(op('create', plist, 2), op('write', plist, 3), viaClose(plist, 4)));
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toBe(`wrote ${plist}`);
  });

  test('a write to a non-launch plist is not flagged', () => {
    expect(findings(writer(op('write', '/Users/u/Library/Preferences/com.example.app.plist')))).toEqual([]);
  });
});

describe('coverage: write and close', () => {
  const withKinds = (kinds: Record<string, number>): CaptureModel => {
    const m = writer();
    m.stats.kinds = { exec: 1, ...kinds };
    return m;
  };

  test('note none-write-close when neither kind is present; absent when close is present', () => {
    const note = coverage(withKinds({})).notes.find(n => n.id === 'none-write-close');
    expect(note).toMatchObject({ level: 'info', title: 'No write or close events', checks: ['persistence-plist'] });
    expect(note!.detail).toContain('overwritten in place');
    expect(coverage(withKinds({ close: 3 })).notes.find(n => n.id === 'none-write-close')).toBeUndefined();
    expect(coverage(withKinds({ write: 1 })).notes.find(n => n.id === 'none-write-close')).toBeUndefined();
  });

  test('no note when close was recorded but no close was modified (counted only as other events)', () => {
    const m = withKinds({});
    m.stats.otherEvents = { close: 40 };
    expect(coverage(m).notes.find(n => n.id === 'none-write-close')).toBeUndefined();
  });
});
