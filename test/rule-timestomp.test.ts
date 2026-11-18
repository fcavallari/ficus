import { describe, expect, test } from 'vitest';
import { analyze, type Finding } from '../src/rules/engine';
import type { CaptureModel, Image } from '../src/model/types';
import { apple, capture, img, proc } from './synth';

const RULE = 'timestomp';
function hits(m: CaptureModel): { queued: Finding[]; context: Finding[] } {
  const a = analyze(m);
  const pick = (map: Map<string, Finding[]>) => [...map.values()].flat().filter(f => f.ruleId === RULE);
  return { queued: pick(a.findings), context: pick(a.contextOnly) };
}
const all = (m: CaptureModel): Finding[] => { const h = hits(m); return [...h.queued, ...h.context]; };

const touch = (args: string[], cwd: string | null = '/Users/u', o: Partial<Image> = {}): Image =>
  apple('/usr/bin/touch', ['touch', ...args], { cwd, seq: 5, ...o });
const one = (image: Image): CaptureModel => capture([proc('100:1', [image])]);

describe('timestomp', () => {
  test('touch -r OneDrive plist onto another LaunchDaemons plist is high, evidence names the reference', () => {
    const f = all(one(touch(['-r', '/Library/LaunchDaemons/com.microsoft.OneDriveUpdaterDaemon.plist', '/Library/LaunchDaemons/com.google.chromeplugin.plist'])));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: 'high', mitre: ['T1070.006'] });
    expect(f[0]!.evidence).toContain('com.microsoft.OneDriveUpdaterDaemon.plist');
    expect(f[0]!.evidence).toContain('com.google.chromeplugin.plist');
  });

  test('the -r reference alone is never a target', () => {
    const f = all(one(touch(['-r', '/Library/LaunchDaemons/a.plist', './build/out.o'], '/Users/u/proj')));
    expect(f.map(x => x.severity)).toEqual(['low']);
  });

  test('relative target resolves against cwd', () => {
    const f = all(one(touch(['-t', '202001010000', 'helper'], '/tmp/x')));
    expect(f.map(x => x.severity)).toEqual(['high']);
    expect(f[0]!.evidence).toContain('/tmp/x/helper');
  });

  test('target a program the capture ran is high', () => {
    const m = capture([
      proc('100:1', [touch(['-d', '2019-03-01T10:00:00', '/usr/local/bin/chrome_plugin'])]),
      proc('200:1', [img({ path: '/usr/local/bin/chrome_plugin', args: ['chrome_plugin'], seq: 9 })]),
    ]);
    const f = hits(m).queued;
    expect(f.map(x => x.severity)).toEqual(['high']);
    expect(f[0]!.evidence).toContain('2019-03-01T10:00:00');
  });

  test('build touch -t on its own outputs is low and context only', () => {
    const m = capture([
      proc('50:1', [apple('/usr/bin/cc', ['cc', '-o', 'build/out.o', 'a.c'], { cwd: '/Users/u/proj', seq: 1 })],
        { fileOps: [{ kind: 'create', path: '/Users/u/proj/build/out.o', time: '2026-11-12T00:00:00.500Z', seq: 2 }] }),
      proc('100:1', [touch(['-t', '202001010000', 'build/out.o'], '/Users/u/proj')]),
    ]);
    const h = hits(m);
    expect(h.queued).toEqual([]);
    expect(h.context.map(x => x.severity)).toEqual(['low']);
  });

  test('SetFile -d and -m count; SetFile -a does not', () => {
    const setfile = (args: string[]) => apple('/usr/bin/SetFile', ['SetFile', ...args], { cwd: '/Users/u', seq: 5 });
    expect(all(one(setfile(['-d', '01/01/2019 10:00:00', '/Users/u/Library/LaunchAgents/x.plist']))).map(x => x.severity)).toEqual(['high']);
    expect(all(one(setfile(['-m', '01/01/2019 10:00:00', 'notes.txt']))).map(x => x.severity)).toEqual(['low']);
    expect(all(one(setfile(['-a', 'V', '/Users/u/Library/LaunchAgents/x.plist'])))).toEqual([]);
  });

  test('plain touch file, and touch -c -m file, are not flagged', () => {
    expect(all(one(touch(['/Users/u/Library/LaunchAgents/x.plist'])))).toEqual([]);
    expect(all(one(touch(['-c', '-m', '/Users/u/Library/LaunchAgents/x.plist'])))).toEqual([]);
  });
});
