import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import { DELETE_WINDOW_MS, DROP_WINDOW_MS } from '../src/rules/rules';
import { hiddenName } from '../src/rules/locations';
import type { CaptureModel, FileOp, Image } from '../src/model/types';
import { apple, capture, img, proc } from './synth';

const RULE = 'dropped-then-executed';
const hits = (m: CaptureModel) =>
  analyze(m).queue.flatMap(q => q.findings.filter(f => f.ruleId === RULE).map(f => ({ ...f, procId: q.procId })));
const at = (sec: number): string => new Date(Date.UTC(2026, 10, 12) + sec * 1000).toISOString();
const fileOp = (kind: FileOp['kind'], path: string, sec: number | null, seq: number, toPath?: string): FileOp =>
  ({ kind, path, ...(toPath !== undefined ? { toPath } : {}), time: (sec === null ? null : at(sec)) as string, seq });

const curl = apple('/usr/bin/curl', ['curl', '-o', '/tmp/x', 'https://x/y'], { time: at(0), seq: 1 });
const teamSigned = (path: string, sec: number | null, seq = 10): Image =>
  img({ path, args: [path], signingId: 'com.example.tool', teamId: 'TEAM123456', time: (sec === null ? null : at(sec)) as string, seq });

/** A writer process holding these file ops, and a runner process executing `run`. */
function story(ops: FileOp[], run: Image, writerImage: Image = curl) {
  return capture([proc('100:1', [writerImage], { fileOps: ops }), proc('200:1', [run])]);
}

describe('dropped-then-executed', () => {
  test('curl output run 3 s later from /tmp is med', () => {
    const m = story([fileOp('create', '/tmp/x', 10, 2)], teamSigned('/tmp/x', 13));
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.procId).toBe('200:1');
    expect(f[0]!.severity).toBe('med');
    expect(f[0]!.mitre).toEqual(['T1105', 'T1204.002']);
    expect(f[0]!.evidence).toContain('/tmp/x');
    expect(f[0]!.evidence).toContain('curl');
    expect(f[0]!.evidence).toContain('3 s');
  });
  test('an unsigned drop is high', () => {
    const m = story([fileOp('create', '/tmp/x', 10, 2)], img({ path: '/tmp/x', args: ['/tmp/x'], signingId: null, time: at(13), seq: 10 }));
    expect(hits(m)[0]!.severity).toBe('high');
  });
  test('an ad-hoc signed drop is high', () => {
    const m = story([fileOp('create', '/tmp/x', 10, 2)], img({ path: '/tmp/x', args: ['/tmp/x'], csFlags: 0x2, time: at(13), seq: 10 }));
    expect(hits(m)[0]!.severity).toBe('high');
  });
  test('a rename into place counts as the drop', () => {
    const m = story([fileOp('rename', '/tmp/x.part', 10, 2, '/tmp/x')], teamSigned('/tmp/x', 12));
    expect(hits(m)).toHaveLength(1);
  });
  test('a path with /private and another case still matches the drop', () => {
    const m = story([fileOp('create', '/private/tmp/X', 10, 2)], teamSigned('/tmp/x', 12));
    expect(hits(m)).toHaveLength(1);
  });
  test('a drop deleted 20 s after the run is high', () => {
    const m = story([fileOp('create', '/tmp/x', 10, 2), fileOp('unlink', '/tmp/x', 33, 20)], teamSigned('/tmp/x', 13));
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('deleted 20 s after');
  });
  test('a delete beyond the delete window does not raise the severity', () => {
    const late = 13 + DELETE_WINDOW_MS / 1000 + 1;
    const m = story([fileOp('create', '/tmp/x', 10, 2), fileOp('unlink', '/tmp/x', late, 20)], teamSigned('/tmp/x', 13));
    expect(hits(m)[0]!.severity).toBe('med');
  });
  test('a delete before the run does not raise the severity', () => {
    const m = story([fileOp('create', '/tmp/x', 10, 2), fileOp('unlink', '/tmp/x', 11, 3)], teamSigned('/tmp/x', 13));
    expect(hits(m)[0]!.severity).toBe('med');
  });
  test('a hidden file in the home folder is high', () => {
    const w = apple('/usr/bin/curl', ['curl', '-o', '/Users/u/.helper', 'https://x/y'], { time: at(0), seq: 1 });
    const m = story([fileOp('create', '/Users/u/.helper', 10, 2)], teamSigned('/Users/u/.helper', 12), w);
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
  });
  test('a drop older than the window is not flagged', () => {
    const m = story([fileOp('create', '/tmp/x', 10, 2)], teamSigned('/tmp/x', 10 + DROP_WINDOW_MS / 1000 + 1));
    expect(hits(m)).toHaveLength(0);
  });
  test('a drop exactly at the window edge is flagged', () => {
    const m = story([fileOp('create', '/tmp/x', 10, 2)], teamSigned('/tmp/x', 10 + DROP_WINDOW_MS / 1000));
    expect(hits(m)).toHaveLength(1);
  });
  test('the latest drop before the run is the one measured', () => {
    const m = story([fileOp('create', '/tmp/x', 0, 2), fileOp('create', '/tmp/x', 40, 3)], teamSigned('/tmp/x', 42));
    expect(hits(m)[0]!.evidence).toContain('2 s');
  });
  test('a write after the run is not a drop of what ran', () => {
    const m = story([fileOp('create', '/tmp/x', 14, 12)], teamSigned('/tmp/x', 13));
    expect(hits(m)).toHaveLength(0);
  });
  test('go-build output is not a drop', () => {
    const path = '/var/folders/ab/cd/T/go-build123/b001/exe/x';
    const goBuild = apple('/usr/local/go/bin/go', ['go', 'run', '.'], { time: at(0), seq: 1 });
    const m = story([fileOp('create', path, 10, 2)], teamSigned(path, 11), goBuild);
    expect(hits(m)).toHaveLength(0);
  });
  test.each(['clang', 'ld', 'cargo', 'make', 'swiftc'])('toolchain writer %s is skipped', tool => {
    const w = apple(`/usr/bin/${tool}`, [tool, '-o', '/tmp/a.out'], { time: at(0), seq: 1 });
    expect(hits(story([fileOp('create', '/tmp/a.out', 10, 2)], teamSigned('/tmp/a.out', 10.5), w))).toHaveLength(0);
  });
  test('an installer writing to /Applications is not flagged', () => {
    const path = '/Applications/Tool.app/Contents/MacOS/Tool';
    const w = apple('/usr/sbin/installer', ['installer', '-pkg', 'x.pkg'], { time: at(0), seq: 1 });
    expect(hits(story([fileOp('create', path, 10, 2)], teamSigned(path, 11), w))).toHaveLength(0);
  });
  test('a hidden file inside a tooling folder is not flagged', () => {
    const path = '/Users/u/proj/node_modules/.bin/tool';
    expect(hits(story([fileOp('create', path, 10, 2)], teamSigned(path, 11)))).toHaveLength(0);
  });
  test('a weak odd place is not a candidate', () => {
    const path = '/Users/u/.cargo/bin/tool';
    expect(hits(story([fileOp('create', path, 10, 2)], teamSigned(path, 11)))).toHaveLength(0);
  });
  test('an inherited image is not a run', () => {
    const run = img({ path: '/tmp/x', args: ['/tmp/x'], time: at(13), seq: 10, inherited: true });
    expect(hits(story([fileOp('create', '/tmp/x', 10, 2)], run))).toHaveLength(0);
  });
  test.each([
    ['null exec time', story([fileOp('create', '/tmp/x', 10, 2)], teamSigned('/tmp/x', null))],
    ['null drop time', story([fileOp('create', '/tmp/x', null, 2)], teamSigned('/tmp/x', 13))],
    ['null path', capture([
      proc('100:1', [curl], { fileOps: [fileOp('create', '/tmp/x', 10, 2)] }),
      proc('200:1', [img({ path: null, args: null, time: at(13), seq: 10 })]),
    ])],
    ['null args', story([fileOp('create', '/tmp/x', 10, 2)], img({ path: '/tmp/x', args: null, time: at(13), seq: 10 }))],
    ['a rename with no destination', story([fileOp('rename', '/tmp/x', 10, 2)], teamSigned('/tmp/x', 13))],
    ['a writer with no image', capture([proc('100:1', [], { fileOps: [fileOp('create', '/tmp/x', 10, 2)] }), proc('200:1', [teamSigned('/tmp/x', 13)])])],
  ])('dropped-then-executed tolerates a capture with missing data: %s', (_name, m) => {
    expect(() => analyze(m)).not.toThrow();
    expect(hits(m).filter(f => f.procId === '200:1').length).toBeLessThanOrEqual(1);
  });
});

describe('hiddenName', () => {
  test.each([['/Users/u/.helper', true], ['/Users/u/visible', false], ['/a/.', false], ['/a/..', false], ['.x', true], ['', false]])(
    '%s -> %s', (path, expected) => expect(hiddenName(path)).toBe(expected));
});
