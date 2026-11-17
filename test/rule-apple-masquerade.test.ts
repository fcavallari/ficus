import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import { APPLE_LABEL_PLIST } from '../src/rules/rules';
import type { CaptureModel } from '../src/model/types';
import { apple, capture, img, op, persistenceItem, proc } from './synth';

const RULE = 'apple-masquerade';
const findings = (m: CaptureModel, id: string) => analyze(m).queue.flatMap(q => q.findings).filter(f => f.ruleId === id);
const hits = (m: CaptureModel) => findings(m, RULE);
const ADHOC = 0x2;

describe('APPLE_LABEL_PLIST', () => {
  test('matches an Apple-labelled plist in a launch folder, hidden or not, in any letter case', () => {
    expect(APPLE_LABEL_PLIST.test('/Users/u/Library/LaunchAgents/com.apple.updater.plist')).toBe(true);
    expect(APPLE_LABEL_PLIST.test('/Library/LaunchAgents/com.apple.x.plist')).toBe(true);
    expect(APPLE_LABEL_PLIST.test('/Library/LaunchDaemons/.com.apple.x.plist')).toBe(true);
    expect(APPLE_LABEL_PLIST.test('/Library/LaunchDaemons/COM.APPLE.X.PLIST')).toBe(true);
  });
  test('leaves other plists and other folders alone', () => {
    expect(APPLE_LABEL_PLIST.test('/Library/LaunchDaemons/com.example.apple.plist')).toBe(false);
    expect(APPLE_LABEL_PLIST.test('/Library/LaunchDaemons/xcom.apple.x.plist')).toBe(false);
    expect(APPLE_LABEL_PLIST.test('/tmp/com.apple.x.plist')).toBe(false);
    expect(APPLE_LABEL_PLIST.test('/Library/Preferences/com.apple.x.plist')).toBe(false);
    expect(APPLE_LABEL_PLIST.test('/Library/LaunchDaemons/sub/com.apple.x.plist')).toBe(false);
  });
});

describe('apple-masquerade', () => {
  test('ad-hoc code claiming an Apple signing ID is high', () => {
    const m = capture([proc('200:1', [img({ path: '/tmp/finder', signingId: 'com.apple.finder.helper', csFlags: ADHOC })])]);
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1036.005']);
    expect(f[0]!.evidence).toBe('/tmp/finder is ad-hoc signed as com.apple.finder.helper');
  });
  test('a genuine non-platform Apple signature is not flagged', () => {
    const x = img({ path: '/Applications/Xcode.app/Contents/MacOS/Xcode', signingId: 'com.apple.dt.Xcode', csFlags: 0, isPlatform: false });
    expect(hits(capture([proc('200:1', [x])]))).toHaveLength(0);
  });
  test('a com.apple signing ID under another team\'s certificate is high', () => {
    const m = capture([proc('200:1', [img({ path: '/tmp/x', signingId: 'com.apple.x', teamId: 'ABCDE12345', csFlags: 0 })])]);
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1036.005']);
    expect(f[0]!.evidence).toBe('/tmp/x claims the signing ID com.apple.x but is signed by team ABCDE12345');
  });
  test('genuine non-platform Apple apps are not flagged: an Apple team ID, or no team ID under an Apple path', () => {
    const cases: [string, string | null, string][] = [
      ['com.apple.dt.Xcode', null, '/Applications/Xcode.app/Contents/MacOS/Xcode'],
      ['com.apple.dt.Xcode', null, '/Applications/Xcode-beta.app/Contents/MacOS/Xcode'],
      ['com.apple.dt.Xcode', '59GAB85EFG', '/Applications/X.app/Contents/MacOS/x'],
      ['com.apple.iWork.Pages', '74J34U3R6X', '/Applications/X.app/Contents/MacOS/x'],
      ['com.apple.garageband10', 'F3LWYJ7GM7', '/Applications/X.app/Contents/MacOS/x'],
      ['com.apple.iMovieApp', 'PTN9T2S29T', '/Applications/X.app/Contents/MacOS/x'],
      ['com.apple.Safari', '', '/System/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari'],
      ['com.apple.x', null, '/usr/libexec/x'],
      ['com.apple.x', null, '/Library/Apple/usr/libexec/x'],
      ['com.apple.clang', null, '/Library/Developer/CommandLineTools/usr/bin/clang'],
    ];
    for (const [signingId, teamId, path] of cases) {
      expect(hits(capture([proc('200:1', [img({ path, signingId, teamId })])])), `${signingId} ${teamId} ${path}`).toHaveLength(0);
    }
  });
  // A2: a signing ID is the signer's choice and a self-signed certificate carries no team ID, so the missing team ID
  // proves nothing outside the places only Apple writes to.
  test.each([
    ['/tmp/x'], ['/Users/u/Downloads/x'], ['/Applications/X.app/Contents/MacOS/x'], ['/usr/local/bin/x'], ['/Users/u/Library/x'],
    ['/usr/Local/bin/x'], ['/USR/local/bin/x'], ['/usr/../tmp/x'], ['/System/../tmp/x'], ['/Applications/Xcode.app/../../tmp/x'],
    ['/usr/./local/bin/x'], ['/Library/Developer/../../tmp/x'],
  ])('a self-signed com.apple.x with no team ID at %s is high', (path) => {
    for (const teamId of [null, '']) {
      const f = hits(capture([proc('200:1', [img({ path, signingId: 'com.apple.x', teamId, csFlags: 0 })])]));
      expect(f, `${path} ${teamId}`).toHaveLength(1);
      expect(f[0]!.severity).toBe('high');
      expect(f[0]!.mitre).toEqual(['T1036.005']);
      expect(f[0]!.evidence).toBe(`${path} claims the signing ID com.apple.x but has no Apple team ID`);
    }
  });
  test('a platform binary is not flagged', () => {
    expect(hits(capture([proc('200:1', [apple('/usr/bin/curl', ['curl', '-V'])])]))).toHaveLength(0);
  });
  test('a non-Apple writer of a com.apple plist in a user\'s LaunchAgents is high', () => {
    const w = img({ path: '/Users/Shared/x/helper', signingId: null, args: ['helper'] });
    const p = proc('200:1', [w], { fileOps: [op('create', '/Users/u/Library/LaunchAgents/com.apple.updater.plist')] });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1036.005', 'T1543.001']);
    expect(f[0]!.evidence).toContain('/Users/u/Library/LaunchAgents/com.apple.updater.plist');
    expect(f[0]!.evidence).toContain('/Users/Shared/x/helper');
  });
  // B6: a platform tool is Apple's, but `cp` copying a plist into a user's LaunchAgents is not Apple writing its own.
  test.each([
    ['cp', '/bin/cp'], ['mv', '/bin/mv'], ['ditto', '/usr/bin/ditto'], ['tee', '/usr/bin/tee'], ['cat', '/bin/cat'],
    ['bash', '/bin/bash'], ['zsh', '/bin/zsh'], ['sh', '/bin/sh'], ['osascript', '/usr/bin/osascript'], ['python3', '/usr/bin/python3'],
    ['python3.11', '/usr/bin/python3.11'], ['perl', '/usr/bin/perl'], ['perl5.34', '/usr/bin/perl5.34'], ['ruby', '/usr/bin/ruby'], ['curl', '/usr/bin/curl'],
  ])('a platform %s writing a com.apple plist into a user\'s LaunchAgents is flagged', (name, path) => {
    const p = proc('200:1', [apple(path, [name])], { fileOps: [op('create', '/Users/u/Library/LaunchAgents/com.apple.x.plist')] });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1036.005', 'T1543.001']);
    expect(f[0]!.evidence).toBe(`${path} created /Users/u/Library/LaunchAgents/com.apple.x.plist`);
  });
  test('the same platform tools writing under /Library are unchanged: not flagged', () => {
    for (const path of ['/bin/cp', '/usr/bin/ditto', '/bin/bash', '/usr/bin/osascript', '/usr/bin/python3', '/usr/bin/curl']) {
      for (const plist of ['/Library/LaunchDaemons/com.apple.x.plist', '/Library/LaunchAgents/com.apple.x.plist']) {
        const p = proc('200:1', [apple(path, [path.split('/').pop()!])], { fileOps: [op('create', plist)] });
        expect(hits(capture([p])), `${path} ${plist}`).toHaveLength(0);
      }
    }
  });
  test('a platform tool that is not a general-purpose one still may write a user\'s com.apple plist', () => {
    const p = proc('200:1', [apple('/usr/libexec/xpcproxy', ['xpcproxy'])], { fileOps: [op('create', '/Users/u/Library/LaunchAgents/com.apple.x.plist')] });
    expect(hits(capture([p]))).toHaveLength(0);
  });
  test('a non-platform Apple-signed writer in a user\'s LaunchAgents is still not flagged', () => {
    const w = img({ path: '/Applications/Xcode.app/Contents/MacOS/Xcode', signingId: 'com.apple.dt.Xcode', teamId: '59GAB85EFG', args: ['Xcode'] });
    const p = proc('200:1', [w], { fileOps: [op('create', '/Users/u/Library/LaunchAgents/com.apple.x.plist')] });
    expect(hits(capture([p]))).toHaveLength(0);
  });
  test('a rename into place counts, and a daemon plist cites the daemon technique', () => {
    const w = img({ path: '/tmp/x', signingId: 'adhoc.x', csFlags: ADHOC });
    const p = proc('200:1', [w], { fileOps: [op('rename', '/tmp/t.plist', 2, '/Library/LaunchDaemons/com.apple.sync.plist')] });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1036.005', 'T1543.004']);
  });
  test('the same plist written by Apple\'s installer is not flagged', () => {
    const w = apple('/usr/sbin/installd', ['installd']);
    const p = proc('200:1', [w], { fileOps: [op('create', '/Library/LaunchDaemons/com.apple.foo.plist')] });
    expect(hits(capture([p]))).toHaveLength(0);
  });
  test('a non-platform Apple-signed writer is not flagged', () => {
    const w = img({ path: '/Applications/Xcode.app/Contents/MacOS/Xcode', signingId: 'com.apple.dt.Xcode', teamId: '59GAB85EFG', csFlags: 0 });
    const p = proc('200:1', [w], { fileOps: [op('create', '/Library/LaunchDaemons/com.apple.foo.plist')] });
    expect(hits(capture([p]))).toHaveLength(0);
  });
  test('a writer with a com.apple signing ID under another team\'s certificate is not exempt', () => {
    const w = img({ path: '/Users/Shared/x/helper', signingId: 'com.apple.x', teamId: 'ABCDE12345', csFlags: 0 });
    const p = proc('200:1', [w], { fileOps: [op('create', '/Library/LaunchDaemons/com.apple.foo.plist')] });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');   // (a) and (b) both apply
    expect(f[0]!.evidence).toContain('claims the signing ID com.apple.x');
    expect(f[0]!.evidence).toContain('created /Library/LaunchDaemons/com.apple.foo.plist');
    expect(f[0]!.mitre).toEqual(['T1036.005', 'T1543.004']);
  });
  test('a hidden com.apple plist name counts', () => {
    const w = img({ path: '/Applications/Tool.app/Contents/MacOS/tool', signingId: 'com.example.tool', teamId: 'ABCDE12345' });
    const p = proc('200:1', [w], { fileOps: [op('create', '/Library/LaunchDaemons/.com.apple.x.plist')] });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('med');
  });
  test('a team-signed writer in a user\'s LaunchAgents is still high', () => {
    const w = img({ path: '/Applications/Tool.app/Contents/MacOS/tool', signingId: 'com.example.tool', teamId: 'ABCDE12345' });
    const p = proc('200:1', [w], { fileOps: [op('create', '/Users/u/Library/LaunchAgents/com.apple.x.plist')] });
    expect(hits(capture([p]))[0]!.severity).toBe('high');
  });
  test('the writer is the image that was running at the time, and only the first exec reports', () => {
    const first = apple('/bin/sh', ['sh'], { seq: 1 });
    const second = img({ path: '/tmp/x', signingId: null, seq: 5, args: ['x'] });
    const p = proc('200:1', [first, second], {
      fileOps: [op('create', '/Library/LaunchDaemons/com.apple.a.plist', 2), op('create', '/Library/LaunchDaemons/com.apple.b.plist', 6)],
    });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toContain('com.apple.b.plist');
    expect(f[0]!.evidence).not.toContain('com.apple.a.plist');
  });
  test('an ordinary launch plist is not flagged', () => {
    const w = img({ path: '/tmp/x', signingId: null });
    const p = proc('200:1', [w], { fileOps: [op('create', '/Users/u/Library/LaunchAgents/com.example.x.plist')] });
    expect(hits(capture([p]))).toHaveLength(0);
  });
  test('apple-masquerade tolerates a capture with missing data', () => {
    const ghost = proc('300:1', [], { ghost: true });
    const bare = img({ path: null, signingId: null, args: null, cwd: null, time: null });
    const noSigner = img({ path: '/tmp/x', signingId: null, args: null });
    const p = proc('301:1', [bare], { fileOps: [op('rename', '/tmp/a')] });
    const q = proc('302:1', [noSigner], { fileOps: [{ kind: 'create', path: '', time: null, seq: 2 } as never, op('rename', '/tmp/a', 3)] });
    expect(() => hits(capture([ghost, p, q]))).not.toThrow();
    expect(hits(capture([ghost, p, q]))).toHaveLength(0);
  });
});

describe('persistence-item with an Apple-named plist', () => {
  const item = (plist: string, exe: string) => persistenceItem({ plistPath: plist, executablePath: exe, itemType: 4 });
  const run = (m: CaptureModel) => findings(m, 'persistence-item');

  test('a launch item named com.apple that runs a non-Apple program is high', () => {
    const f = run(capture([], [item('/Library/LaunchDaemons/com.apple.sync.plist', '/Library/Caches/sync')]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('Apple-named plist but runs /Library/Caches/sync');
  });
  test('the same plist running an Apple path stays as before', () => {
    for (const exe of ['/usr/libexec/foo', '/System/Library/CoreServices/x', '/bin/x', '/sbin/x', '/usr/bin/x', '/Library/Apple/usr/libexec/x']) {
      const f = run(capture([], [item('/Library/LaunchDaemons/com.apple.sync.plist', exe)]));
      expect(f[0]!.severity, exe).toBe('med');
      expect(f[0]!.evidence, exe).not.toContain('Apple-named plist');
    }
  });
  test('/usr/local is not Apple\'s', () => {
    const f = run(capture([], [item('/Library/LaunchDaemons/com.apple.sync.plist', '/usr/local/bin/sync')]));
    expect(f[0]!.severity).toBe('high');
  });
  test('a captured platform binary at the target path keeps it as before', () => {
    const p = proc('200:1', [apple('/Library/Caches/sync', ['sync'])]);
    const f = run(capture([p], [item('/Library/LaunchDaemons/com.apple.sync.plist', '/Library/Caches/sync')]));
    expect(f[0]!.severity).toBe('med');
  });
  test('a genuine Apple-signed non-platform item at the target keeps it as before', () => {
    const x = img({ path: '/Library/Caches/sync', signingId: 'com.apple.sync', teamId: '59GAB85EFG', csFlags: 0, args: ['sync'] });
    const f = run(capture([proc('200:1', [x])], [item('/Library/LaunchDaemons/com.apple.sync.plist', '/Library/Caches/sync')]));
    expect(f[0]!.severity).toBe('med');
    // A com.apple signing ID under another team's certificate does not earn it.
    const spoof = img({ path: '/Library/Caches/sync', signingId: 'com.apple.sync', teamId: 'ABCDE12345', csFlags: 0, args: ['sync'] });
    expect(run(capture([proc('200:1', [spoof])], [item('/Library/LaunchDaemons/com.apple.sync.plist', '/Library/Caches/sync')]))[0]!.severity).toBe('high');
  });
  test.each(['/usr/Local/bin/sync', '/USR/local/bin/sync', '/usr/../tmp/sync', '/System/../tmp/sync', '/usr/./local/sync'])('%s is not an Apple path', (exe) => {
    const f = run(capture([], [item('/Library/LaunchDaemons/com.apple.sync.plist', exe)]));
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('Apple-named plist');
  });
  test('Apple paths are matched in any letter case', () => {
    const f = run(capture([], [item('/Library/LaunchDaemons/com.apple.sync.plist', '/SYSTEM/Library/x')]));
    expect(f[0]!.severity).toBe('med');
  });
  test('a plist without an Apple label is judged by what it runs, as before', () => {
    const f = run(capture([], [item('/Library/LaunchDaemons/com.example.sync.plist', '/Library/Caches/sync')]));
    expect(f[0]!.severity).toBe('med');
    expect(f[0]!.evidence).not.toContain('Apple-named plist');
  });
  test('an item that names no program is not sharpened', () => {
    const f = run(capture([], [persistenceItem({ plistPath: '/Library/LaunchDaemons/com.apple.sync.plist', itemType: 4 })]));
    expect(f[0]!.severity).toBe('med');
  });
});
