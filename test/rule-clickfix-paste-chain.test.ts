import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import { PASTE_WINDOW_MS, siblings, underAgentShell } from '../src/rules/context';
import type { CaptureModel, Image, Process } from '../src/model/types';
import { apple, capture, img, proc } from './synth';

const RULE = 'clickfix-paste-chain';
const findings = (m: CaptureModel, id: string) =>
  analyze(m).queue.flatMap(q => q.findings.filter(f => f.ruleId === id).map(f => ({ ...f, procId: q.procId })));
const hits = (m: CaptureModel) => findings(m, RULE);
const at = (sec: number): string => new Date(Date.UTC(2026, 10, 12) + sec * 1000).toISOString();

/** A parent shell and these children (id, image), each forked from it. */
function story(children: [string, Image][], parentImage: Image = apple('/bin/zsh', ['zsh'], { seq: 1 })): CaptureModel {
  const parent = proc('100:1', [parentImage]);
  return capture([parent, ...children.map(([id, i]) => proc(id, [i], { originalParent: parent.id }))]);
}
const decoder = (sec: number, seq = 2): Image => apple('/usr/bin/base64', ['base64', '-d'], { time: at(sec), seq });
const reader = (path: string, args: string[], sec: number, seq = 3): Image =>
  apple(path, args, { time: at(sec), seq, stdinIsPipe: true });
const curl = (args: string[], sec: number, seq = 2): Image => apple('/usr/bin/curl', ['curl', ...args], { time: at(sec), seq });

describe('clickfix-paste-chain', () => {
  test('a decoder and a piped shell under one parent is a paste chain', () => {
    const m = story([['201:1', decoder(10)], ['202:1', reader('/bin/bash', ['bash', '-s'], 11)]]);
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.procId).toBe('202:1');
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1059.004', 'T1140', 'T1204.004']);
    expect(f[0]!.evidence).toContain('bash -s');
    expect(f[0]!.evidence).toContain('base64 -d');
    expect(findings(m, 'shell-from-pipe').map(x => x.procId)).toEqual(['202:1']);
  });
  test('curl -k piped to zsh is a paste chain', () => {
    const m = story([['201:1', curl(['-kfsSL', 'https://x/y'], 10)], ['202:1', reader('/bin/zsh', ['zsh'], 10.5)]]);
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1059.004', 'T1105', 'T1204.004']);
    expect(f[0]!.evidence).toContain('curl -kfsSL https://x/y');
  });
  test('curl with a custom user agent piped to zsh is a paste chain', () => {
    const m = story([['201:1', curl(['-A', 'Mac OS X 10_15_7', '-fsSL', 'https://x/y'], 10)], ['202:1', reader('/bin/zsh', ['zsh'], 11)]]);
    expect(hits(m)).toHaveLength(1);
  });
  test('wget without certificate checks piped to a shell is a paste chain', () => {
    const w = apple('/usr/local/bin/wget', ['wget', '-qO-', '--no-check-certificate', 'https://x/y'], { time: at(10), seq: 2 });
    expect(hits(story([['201:1', w], ['202:1', reader('/bin/sh', ['sh'], 11)]]))).toHaveLength(1);
  });
  test('openssl enc -d and xxd -r are decoders', () => {
    const o = apple('/usr/bin/openssl', ['openssl', 'enc', '-d', '-base64'], { time: at(10), seq: 2 });
    const x = apple('/usr/bin/xxd', ['xxd', '-r', '-p'], { time: at(10), seq: 2 });
    expect(hits(story([['201:1', o], ['202:1', reader('/bin/bash', ['bash'], 11)]]))).toHaveLength(1);
    expect(hits(story([['201:1', x], ['202:1', reader('/bin/bash', ['bash'], 11)]]))).toHaveLength(1);
  });
  test('an openssl digest with -d is not a decoder', () => {
    const o = apple('/usr/bin/openssl', ['openssl', 'dgst', '-sha256', '-d'], { time: at(10), seq: 2 });
    expect(hits(story([['201:1', o], ['202:1', reader('/bin/bash', ['bash'], 11)]]))).toHaveLength(0);
  });
  test('plain curl piped to bash is not a paste chain', () => {
    const m = story([['201:1', curl(['-fsSL', 'https://brew.example/install.sh'], 10)], ['202:1', reader('/bin/bash', ['bash'], 10.5)]]);
    expect(hits(m)).toHaveLength(0);
    expect(findings(m, 'shell-from-pipe')).toHaveLength(1);
  });
  test('siblings more than 3 s apart are not a chain', () => {
    expect(PASTE_WINDOW_MS).toBe(3000);
    expect(hits(story([['201:1', decoder(10)], ['202:1', reader('/bin/bash', ['bash', '-s'], 13.5)]]))).toHaveLength(0);
    expect(hits(story([['201:1', decoder(10)], ['202:1', reader('/bin/bash', ['bash', '-s'], 12.9)]]))).toHaveLength(1);
  });
  test('an osascript fed from a pipe after curl -k is a paste chain', () => {
    const m = story([['201:1', curl(['-k', 'https://x/y'], 10)], ['202:1', reader('/usr/bin/osascript', ['osascript', '-'], 11)]]);
    const f = hits(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.mitre).toEqual(['T1105', 'T1204.004']);
  });
  test('an osascript running a file or inline code is not a reader', () => {
    const c = curl(['-k', 'https://x/y'], 10);
    expect(hits(story([['201:1', c], ['202:1', reader('/usr/bin/osascript', ['osascript', '/tmp/x.scpt'], 11)]]))).toHaveLength(0);
    expect(hits(story([['201:1', c], ['202:1', reader('/usr/bin/osascript', ['osascript', '-e', 'beep'], 11)]]))).toHaveLength(0);
  });
  test('a reader whose stdin is not a pipe is ignored', () => {
    const r = apple('/bin/bash', ['bash', '-s'], { time: at(11), seq: 3, stdinIsPipe: false });
    expect(hits(story([['201:1', decoder(10)], ['202:1', r]]))).toHaveLength(0);
  });
  test('a decoder under an AI agent shell is ignored', () => {
    const parent = apple('/bin/zsh', ['zsh', '-c', 'source /Users/u/.claude/shell-snapshots/snapshot-zsh-1.sh && eval "$(echo aGk= | base64 -d)"'], { seq: 1 });
    expect(hits(story([['201:1', decoder(10)], ['202:1', reader('/bin/bash', ['bash', '-s'], 11)]], parent))).toHaveLength(0);
  });
  test('each process is reported once, even when sh re-execs bash', () => {
    const first = reader('/bin/sh', ['sh', '-s'], 11, 3);
    const second = reader('/bin/bash', ['bash', '-s'], 11.1, 4);
    const m = capture([
      proc('100:1', [apple('/bin/zsh', ['zsh'], { seq: 1 })]),
      proc('201:1', [decoder(10)], { originalParent: '100:1' }),
      proc('202:1', [first, second], { originalParent: '100:1' }),
    ]);
    expect(hits(m)).toHaveLength(1);
  });
  test('clickfix-paste-chain tolerates a capture with missing data', () => {
    const parent = proc('100:1', [apple('/bin/zsh', ['zsh'], { seq: 1 })]);
    const noParent = proc('202:1', [reader('/bin/bash', ['bash', '-s'], 11)]);
    expect(hits(capture([parent, proc('201:1', [decoder(10)], { originalParent: '100:1' }), noParent]))).toHaveLength(0);
    const noTime = proc('202:1', [reader('/bin/bash', ['bash', '-s'], 11, 3)], { originalParent: '100:1' });
    noTime.images[0]!.time = null;
    expect(hits(capture([parent, proc('201:1', [decoder(10)], { originalParent: '100:1' }), noTime]))).toHaveLength(0);
    const sibNoTime = decoder(10);
    sibNoTime.time = null;
    expect(hits(capture([parent, proc('201:1', [sibNoTime], { originalParent: '100:1' }),
      proc('202:1', [reader('/bin/bash', ['bash', '-s'], 11)], { originalParent: '100:1' })]))).toHaveLength(0);
    const noArgs = img({ path: '/usr/bin/base64', args: null, time: at(10), seq: 2 });
    expect(hits(capture([parent, proc('201:1', [noArgs], { originalParent: '100:1' }),
      proc('202:1', [reader('/bin/bash', ['bash', '-s'], 11)], { originalParent: '100:1' })]))).toHaveLength(0);
    const ghost: Process = proc('201:1', [decoder(10)], { originalParent: '100:1', ghost: true });
    expect(hits(capture([parent, ghost, proc('202:1', [reader('/bin/bash', ['bash', '-s'], 11)], { originalParent: '100:1' })]))).toHaveLength(0);
    const orphanParent = proc('202:1', [reader('/bin/bash', ['bash', '-s'], 11)], { originalParent: '999:9' });
    expect(hits(capture([orphanParent]))).toHaveLength(0);
  });
});

describe('context helpers', () => {
  test('siblings are the other live processes with the same original parent', () => {
    const m = story([['201:1', decoder(10)], ['202:1', reader('/bin/bash', ['bash'], 11)]]);
    const p = m.processes.get('202:1')!;
    expect(siblings(m, p).map(s => s.id)).toEqual(['201:1']);
    expect(siblings(m, m.processes.get('100:1')!)).toEqual([]);
  });
  test('underAgentShell sees the three agents\' snapshot folders and nothing else', () => {
    const under = (arg: string): boolean => {
      const m = story([['201:1', decoder(10)]], apple('/bin/zsh', ['zsh', '-c', `source ${arg}`], { seq: 1 }));
      return underAgentShell(m, m.processes.get('201:1')!);
    };
    expect(under('/Users/u/.claude/shell-snapshots/s.sh')).toBe(true);
    expect(under('/Users/u/.codex/shell_snapshots/s.sh')).toBe(true);
    expect(under('/Users/u/.cursor/shell-snapshots/s.sh')).toBe(true);
    expect(under('/Users/u/.zshrc')).toBe(false);
    expect(under('/Users/u/claude/shell-snapshots/s.sh')).toBe(false);
  });
});
