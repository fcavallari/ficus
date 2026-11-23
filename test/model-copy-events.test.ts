import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import type { CaptureModel, FileOp, Image } from '../src/model/types';
import { analyze } from '../src/rules/engine';
import { fileLedger } from '../src/rules/ledger';
import { processTimeline } from '../src/ui/timeline';
import { capture, img, proc } from './synth';

// `clone` (APFS clonefile) and `copyfile` events are how `cp`, Finder and a stealer's own code copy files on a modern Mac.
// They are modelled as one file operation, kind 'copy': path is the source, toPath the destination.
const CLONE_LINE = fs.readFileSync(path.resolve(__dirname, 'fixtures', 'lab-unmodelled-events.jsonl'), 'utf8')
  .split('\n').find(l => l.includes('"clone"'))!;

/** The real clone line, turned into a copyfile event (and optionally given a target file). */
function copyfileLine(targetFile: string | null): string {
  const o = JSON.parse(CLONE_LINE) as { event: Record<string, Record<string, unknown>> };
  const c = o.event.clone!;
  o.event = { copyfile: { source: c.source, target_file: targetFile === null ? null : { path: targetFile, path_truncated: false },
    target_dir: c.target_dir, target_name: c.target_name, mode: 33188, flags: 0 } };
  return JSON.stringify(o);
}

const copyOps = (m: CaptureModel): FileOp[] => [...m.processes.values()].flatMap(p => p.fileOps).filter(o => o.kind === 'copy');

describe('clone and copyfile events', () => {
  test('a clone is a copy from the source to target_dir/target_name', () => {
    const m = buildModel([CLONE_LINE]);
    const ops = copyOps(m);
    expect(ops).toHaveLength(1);
    expect(ops[0]).toMatchObject({
      kind: 'copy', via: 'clone',
      path: '/Users/admin/Library/Metadata/CoreSpotlight/Priority/index.spotlightV3/.store.db',
      toPath: '/Users/admin/Library/Metadata/CoreSpotlight/Priority/index.spotlightV3/store.db.tmp',
    });
  });

  test('it is a modelled event: counted as clone, not as an event the viewer does not model', () => {
    const m = buildModel([CLONE_LINE]);
    expect(m.stats.kinds?.clone).toBe(1);
    expect(m.stats.otherEvents.clone).toBeUndefined();
  });

  test('a copyfile into a file that exists names that file; into a new name it is target_dir/target_name', () => {
    const existing = copyOps(buildModel([copyfileLine('/tmp/already/there.db')]));
    expect(existing[0]).toMatchObject({ kind: 'copy', via: 'copyfile', toPath: '/tmp/already/there.db' });
    const fresh = copyOps(buildModel([copyfileLine(null)]));
    expect(fresh[0]).toMatchObject({ via: 'copyfile', toPath: '/Users/admin/Library/Metadata/CoreSpotlight/Priority/index.spotlightV3/store.db.tmp' });
  });

  test('a copy with no usable destination is not recorded', () => {
    const o = JSON.parse(CLONE_LINE) as { event: { clone: Record<string, unknown> } };
    delete o.event.clone.target_name;
    expect(copyOps(buildModel([JSON.stringify(o)]))).toHaveLength(0);
  });

  test('the timeline shows it with its source and destination', () => {
    const m = buildModel([CLONE_LINE]);
    const p = [...m.processes.values()].find(x => x.fileOps.length > 0)!;
    const e = processTimeline({ model: m, analysis: analyze(m), fingerprint: 'f', fileName: 'x', size: 1 }, p.id, false).events.find(x => x.kind === 'copy')!;
    expect(e.path).toContain('.store.db');
    expect(e.toPath).toContain('store.db.tmp');
  });
});

describe('what the rules do with a copy', () => {
  const unsigned = (p: string): Image => img({ path: p, signingId: null, args: [p], seq: 1 });
  const signed = (p: string): Image => img({ path: p, signingId: 'com.example.tool', teamId: 'ABCDE12345', args: [p], seq: 1 });
  const copy = (from: string, to: string, seq = 2): FileOp => ({ kind: 'copy', path: from, toPath: to, time: '2026-11-12T00:00:01.000Z', seq, via: 'clone' });
  const story = (image: Image, fileOps: FileOp[]): CaptureModel => capture([proc('100:1', [image], { fileOps })]);
  const findings = (m: CaptureModel, rule: string) => analyze(m).queue.flatMap(q => q.findings).filter(f => f.ruleId === rule);
  const LOGIN_DATA = '/Users/u/Library/Application Support/Google/Chrome/Default/Login Data';

  test('credential-store-copy: a browser store cloned to an unrelated name in a staging place', () => {
    const f = findings(story(unsigned('/Users/u/Downloads/s/x'), [copy(LOGIN_DATA, '/tmp/stage/d1')]), 'credential-store-copy');
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toContain(LOGIN_DATA);
    expect(f[0]!.evidence).toContain('browser logins or cookies');
    expect(f[0]!.severity).toBe('high');
  });

  test('credential-store-copy: a signed program copying a store to an ordinary folder is left alone', () => {
    expect(findings(story(signed('/Applications/Backup.app/Contents/MacOS/Backup'), [copy(LOGIN_DATA, '/Users/u/Backups/d1')]), 'credential-store-copy')).toHaveLength(0);
  });

  test('credential-store-copy: an SSH key cloned to an unrelated name in a staging place, and cloned away by an unsigned program', () => {
    expect(findings(story(unsigned('/Users/u/Downloads/s/x'), [copy('/Users/u/.ssh/id_rsa', '/tmp/loot/k1')]), 'credential-store-copy')).toHaveLength(1);
    expect(findings(story(unsigned('/Users/u/Downloads/s/x'), [copy('/Users/u/.ssh/id_rsa', '/Users/u/Documents/k1')]), 'credential-store-copy')).toHaveLength(1);
    expect(findings(story(signed('/usr/bin/tool'), [copy('/Users/u/.ssh/id_rsa', '/Users/u/Documents/k1')]), 'credential-store-copy')).toHaveLength(0);
  });

  test('credential-store-copy: the destination named like a store counts once, even with a create beside the copy', () => {
    const ops: FileOp[] = [
      { kind: 'create', path: '/tmp/stage/Login Data', time: '2026-11-12T00:00:01.000Z', seq: 2 },
      copy(LOGIN_DATA, '/tmp/stage/Login Data', 3),
    ];
    const f = findings(story(unsigned('/Users/u/Downloads/s/x'), ops), 'credential-store-copy');
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence.match(/Login Data \(browser/g)).toHaveLength(1);
  });

  test('persistence-plist: a plist cloned into LaunchAgents is a plist written there', () => {
    const f = findings(story(unsigned('/Users/u/Downloads/s/x'), [copy('/tmp/a.plist', '/Users/u/Library/LaunchAgents/com.evil.plist')]), 'persistence-plist');
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toContain('/Users/u/Library/LaunchAgents/com.evil.plist');
  });

  test('the file ledger counts the destination of a copy as a file that appeared', () => {
    const m = story(unsigned('/Users/u/Downloads/s/x'), [copy('/tmp/a', '/tmp/b')]);
    expect(fileLedger(m).drops.get('/tmp/b')).toHaveLength(1);
    expect(fileLedger(m).drops.get('/tmp/a')).toBeUndefined();
  });

  test('mass-rename ignores copies: ten clones to one new extension are not renames', () => {
    const ops = Array.from({ length: 12 }, (_, i) => copy(`/Users/u/Documents/f${i}.txt`, `/Users/u/Documents/f${i}.txt.locked`, 2 + i));
    expect(findings(story(unsigned('/Users/u/Downloads/s/x'), ops), 'mass-rename')).toHaveLength(0);
  });
});
