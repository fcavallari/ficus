import { describe, expect, test } from 'vitest';
import { fileLedger } from '../src/rules/ledger';
import type { FileOp } from '../src/model/types';
import { capture, img, proc } from './synth';

const fileOp = (kind: FileOp['kind'], path: string, seq: number, time: string | null = '2026-11-12T00:00:05.000Z', toPath?: string): FileOp =>
  ({ kind, path, ...(toPath !== undefined ? { toPath } : {}), time: time as string, seq });
const ledgerOf = (...ops: FileOp[]) => fileLedger(capture([proc('100:1', [img({})], { fileOps: ops })]));

describe('fileLedger', () => {
  test('create and rename destinations are drops', () => {
    const l = ledgerOf(
      fileOp('create', '/tmp/a', 3),
      fileOp('rename', '/tmp/stage', 4, '2026-11-12T00:00:06.000Z', '/tmp/b'),
      fileOp('write', '/tmp/c', 5),
    );
    expect(l.drops.get('/tmp/a')).toEqual([{ path: '/tmp/a', writer: '100:1', seq: 3, ms: Date.parse('2026-11-12T00:00:05.000Z') }]);
    expect(l.drops.get('/tmp/b')).toEqual([{ path: '/tmp/b', writer: '100:1', seq: 4, ms: Date.parse('2026-11-12T00:00:06.000Z') }]);
    expect([...l.drops.keys()].sort()).toEqual(['/tmp/a', '/tmp/b']);
  });
  test.each([
    ['create', '/private/tmp/Lab/Stage', '/tmp/lab/stage'],
    ['rename', '/tmp/lab/stage', '/private/tmp/LAB/STAGE'],
    ['rename', '/tmp/x', '/users/u/Downloads/X'],
  ])('keys ignore case and /private: %s %s', (kind, a, b) => {
    const l = fileLedger(capture([
      proc('100:1', [img({})], { fileOps: [kind === 'create' ? fileOp('create', a, 3) : fileOp('rename', a, 3, undefined, b)] }),
    ]));
    const key = (kind === 'create' ? a : b).replace(/^\/private/, '').replace(/^\/users\//, '/Users/').toLowerCase();
    expect([...l.drops.keys()]).toEqual([key]);
    expect(l.drops.get(key)![0]!.path).toBe(kind === 'create' ? a : b);
  });
  test('unlinks are indexed separately', () => {
    const l = ledgerOf(fileOp('unlink', '/tmp/A', 7, '2026-11-12T00:00:09.000Z'));
    expect(l.drops.size).toBe(0);
    expect(l.unlinks.get('/tmp/a')).toEqual([{ seq: 7, ms: Date.parse('2026-11-12T00:00:09.000Z') }]);
  });
  test('a null time gives ms null', () => {
    const l = ledgerOf(fileOp('create', '/tmp/a', 3, null), fileOp('unlink', '/tmp/a', 4, null));
    expect(l.drops.get('/tmp/a')![0]!.ms).toBeNull();
    expect(l.unlinks.get('/tmp/a')![0]!.ms).toBeNull();
  });
  test('a rename without a destination is skipped', () => {
    expect(ledgerOf(fileOp('rename', '/tmp/a', 3)).drops.size).toBe(0);
  });
  test('the ledger is built once per model', () => {
    const m = capture([proc('100:1', [img({})], { fileOps: [fileOp('create', '/tmp/a', 3)] })]);
    expect(fileLedger(m)).toBe(fileLedger(m));
    expect(fileLedger(capture([]))).not.toBe(fileLedger(m));
  });
});
