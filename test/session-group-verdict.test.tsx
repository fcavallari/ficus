// @vitest-environment jsdom
import 'fake-indexeddb/auto';
import '@testing-library/jest-dom/vitest';
import { IDBFactory } from 'fake-indexeddb';
import { act, cleanup, render, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import { runLoad } from '../src/ingest/run';
import { analyze } from '../src/rules/engine';
import { SessionProvider, useSession, type SessionCtx } from '../src/ui/App';
import { openStore, type Store } from '../src/session/store';
import { children, world } from './group-fixture';

// A verdict on a grouped queue row covers every process the row stands for.
vi.mock('../src/ingest/run', () => ({ runLoad: vi.fn() }));
const runLoadMock = vi.mocked(runLoad);

let ctx: SessionCtx;
function Probe() { ctx = useSession(); return null; }

const m = world([...children(3), ...children(1, ['--other'], 300)]);
const loaded = (): LoadedCapture => ({ fingerprint: 'fp-group', fileName: 'loop.jsonl', size: 1, model: m, analysis: analyze(m) });

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
  runLoadMock.mockReset();
  runLoadMock.mockImplementation(async () => loaded());
});
afterEach(cleanup);

async function open(): Promise<Store> {
  const store = await openStore();
  const s = await store.createSession('group');
  render(<SessionProvider store={store}><Probe /></SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  await act(async () => { await ctx.loadFiles([new File(['x'], 'loop.jsonl')]); });
  return store;
}
const status = (id: string) => ctx.verdicts.get(id)?.status ?? 'unreviewed';

test('toggling a grouped row sets every member, and undo gives each member its own previous status back', async () => {
  await open();
  const row = ctx.capture!.analysis.queue.find(q => q.members.length === 3)!;
  expect(row.members).toEqual(['200:1', '201:1', '202:1']);
  await act(async () => { await ctx.setVerdict('201:1', 'benign'); });   // an earlier verdict on one member only
  expect(row.members.map(status)).toEqual(['unreviewed', 'benign', 'unreviewed']);

  await act(async () => { await ctx.toggleVerdict('200:1', 'confirmed'); });
  expect(row.members.map(status)).toEqual(['confirmed', 'confirmed', 'confirmed']);
  expect(status('300:1')).toBe('unreviewed');   // a different row is untouched

  await act(async () => { await ctx.undoLastVerdict(); });
  expect(row.members.map(status)).toEqual(['unreviewed', 'benign', 'unreviewed']);
});

test('pressing the verdict on any member acts on the whole group', async () => {
  await open();
  await act(async () => { await ctx.toggleVerdict('202:1', 'benign'); });
  expect(['200:1', '201:1', '202:1'].map(status)).toEqual(['benign', 'benign', 'benign']);
  await act(async () => { await ctx.toggleVerdict('202:1', 'benign'); });   // the representative says benign, so this takes it back
  expect(['200:1', '201:1', '202:1'].map(status)).toEqual(['unreviewed', 'unreviewed', 'unreviewed']);
});

test('a note belongs to the one process it was written on', async () => {
  const store = await open();
  await act(async () => { await ctx.setNote('201:1', 'second pass', ctx.active!); });
  await act(async () => { await ctx.toggleVerdict('200:1', 'confirmed'); });
  const notes = new Map((await store.listVerdicts(ctx.session!.id, ctx.active!)).map(v => [v.procKey, v.note]));
  expect(notes.get('201:1')).toBe('second pass');
  expect(notes.get('200:1')).toBe('');
});

test('a row of one process behaves as before', async () => {
  await open();
  await act(async () => { await ctx.toggleVerdict('300:1', 'confirmed'); });
  expect(['200:1', '201:1', '202:1', '300:1'].map(status)).toEqual(['unreviewed', 'unreviewed', 'unreviewed', 'confirmed']);
  await act(async () => { await ctx.undoLastVerdict(); });
  expect(status('300:1')).toBe('unreviewed');
});
