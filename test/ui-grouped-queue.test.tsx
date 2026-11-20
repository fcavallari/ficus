// @vitest-environment jsdom
import 'fake-indexeddb/auto';
import '@testing-library/jest-dom/vitest';
import { IDBFactory } from 'fake-indexeddb';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { LoadedCapture } from '../src/ingest/load';
import { runLoad } from '../src/ingest/run';
import { analyze } from '../src/rules/engine';
import { SessionProvider, useSession, type SessionCtx } from '../src/ui/App';
import { ConfirmedTab } from '../src/ui/ConfirmedTab';
import { TriageView } from '../src/ui/TriageView';
import { openStore } from '../src/session/store';
import { children, world } from './group-fixture';

// The queue shows a grouped row once, with its count; any member selects it; the detail pane lists the members.
vi.mock('../src/ingest/run', () => ({ runLoad: vi.fn() }));
const runLoadMock = vi.mocked(runLoad);

let ctx: SessionCtx;
function Probe() { ctx = useSession(); return null; }

const alone = world(children(1, ['--other'], 300));
const m = world([...children(3), ...children(1, ['--other'], 300)]);
const make = (model: typeof m): LoadedCapture => ({ fingerprint: 'fp-ui', fileName: 'loop.jsonl', size: 1, model, analysis: analyze(model) });

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
  runLoadMock.mockReset();
});
afterEach(cleanup);

async function open(model: typeof m = m, extra: ReactNode = null): Promise<void> {
  runLoadMock.mockImplementation(async () => make(model));
  const store = await openStore();
  const s = await store.createSession('ui');
  render(<SessionProvider store={store}><Probe /><TriageView />{extra}</SessionProvider>);
  await waitFor(() => { expect(ctx).toBeDefined(); });
  await act(async () => { await ctx.openSession(s.id); });
  await act(async () => { await ctx.loadFiles([new File(['x'], 'loop.jsonl')]); });
}
const options = () => screen.getAllByRole('option');

test('a group is one row with its count, and a row of one process has none', async () => {
  await open();
  const rows = options().filter(o => /helper/.test(o.textContent ?? ''));
  expect(rows).toHaveLength(2);
  expect(rows.filter(r => r.textContent?.includes('×3'))).toHaveLength(1);
  expect(rows.filter(r => r.textContent?.includes('×'))).toHaveLength(1);
});

test('a capture with no repeats shows no count', async () => {
  await open(alone);
  expect(options().some(o => o.textContent?.includes('×'))).toBe(false);
});

test('selecting any member selects the group row, and the detail pane lists the members', async () => {
  await open();
  act(() => { ctx.selectProc('202:1'); });
  const row = options().find(o => o.textContent?.includes('×3'))!;
  await waitFor(() => { expect(row).toHaveAttribute('aria-selected', 'true'); });
  const pane = screen.getByRole('region', { name: 'Selected process' });
  expect(within(pane).getByRole('heading', { name: /Repeated 3 times/ })).toBeInTheDocument();
  // Each member is a button; choosing one selects that process.
  const members = within(pane).getAllByRole('button', { name: /^pid 20[012]/ });
  expect(members).toHaveLength(3);
  fireEvent.click(members[1]!);
  expect(ctx.selected).toBe('201:1');
  expect(row).toHaveAttribute('aria-selected', 'true');
});

test('j and k move on from a member of a group', async () => {
  await open();
  act(() => { ctx.selectProc('201:1'); });
  const before = options().findIndex(o => o.textContent?.includes('×3'));
  fireEvent.keyDown(window, { key: 'j' });
  await waitFor(() => { expect(options()[before + 1]).toHaveAttribute('aria-selected', 'true'); });
});

test('a process that is alone has no member list', async () => {
  await open();
  act(() => { ctx.selectProc('300:1'); });
  const pane = screen.getByRole('region', { name: 'Selected process' });
  expect(within(pane).queryByRole('heading', { name: /Repeated/ })).toBeNull();
});

test('the Suspicious tab lists a confirmed group once, with its count', async () => {
  await open(m, <ConfirmedTab />);
  await act(async () => { await ctx.toggleVerdict('200:1', 'confirmed'); });
  const list = screen.getByRole('list', { name: 'Suspicious processes' });
  const items = within(list).getAllByRole('listitem');
  expect(items).toHaveLength(1);
  expect(items[0]).toHaveTextContent('×3');
  expect(screen.getByRole('heading', { name: /Marked suspicious in this session/ })).toHaveTextContent('1');
});
