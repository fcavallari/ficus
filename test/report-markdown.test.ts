import { expect, test } from 'vitest';
import { buildModel } from '../src/model/builder';
import { reportMarkdown, text } from '../src/report/markdown';
import { buildReport, type Report, type ReportRow } from '../src/report/report';
import { readLines } from './fixtures';
import { procByPid, queued } from './helpers';
import { GEN, input, lab, verdict } from './report-fixture';

const build = (over: Parameters<typeof input>[0] = {}, redactArgs = false): Report =>
  buildReport(input(over), { redactArgs, generated: GEN });
const allRows = (r: Report): ReportRow[] => r.captures.flatMap(c => [...(c.rows ?? []), ...(c.userMarked ?? [])]);
const { m, a } = queued('synthetic-lab.jsonl');
const gone = { ...input().capRecs[0]!, fingerprint: 'gone', fileName: 'gone.jsonl' };
const SECTION = { high: '## High', med: '## Medium', low: '## Low' } as const;
const USER = '## Marked by the user, not flagged by the rules';

test('snapshot of the lab report', () => {
  const r = build({ verdicts: [verdict('fp', procByPid(m, 7006).id, 'confirmed', 'asked for my password'), verdict('fp', procByPid(m, 7001).id, 'benign')] });
  expect(reportMarkdown(r)).toMatchSnapshot();
});

test('the Markdown agrees with the JSON: every row under its own section', () => {
  const queuedIds = new Set(a.queue.map(q => q.procId));
  const unflagged = [...m.processes.values()].find(x => !queuedIds.has(x.id) && !x.ghost)!;
  const r = build({ verdicts: [verdict('fp', unflagged.id, 'confirmed', 'odd')] });
  const lines = reportMarkdown(r).split('\n');
  for (const row of allRows(r)) {
    const at = lines.findIndex(l => l.startsWith(`### ${row.n}. ${text(row.name)}`));
    expect(at, `row ${row.n}`).toBeGreaterThan(-1);
    const section = lines.slice(0, at).reverse().find(l => l.startsWith('## '));
    expect(section, `row ${row.n}`).toBe(row.severity === null ? USER : SECTION[row.severity]);
  }
});

test('escapes hostile capture text', () => {
  const r = build({ verdicts: [verdict('fp', procByPid(m, 7006).id, 'confirmed', 'see [here](http://evil.example)\n# not a heading')] });
  const row = allRows(r).find(x => x.process?.pid === 7006)!;
  row.name = 'a`b|c[x](http://e)<script>\n# h';
  row.findings[0]!.title = 'T *bold* <img src=x>';
  const img = row.process!.images[row.process!.images.length - 1]!;
  img.path = '/tmp/`weird` path\nnext';
  const md = reportMarkdown(r);
  const headings = md.split('\n').filter(l => l.startsWith('#'));
  for (const h of headings) expect(h).toMatch(/^(# Gameleira report: |## |### \d+\. )/);
  expect(md).not.toMatch(/(?<!\\)\]\(http/);
  expect(md).not.toMatch(/(?<![\\`])<script/);
  expect(md).not.toMatch(/(?<![\\`])<img/);
  expect(md).toContain('``/tmp/`weird` path⏎next``');
});

test('renders an empty report', () => {
  const md = reportMarkdown(build({ loaded: new Map([['fp', { ...lab(), analysis: { ...a, queue: [] } }]]) }));
  expect(md).toContain('No flagged rows.');
  expect(md).toContain('## Captures');
  expect(md).not.toContain('## High');
});

test('says whether command lines are redacted', () => {
  expect(reportMarkdown(build({}, true))).toContain('Command-line arguments are redacted.');
  expect(reportMarkdown(build({}, false))).not.toContain('Command-line arguments are redacted.');
  expect(reportMarkdown(build({}, false))).toContain('Command lines are complete and may contain secrets.');
});

test('names a capture that is not loaded before the capture list', () => {
  const md = reportMarkdown(build({ capRecs: [...input().capRecs, gone], verdicts: [verdict('gone', 'p1', 'confirmed', '', { name: 'evil' })] }));
  const warn = md.indexOf('gone.jsonl');
  expect(warn).toBeGreaterThan(-1);
  expect(warn).toBeLessThan(md.indexOf('## Captures'));
  expect(md).toContain('## Captures not loaded');
});

test('redacted Markdown holds no secret: loaded, not loaded, and cut in half', () => {
  const over = { capRecs: [...input().capRecs, gone],
    verdicts: [verdict('gone', 'p1', 'confirmed', '', { args: ['dscl', '.', '-authonly', 'labuser', 'labpass-not-real'] })] };
  expect(reportMarkdown(build(over, true))).not.toContain('labpass-not-real');
  expect(reportMarkdown(build(over, false))).toContain('labpass-not-real');
  const fresh = buildModel(readLines('synthetic-lab.jsonl'));
  procByPid(fresh, 7016).images.find(i => i.args?.[0] === 'dscl')!.args = ['dscl', '.', '-authonly', 'labuser', 'x'.repeat(280) + 'SECRETSECRETSECRET'];
  const md = reportMarkdown(build({ loaded: new Map([['fp', lab('fp', fresh)]]) }, true));
  expect(md).not.toContain('xxxxxxxxxx');
  expect(md).not.toContain('SECRET');
});

test('a process known only by its pid is named once, without the pid repeated', () => {
  expect(reportMarkdown(build())).not.toMatch(/pid (\d+)[^\n(]*\(pid \1\)/);
});

test('Program describes the program the row is named after; a command line from an earlier exec says so', () => {
  const fresh = buildModel(readLines('synthetic-lab.jsonl'));
  const p = procByPid(fresh, 7016);
  const last = p.images[p.images.length - 1]!;
  p.images.push({ ...last, path: '/tmp/evil', signingId: null, teamId: null, isPlatform: false, csFlags: 0, args: null,
    cwd: null, env: null, script: null, stdinIsPipe: null, seq: last.seq + 1, inherited: false });
  const md = reportMarkdown(build({ loaded: new Map([['fp', lab('fp', fresh)]]) }));
  const section = md.slice(md.indexOf('evil (pid 7016)'));
  const block = section.slice(0, section.indexOf('\n### '));
  expect(block).toContain('- **Program:** `/tmp/evil`, unsigned');
  expect(block).toContain('- **Command line** (of `/usr/bin/dscl`, the last exec captured): `dscl . -authonly labuser labpass-not-real`');
});
