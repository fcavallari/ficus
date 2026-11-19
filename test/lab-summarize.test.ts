import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { compare, countDrops, filterUnder, findingsTsv, gapMarkdown, linesOf, parseExpected, schemaNotes, summarize, type FindingRow } from '../lab/summarize-core';
import { RULES } from '../src/rules/rules';

// lab/summarize-core.ts turns a lab capture into findings (through Ficus's own model and rules) and compares them with the
// behaviors public reports say the sample shows.
const SYNTHETIC = execFileSync('/bin/bash', [path.resolve(__dirname, '..', 'scripts', 'ficus-lab.sh'), 'synthetic', '--stdout'], { maxBuffer: 16 << 20 })
  .toString('utf8').split('\n');
const UNMODELLED = fs.readFileSync(path.resolve(__dirname, 'fixtures', 'lab-unmodelled-events.jsonl'), 'utf8').split('\n');

const row = (ruleId: string, severity: FindingRow['severity'] = 'med', extra: Partial<FindingRow> = {}): FindingRow =>
  ({ ruleId, severity, process: '/bin/x', evidence: 'e', mitre: [], queued: true, lineage: [], ...extra });
const HEADER = 'behavior\tmitre\trule\tsource';

describe('summarize', () => {
  const s = summarize(SYNTHETIC);

  test('a clean capture loads with no bad lines and reports its schema version', () => {
    expect(s.badLines).toBe(0);
    expect(s.versions).toEqual([11]);
    expect(s.events).toBeGreaterThan(0);
    expect(s.processes).toBeGreaterThan(0);
  });

  test('there is a row for every rule, bar the one that needs a published family name', () => {
    const fired = new Set(s.rows.map(r => r.ruleId));
    expect(RULES.map(r => r.id).filter(id => id !== 'known-indicator' && !fired.has(id))).toEqual([]);
  });

  test('every row names its process and evidence, and both queued and context rows appear', () => {
    for (const r of s.rows) {
      expect(['high', 'med', 'low']).toContain(r.severity);
      expect(r.process, r.ruleId).not.toBe('');
      expect(r.evidence, r.ruleId).not.toBe('');
    }
    expect(s.rows.some(r => r.queued)).toBe(true);
    expect(s.rows.some(r => !r.queued)).toBe(true);
  });

  test('a finding is labelled with the program it is about, not the shell that started it', () => {
    const strip = s.rows.find(r => r.ruleId === 'quarantine-strip');
    expect(strip?.evidence).toContain('xattr');
    expect(strip?.process).toMatch(/xattr$/);
  });

  test('a launch-item finding is labelled with the plist it is about', () => {
    const items = s.rows.filter(r => r.ruleId === 'persistence-item');
    expect(items.length).toBeGreaterThan(0);
    expect(items.some(r => /LaunchAgents|LaunchDaemons|\.plist/.test(r.process))).toBe(true);
  });

  test('events Ficus does not model (signal, mount, tcc_modify, xp_malware_detected and others) load with zero bad lines', () => {
    const u = summarize(UNMODELLED);
    expect(u.badLines).toBe(0);
    for (const kind of ['signal', 'mount', 'uipc_connect', 'tcc_modify', 'xp_malware_detected']) expect(u.otherEvents[kind] ?? 0, kind).toBeGreaterThan(0);
  });

  test('it accepts any iterable of lines, not only an array', () => {
    function* gen() { yield* SYNTHETIC; }
    expect(summarize(gen()).rows).toHaveLength(s.rows.length);
  });

  test('a capture with holes in its sequence numbers reports them', () => {
    const lines = SYNTHETIC.filter(l => l !== '');
    const withoutOne = [...lines.slice(0, 3), ...lines.slice(4)];
    expect(summarize(withoutOne).seqGaps).toBeGreaterThan(0);
    expect(s.seqGaps).toBe(0);
  });
});

describe('lineage and filterUnder', () => {
  const s = summarize(SYNTHETIC);

  test('a process finding carries the programs of its ancestors, nearest first; a launch-item finding has none', () => {
    const withLineage = s.rows.filter(r => r.lineage.length > 0);
    expect(withLineage.length).toBeGreaterThan(0);
    for (const r of withLineage) for (const p of r.lineage) expect(p, r.ruleId).not.toBe('');
  });

  test('keeps the process itself and its descendants, and drops the rest', () => {
    const parent = s.rows.find(r => r.lineage.length > 0)!.lineage[0]!;
    const kept = filterUnder(s.rows, parent);
    expect(kept.length).toBeGreaterThan(0);
    expect(kept.length).toBeLessThan(s.rows.length);
    for (const r of kept) expect(r.process.includes(parent) || r.lineage.some(p => p.includes(parent)), r.evidence).toBe(true);
    const dropped = s.rows.filter(r => !kept.includes(r));
    for (const r of dropped) expect(r.process.includes(parent) || r.lineage.some(p => p.includes(parent))).toBe(false);
  });

  test('a program that is nowhere in the capture keeps nothing, and an empty needle is refused', () => {
    expect(filterUnder(s.rows, 'no-such-program-anywhere')).toEqual([]);
    expect(() => filterUnder(s.rows, '')).toThrow(/--under/);
  });

  test('a comparison on the filtered rows does not count the guest\'s own activity as a hit', () => {
    const rows = [row('recon', 'low', { process: '/usr/bin/ps', lineage: ['/usr/libexec/tart-guest-agent'] }),
      row('dscl-authonly', 'high', { process: '/usr/bin/dscl', lineage: ['/tmp/sample/Helper', '/bin/bash'] })];
    const mine = filterUnder(rows, '/tmp/sample/Helper');
    const c = compare(mine, [{ behavior: 'Fingerprints the Mac', mitre: 'x', rule: 'recon', source: 's' }]);
    expect(c.hit).toEqual([]);
    expect(c.miss).toHaveLength(1);
    expect(c.review.map(r => r.ruleId)).toEqual(['dscl-authonly']);
  });
});

describe('countDrops', () => {
  const ev = (type: string, seq: number) => JSON.stringify({ event: { [type]: {} }, seq_num: seq });

  test('finds holes in each event type\'s own sequence, counting from zero', () => {
    const d = countDrops([ev('exec', 0), ev('exec', 1), ev('exec', 3), ev('fork', 2), ev('fork', 3), ev('create', 0)]);
    expect(d.byType).toEqual({ exec: 1, fork: 2 }); // fork starts at 2: events 0 and 1 are missing
    expect(d.total).toBe(3);
  });

  test('ignores close, which the harness filters on purpose', () => {
    expect(countDrops([ev('close', 5), ev('close', 900)]).total).toBe(0);
    expect(countDrops([ev('close', 5), ev('close', 900)], []).total).toBeGreaterThan(0);
  });

  test('skips blank lines, lines that are not JSON and records without a sequence number', () => {
    expect(countDrops(['', 'not json', '{"event":{"exec":{}}}', ev('exec', 0), ev('exec', 1)]).total).toBe(0);
  });

  test('a complete capture has no drops', () => {
    expect(countDrops([ev('exec', 0), ev('exec', 1), ev('exec', 2)]).total).toBe(0);
  });
});

describe('schemaNotes', () => {
  test('says which checks cannot fire below schema 11, and nothing at 11', () => {
    expect(schemaNotes([10]).join(' ')).toMatch(/schema 10.*shell-from-pipe.*reverse-shell/);
    expect(schemaNotes([11])).toEqual([]);
    expect(schemaNotes([10, 11])).not.toEqual([]);
  });
});

describe('parseExpected', () => {
  test('reads rows, skipping comments and blank lines', () => {
    const rows = parseExpected(`# a note\n${HEADER}\n\n# another\nDrops a launch agent\tT1543.001\tpersistence-plist\tObjective-See blog\nEncrypts files\tT1486\t-\tTAOMM ch. 9\n`);
    expect(rows).toEqual([
      { behavior: 'Drops a launch agent', mitre: 'T1543.001', rule: 'persistence-plist', source: 'Objective-See blog' },
      { behavior: 'Encrypts files', mitre: 'T1486', rule: '-', source: 'TAOMM ch. 9' },
    ]);
  });

  test('rejects a wrong header', () => {
    expect(() => parseExpected('behaviour\tmitre\trule\tsource\n')).toThrow(/header/);
  });

  test('rejects a row with too few columns, naming the line', () => {
    expect(() => parseExpected(`${HEADER}\nDrops a thing\tT1\tdownload\n`)).toThrow(/line 2/);
  });

  test('rejects a rule id that does not exist, so a typo is not read as a miss', () => {
    expect(() => parseExpected(`${HEADER}\nx\tT1\treverse-shel\ts\n`)).toThrow(/reverse-shel/);
  });
});

describe('compare', () => {
  const exp = (rule: string, behavior = rule) => ({ behavior, mitre: 'T1', rule, source: 's' });

  test('a rule that fired is a hit, one that did not is a miss, a behavior with no rule yet is a gap', () => {
    const c = compare([row('download')], [exp('download'), exp('timestomp'), exp('-', 'Encrypts files')]);
    expect(c.hit.map(r => r.rule)).toEqual(['download']);
    expect(c.miss.map(r => r.rule)).toEqual(['timestomp']);
    expect(c.gap.map(r => r.behavior)).toEqual(['Encrypts files']);
  });

  test('a high finding whose rule no expected row names is listed for review', () => {
    const c = compare([row('quarantine-strip', 'high'), row('download', 'high'), row('recon', 'low'), row('unsigned', 'med')], [exp('download')]);
    expect(c.review.map(r => r.ruleId)).toEqual(['quarantine-strip']);
  });

  test('a context-only finding still counts as a hit', () => {
    expect(compare([row('timestomp', 'low', { queued: false })], [exp('timestomp')]).hit).toHaveLength(1);
  });

  test('no expected rows: nothing hit, every high finding for review', () => {
    const c = compare([row('a', 'high')], []);
    expect([c.hit, c.miss, c.gap]).toEqual([[], [], []]);
    expect(c.review).toHaveLength(1);
  });
});

describe('gapMarkdown', () => {
  test('has the four sections in order, writes "none" for an empty one, and keeps a pipe inside a cell', () => {
    const c = compare([row('quarantine-strip', 'high', { evidence: 'xattr -c a|b' })], [{ behavior: 'Strips | quarantine', mitre: 'T1553.001', rule: 'quarantine-strip', source: 's' }]);
    const md = gapMarkdown('Banshee', c);
    expect(md).toContain('# Banshee');
    const at = ['## Hit', '## Miss', '## Gap', '## Review'].map(h => md.indexOf(h));
    expect(at.every(i => i >= 0)).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
    expect(md.slice(md.indexOf('## Miss'), md.indexOf('## Gap')).split('\n')).toContain('none');
    expect(md.slice(md.indexOf('## Hit'), md.indexOf('## Miss')).split('\n')).not.toContain('none');
    expect(md).toContain('Strips \\| quarantine');
    // every table row has four cells: five separators once the escaped pipes are taken out
    for (const line of md.split('\n').filter(l => l.startsWith('| '))) expect(line.replace(/\\\|/g, '').split('|').length, line).toBe(6);
  });
});

describe('gapMarkdown scope', () => {
  test('says whether the findings were limited to the sample\'s process tree', () => {
    const c = compare([], []);
    expect(gapMarkdown('X', c)).toContain('All findings in the capture were compared');
    expect(gapMarkdown('X', c, '/tmp/s/Helper')).toContain('process tree under `/tmp/s/Helper`');
  });
});

describe('findingsTsv', () => {
  test('is one line per finding with five columns, whatever the evidence holds', () => {
    const tsv = findingsTsv([row('download', 'med', { evidence: 'a\tb\nc' })]);
    const lines = tsv.trimEnd().split('\n');
    expect(lines[0]).toBe('queued\trule\tseverity\tprocess\tevidence');
    expect(lines).toHaveLength(2);
    expect(lines[1]!.split('\t')).toHaveLength(5);
  });
});

describe('linesOf', () => {
  test('yields every line of a file across chunk boundaries, with multi-byte characters intact and a last line with no newline', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-sum-'));
    try {
      const f = path.join(dir, 'x.jsonl');
      fs.writeFileSync(f, 'alpha\nbéta 😀 end\r\n\ngamma');
      for (const chunk of [1, 3, 7, 1 << 20]) expect([...linesOf(f, chunk)], `chunk ${chunk}`).toEqual(['alpha', 'béta 😀 end', '', 'gamma']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
