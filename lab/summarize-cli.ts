// summarize-cli.ts: the command line for summarize-core. Built to dist-lab/lab-summarize.mjs with `npm run build:lab`.
//
//   node dist-lab/lab-summarize.mjs RUN_DIR [EXPECTED_TSV]
//
// RUN_DIR is a run folder from lab-run.sh (it holds capture.jsonl), or a capture file itself. Prints the findings as a table
// (tab-separated) on stdout; the facts about the capture and any notes go to stderr. With EXPECTED_TSV (see lab/expected/README.md)
// it also writes gap.md beside the capture. Exit 0 whatever the findings, 1 on a missing file or an unreadable expected file, 2 on usage.
import fs from 'node:fs';
import path from 'node:path';
import { compare, countDrops, findingsTsv, gapMarkdown, linesOf, parseExpected, schemaNotes, summarize } from './summarize-core';

const USAGE = 'usage: lab-summarize.mjs RUN_DIR [EXPECTED_TSV]\n';

function main(argv: string[]): number {
  if (argv.length < 1 || argv.length > 2 || argv.some(a => a.startsWith('-'))) { process.stderr.write(USAGE); return 2; }
  const [target, expectedFile] = argv as [string, string | undefined];
  const isFile = fs.existsSync(target) && fs.statSync(target).isFile();
  const dir = isFile ? path.dirname(target) : target;
  const capture = isFile ? target : path.join(target, 'capture.jsonl');
  if (!fs.existsSync(capture)) { process.stderr.write(`error: ${capture} does not exist\n`); return 1; }

  let expected;
  if (expectedFile !== undefined) {
    try { expected = parseExpected(fs.readFileSync(expectedFile, 'utf8')); }
    catch (e) { process.stderr.write(`error: ${expectedFile}: ${(e as Error).message}\n`); return 1; }
  }

  const s = summarize(linesOf(capture));
  const drops = countDrops(linesOf(capture));
  process.stdout.write(findingsTsv(s.rows));
  process.stderr.write(`events ${s.events}, processes ${s.processes}, schema ${s.versions.join('/') || 'unknown'}, bad lines ${s.badLines}, dropped events ${drops.total}, findings ${s.rows.length}\n`);
  for (const note of schemaNotes(s.versions)) process.stderr.write(`note: ${note}\n`);
  if (drops.total > 0) {
    process.stderr.write(`note: Endpoint Security dropped events while recording (${Object.entries(drops.byType).map(([t, n]) => `${t} ${n}`).join(', ')}); the capture is incomplete, so a miss may be a missing event\n`);
  }
  if (s.badLines > 0) process.stderr.write(`note: ${s.badLines} lines could not be read\n`);

  if (expected) {
    let family = path.basename(path.resolve(dir));
    try { family = (JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8')) as { family?: string }).family ?? family; } catch { /* no meta.json: the folder name will do */ }
    const c = compare(s.rows, expected);
    const out = path.join(dir, 'gap.md');
    fs.writeFileSync(out, gapMarkdown(family, c));
    process.stderr.write(`${out}: hit ${c.hit.length}, miss ${c.miss.length}, gap ${c.gap.length}, review ${c.review.length}\n`);
  }
  return 0;
}

process.exit(main(process.argv.slice(2)));
